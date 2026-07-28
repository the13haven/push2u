package io.push2u;

import static io.push2u.TestVectors.b64;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * End-to-end send-pipeline tests: a real {@link PushSender} (real RFC 8291 encryption + RFC 8292
 * VAPID + the JDK HTTP client) against an in-process {@link MockPushReceiver}, asserting the
 * status-code → {@link PushResult} mapping and the retry behaviour. A {@link RecordingSleeper}
 * runs the retry loop without real backoff delays.
 */
class PushSenderTest {

    private final RecordingSleeper sleeper = new RecordingSleeper();

    @Test
    void deliversOn201AndSendsAWellFormedRequest() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushResult result = pusher().send(
                subscription(receiver), PushMessage.builder(bytes("hello")).ttl(Duration.ofHours(1)).build());

            assertThat(result.delivered()).isTrue();
            assertThat(result.statusCode()).isEqualTo(201);
            assertThat(result.attempts()).isEqualTo(1);

            assertThat(receiver.requests()).hasSize(1);
            MockPushReceiver.RecordedRequest request = receiver.requests().getFirst();
            assertThat(request.method()).isEqualTo("POST");
            assertThat(request.headers())
                .containsEntry("content-encoding", "aes128gcm")
                .containsEntry("ttl", "3600");
            assertThat(request.headers().get("authorization")).startsWith("vapid t=");
            // aes128gcm body = 86-byte header + plaintext(5) + delimiter(1) + GCM tag(16)
            assertThat(request.bodyLength()).isEqualTo(86 + 5 + 1 + 16);
        }
    }

    @Test
    void deadSubscriptionIsAResultNotAnException() throws IOException {
        for (int status : new int[] {404, 410}) {
            try (MockPushReceiver receiver = new MockPushReceiver()) {
                receiver.enqueue(status);
                PushResult result = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

                assertThat(result.isSubscriptionExpired()).as("status %d", status).isTrue();
                assertThat(result.attempts()).as("no retry on %d", status).isEqualTo(1);
                assertThat(receiver.requests()).hasSize(1);
            }
        }
    }

    @Test
    void nonRetryableClientErrorFailsImmediately() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.enqueue(413);
            PushResult result = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(result.status()).isEqualTo(PushResult.Status.FAILED);
            assertThat(result.statusCode()).isEqualTo(413);
            assertThat(result.attempts()).isEqualTo(1);
            assertThat(receiver.requests()).hasSize(1);
        }
    }

    @Test
    void retriesServerErrorThenSucceeds() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.enqueue(500);
            receiver.enqueue(201);
            PushResult result = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(result.delivered()).isTrue();
            assertThat(result.attempts()).isEqualTo(2);
            assertThat(receiver.requests()).hasSize(2);
            assertThat(sleeper.sleeps).as("one backoff between the two attempts").hasSize(1);
        }
    }

    @Test
    void exhaustsRetriesThenFails() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.enqueue(500);
            receiver.enqueue(503);
            receiver.enqueue(500);
            PushResult result = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(result.status()).isEqualTo(PushResult.Status.FAILED);
            assertThat(result.attempts()).as("RetryPolicy.defaults() caps at 3 attempts").isEqualTo(3);
            assertThat(receiver.requests()).hasSize(3);
            assertThat(sleeper.sleeps).hasSize(2);
        }
    }

    @Test
    void honoursRetryAfterOn429() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.enqueue(429, "2");
            receiver.enqueue(201);
            PushResult result = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(result.delivered()).isTrue();
            assertThat(result.attempts()).isEqualTo(2);
            assertThat(sleeper.sleeps).containsExactly(Duration.ofSeconds(2));
        }
    }

    @Test
    void sendAsyncCompletesWithTheResult() throws Exception {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushResult result = pusher()
                .sendAsync(subscription(receiver), PushMessage.of(bytes("x")))
                .get(5, TimeUnit.SECONDS);
            assertThat(result.delivered()).isTrue();
        }
    }

    @Test
    void externalSignerPathDelivers() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            VapidSigner externalSigner = new LocalEcVapidSigner(generateVapidKeys());
            PushSender pusher = PushSender.builder().signer(externalSigner).contact("mailto:ops@example.com").sleeper(sleeper).build();

            assertThat(pusher.send(subscription(receiver), PushMessage.of(bytes("x"))).delivered()).isTrue();
        }
    }

    @Test
    void builderRequiresExactlyOneKeySource() {
        VapidKeys keys = generateVapidKeys();

        PushSender.Builder noKeySource = PushSender.builder().contact("mailto:ops@example.com");
        assertThatThrownBy(noKeySource::build)
            .as("neither vapid nor signer")
            .isInstanceOf(IllegalStateException.class);

        PushSender.Builder bothSources = PushSender.builder()
            .contact("mailto:ops@example.com").vapid(keys).signer(new LocalEcVapidSigner(keys));
        assertThatThrownBy(bothSources::build)
            .as("both vapid and signer")
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void builderRequiresContact() {
        PushSender.Builder noContact = PushSender.builder().vapid(generateVapidKeys());
        assertThatThrownBy(noContact::build).isInstanceOf(IllegalStateException.class);
    }

    private PushSender pusher() {
        return PushSender.builder()
            .vapid(generateVapidKeys())
            .contact("mailto:ops@example.com")
            .sleeper(sleeper)
            .build();
    }

    private static Subscription subscription(MockPushReceiver receiver) {
        return new Subscription(
            receiver.endpoint().toString(), b64(TestVectors.UA_PUBLIC), b64(TestVectors.AUTH_SECRET));
    }

    private static VapidKeys generateVapidKeys() {
        KeyPair keyPair = EcKeys.generateP256(Jca.platform());
        return VapidKeys.of(
            EcKeys.encodeUncompressed((ECPublicKey) keyPair.getPublic()),
            TestVectors.scalar32((ECPrivateKey) keyPair.getPrivate()));
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    /** Records backoff durations instead of sleeping, so the retry tests run instantly. */
    static final class RecordingSleeper implements Sleeper {
        final List<Duration> sleeps = new ArrayList<>();

        @Override
        public void sleep(Duration duration) {
            sleeps.add(duration);
        }
    }
}
