package com.the13haven.push2u;

import static com.the13haven.push2u.PushTestSupport.generateVapidKeys;
import static com.the13haven.push2u.PushTestSupport.subscription;
import static com.the13haven.push2u.TestVectors.b64;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ForkJoinWorkerThread;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

/**
 * End-to-end send-pipeline tests: a real {@link PushSender} (real RFC 8291 encryption + RFC 8292 VAPID + the JDK HTTP
 * client) against an in-process {@link MockPushReceiver}, asserting the request shape, the VAPID claims of a real
 * request, the {@code Retry-After} handling and the async execution contract. A {@link RecordingSleeper} runs the retry
 * loop without real backoff delays. The full status-code → {@link PushResult} classification table (ranges and their
 * edges) lives in {@link PushSenderStatusClassificationTest}.
 */
class PushSenderTest {

    private final RecordingSleeper sleeper = new RecordingSleeper();

    @Test
    void deliversOn201AndSendsAWellFormedRequest() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushResult result = pusher().send(
                            subscription(receiver),
                            PushMessage.builder(bytes("hello"))
                                    .ttl(Duration.ofHours(1))
                                    .build());

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
    void audClaimCarriesTheNormalizedRfc6454Origin() {
        // A capturing transport instead of the receiver: the endpoint's uppercase scheme/host and
        // explicit :443 exist purely to exercise the origin serialization, not real delivery.
        AtomicReference<Map<String, String>> captured = new AtomicReference<>();
        PushHttpClient capturingClient = (endpoint, headers, body) -> {
            captured.set(headers);
            return PushResponse.of(201);
        };
        Subscription subscription = new Subscription(
                "HTTPS://PUSH.Example:443/subscriber-token", b64(TestVectors.UA_PUBLIC), b64(TestVectors.AUTH_SECRET));

        PushResult result = PushSender.builder()
                .vapid(generateVapidKeys())
                .contact("mailto:ops@example.com")
                .httpClient(capturingClient)
                .build()
                .send(subscription, PushMessage.of(bytes("x")));

        assertThat(result.delivered()).isTrue();
        String claims = claimsOf(captured.get().get("Authorization"));
        assertThat(claims)
                .as("aud is the RFC 6454 §6.1 origin: lowercase scheme+host, default port dropped (RFC 8292 §2)")
                .contains("\"aud\":\"https://push.example\"")
                .doesNotContain("PUSH.Example")
                .doesNotContain(":443");
    }

    @Test
    void expClaimOfASentRequestIsThePinnedClockPlusTheConfiguredExpiry() throws IOException {
        // RFC 8292 §2 caps exp at 24 hours after the request; the builder already rejects a larger
        // configuration (PushSenderOptionsTest), so what is left unproven is the request itself:
        // exp must be exactly clock-now plus the configured expiry. Configuring the 24h ceiling
        // makes the equality double as the RFC bound — an arithmetic slip that lands exp even one
        // second later produces a JWT every push service is entitled to answer with 401.
        Instant now = Instant.parse("2030-01-01T00:00:00Z");
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushSender pusher = PushSender.builder()
                    .vapid(generateVapidKeys())
                    .contact("mailto:ops@example.com")
                    .sleeper(sleeper)
                    .clock(Clock.fixed(now, ZoneOffset.UTC))
                    .jwtExpiry(Duration.ofHours(24))
                    .build();

            PushResult result = pusher.send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(result.delivered()).isTrue();
            String claims = claimsOf(receiver.requests().getFirst().headers().get("authorization"));
            assertThat(claims)
                    .as("exp is exactly now + 24h, the RFC 8292 §2 maximum (the trailing comma pins"
                            + " the whole number, not a prefix of a larger one)")
                    .contains("\"exp\":" + now.plus(Duration.ofHours(24)).getEpochSecond() + ",");
        }
    }

    @Test
    void expClaimDefaultsToTwelveHoursAfterTheClock() throws IOException {
        // Pins the documented builder default: a sender that never calls jwtExpiry() must sign
        // 12h ahead, not silently drift to some other offset the Javadoc no longer matches.
        Instant now = Instant.parse("2030-01-01T00:00:00Z");
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushSender pusher = PushSender.builder()
                    .vapid(generateVapidKeys())
                    .contact("mailto:ops@example.com")
                    .sleeper(sleeper)
                    .clock(Clock.fixed(now, ZoneOffset.UTC))
                    .build();

            PushResult result = pusher.send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(result.delivered()).isTrue();
            String claims = claimsOf(receiver.requests().getFirst().headers().get("authorization"));
            assertThat(claims)
                    .contains("\"exp\":" + now.plus(Duration.ofHours(12)).getEpochSecond() + ",");
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
    void honoursRetryAfterOn503() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.enqueue(503, "3");
            receiver.enqueue(201);
            PushResult result = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(result.delivered()).isTrue();
            assertThat(result.attempts()).isEqualTo(2);
            assertThat(sleeper.sleeps).containsExactly(Duration.ofSeconds(3));
        }
    }

    @Test
    void honoursHttpDateRetryAfterAgainstThePinnedClock() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.enqueue(429, "Tue, 01 Jan 2030 00:00:30 GMT");
            receiver.enqueue(201);
            PushSender pusher = PushSender.builder()
                    .vapid(generateVapidKeys())
                    .contact("mailto:ops@example.com")
                    .sleeper(sleeper)
                    .clock(Clock.fixed(Instant.parse("2030-01-01T00:00:00Z"), ZoneOffset.UTC))
                    .build();
            PushResult result = pusher.send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(result.delivered()).isTrue();
            assertThat(sleeper.sleeps).containsExactly(Duration.ofSeconds(30));
        }
    }

    @Test
    void unparseableRetryAfterFallsBackToTheExponentialBackoff() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.enqueue(429, "soon");
            receiver.enqueue(201);
            PushResult result = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(result.delivered()).isTrue();
            assertThat(sleeper.sleeps)
                    .as("the first retry waits exactly RetryPolicy.defaults().initialBackoff()")
                    .containsExactly(RetryPolicy.defaults().initialBackoff());
        }
    }

    @Test
    void overflowingRetryAfterDoesNotFailTheSend() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.enqueue(429, "99999999999999999999");
            receiver.enqueue(201);
            PushResult result = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(result.delivered()).isTrue();
            assertThat(result.attempts()).isEqualTo(2);
            assertThat(sleeper.sleeps)
                    .as("overflow is treated as unparseable, not propagated")
                    .containsExactly(RetryPolicy.defaults().initialBackoff());
        }
    }

    @Test
    void capsRetryAfterAtMaxBackoff() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.enqueue(429, "3600");
            receiver.enqueue(201);
            PushResult result = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(result.delivered()).isTrue();
            assertThat(sleeper.sleeps).containsExactly(RetryPolicy.defaults().maxBackoff());
        }
    }

    @Test
    void sendAsyncCompletesWithTheResult() throws Exception {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushResult result = pusher().sendAsync(subscription(receiver), PushMessage.of(bytes("x")))
                    .get(5, TimeUnit.SECONDS);
            assertThat(result.delivered()).isTrue();
        }
    }

    @Test
    void sendAsyncDefaultRunsOnAVirtualThreadNotTheCommonPool() throws Exception {
        AtomicReference<Thread> sendThread = new AtomicReference<>();
        PushHttpClient capturingClient = (endpoint, headers, body) -> {
            sendThread.set(Thread.currentThread());
            return PushResponse.of(201);
        };
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushResult result = PushSender.builder()
                    .vapid(generateVapidKeys())
                    .contact("mailto:ops@example.com")
                    .httpClient(capturingClient)
                    .build()
                    .sendAsync(subscription(receiver), PushMessage.of(bytes("x")))
                    .get(5, TimeUnit.SECONDS);

            assertThat(result.delivered()).isTrue();
            Thread thread = sendThread.get();
            assertThat(thread.isVirtual())
                    .as("the default async executor runs each send on a virtual thread")
                    .isTrue();
            assertThat(thread)
                    .as("a blocking send must never occupy a common-ForkJoinPool worker")
                    .isNotInstanceOf(ForkJoinWorkerThread.class);
        }
    }

    @Test
    void sendAsyncRunsOnTheConfiguredExecutor() throws Exception {
        AtomicReference<Thread> executorThread = new AtomicReference<>();
        ExecutorService executor = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "push2u-configured-executor");
            executorThread.set(thread);
            return thread;
        });
        AtomicReference<Thread> sendThread = new AtomicReference<>();
        PushHttpClient capturingClient = (endpoint, headers, body) -> {
            sendThread.set(Thread.currentThread());
            return PushResponse.of(201);
        };
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushResult result = PushSender.builder()
                    .vapid(generateVapidKeys())
                    .contact("mailto:ops@example.com")
                    .httpClient(capturingClient)
                    .executor(executor)
                    .build()
                    .sendAsync(subscription(receiver), PushMessage.of(bytes("x")))
                    .get(5, TimeUnit.SECONDS);

            assertThat(result.delivered()).isTrue();
            assertThat(sendThread.get())
                    .as("the send runs on the single thread of the executor passed to .executor(...)")
                    .isSameAs(executorThread.get());
        } finally {
            executor.shutdown();
        }
    }

    @Test
    void sendAsyncPropagatesAnExecutorRejectionSynchronously() throws IOException {
        // CompletableFuture.supplyAsync calls execute() inline, so a rejecting executor throws
        // out of sendAsync rather than completing the returned future exceptionally — callers
        // that only attach an exception handler to the future would otherwise miss it.
        Executor rejecting = runnable -> {
            throw new RejectedExecutionException("saturated");
        };
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushSender pusher = PushSender.builder()
                    .vapid(generateVapidKeys())
                    .contact("mailto:ops@example.com")
                    .executor(rejecting)
                    .build();
            Subscription subscription = subscription(receiver);
            PushMessage message = PushMessage.of(bytes("x"));

            assertThatThrownBy(() -> pusher.sendAsync(subscription, message))
                    .isInstanceOf(RejectedExecutionException.class)
                    .hasMessage("saturated");
        }
    }

    @Test
    void externalSignerPathDelivers() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            VapidSigner externalSigner = new LocalEcVapidSigner(generateVapidKeys());
            PushSender pusher = PushSender.builder()
                    .signer(externalSigner)
                    .contact("mailto:ops@example.com")
                    .sleeper(sleeper)
                    .build();

            assertThat(pusher.send(subscription(receiver), PushMessage.of(bytes("x")))
                            .delivered())
                    .isTrue();
        }
    }

    // The same full pipeline with BC-FIPS as the crypto provider (the ES256 DER fallback) lives
    // in BcFipsPushSenderTest in the fipsTest source set — bc-fips cannot share a classpath with
    // the stock bcprov this source set carries.

    @Test
    void builderRequiresExactlyOneKeySource() {
        VapidKeys keys = generateVapidKeys();

        PushSender.Builder noKeySource = PushSender.builder().contact("mailto:ops@example.com");
        assertThatThrownBy(noKeySource::build).as("neither vapid nor signer").isInstanceOf(IllegalStateException.class);

        PushSender.Builder bothSources = PushSender.builder()
                .contact("mailto:ops@example.com")
                .vapid(keys)
                .signer(new LocalEcVapidSigner(keys));
        assertThatThrownBy(bothSources::build).as("both vapid and signer").isInstanceOf(IllegalStateException.class);
    }

    @Test
    void builderRequiresContact() {
        PushSender.Builder noContact = PushSender.builder().vapid(generateVapidKeys());
        assertThatThrownBy(noContact::build).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void builderRejectsABlankContact() {
        // A blank contact would still build a JWT carrying an empty/whitespace 'sub' claim, which
        // satisfies push2u's contact contract no better than the omission RFC 8292 §2.1 permits —
        // reject it here rather than ship a claim a push service may or may not refuse.
        PushSender.Builder blankContact =
                PushSender.builder().vapid(generateVapidKeys()).contact("   ");
        assertThatThrownBy(blankContact::build)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("contact is required");
    }

    private PushSender pusher() {
        return PushSender.builder()
                .vapid(generateVapidKeys())
                .contact("mailto:ops@example.com")
                .sleeper(sleeper)
                .build();
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    /** The decoded claims JSON of the JWT inside a {@code vapid t=<jwt>, k=<key>} Authorization header. */
    private static String claimsOf(String authorization) {
        String jwt = authorization.substring("vapid t=".length(), authorization.indexOf(", k="));
        return new String(Base64Url.decode(jwt.split("\\.", -1)[1]), StandardCharsets.UTF_8);
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
