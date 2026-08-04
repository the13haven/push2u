package com.the13haven.push2u;

import static com.the13haven.push2u.PushTestSupport.generateVapidKeys;
import static com.the13haven.push2u.PushTestSupport.subscription;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The complete HTTP status → {@link PushResult} classification table of {@link PushSender}, edges included, driven
 * through the real pipeline against the in-process {@link MockPushReceiver}. The tests in {@link PushSenderTest} pin
 * behaviours whose value is not the status code itself (request shape, {@code Retry-After} honouring); this class pins
 * the three classification predicates at their range boundaries — 299/300, 499/500, 599/600 — where an off-by-one in a
 * comparison silently reclassifies a status while every mid-range test stays green. A misclassification is quiet in
 * production too: a retried plain 4xx hammers a service that meant "go away", and a 5xx treated as fatal drops a
 * message one more attempt would have delivered.
 *
 * <p>Also the retry-exhaustion invariant: exhaustion is FAILED with {@code attempts == maxAttempts} and exactly
 * {@code maxAttempts - 1} recorded backoffs — a backoff after the final attempt would delay the caller for nothing.
 */
class PushSenderStatusClassificationTest {

    private final PushSenderTest.RecordingSleeper sleeper = new PushSenderTest.RecordingSleeper();

    @ParameterizedTest(name = "HTTP {0} is DELIVERED")
    @ValueSource(ints = {200, 201, 204, 299})
    void anyTwoHundredClassStatusIsDeliveredInOneAttempt(int status) throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.enqueue(status);

            PushResult result = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(result.status()).as("HTTP %d", status).isEqualTo(PushResult.Status.DELIVERED);
            assertThat(result.statusCode()).isEqualTo(status);
            assertThat(result.attempts()).isEqualTo(1);
            assertThat(sleeper.sleeps).as("no backoff on success").isEmpty();
        }
    }

    @ParameterizedTest(name = "HTTP {0} is SUBSCRIPTION_EXPIRED")
    @ValueSource(ints = {404, 410})
    void aGoneSubscriptionStatusExpiresInOneAttemptWithoutRetry(int status) throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.enqueue(status);

            PushResult result = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(result.status()).as("HTTP %d", status).isEqualTo(PushResult.Status.SUBSCRIPTION_EXPIRED);
            assertThat(result.statusCode()).isEqualTo(status);
            assertThat(result.attempts())
                    .as("a dead subscription is never retried")
                    .isEqualTo(1);
            assertThat(receiver.requests()).hasSize(1);
            assertThat(sleeper.sleeps).isEmpty();
        }
    }

    /**
     * The receiver answers 201 once its queue drains, so a retried send succeeds: DELIVERED on attempt 2 proves the
     * enqueued status was classified retryable, and the recorded backoff proves the sleep sat between the attempts. 500
     * and 599 are the edges of the 5xx range; 429 is the lone retryable 4xx.
     */
    @ParameterizedTest(name = "HTTP {0} is retried")
    @ValueSource(ints = {429, 500, 503, 599})
    void aRetryableStatusIsRetriedAfterOneBackoff(int status) throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.enqueue(status);

            PushResult result = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(result.status()).as("HTTP %d then 201", status).isEqualTo(PushResult.Status.DELIVERED);
            assertThat(result.attempts()).isEqualTo(2);
            assertThat(receiver.requests()).hasSize(2);
            assertThat(sleeper.sleeps)
                    .as("no Retry-After header on the %d, so the policy's initial backoff", status)
                    .containsExactly(RetryPolicy.defaults().initialBackoff());
        }
    }

    /**
     * 499 and 600 sit one past the retryable ranges. The receiver would answer 201 to a second request, so a status
     * misclassified as retryable would surface loudly here as DELIVERED with two attempts, not FAILED with one.
     */
    @ParameterizedTest(name = "HTTP {0} is FAILED without retry")
    @ValueSource(ints = {300, 400, 401, 403, 413, 418, 499, 600})
    void anyOtherStatusFailsInOneAttemptWithoutRetry(int status) throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.enqueue(status);

            PushResult result = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(result.status()).as("HTTP %d", status).isEqualTo(PushResult.Status.FAILED);
            assertThat(result.statusCode()).isEqualTo(status);
            assertThat(result.attempts()).isEqualTo(1);
            assertThat(receiver.requests()).hasSize(1);
            assertThat(sleeper.sleeps).isEmpty();
        }
    }

    @Test
    void exhaustedRetriesFailWithMaxAttemptsAndNoBackoffAfterTheFinalAttempt() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            RetryPolicy policy = new RetryPolicy(4, Duration.ofSeconds(1), Duration.ofSeconds(60));
            for (int attempt = 0; attempt < policy.maxAttempts(); attempt++) {
                receiver.enqueue(503);
            }
            PushSender pusher = PushSender.builder()
                    .vapid(generateVapidKeys())
                    .contact("mailto:ops@example.com")
                    .retryPolicy(policy)
                    .sleeper(sleeper)
                    .build();

            PushResult result = pusher.send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(result.status()).isEqualTo(PushResult.Status.FAILED);
            assertThat(result.statusCode())
                    .as("the final attempt's status is what the result reports")
                    .isEqualTo(503);
            assertThat(result.attempts()).isEqualTo(policy.maxAttempts());
            assertThat(receiver.requests())
                    .as("the loop stops POSTing at maxAttempts")
                    .hasSize(policy.maxAttempts());
            assertThat(sleeper.sleeps)
                    .as("exactly maxAttempts - 1 backoffs on the exponential schedule — a fourth entry would be"
                            + " a sleep after the final attempt, delaying the caller for nothing")
                    .containsExactly(Duration.ofSeconds(1), Duration.ofSeconds(2), Duration.ofSeconds(4));
        }
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
}
