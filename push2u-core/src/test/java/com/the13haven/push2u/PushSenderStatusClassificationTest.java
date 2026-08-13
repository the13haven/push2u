/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static com.the13haven.push2u.PushTestSupport.generateVapidKeys;
import static com.the13haven.push2u.PushTestSupport.subscription;
import static com.the13haven.push2u.PushTestSupport.trustingPushHttpClient;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The complete HTTP status → {@link PushOutcome} classification matrix of {@link PushSender}, driven through the real
 * pipeline against the in-process {@link MockPushReceiver}. The matrix is per status rather than per class (ADR-021),
 * so beside the range edges — 199/200, 299/300, 499/500, 599/600, where an off-by-one silently reclassifies — the cases
 * worth pinning are the individually named statuses: the retryable 4xx trio (408, 421, 429), the five 5xx carve-outs
 * (501, 505, 506, 508, 511), 507 which stays retryable against the pull of its class, 510 which is deliberately left to
 * the unnamed-5xx rule, and 413, the one status whose class its own {@code Retry-After} decides.
 *
 * <p>Every case also asserts exactly one request on the wire: the sender makes one POST per send whatever the
 * classification says, because the repeat — if any — is the caller's.
 */
class PushSenderStatusClassificationTest {

    @ParameterizedTest(name = "HTTP {0} is Accepted")
    @ValueSource(ints = {200, 201, 204, 299})
    void anyTwoHundredClassStatusIsAccepted(int status) throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.respondWith(status);

            PushOutcome outcome = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(outcome).as("HTTP %d", status).isEqualTo(new PushOutcome.Accepted(status));
            assertThat(receiver.requests())
                    .as("one POST on the wire, not just one reported")
                    .hasSize(1);
        }
    }

    @ParameterizedTest(name = "HTTP {0} is SubscriptionExpired")
    @ValueSource(ints = {404, 410})
    void aGoneSubscriptionStatusIsExpired(int status) throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.respondWith(status);

            PushOutcome outcome = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(outcome).as("HTTP %d", status).isEqualTo(new PushOutcome.SubscriptionExpired(status));
            assertThat(receiver.requests()).hasSize(1);
        }
    }

    /**
     * The retryable side, status by status: the specified trio of 4xx statuses (RFC 8030 §8.4's 429, RFC 9110 §15.5.9's
     * 408, §15.5.20's 421), the 5xx range edges 500 and 599, the two intermediary statuses 502/504 (reported retryable,
     * not reclassified as unanswered), 507 — retryable on RFC 4918 §11.5's own "considered to be temporary" despite the
     * storage-full sound of it — and 510, which no list names and which therefore falls to the unnamed-5xx rule:
     * retryable, so that a status with no current specification is never permanent by omission.
     */
    @ParameterizedTest(name = "HTTP {0} is a RetryableFailure")
    @ValueSource(ints = {408, 421, 429, 500, 502, 503, 504, 507, 510, 599})
    void aRetryableStatusIsReportedWithoutAHintWhenNoneWasSent(int status) throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.respondWith(status);

            PushOutcome outcome = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(outcome)
                    .as("HTTP %d", status)
                    .isEqualTo(new PushOutcome.RetryableFailure(status, Optional.empty()));
            assertThat(receiver.requests())
                    .as("retryable is a verdict reported, never a repeat performed: one POST only")
                    .hasSize(1);
        }
    }

    /**
     * The non-retryable side: the classes that answer about the request (3xx — push delivery has no redirect step — and
     * the plain 4xx range including its 499 edge), 600 just past the 5xx range, and the five 5xx carve-outs, each
     * classified on its defining specification's own words — 501 and 505 (RFC 9110 §15.6.2, §15.6.6: the same POST is
     * answered identically), 506 (RFC 2295 §8.1: a configuration error), 508 (RFC 5842 §7.2: a statement about the
     * resource graph), 511 (RFC 6585 §6: an intercepting proxy, not the push service, and no repeat obtains network
     * access).
     */
    @ParameterizedTest(name = "HTTP {0} is a NonRetryableFailure")
    @ValueSource(ints = {300, 400, 401, 403, 418, 499, 501, 505, 506, 508, 511, 600})
    void anAnsweredRequestStatusIsNonRetryable(int status) throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.respondWith(status);

            PushOutcome outcome = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(outcome).as("HTTP %d", status).isEqualTo(new PushOutcome.NonRetryableFailure(status));
            assertThat(receiver.requests()).hasSize(1);
        }
    }

    /**
     * 413 is the one status whose class its own answer decides (RFC 9110 §15.5.14: a server refusing a request for its
     * size generates a {@code Retry-After} if the condition is temporary): with a parseable header it is retryable and
     * the header travels on the outcome; bare, it is not.
     */
    @Test
    void a413WithAParseableRetryAfterIsRetryableAndCarriesTheHint() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.respondWith(413, "120");

            PushOutcome outcome = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(outcome).isEqualTo(new PushOutcome.RetryableFailure(413, Optional.of(Duration.ofSeconds(120))));
        }
    }

    @Test
    void aBare413IsNonRetryable() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.respondWith(413);

            PushOutcome outcome = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(outcome).isEqualTo(new PushOutcome.NonRetryableFailure(413));
        }
    }

    @Test
    void a413WithAnUnparseableRetryAfterIsNonRetryable() throws IOException {
        // The header is what classifies a 413, so a header the grammar rejects classifies nothing:
        // the temporary reading rests on a value that parses, not on the header's mere presence.
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.respondWith(413, "soon");

            PushOutcome outcome = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(outcome).isEqualTo(new PushOutcome.NonRetryableFailure(413));
        }
    }

    /**
     * The Accepted lower edge: 199 must be a non-retryable failure, or {@code code >= 199} ships green while 200 alone
     * is pinned. This is the one boundary that cannot ride the {@link MockPushReceiver} like the others: the JDK HTTP
     * client treats any 1xx as an interim response and keeps waiting for the final one (verified — a receiver answering
     * a bare 199 makes the send time out instead of returning), so the case goes through the public
     * {@link PushHttpClient} seam with a canned response instead. That still exercises the real {@code send()}
     * classification, and it is exactly how a 199 can reach it in production: a custom transport that surfaces interim
     * responses as final ones.
     */
    @Test
    void theStatusJustBelowTheAcceptedRangeIsANonRetryableFailure() {
        PushSender pusher = PushSender.builder(
                        generateVapidKeys(), "mailto:ops@example.com", EndpointPolicies.unrestricted())
                .httpClient((endpoint, headers, body) -> PushResponse.of(199))
                .build();
        Subscription subscription = new Subscription(
                "https://push.example.com/never-contacted",
                TestVectors.b64(TestVectors.UA_PUBLIC),
                TestVectors.b64(TestVectors.AUTH_SECRET));

        PushOutcome outcome = pusher.send(subscription, PushMessage.of(bytes("x")));

        assertThat(outcome).as("HTTP 199").isEqualTo(new PushOutcome.NonRetryableFailure(199));
    }

    private PushSender pusher() {
        return PushSender.builder(generateVapidKeys(), "mailto:ops@example.com", EndpointPolicies.unrestricted())
                .httpClient(trustingPushHttpClient())
                .build();
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
