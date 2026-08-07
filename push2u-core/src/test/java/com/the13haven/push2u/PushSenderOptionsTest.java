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

import org.junit.jupiter.api.Test;

/**
 * The optional per-message headers of RFC 8030 and the builder bounds of RFC 8292, neither of which the happy-path send
 * tests exercise.
 *
 * <p>The headers matter because they are the only way a caller can influence what the push service does with a message
 * it cannot deliver immediately: {@code Urgency} decides whether a sleeping device is woken, {@code Topic} decides
 * whether an undelivered message is replaced rather than queued. Sending them under the wrong name, or not at all, is
 * silent — the push service simply applies its defaults and every test that only looks at the status code still passes.
 */
class PushSenderOptionsTest {

    private final PushTestSupport.RecordingSleeper sleeper = new PushTestSupport.RecordingSleeper();

    @Test
    void urgencyAndTopicAreSentUnderTheirRfc8030HeaderNames() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            pusher().send(
                            subscription(receiver),
                            PushMessage.builder(bytes("x"))
                                    .urgency(Urgency.VERY_LOW)
                                    .topic("news-42")
                                    .build());

            assertThat(receiver.requests().getFirst().headers())
                    .containsEntry("urgency", "very-low")
                    .containsEntry("topic", "news-42");
        }
    }

    @Test
    void everyUrgencyLevelHasTheWireSpellingTheRfcDefines() throws IOException {
        for (Urgency urgency : Urgency.values()) {
            try (MockPushReceiver receiver = new MockPushReceiver()) {
                pusher().send(
                                subscription(receiver),
                                PushMessage.builder(bytes("x")).urgency(urgency).build());

                assertThat(receiver.requests().getFirst().headers())
                        .as("%s", urgency)
                        .containsEntry("urgency", urgency.headerValue());
            }
        }
    }

    /** A message that sets neither must not invent them: an absent header and a defaulted one are not the same. */
    @Test
    void neitherHeaderIsSentWhenTheMessageDoesNotSetIt() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(receiver.requests().getFirst().headers())
                    .doesNotContainKey("urgency")
                    .doesNotContainKey("topic");
        }
    }

    @Test
    void aMessageWithoutATtlFallsBackToTheSenderDefault() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushSender.builder(generateVapidKeys(), "mailto:ops@example.com", EndpointPolicies.unrestricted())
                    .httpClient(trustingPushHttpClient())
                    .sleeper(sleeper)
                    .defaultTtl(Duration.ofMinutes(5))
                    .build()
                    .send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(receiver.requests().getFirst().headers()).containsEntry("ttl", "300");
        }
    }

    // ---- builder bounds -------------------------------------------------------------------------

    /**
     * RFC 8292 §2 caps the JWT lifetime at 24 hours, and a push service is entitled to reject anything longer. Catching
     * it in the builder turns a per-send 401 from a push service into a startup failure with a readable message.
     */
    @Test
    void jwtExpiryIsBoundedByTheRfc() {
        assertThat(catchBuilderFailure(builder -> builder.jwtExpiry(Duration.ofHours(24))))
                .as("24h exactly is legal")
                .isNull();

        for (Duration invalid : new Duration[] {
            Duration.ZERO, Duration.ofSeconds(-1), Duration.ofHours(24).plusSeconds(1)
        }) {
            assertThat(catchBuilderFailure(builder -> builder.jwtExpiry(invalid)))
                    .as("%s", invalid)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("24h");
        }
    }

    @Test
    void aNegativeDefaultTtlIsRejectedButZeroIsNot() {
        assertThat(catchBuilderFailure(builder -> builder.defaultTtl(Duration.ZERO)))
                .as("TTL 0 means deliver now or drop — a legitimate choice")
                .isNull();

        assertThat(catchBuilderFailure(builder -> builder.defaultTtl(Duration.ofSeconds(-1))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("negative");
    }

    @Test
    void theBuilderRejectsNullsRatherThanFailingLaterInASend() {
        assertThat(catchBuilderFailure(builder -> builder.jwtExpiry(null))).isInstanceOf(NullPointerException.class);
        assertThat(catchBuilderFailure(builder -> builder.defaultTtl(null))).isInstanceOf(NullPointerException.class);
    }

    /** Applies a builder mutation and returns what it threw, or {@code null} if it was accepted. */
    private @org.jspecify.annotations.Nullable Throwable catchBuilderFailure(
            java.util.function.Consumer<PushSender.Builder> mutation) {
        try {
            mutation.accept(
                    PushSender.builder(generateVapidKeys(), "mailto:ops@example.com", EndpointPolicies.unrestricted()));
            return null;
        } catch (RuntimeException e) {
            return e;
        }
    }

    private PushSender pusher() {
        return PushSender.builder(generateVapidKeys(), "mailto:ops@example.com", EndpointPolicies.unrestricted())
                .httpClient(trustingPushHttpClient())
                .sleeper(sleeper)
                .build();
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
