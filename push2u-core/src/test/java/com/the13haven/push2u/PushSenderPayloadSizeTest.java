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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;

import org.junit.jupiter.api.Test;

/**
 * The size precondition of a send, checked before any cryptography or network I/O, and reported as the
 * {@link PushOutcome.PayloadRejected} outcome in plaintext octets — {@code payloadBytes} against
 * {@code maximumPayloadBytes}, the smaller of what the two preconditions permit: the RFC 8030 §7.2 ceiling on the
 * encrypted entity body less the fixed 103-octet framing (default 4096, so 3993 octets of plaintext), and the RFC 8291
 * §4 rule that {@code rs} strictly exceed the plaintext plus 17 (so {@code rs − 18}). The two configured values stay
 * independent — raising one never adjusts the other — and which one bound is readable off the maximum reported.
 */
class PushSenderPayloadSizeTest {

    private static final int MAX_DEFAULT_PAYLOAD = 3993;

    @Test
    void theLargestPayloadThatFitsTheDefaultBodyLimitIsAccepted() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushOutcome outcome =
                    sender(builder()).send(subscription(receiver), PushMessage.of(new byte[MAX_DEFAULT_PAYLOAD]));

            assertThat(outcome).isInstanceOf(PushOutcome.Accepted.class);
            assertThat(receiver.requests().getFirst().bodyLength())
                    .as("3993 bytes of plaintext fill the 4096-byte body exactly")
                    .isEqualTo(4096);
        }
    }

    @Test
    void onePayloadByteOverTheBodyLimitIsRejectedBeforeAnyRequest() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushOutcome outcome =
                    sender(builder()).send(subscription(receiver), PushMessage.of(new byte[MAX_DEFAULT_PAYLOAD + 1]));

            assertThat(outcome)
                    .as("both numbers are plaintext octets — the unit the caller can act in")
                    .isEqualTo(new PushOutcome.PayloadRejected(MAX_DEFAULT_PAYLOAD + 1, MAX_DEFAULT_PAYLOAD));
            assertThat(receiver.requests())
                    .as("rejected before encrypting or contacting the service")
                    .isEmpty();
        }
    }

    @Test
    void raisingTheBodyLimitAloneLeavesTheRecordSizeBoundDecidingTheMaximum() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushOutcome outcome = sender(builder().maxEncryptedBodyBytes(8192))
                    .send(subscription(receiver), PushMessage.of(new byte[5000]));

            assertThat(outcome)
                    .as("the body fits 8192, but rs stays 4096, so the maximum is rs − 18 = 4078 — an operator"
                            + " holding both configured values reads which one bound from the maximum reported")
                    .isEqualTo(new PushOutcome.PayloadRejected(5000, 4078));
            assertThat(receiver.requests()).isEmpty();
        }
    }

    @Test
    void raisingBothTheBodyLimitAndTheRecordSizeAcceptsTheLargerPayload() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushOutcome outcome = sender(builder().maxEncryptedBodyBytes(8192).recordSize(8192))
                    .send(subscription(receiver), PushMessage.of(new byte[5000]));

            assertThat(outcome).isInstanceOf(PushOutcome.Accepted.class);
            assertThat(receiver.requests().getFirst().bodyLength()).isEqualTo(5000 + 103);
        }
    }

    @Test
    void recordSizeAtTheRfc8291BoundaryIsAcceptedOneBelowItIsNot() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            Subscription subscription = subscription(receiver);
            PushMessage message = PushMessage.of(new byte[100]);

            assertThat(sender(builder().recordSize(117)).send(subscription, message))
                    .as("rs == plaintext(100) + delimiter(1) + tag(16) is not *greater than* the sum, so the"
                            + " maximum this configuration carries is 99")
                    .isEqualTo(new PushOutcome.PayloadRejected(100, 99));

            assertThat(sender(builder().recordSize(118)).send(subscription, message))
                    .as("one octet more is the smallest legal rs for this payload")
                    .isInstanceOf(PushOutcome.Accepted.class);
        }
    }

    @Test
    void builderRejectsARecordSizeBelowTheRfc8188Minimum() {
        for (int invalid : new int[] {Integer.MIN_VALUE, -1, 0, 17}) {
            assertThatThrownBy(() -> builder().recordSize(invalid))
                    .as("rs %d", invalid)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("recordSize must be at least 18");
        }
        assertThat(builder().recordSize(18)).as("18 is legal (RFC 8188 §2)").isNotNull();
    }

    @Test
    void builderRejectsAMaxEncryptedBodyTooSmallForAnEmptyPayload() {
        for (int invalid : new int[] {Integer.MIN_VALUE, -1, 0, 102}) {
            assertThatThrownBy(() -> builder().maxEncryptedBodyBytes(invalid))
                    .as("maxEncryptedBodyBytes %d", invalid)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("must be at least the fixed 103-byte aes128gcm overhead");
        }
        // 103 is the body of an empty payload, which the library does send — so the limit that
        // admits exactly that body is legal, not one byte above it.
        assertThat(builder().maxEncryptedBodyBytes(103)).isNotNull();
    }

    @Test
    void anEmptyPayloadFitsTheSmallestLegalBodyLimit() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushOutcome outcome = sender(builder().maxEncryptedBodyBytes(103))
                    .send(subscription(receiver), PushMessage.of(new byte[0]));

            assertThat(outcome).isInstanceOf(PushOutcome.Accepted.class);
            assertThat(receiver.requests().getFirst().bodyLength())
                    .as("an empty payload encrypts to exactly the fixed overhead")
                    .isEqualTo(103);
        }
    }

    @Test
    void aOneBytePayloadAgainstTheSmallestLegalBodyLimitReportsAMaximumOfZero() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushOutcome outcome = sender(builder().maxEncryptedBodyBytes(103))
                    .send(subscription(receiver), PushMessage.of(new byte[1]));

            assertThat(outcome).isEqualTo(new PushOutcome.PayloadRejected(1, 0));
            assertThat(receiver.requests()).isEmpty();
        }
    }

    @Test
    void theMaximumComputationDoesNotWrapNearIntegerMaxValue() {
        // Driven through the length-free computation so the boundary is covered without allocating
        // multi-gigabyte arrays. int arithmetic would actually break here: Integer.MAX_VALUE + 103
        // wraps negative, which is below any limit, so an oversized payload would sail through.
        assertThat(WebPushEncryptor.maxPlaintextBytes(Integer.MAX_VALUE, Integer.MAX_VALUE))
                .as("with both limits at Integer.MAX_VALUE the body ceiling binds: MAX − 103")
                .isEqualTo(Integer.MAX_VALUE - 103);
        assertThat(WebPushEncryptor.maxPlaintextBytes(4096, Integer.MAX_VALUE))
                .as("an rs left at the default binds long before an enormous body ceiling")
                .isEqualTo(4078);
        assertThat(WebPushEncryptor.maxPlaintextBytes(Integer.MAX_VALUE, 4096))
                .as("and the other way round")
                .isEqualTo(3993);
    }

    @Test
    void theEncryptorsOwnRecordSizeCheckStillRefusesWithTheExactMinimumNamed() {
        // The direct-encryption path keeps its IllegalArgumentException: checkRecordSize guards
        // encrypt() itself, which is reachable without the sender's pre-flight, and its message
        // names the exact rs to raise to. Same rule, one implementation — the pre-flight's maximum
        // is the same subtraction inverted.
        assertThatThrownBy(() -> WebPushEncryptor.checkRecordSize(100, 117))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("recordSize 117 is too small for a 100-byte payload")
                .hasMessageContaining("RFC 8291 §4")
                .hasMessageContaining("raise recordSize to at least 118");

        // Near the int extreme the sum in the message must not wrap either.
        assertThatThrownBy(() -> WebPushEncryptor.checkRecordSize(Integer.MAX_VALUE - 103, 4096))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("raise recordSize to at least 2147483562");

        // A plaintext that would overflow int arithmetic entirely still fails loudly.
        assertThatThrownBy(() -> WebPushEncryptor.checkRecordSize(Integer.MAX_VALUE, Integer.MAX_VALUE))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /** A builder pre-loaded with the required key source and contact — these tests exercise only optional steps. */
    private static PushSender.Builder builder() {
        return PushSender.builder(generateVapidKeys(), "mailto:ops@example.com", EndpointPolicies.unrestricted())
                .httpClient(trustingPushHttpClient());
    }

    private static PushSender sender(PushSender.Builder builder) {
        return builder.build();
    }
}
