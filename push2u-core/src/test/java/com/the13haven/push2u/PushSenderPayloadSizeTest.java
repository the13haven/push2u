/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static com.the13haven.push2u.PushTestSupport.generateVapidKeys;
import static com.the13haven.push2u.PushTestSupport.subscription;
import static com.the13haven.push2u.PushTestSupport.trustingPushHttpClient;
import static com.the13haven.push2u.TestVectors.b64;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * The size precondition of a send and its pre-flight twin. One number is configured — the RFC 8030 §7.2 ceiling on the
 * encrypted entity body, default 4096 — and everything else is derived from it: the maximum payload is the ceiling less
 * the fixed 103-octet framing (3993 at the default), and the {@code rs} the RFC 8188 header advertises is that maximum
 * plus the record overhead plus the one octet RFC 8291 §4 requires, so the record-size rule can never be the bound that
 * binds through {@link PushSender}. The check runs before any cryptography or network I/O and reports as
 * {@link PushOutcome.PayloadRejected} in plaintext octets; {@link PushSender#assessPayloadSize(byte[])} answers the
 * same question before a send, with the same two numbers on its refusing branch.
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
    void raisingTheBodyLimitAloneRaisesTheMaximum() throws IOException {
        // The whole of raising the limit is one call: rs is derived from the ceiling, so there is
        // no second parameter left behind to keep the maximum where it was.
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushOutcome outcome = sender(builder().maxEncryptedBodyBytes(8192))
                    .send(subscription(receiver), PushMessage.of(new byte[5000]));

            assertThat(outcome).isInstanceOf(PushOutcome.Accepted.class);
            assertThat(receiver.requests().getFirst().bodyLength()).isEqualTo(5000 + 103);
        }
    }

    @Test
    void theEmittedHeaderAdvertisesTheDerivedRecordSizeNotAConstant() {
        // rs is the 4-byte big-endian field after the 16-byte salt (RFC 8188 §2.1). Asserted on the
        // body a real send emits, per configuration, against the derivation's own table: the
        // ceiling less 103 octets of framing, plus the delimiter, the tag and RFC 8291 §4's one
        // octet — the ceiling less 85. No floor: a small ceiling advertises a small record.
        int[][] table = {
            // maxEncryptedBodyBytes, expected rs
            {103, 18},
            {2048, 1963},
            {4096, 4011},
            {8192, 8107},
        };
        for (int[] row : table) {
            List<byte[]> bodies = new ArrayList<>();
            PushSender sender = capturingSender(builder().maxEncryptedBodyBytes(row[0]), bodies);

            PushOutcome outcome = sender.send(loopbackFreeSubscription(), PushMessage.of(new byte[0]));

            assertThat(outcome).isInstanceOf(PushOutcome.Accepted.class);
            assertThat(ByteBuffer.wrap(bodies.getFirst(), 16, Integer.BYTES).getInt())
                    .as("rs for a body ceiling of %d", row[0])
                    .isEqualTo(row[1]);
        }
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
                    .as("an empty payload encrypts to exactly the fixed overhead — under the derived rs of 18,"
                            + " the smallest legal value")
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
        assertThat(WebPushEncryptor.maxPlaintextBytes(Integer.MAX_VALUE))
                .as("a ceiling at Integer.MAX_VALUE admits MAX − 103 octets of plaintext")
                .isEqualTo(Integer.MAX_VALUE - 103);
        assertThat(WebPushEncryptor.maxPlaintextBytes(4096)).isEqualTo(3993);
        assertThat(WebPushEncryptor.maxPlaintextBytes(Integer.MIN_VALUE))
                .as("inputs below the builder's minimum clamp to zero — a negative long narrowed to int would"
                        + " wrap into a large positive maximum, the one failure a size bound must never have")
                .isZero();
    }

    @Test
    void assessPayloadSizeAnswersBothBranchesWithTheBoundaryOctetOnEachSide() {
        PushSender sender = sender(builder());

        assertThat(sender.assessPayloadSize(new byte[MAX_DEFAULT_PAYLOAD]))
                .as("the largest fitting payload is within the limit — the comparison is inclusive")
                .isEqualTo(new PayloadSizeAssessment.WithinLimit());
        assertThat(sender.assessPayloadSize(new byte[MAX_DEFAULT_PAYLOAD + 1]))
                .as("one octet more exceeds it, carrying the payload's size and the budget for the next render")
                .isEqualTo(new PayloadSizeAssessment.ExceedsLimit(MAX_DEFAULT_PAYLOAD + 1, MAX_DEFAULT_PAYLOAD));

        PushSender smallest = sender(builder().maxEncryptedBodyBytes(103));
        assertThat(smallest.assessPayloadSize(new byte[0]))
                .as("a zero budget still fits an empty payload")
                .isEqualTo(new PayloadSizeAssessment.WithinLimit());
        assertThat(smallest.assessPayloadSize(new byte[1]))
                .as("and reports a maximum of zero for anything else")
                .isEqualTo(new PayloadSizeAssessment.ExceedsLimit(1, 0));

        assertThatThrownBy(() -> sender.assessPayloadSize(null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void assessPayloadSizeReadsTheLengthAloneCopiesNothingAndRetainsNothing() {
        PushSender sender = sender(builder());
        byte[] payload = new byte[MAX_DEFAULT_PAYLOAD + 1];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte) i;
        }
        byte[] before = payload.clone();

        PayloadSizeAssessment assessment = sender.assessPayloadSize(payload);

        assertThat(payload).as("the array is read, never written").isEqualTo(before);
        // Nothing of the array survives in the answer: the assessment's components are two ints, so
        // there is no reference through which the payload could be reached or held. Scrambling
        // every octet and asking again demonstrates that only the length was ever read.
        Arrays.fill(payload, (byte) 0x5A);
        assertThat(sender.assessPayloadSize(payload)).isEqualTo(assessment);
    }

    @Test
    void theAssessmentAndTheRefusalAgreeOnTheSameTwoNumbers() throws IOException {
        // The pre-flight replaces nothing: the largest payload assessed WithinLimit sends, and the
        // smallest assessed ExceedsLimit comes back from send as PayloadRejected carrying exactly
        // the pair the assessment carried — one rule, asked twice.
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushSender sender = sender(builder());

            byte[] largestFitting = new byte[MAX_DEFAULT_PAYLOAD];
            assertThat(sender.assessPayloadSize(largestFitting)).isEqualTo(new PayloadSizeAssessment.WithinLimit());
            assertThat(sender.send(subscription(receiver), PushMessage.of(largestFitting)))
                    .isInstanceOf(PushOutcome.Accepted.class);

            byte[] smallestExceeding = new byte[MAX_DEFAULT_PAYLOAD + 1];
            PayloadSizeAssessment assessment = sender.assessPayloadSize(smallestExceeding);
            PushOutcome outcome = sender.send(subscription(receiver), PushMessage.of(smallestExceeding));
            assertThat(assessment)
                    .isEqualTo(new PayloadSizeAssessment.ExceedsLimit(MAX_DEFAULT_PAYLOAD + 1, MAX_DEFAULT_PAYLOAD));
            assertThat(outcome)
                    .isEqualTo(new PushOutcome.PayloadRejected(MAX_DEFAULT_PAYLOAD + 1, MAX_DEFAULT_PAYLOAD));
        }
    }

    @Test
    void aSendLeavesTheMessagesPayloadByteForByteUnchanged() throws IOException {
        // The pipeline reads the message's snapshot without copying it, so the immutability the
        // removed per-send copy used to provide is asserted here instead: two sends of one message,
        // each leaving the payload exactly as constructed — and the construction-time snapshot
        // still shields the message from the caller's own later writes.
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            byte[] input = new byte[512];
            for (int i = 0; i < input.length; i++) {
                input[i] = (byte) (i * 31);
            }
            byte[] expected = input.clone();
            PushMessage message = PushMessage.of(input);
            input[0] ^= 0x7f; // the caller scribbling on its own array must not reach the message

            PushSender sender = sender(builder());
            assertThat(sender.send(subscription(receiver), message)).isInstanceOf(PushOutcome.Accepted.class);
            assertThat(message.payload()).isEqualTo(expected);
            assertThat(sender.send(subscription(receiver), message)).isInstanceOf(PushOutcome.Accepted.class);
            assertThat(message.payload())
                    .as("a second send encrypts the same plaintext — nothing consumed or mutated it")
                    .isEqualTo(expected);
        }
    }

    @Test
    void theEncryptorsOwnRecordSizeCheckStillRefusesWithTheExactMinimumNamed() {
        // The direct-encryption path keeps its IllegalArgumentException: checkRecordSize guards
        // encrypt() itself, whose rs parameter stays and is reachable without the sender's derived
        // value, and its message names the exact rs to raise to — computed by the same inverse the
        // sender derives its rs with. Same rule, one implementation, both directions.
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

    /** The same builder, with the transport swapped for one that records each body and answers 201. */
    private static PushSender capturingSender(PushSender.Builder builder, List<byte[]> bodies) {
        return builder.httpClient((endpoint, headers, body) -> {
                    bodies.add(body);
                    return new PushResponse(201, Map.of());
                })
                .build();
    }

    /** A well-formed subscription for the capturing transport, which never opens a connection. */
    private static Subscription loopbackFreeSubscription() {
        return new Subscription(
                "https://push.example.test/send/abc", b64(TestVectors.UA_PUBLIC), b64(TestVectors.AUTH_SECRET));
    }
}
