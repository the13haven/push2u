package io.push2u;

import static io.push2u.PushTestSupport.generateVapidKeys;
import static io.push2u.PushTestSupport.subscription;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;

import org.junit.jupiter.api.Test;

/**
 * The two size preconditions of a send, checked before any cryptography or network I/O: the RFC 8030 §7.2 ceiling on
 * the encrypted entity body (default 4096 bytes, leaving 3993 bytes of plaintext) and the RFC 8291 §4 rule that
 * {@code rs} strictly exceed what one record holds. They are independent — raising one never adjusts the other — and
 * each has its own message.
 */
class PushSenderPayloadSizeTest {

    private static final int MAX_DEFAULT_PAYLOAD = 3993;

    @Test
    void theLargestPayloadThatFitsTheDefaultBodyLimitIsDelivered() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushResult result = sender(PushSender.builder())
                    .send(subscription(receiver), PushMessage.of(new byte[MAX_DEFAULT_PAYLOAD]));

            assertThat(result.delivered()).isTrue();
            assertThat(receiver.requests().getFirst().bodyLength())
                    .as("3993 bytes of plaintext fill the 4096-byte body exactly")
                    .isEqualTo(4096);
        }
    }

    @Test
    void onePayloadByteOverTheBodyLimitIsRejectedBeforeAnyRequest() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushSender sender = sender(PushSender.builder());
            Subscription subscription = subscription(receiver);
            PushMessage message = PushMessage.of(new byte[MAX_DEFAULT_PAYLOAD + 1]);

            assertThatThrownBy(() -> sender.send(subscription, message))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Encrypted Web Push body would be 4097 bytes, exceeding the configured maximum of "
                            + "4096 bytes; maximum plaintext payload is 3993 bytes");
            assertThat(receiver.requests())
                    .as("rejected before encrypting or contacting the service")
                    .isEmpty();
        }
    }

    @Test
    void raisingTheBodyLimitAloneFailsOnRecordSizeWithItsOwnMessage() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushSender sender = sender(PushSender.builder().maxEncryptedBodyBytes(8192));
            Subscription subscription = subscription(receiver);
            PushMessage message = PushMessage.of(new byte[5000]);

            assertThatThrownBy(() -> sender.send(subscription, message))
                    .as("the body fits 8192, but rs is still the default 4096")
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("recordSize 4096 is too small for a 5000-byte payload")
                    .hasMessageContaining("RFC 8291 §4")
                    .hasMessageContaining("raise recordSize to at least 5018");
            assertThat(receiver.requests()).isEmpty();
        }
    }

    @Test
    void raisingBothTheBodyLimitAndTheRecordSizeDelivers() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushResult result = sender(
                            PushSender.builder().maxEncryptedBodyBytes(8192).recordSize(8192))
                    .send(subscription(receiver), PushMessage.of(new byte[5000]));

            assertThat(result.delivered()).isTrue();
            assertThat(receiver.requests().getFirst().bodyLength()).isEqualTo(5000 + 103);
        }
    }

    @Test
    void recordSizeAtTheRfc8291BoundaryIsAcceptedOneBelowItIsNot() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            Subscription subscription = subscription(receiver);
            PushMessage message = PushMessage.of(new byte[100]);

            PushSender tooSmall = sender(PushSender.builder().recordSize(117));
            assertThatThrownBy(() -> tooSmall.send(subscription, message))
                    .as("rs == plaintext(100) + delimiter(1) + tag(16) is not *greater than* the sum")
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("recordSize 117 is too small");

            assertThat(sender(PushSender.builder().recordSize(118))
                            .send(subscription, message)
                            .delivered())
                    .as("one octet more is the smallest legal rs")
                    .isTrue();
        }
    }

    @Test
    void builderRejectsARecordSizeBelowTheRfc8188Minimum() {
        for (int invalid : new int[] {Integer.MIN_VALUE, -1, 0, 17}) {
            assertThatThrownBy(() -> PushSender.builder().recordSize(invalid))
                    .as("rs %d", invalid)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("recordSize must be at least 18");
        }
        assertThat(PushSender.builder().recordSize(18))
                .as("18 is legal (RFC 8188 §2)")
                .isNotNull();
    }

    @Test
    void builderRejectsAMaxEncryptedBodyTooSmallForAnEmptyPayload() {
        for (int invalid : new int[] {Integer.MIN_VALUE, -1, 0, 102}) {
            assertThatThrownBy(() -> PushSender.builder().maxEncryptedBodyBytes(invalid))
                    .as("maxEncryptedBodyBytes %d", invalid)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("must be at least the fixed 103-byte aes128gcm overhead");
        }
        // 103 is the body of an empty payload, which the library does send — so the limit that
        // admits exactly that body is legal, not one byte above it.
        assertThat(PushSender.builder().maxEncryptedBodyBytes(103)).isNotNull();
    }

    @Test
    void anEmptyPayloadFitsTheSmallestLegalBodyLimit() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushResult result = sender(PushSender.builder().maxEncryptedBodyBytes(103))
                    .send(subscription(receiver), PushMessage.of(new byte[0]));

            assertThat(result.delivered()).isTrue();
            assertThat(receiver.requests().getFirst().bodyLength())
                    .as("an empty payload encrypts to exactly the fixed overhead")
                    .isEqualTo(103);
        }
    }

    @Test
    void theBodySizeSumDoesNotWrapNearIntegerMaxValue() {
        // Driven through the length-taking checks so the boundary is covered without allocating a
        // two-gigabyte payload. This is the one sum where int arithmetic would actually break:
        // Integer.MAX_VALUE + 103 wraps to -2147483546, which is below any limit, so the payload
        // would sail through the check.
        assertThatThrownBy(() ->
                        WebPushEncryptor.checkPayloadFits(Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("body would be 2147483750 bytes");

        // The largest payload an Integer.MAX_VALUE body limit admits, with an rs to match: the
        // body sum lands exactly on the limit rather than past it.
        WebPushEncryptor.checkPayloadFits(Integer.MAX_VALUE - 103, Integer.MAX_VALUE, Integer.MAX_VALUE);
    }

    @Test
    void theRecordSizeBranchNamesTheExactMinimumForAHugePayload() {
        // Past the body check (its limit is raised out of the way), so only the RFC 8291 §4 rule
        // speaks: 2147483544 + 17 + 1. Nothing here overflows — a payload big enough to wrap that
        // sum cannot reach it, since the body check would already have failed.
        assertThatThrownBy(() -> WebPushEncryptor.checkPayloadFits(Integer.MAX_VALUE - 103, 4096, Integer.MAX_VALUE))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("raise recordSize to at least 2147483562");
    }

    private static PushSender sender(PushSender.Builder builder) {
        return builder.vapid(generateVapidKeys())
                .contact("mailto:ops@example.com")
                .build();
    }
}
