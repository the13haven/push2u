package io.push2u;

import static io.push2u.PushTestSupport.generateVapidKeys;
import static io.push2u.PushTestSupport.subscription;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import org.junit.jupiter.api.Test;

/**
 * The two size preconditions of a send, checked before any cryptography or network I/O: the
 * RFC 8030 §7.2 ceiling on the encrypted entity body (default 4096 bytes, leaving 3993 bytes of
 * plaintext) and the RFC 8291 §4 rule that {@code rs} strictly exceed what one record holds.
 * They are independent — raising one never adjusts the other — and each has its own message.
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
            assertThat(receiver.requests()).as("rejected before encrypting or contacting the service").isEmpty();
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
            PushResult result = sender(PushSender.builder().maxEncryptedBodyBytes(8192).recordSize(8192))
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

            assertThat(sender(PushSender.builder().recordSize(118)).send(subscription, message).delivered())
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
        assertThat(PushSender.builder().recordSize(18)).as("18 is legal (RFC 8188 §2)").isNotNull();
    }

    @Test
    void builderRejectsAMaxEncryptedBodyThatLeavesNoRoomForAPayload() {
        for (int invalid : new int[] {Integer.MIN_VALUE, -1, 0, 103}) {
            assertThatThrownBy(() -> PushSender.builder().maxEncryptedBodyBytes(invalid))
                .as("maxEncryptedBodyBytes %d", invalid)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must be greater than the fixed 103-byte aes128gcm overhead");
        }
        assertThat(PushSender.builder().maxEncryptedBodyBytes(104)).isNotNull();
    }

    @Test
    void sizeArithmeticDoesNotOverflowAtTheIntBoundaries() {
        // Exercised through the package-private seam so the boundaries near Integer.MAX_VALUE are
        // covered without allocating multi-gigabyte payloads.
        assertThatThrownBy(() ->
            PushSender.checkPayloadFits(Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE))
            .as("payload + 103 must not wrap to a negative body size")
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("body would be 2147483750 bytes");

        assertThatThrownBy(() ->
            PushSender.checkPayloadFits(Integer.MAX_VALUE - 103, 4096, Integer.MAX_VALUE))
            .as("payload + 18 must not wrap either")
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("raise recordSize to at least 2147483562");

        // The largest payload an Integer.MAX_VALUE body limit admits, with an rs large enough for
        // it: both checks pass without either sum overflowing.
        PushSender.checkPayloadFits(Integer.MAX_VALUE - 103, Integer.MAX_VALUE, Integer.MAX_VALUE);
    }

    private static PushSender sender(PushSender.Builder builder) {
        return builder.vapid(generateVapidKeys()).contact("mailto:ops@example.com").build();
    }
}
