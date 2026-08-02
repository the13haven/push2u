package io.push2u;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * Deterministic vectors for the strict DER → P1363 conversion: short coordinates are right-aligned to 32 bytes,
 * sign-padding bytes are removed, and every deviation from minimal two-INTEGER DER is rejected.
 */
class EcdsaDerTest {

    // ---- happy path ---------------------------------------------------------------------------

    @Test
    void thirtyOneByteCoordinatesAreRightAlignedWithALeadingZero() {
        byte[] r = counting(31, (byte) 0x11);
        byte[] s = counting(31, (byte) 0x51);

        byte[] out = EcdsaDer.toP1363(sequence(integer(r), integer(s)));

        assertThat(out).hasSize(64);
        assertThat(out[0]).as("r padded to 32 bytes").isEqualTo((byte) 0x00);
        assertThat(Arrays.copyOfRange(out, 1, 32)).isEqualTo(r);
        assertThat(out[32]).as("s padded to 32 bytes").isEqualTo((byte) 0x00);
        assertThat(Arrays.copyOfRange(out, 33, 64)).isEqualTo(s);
    }

    @Test
    void exactlyThirtyTwoByteCoordinatesPassThroughUnchanged() {
        byte[] r = counting(32, (byte) 0x01); // high bit clear — no sign byte in DER
        byte[] s = counting(32, (byte) 0x41);

        byte[] out = EcdsaDer.toP1363(sequence(integer(r), integer(s)));

        assertThat(Arrays.copyOfRange(out, 0, 32)).isEqualTo(r);
        assertThat(Arrays.copyOfRange(out, 32, 64)).isEqualTo(s);
    }

    @Test
    void signPaddingZeroIsStrippedFromAHighBitCoordinate() {
        byte[] r = counting(32, (byte) 0x91); // high bit set — DER needs a 0x00 sign byte
        byte[] s = counting(31, (byte) 0x21);
        byte[] paddedR = new byte[33];
        System.arraycopy(r, 0, paddedR, 1, 32); // 0x00 || r — a 33-byte INTEGER body

        byte[] out = EcdsaDer.toP1363(sequence(integer(paddedR), integer(s)));

        assertThat(Arrays.copyOfRange(out, 0, 32))
                .as("sign byte removed, value kept")
                .isEqualTo(r);
        assertThat(Arrays.copyOfRange(out, 33, 64)).isEqualTo(s);
    }

    @Test
    void minimalZeroIntegerYieldsAnAllZeroCoordinate() {
        // 02 01 00 is well-formed DER for the value zero, so the converter accepts it and emits
        // 32 zero bytes: this parser owns the representation only — r = 0 can never verify, and
        // rejecting cryptographically impossible values is the verifier's job.
        byte[] s = counting(31, (byte) 0x21);

        byte[] out = EcdsaDer.toP1363(sequence(integer(new byte[] {0x00}), integer(s)));

        assertThat(Arrays.copyOfRange(out, 0, 32)).as("zero r → 32 zero bytes").containsOnly((byte) 0x00);
        assertThat(Arrays.copyOfRange(out, 33, 64)).isEqualTo(s);
    }

    // ---- rejections ---------------------------------------------------------------------------

    @Test
    void rejectsAWrongOuterTag() {
        byte[] der = sequence(integer(counting(4, (byte) 1)), integer(counting(4, (byte) 9)));
        der[0] = 0x31;

        assertThatThrownBy(() -> EcdsaDer.toP1363(der))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("SEQUENCE tag");
    }

    @Test
    void rejectsALongFormSequenceLength() {
        byte[] body = concat(integer(counting(4, (byte) 1)), integer(counting(4, (byte) 9)));
        byte[] der = concat(new byte[] {0x30, (byte) 0x81, (byte) body.length}, body);

        assertThatThrownBy(() -> EcdsaDer.toP1363(der))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("long-form");
    }

    // The next test and rejectsASequenceLengthShorterThanTheInput below exercise the SAME guard
    // (the SEQUENCE length must span exactly the rest of the input) from its two sides: a length
    // claiming more bytes than are present, and an input carrying bytes beyond the claimed length.

    @Test
    void rejectsASequenceLengthLongerThanTheInput() {
        byte[] der = sequence(integer(counting(4, (byte) 1)), integer(counting(4, (byte) 9)));
        der[1] = (byte) (der[1] + 1); // claims one byte more than is present

        assertThatThrownBy(() -> EcdsaDer.toP1363(der))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("SEQUENCE length");
    }

    @Test
    void rejectsALongFormIntegerLength() {
        // 02 81 04 ... — long-form length on the INTEGER itself (the SEQUENCE case is separate).
        byte[] longFormInteger = concat(new byte[] {0x02, (byte) 0x81, 0x04}, counting(4, (byte) 1));
        byte[] der = sequence(longFormInteger, integer(counting(4, (byte) 9)));

        assertThatThrownBy(() -> EcdsaDer.toP1363(der))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("long-form INTEGER length");
    }

    @Test
    void rejectsAZeroLengthInteger() {
        byte[] der = sequence(integer(new byte[0]), integer(counting(4, (byte) 9)));

        assertThatThrownBy(() -> EcdsaDer.toP1363(der))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("empty INTEGER");
    }

    @Test
    void rejectsANegativeInteger() {
        byte[] negative = counting(32, (byte) 0x91); // high bit set, no sign byte → negative

        assertThatThrownBy(() -> EcdsaDer.toP1363(sequence(integer(negative), integer(counting(4, (byte) 9)))))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("negative INTEGER");
    }

    @Test
    void rejectsANonMinimalLeadingZero() {
        byte[] nonMinimal = concat(new byte[] {0x00}, counting(4, (byte) 0x01)); // 0x00 before < 0x80

        assertThatThrownBy(() -> EcdsaDer.toP1363(sequence(integer(nonMinimal), integer(counting(4, (byte) 9)))))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("non-minimal");
    }

    @Test
    void rejectsACoordinateLongerThan32Bytes() {
        byte[] oversized = counting(33, (byte) 0x01); // 33 value bytes even without a sign byte

        assertThatThrownBy(() -> EcdsaDer.toP1363(sequence(integer(counting(4, (byte) 1)), integer(oversized))))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("longer than 32");
    }

    @Test
    void rejectsAMissingSecondInteger() {
        assertThatThrownBy(() -> EcdsaDer.toP1363(sequence(integer(counting(4, (byte) 1)))))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("missing INTEGER");
    }

    @Test
    void rejectsAThirdElementAfterS() {
        byte[] der = sequence(
                integer(counting(4, (byte) 1)), integer(counting(4, (byte) 9)), integer(counting(4, (byte) 17)));

        assertThatThrownBy(() -> EcdsaDer.toP1363(der))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("trailing bytes");
    }

    @Test
    void rejectsTrailingBytesInsideTheSequence() {
        byte[] der = sequence(integer(counting(4, (byte) 1)), integer(counting(4, (byte) 9)), new byte[] {0x00});

        assertThatThrownBy(() -> EcdsaDer.toP1363(der))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("trailing bytes");
    }

    @Test
    void rejectsASequenceLengthShorterThanTheInput() {
        byte[] valid = sequence(integer(counting(4, (byte) 1)), integer(counting(4, (byte) 9)));
        byte[] der = concat(valid, new byte[] {0x00}); // SEQUENCE length no longer spans the input

        assertThatThrownBy(() -> EcdsaDer.toP1363(der))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("SEQUENCE length");
    }

    // ---- DER building blocks ------------------------------------------------------------------

    /** {@code length} bytes counting up from {@code from} — deterministic, high bit of byte 0 known. */
    private static byte[] counting(int length, byte from) {
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            out[i] = (byte) (from + i);
        }
        return out;
    }

    /** A DER INTEGER TLV over the given body bytes (taken verbatim — tests control the padding). */
    private static byte[] integer(byte[] body) {
        return concat(new byte[] {0x02, (byte) body.length}, body);
    }

    /** A DER SEQUENCE TLV over the concatenated elements. */
    private static byte[] sequence(byte[]... elements) {
        byte[] body = concat(elements);
        return concat(new byte[] {0x30, (byte) body.length}, body);
    }

    private static byte[] concat(byte[]... parts) {
        return TestVectors.concat(parts);
    }
}
