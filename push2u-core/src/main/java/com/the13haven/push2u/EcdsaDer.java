package com.the13haven.push2u;

/**
 * Strict conversion of a DER-encoded P-256 ECDSA signature — {@code SEQUENCE { INTEGER r, INTEGER s }} — into the
 * 64-byte raw {@code r || s} pair JOSE ES256 requires (RFC 7518 §3.4), each coordinate normalised to exactly 32
 * unsigned big-endian bytes.
 *
 * <p>This is a re-encoding of the signature's <em>representation</em>, not a cryptographic operation: the private key
 * and the ECDSA computation itself stay entirely inside the JCE provider that produced the signature. It exists for
 * providers that register only the standard DER-output ECDSA name (BouncyCastle FIPS among them) and no raw-format
 * variant.
 *
 * <p>The parser is deliberately strict and rejects anything but the minimal DER a well-formed P-256 signature can
 * produce: wrong tags, long-form lengths (impossible at P-256 sizes), negative or non-minimally-encoded INTEGERs,
 * coordinates longer than 32 bytes after removing the sign byte, a missing or extra element, and any
 * length/trailing-byte mismatch. One boundary case is accepted on purpose: a minimally-encoded zero INTEGER ({@code 02
 * 01 00}) is well-formed DER and converts to an all-zero coordinate — this converter owns only the representation, and
 * a zero {@code r} or {@code s} can never verify, so rejecting cryptographically impossible values is the verifier's
 * job, not the re-encoder's.
 */
final class EcdsaDer {

    private static final int COORDINATE_LENGTH = 32;
    private static final byte SEQUENCE_TAG = 0x30;
    private static final byte INTEGER_TAG = 0x02;

    private EcdsaDer() {}

    /**
     * Converts a strict DER {@code SEQUENCE { INTEGER r, INTEGER s }} to 64 raw bytes {@code r || s}.
     *
     * @param der the DER-encoded ECDSA signature
     * @return the 64-byte P1363 form
     * @throws PushCryptoException if the input is not a well-formed minimal P-256 signature
     */
    static byte[] toP1363(byte[] der) {
        if (der == null || der.length < 2) {
            throw malformed("input too short for a SEQUENCE header");
        }
        if (der[0] != SEQUENCE_TAG) {
            throw malformed("expected a SEQUENCE tag");
        }
        int sequenceLength = shortFormLength(der[1], "SEQUENCE");
        if (sequenceLength != der.length - 2) {
            throw malformed("SEQUENCE length does not match the input length");
        }
        byte[] out = new byte[2 * COORDINATE_LENGTH];
        int afterR = readCoordinate(der, 2, out, 0);
        int afterS = readCoordinate(der, afterR, out, COORDINATE_LENGTH);
        if (afterS != der.length) {
            throw malformed("trailing bytes after the second INTEGER");
        }
        return out;
    }

    /**
     * Reads one INTEGER at {@code at}, writes its value right-aligned into {@code out[outOffset .. outOffset+31]}, and
     * returns the offset just past it.
     */
    // CyclomaticComplexity: every branch is one malformed-DER case reported with its own message.
    // Splitting them up would scatter the encoding rules this method exists to state in one place.
    @SuppressWarnings("PMD.CyclomaticComplexity")
    private static int readCoordinate(byte[] der, int at, byte[] out, int outOffset) {
        if (at + 2 > der.length) {
            throw malformed("missing INTEGER");
        }
        if (der[at] != INTEGER_TAG) {
            throw malformed("expected an INTEGER tag");
        }
        int length = shortFormLength(der[at + 1], "INTEGER");
        int start = at + 2;
        if (length < 1) {
            throw malformed("empty INTEGER");
        }
        if (start + length > der.length) {
            throw malformed("INTEGER length exceeds the input");
        }
        if ((der[start] & 0x80) != 0) {
            throw malformed("negative INTEGER");
        }
        if (length > 1 && der[start] == 0x00 && (der[start + 1] & 0x80) == 0) {
            throw malformed("non-minimal INTEGER encoding (redundant leading zero)");
        }
        int valueStart = start;
        int valueLength = length;
        if (der[valueStart] == 0x00) {
            // The sign byte a 32-byte coordinate with its high bit set needs; not part of the value.
            valueStart++;
            valueLength--;
        }
        if (valueLength > COORDINATE_LENGTH) {
            throw malformed("INTEGER longer than " + COORDINATE_LENGTH + " bytes");
        }
        System.arraycopy(der, valueStart, out, outOffset + COORDINATE_LENGTH - valueLength, valueLength);
        return start + length;
    }

    /**
     * Decodes a DER length byte requiring the short form. A P-256 signature is at most 72 bytes, so a long-form length
     * (high bit set) can never legitimately occur.
     */
    private static int shortFormLength(byte lengthByte, String what) {
        if ((lengthByte & 0x80) != 0) {
            throw malformed("long-form " + what + " length");
        }
        return lengthByte & 0x7F;
    }

    private static PushCryptoException malformed(String detail) {
        return new PushCryptoException("malformed DER ECDSA signature: " + detail);
    }
}
