/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

/**
 * Strict conversion between the two representations of a P-256 ECDSA signature: DER ({@code SEQUENCE { INTEGER r,
 * INTEGER s }}) and the 64-byte raw {@code r || s} pair JOSE ES256 requires (RFC 7518 §3.4), each coordinate normalised
 * to exactly 32 unsigned big-endian bytes. {@link #toP1363} converts DER output to raw for signing; {@link #toDer}
 * converts raw back to DER for verifying.
 *
 * <p>Both directions are re-encodings of the signature's <em>representation</em>, not cryptographic operations: the
 * private key and the ECDSA computation itself stay entirely inside the JCE provider involved. They exist for providers
 * that register only the standard DER-form ECDSA name (BouncyCastle FIPS among them) and no raw-format variant.
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
     * Converts a raw 64-byte {@code r || s} signature into the minimal DER {@code SEQUENCE { INTEGER r, INTEGER s }} —
     * the exact inverse of {@link #toP1363}. Like its counterpart this is a re-encoding of the signature's
     * representation, not a cryptographic operation. It exists for the verifying direction of the same provider gap:
     * handing a JOSE signature to a provider that registers only the standard DER-input ECDSA name (BouncyCastle FIPS
     * among them) requires the DER form. The output is strictly minimal — leading zero bytes are dropped from each
     * coordinate and a {@code 0x00} sign byte is added only when the top bit is set — because DER admits exactly one
     * encoding and strict verifiers (the FIPS ones in particular) reject anything else.
     *
     * <p>An all-zero coordinate encodes as the minimal zero INTEGER ({@code 02 01 00}) — the same boundary
     * {@link #toP1363} accepts, and for the same reason: rejecting cryptographically impossible values is the
     * verifier's job, not the re-encoder's.
     *
     * @param p1363 the 64-byte raw {@code r || s} signature
     * @return the minimal DER encoding
     * @throws IllegalArgumentException if the input is not exactly 64 bytes
     */
    static byte[] toDer(byte[] p1363) {
        if (p1363 == null || p1363.length != 2 * COORDINATE_LENGTH) {
            throw new IllegalArgumentException("Expected a 64-byte raw r||s ES256 signature");
        }
        byte[] r = encodeInteger(p1363, 0);
        byte[] s = encodeInteger(p1363, COORDINATE_LENGTH);
        // Worst case 2 + 35 + 35 = 72 bytes: the body always fits a short-form SEQUENCE length.
        byte[] out = new byte[2 + r.length + s.length];
        out[0] = SEQUENCE_TAG;
        out[1] = (byte) (r.length + s.length);
        System.arraycopy(r, 0, out, 2, r.length);
        System.arraycopy(s, 0, out, 2 + r.length, s.length);
        return out;
    }

    /** One minimally-encoded INTEGER TLV over the 32-byte big-endian coordinate at {@code offset}. */
    private static byte[] encodeInteger(byte[] src, int offset) {
        int start = offset;
        int end = offset + COORDINATE_LENGTH;
        // Drop leading zeros, keeping at least one byte so a zero coordinate stays representable.
        while (start < end - 1 && src[start] == 0) {
            start++;
        }
        int valueLength = end - start;
        // DER INTEGERs are signed: a value whose top bit is set needs a 0x00 sign byte to stay positive.
        boolean needsSignByte = (src[start] & 0x80) != 0;
        byte[] out = new byte[2 + (needsSignByte ? 1 : 0) + valueLength];
        out[0] = INTEGER_TAG;
        out[1] = (byte) (out.length - 2);
        System.arraycopy(src, start, out, out.length - valueLength, valueLength);
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
