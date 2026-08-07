/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.util.Arrays;

/**
 * P-256 key import/export and ECDH, all through the JDK ({@link Jca}). Handles the two wire forms Web Push uses: the
 * X9.62 uncompressed point ({@code 0x04 || X || Y}, 65 bytes) for public keys ({@code p256dh}, VAPID {@code k}) and the
 * raw 32-byte scalar for the VAPID private key.
 */
final class EcKeys {

    static final int UNCOMPRESSED_LENGTH = P256PublicKeys.UNCOMPRESSED_LENGTH;
    static final int COORDINATE_LENGTH = P256PublicKeys.COORDINATE_LENGTH;
    private static final byte UNCOMPRESSED_TAG = P256PublicKeys.UNCOMPRESSED_TAG;

    private EcKeys() {}

    /**
     * Parse a 65-byte uncompressed P-256 point into a public key, refusing any point that is not on the curve (see
     * {@link #requireOnCurve}) before the provider ever sees it.
     */
    static ECPublicKey decodeP256PublicKey(byte[] uncompressed, Jca jca) {
        P256PublicKeys.requireUncompressedPoint(uncompressed, "public key");
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(uncompressed, 1, 1 + COORDINATE_LENGTH));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(uncompressed, 1 + COORDINATE_LENGTH, UNCOMPRESSED_LENGTH));
        ECParameterSpec parameters = jca.p256Parameters();
        requireOnCurve(x, y, parameters);
        try {
            KeyFactory keyFactory = jca.ecKeyFactory();
            return (ECPublicKey) keyFactory.generatePublic(new ECPublicKeySpec(new ECPoint(x, y), parameters));
        } catch (GeneralSecurityException e) {
            throw new PushCryptoException("Invalid P-256 public key", e);
        }
    }

    /**
     * Refuse a point that is not on the curve of {@code parameters}: {@code 0 <= x, y < p} (coordinates inside the
     * prime field), then the short Weierstrass equation {@code y² ≡ x³ + ax + b (mod p)}. The {@code p256dh}
     * subscription key is attacker-reachable input (RFC 8291 §3.1 requires the user agent's key on P-256, but nothing
     * upstream enforces it), and an off-curve point fed into ECDH is the entry ticket for an invalid-curve attack. The
     * check happens here, before {@link KeyFactory#generatePublic}: {@code ECPublicKeySpec} is a container, not a
     * validator, and whether {@code KeyAgreement.doPhase} refuses the point later is a per-provider choice —
     * {@code Jca.using(...)} accepts arbitrary providers, so the library cannot rest on it.
     *
     * <p>{@code 0x04 || 0^32 || 0^32} gets no special message: the X9.62 wire format cannot express the point at
     * infinity (it encodes infinity as a single {@code 0x00} byte, which already fails the length check), so those
     * bytes are merely the affine point {@code (0, 0)} — off the curve like any other, because P-256's {@code b} is
     * non-zero. The messages quote no coordinates: the failure is structural, and the digits would only copy
     * attacker-chosen bytes into logs.
     *
     * <p>The parameters come from {@link Jca#p256Parameters()}, which asks the configured provider for
     * {@code secp256r1} by name and has already verified the answer value for value against the published NIST P-256
     * constants — including that the field is prime, which is what makes the cast below safe. This is deliberately not
     * a call to {@link P256PublicKeys#requireOnCurve}: that one checks the bytes against the published P-256 constants,
     * this one checks the point against the (verified) parameters of the provider that is about to run ECDH — only the
     * equation arithmetic is shared.
     */
    private static void requireOnCurve(BigInteger x, BigInteger y, ECParameterSpec parameters) {
        EllipticCurve curve = parameters.getCurve();
        BigInteger p = ((ECFieldFp) curve.getField()).getP();
        if (x.signum() < 0 || x.compareTo(p) >= 0 || y.signum() < 0 || y.compareTo(p) >= 0) {
            throw new PushCryptoException("P-256 public key has a coordinate outside the field (0 <= x, y < p), "
                    + "so it is not a point on the curve");
        }
        if (!P256PublicKeys.satisfiesCurveEquation(x, y, p, curve.getA(), curve.getB())) {
            throw new PushCryptoException("P-256 public key does not satisfy the curve equation (y² = x³ + ax + b), "
                    + "so it is not a point on the curve");
        }
    }

    /** Build a private key from the raw 32-byte P-256 scalar {@code d}. */
    static ECPrivateKey decodeP256PrivateKey(byte[] scalar, Jca jca) {
        if (scalar.length != COORDINATE_LENGTH) {
            throw new IllegalArgumentException("Expected a 32-byte P-256 private scalar");
        }
        BigInteger s = new BigInteger(1, scalar);
        try {
            KeyFactory keyFactory = jca.ecKeyFactory();
            return (ECPrivateKey) keyFactory.generatePrivate(new ECPrivateKeySpec(s, jca.p256Parameters()));
        } catch (GeneralSecurityException e) {
            throw new PushCryptoException("Invalid P-256 private key", e);
        }
    }

    /**
     * Encode a public key as the 65-byte X9.62 uncompressed point. The fixed 32-byte coordinate fields are P-256's
     * field size, and a coordinate from a larger curve is rejected rather than truncated (see {@link #writeFixed}).
     */
    static byte[] encodeUncompressed(ECPublicKey key) {
        ECPoint point = key.getW();
        byte[] out = new byte[UNCOMPRESSED_LENGTH];
        out[0] = UNCOMPRESSED_TAG;
        writeFixed(point.getAffineX(), out, 1);
        writeFixed(point.getAffineY(), out, 1 + COORDINATE_LENGTH);
        return out;
    }

    /**
     * Generate a fresh ephemeral P-256 key pair (the per-message application-server key). The generator resolves the
     * {@code secp256r1} name itself, so the verification {@link Jca#p256Parameters()} applies to imported keys does not
     * reach this path — and the generated pair sits on the same trust boundary: its public half is published in the
     * {@code aes128gcm} header and its private half drives the ECDH agreement. Hence the returned pair gets the same
     * standard of verification before it is used (see {@link #requireGeneratedOnP256}): both halves must be EC keys
     * whose declared domain parameters match the published NIST P-256 constants value for value, and the public point
     * must additionally satisfy the curve equation — so a generator that honoured the name with some other curve, or
     * with P-256's curve under a substituted order, generator point or cofactor, fails loudly here instead of deriving
     * the content-encryption keys on parameters nobody chose.
     */
    static KeyPair generateP256(Jca jca) {
        KeyPair pair;
        try {
            KeyPairGenerator generator = jca.ecKeyPairGenerator();
            generator.initialize(new ECGenParameterSpec(Algorithms.SECP256R1));
            pair = generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new PushCryptoException("P-256 key-pair generation failed", e);
        }
        requireGeneratedOnP256(pair);
        return pair;
    }

    /**
     * Refuse a generated pair that is not, in every respect checkable from the outside, a NIST P-256 key pair. The
     * generator already answered the {@code secp256r1} lookup, so honouring the name must be proven rather than
     * assumed, and two checks of different reach do it: each half's declared domain parameters are compared value for
     * value against the published NIST constants, and the public point is required to satisfy the curve equation.
     * Neither check covers the other — parameter equality proves what the generator <em>declares</em>, the equation
     * proves the point it actually <em>returned</em> lies on the declared curve. The parameter comparison is what
     * catches the sharpest defect: a wrong order {@code n} leaves every generated point genuinely on P-256, but
     * {@code n} bounds the private scalar, so a small substituted order draws a guessable scalar and a guessable ECDH
     * secret. The private half gets the type and parameter checks too — the scalar has no equation to satisfy, but the
     * agreement runs on its parameters. The messages quote no coordinates or scalars: the values are fresh key
     * material, and the failure is structural.
     */
    private static void requireGeneratedOnP256(KeyPair pair) {
        if (!(pair.getPublic() instanceof ECPublicKey publicKey)) {
            throw new PushCryptoException("P-256 key-pair generation returned a "
                    + pair.getPublic().getAlgorithm() + " public key, not an EC one");
        }
        requireGeneratedP256Parameters(publicKey.getParams(), "public");
        requireGeneratedPointOnP256(publicKey.getW());
        if (!(pair.getPrivate() instanceof ECPrivateKey privateKey)) {
            throw new PushCryptoException("P-256 key-pair generation returned a "
                    + pair.getPrivate().getAlgorithm() + " private key, not an EC one");
        }
        requireGeneratedP256Parameters(privateKey.getParams(), "private");
    }

    /**
     * The parameter check of {@link #requireGeneratedOnP256}: the {@code half} key's declared domain parameters must be
     * the published NIST P-256 values — prime field modulus, both coefficients, generator, order and cofactor. The
     * message names the mismatched component and quotes no values, the same way the import-side parameter verification
     * reports it.
     */
    private static void requireGeneratedP256Parameters(ECParameterSpec parameters, String half) {
        String mismatch = P256PublicKeys.nistP256Mismatch(parameters);
        if (mismatch != null) {
            throw new PushCryptoException("P-256 key-pair generation returned a " + half
                    + " key whose parameters are not the published NIST P-256 domain parameters (" + mismatch
                    + "), so the generator did not honour the secp256r1 name");
        }
    }

    /**
     * The point check of {@link #requireGeneratedOnP256}, against the hard-coded published constants: not the point at
     * infinity (whose affine coordinates are {@code null}, so it is refused before the arithmetic), both coordinates
     * inside the prime field, and the curve equation satisfied.
     */
    private static void requireGeneratedPointOnP256(ECPoint w) {
        if (ECPoint.POINT_INFINITY.equals(w)) {
            throw new PushCryptoException(
                    "P-256 key-pair generation returned the point at infinity, which is not a usable public key");
        }
        if (!P256PublicKeys.isOnNistP256(w.getAffineX(), w.getAffineY())) {
            throw new PushCryptoException("P-256 key-pair generation returned a public point that is not on NIST "
                    + "P-256, so the generator did not honour the secp256r1 name");
        }
    }

    /** ECDH on P-256: the shared secret is the 32-byte X coordinate of the agreed point. */
    static byte[] ecdh(ECPrivateKey privateKey, ECPublicKey publicKey, Jca jca) {
        try {
            var agreement = jca.ecdh();
            agreement.init(privateKey);
            agreement.doPhase(publicKey, true);
            return agreement.generateSecret();
        } catch (GeneralSecurityException e) {
            throw new PushCryptoException("ECDH key agreement failed", e);
        }
    }

    /**
     * Write {@code value} as a fixed 32-byte big-endian field at {@code offset} (right-aligned).
     * {@link BigInteger#toByteArray()} is two's complement, so a 256-bit coordinate with its top bit set carries a
     * leading {@code 0x00} sign byte — padding, dropped here — and a small coordinate arrives short of 32 bytes and is
     * left-padded. Anything wider than one sign byte's worth of padding is <em>significant</em> and fails loudly:
     * truncating it would publish a plausible-looking but wrong point as the message's application-server key or as a
     * VAPID public key, and the only symptom would be a much later, opaque failure at the user agent or push service.
     */
    private static void writeFixed(BigInteger value, byte[] out, int offset) {
        byte[] bytes = value.toByteArray();
        int start = 0;
        while (start < bytes.length - COORDINATE_LENGTH && bytes[start] == 0) {
            start++;
        }
        int length = bytes.length - start;
        // Two distinct failures, reported apart: BigInteger.bitLength() is the length of the
        // MINIMAL two's-complement representation excluding the sign bit, so it is 0 for -1 and
        // would turn a negative coordinate into a nonsensical "0 bits" complaint.
        if (value.signum() < 0) {
            throw new PushCryptoException(
                    "The public key being encoded has a negative coordinate, which is not a P-256 field element");
        }
        if (length > COORDINATE_LENGTH) {
            throw new PushCryptoException("The public key being encoded has a coordinate that is not a P-256 field "
                    + "element: " + value.bitLength() + " bits, expected at most " + (COORDINATE_LENGTH * Byte.SIZE));
        }
        System.arraycopy(bytes, start, out, offset + COORDINATE_LENGTH - length, length);
    }
}
