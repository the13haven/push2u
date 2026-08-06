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
     * {@code secp256r1} by name — a prime-field curve. A provider reporting any other field type for that name is
     * defective, and a point this check cannot verify is a point it refuses (fail closed). This is deliberately not a
     * call to {@link P256PublicKeys#requireOnCurve}: that one checks the bytes against the published P-256 constants,
     * this one checks the point against the parameters of the provider that is about to run ECDH — only the equation
     * arithmetic is shared.
     */
    private static void requireOnCurve(BigInteger x, BigInteger y, ECParameterSpec parameters) {
        EllipticCurve curve = parameters.getCurve();
        if (!(curve.getField() instanceof ECFieldFp primeField)) {
            throw new PushCryptoException(
                    "The configured provider reports P-256 (secp256r1) parameters over a non-prime field, "
                            + "so the public key cannot be validated");
        }
        BigInteger p = primeField.getP();
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

    /** Encode a public key as the 65-byte X9.62 uncompressed point. */
    static byte[] encodeUncompressed(ECPublicKey key) {
        ECPoint point = key.getW();
        byte[] out = new byte[UNCOMPRESSED_LENGTH];
        out[0] = UNCOMPRESSED_TAG;
        writeFixed(point.getAffineX(), out, 1);
        writeFixed(point.getAffineY(), out, 1 + COORDINATE_LENGTH);
        return out;
    }

    /** Generate a fresh ephemeral P-256 key pair (the per-message application-server key). */
    static KeyPair generateP256(Jca jca) {
        try {
            KeyPairGenerator generator = jca.ecKeyPairGenerator();
            generator.initialize(new ECGenParameterSpec(Algorithms.SECP256R1));
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new PushCryptoException("P-256 key-pair generation failed", e);
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
     * Big-endian, fixed 32-byte serialization of a coordinate. {@link BigInteger#toByteArray()} can prepend a 0x00 sign
     * byte (33 bytes) or omit leading zeros (&lt;32 bytes); normalise both to exactly 32 bytes.
     */
    private static void writeFixed(BigInteger value, byte[] out, int offset) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == COORDINATE_LENGTH) {
            System.arraycopy(bytes, 0, out, offset, COORDINATE_LENGTH);
        } else if (bytes.length > COORDINATE_LENGTH) {
            System.arraycopy(bytes, bytes.length - COORDINATE_LENGTH, out, offset, COORDINATE_LENGTH);
        } else {
            System.arraycopy(bytes, 0, out, offset + (COORDINATE_LENGTH - bytes.length), bytes.length);
        }
    }
}
