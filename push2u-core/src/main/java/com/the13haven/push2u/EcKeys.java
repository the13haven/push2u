/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
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

import org.jspecify.annotations.Nullable;

/**
 * P-256 key import/export and ECDH, all through the JDK ({@link Jca}). Handles the two wire forms Web Push uses: the
 * X9.62 uncompressed point ({@code 0x04 || X || Y}, 65 bytes) for public keys ({@code p256dh}, VAPID {@code k}) and the
 * raw 32-byte scalar for the VAPID private key.
 */
// GodClass: tipped over the metric (WMC 48 against the rule's 47) by one added branch of the
// generated-key verification, which refuses a degenerate provider answer by name instead of
// dereferencing it. The class is the single home for P-256 key import/export and the provider
// checks guarding those operations; splitting the checks out to satisfy the metric would separate
// them from what they guard.
@SuppressWarnings("PMD.GodClass")
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
     * Encode a public key as the 65-byte X9.62 uncompressed point. Call only with a key already validated to carry a
     * real point: the one production caller serialises the freshly generated ephemeral key, whose {@code getW()} has
     * been refused by {@link #generateP256} if it was {@code null} or the point at infinity, so neither is re-checked
     * here — a key that passed those checks and answers differently on this read is lying, and a liar can equally
     * answer with a different <em>valid</em> point, which no re-check could catch. The fixed 32-byte coordinate fields
     * are P-256's field size, and a coordinate from a larger curve is rejected rather than truncated (see
     * {@link #writeFixed}).
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
     * Refuse a generated pair that fails what this library verifies of a NIST P-256 key pair — three checks, exactly:
     * both halves must be EC keys, both halves' declared domain parameters must equal the published NIST P-256
     * constants value for value, and the public point must lie on the curve of those constants. The generator already
     * answered the {@code secp256r1} lookup, so honouring the name must be proven rather than assumed, and the last two
     * checks prove different things — parameter equality proves what the generator <em>declares</em>, the curve
     * equation proves the point it actually <em>returned</em> lies on the declared curve. The parameter comparison is
     * what catches the sharpest checkable defect: a wrong order {@code n} leaves every generated point genuinely on
     * P-256, but {@code n} bounds the private scalar, so a small substituted order draws a guessable scalar and a
     * guessable ECDH secret.
     *
     * <p>Two failure modes are outside this check's reach, on purpose. A provider that declares the correct parameters
     * and simply draws a weak or attacker-known scalar passes undetected — no parameter verification can catch that,
     * which is why the choice of provider remains a trust decision. And the two halves are not checked to belong
     * together ({@code W = d·G} is not evaluated): that needs point multiplication, which this library deliberately
     * does not implement, and it would buy nothing against a hostile provider, which can always hand over a
     * self-consistent pair whose scalar it knows. The scalar's range is not checked either: for a pair whose halves do
     * belong together, a scalar of zero shows up as a public point at infinity, which the point check refuses — and for
     * a mismatched pair it is no worse than any other scalar the previous sentence already leaves uncaught. A scalar at
     * or above {@code n} acts as its residue {@code d mod n} and is no weaker for it, and the private-scalar import
     * path applies no range check, which is the standard this path is held to.
     *
     * <p>The messages quote no coordinates or scalars: the values are fresh key material, and the failure is
     * structural.
     */
    private static void requireGeneratedOnP256(KeyPair pair) {
        if (!(pair.getPublic() instanceof ECPublicKey publicKey)) {
            throw notAnEcKey(pair.getPublic(), "public");
        }
        requireGeneratedP256Parameters(publicKey.getParams(), "public");
        requireGeneratedPointOnP256(publicKey.getW());
        if (!(pair.getPrivate() instanceof ECPrivateKey privateKey)) {
            throw notAnEcKey(pair.getPrivate(), "private");
        }
        requireGeneratedP256Parameters(privateKey.getParams(), "private");
    }

    /**
     * The type-check failure of {@link #requireGeneratedOnP256}, phrased for both degenerate shapes: a key of some
     * other algorithm, and no key at all — {@link KeyPair} stores whatever references it was handed, {@code null}
     * included, and the refusal must stay this library's own crypto exception rather than a
     * {@link NullPointerException} escaping from the diagnostic itself.
     */
    private static PushCryptoException notAnEcKey(@Nullable Key key, String half) {
        if (key == null) {
            return new PushCryptoException("P-256 key-pair generation returned no " + half + " key at all");
        }
        return new PushCryptoException(
                "P-256 key-pair generation returned a " + key.getAlgorithm() + " " + half + " key, not an EC one");
    }

    /**
     * The parameter check of {@link #requireGeneratedOnP256}: the {@code half} key's declared domain parameters must be
     * the published NIST P-256 values — prime field modulus, both coefficients, generator, order and cofactor. The
     * message names the mismatched component and quotes no values, the same way the import-side parameter verification
     * reports it. A key answering {@code getParams()} with {@code null} — the provider's own key implementation is what
     * answers, and nothing obliges a defective one to answer at all — is reported the same way, as having no domain
     * parameters, rather than dereferenced.
     */
    private static void requireGeneratedP256Parameters(@Nullable ECParameterSpec parameters, String half) {
        String mismatch = P256PublicKeys.nistP256Mismatch(parameters);
        if (mismatch != null) {
            throw new PushCryptoException("P-256 key-pair generation returned a " + half
                    + " key whose parameters are not the published NIST P-256 domain parameters (" + mismatch
                    + "), so the generator did not honour the secp256r1 name");
        }
    }

    /**
     * The point check of {@link #requireGeneratedOnP256}, against the hard-coded published constants: a point at all
     * (the provider's key implementation answers {@code getW()}, and a defective one can answer {@code null} — which
     * {@code ECPoint.POINT_INFINITY.equals(null)} quietly reports as {@code false}, so it must be refused by name
     * before that comparison), not the point at infinity (whose affine coordinates are {@code null}, so it is refused
     * before the arithmetic), both coordinates inside the prime field, and the curve equation satisfied.
     */
    private static void requireGeneratedPointOnP256(@Nullable ECPoint w) {
        if (w == null) {
            throw new PushCryptoException(
                    "P-256 key-pair generation returned a public key reporting no point at all, which is not a usable"
                            + " public key");
        }
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
