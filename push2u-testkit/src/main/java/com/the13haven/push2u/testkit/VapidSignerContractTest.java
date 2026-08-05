/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import com.the13haven.push2u.VapidSigner;

/**
 * The conformance contract every {@link VapidSigner} must satisfy: the advertised public key is a 65-byte uncompressed
 * point that actually lies on NIST P-256 and arrives as a fresh copy on every call, and signing produces a raw {@code r
 * || s} ES256 signature (64 bytes) that verifies against it. Each implementation extends this and supplies a configured
 * signer via {@link #signer()} — the local signer's unit test and every remote signer's integration test.
 *
 * <p>Verification uses only the JDK and the public {@link VapidSigner} surface, so the contract is self-contained and
 * carries no push2u-internal dependency. It also runs wherever the library itself runs: signature verification prefers
 * the provider's native {@code SHA256withECDSAinP1363Format} and, on a JVM whose providers register only the DER form
 * {@code SHA256withECDSA} (a FIPS-only platform — BouncyCastle FIPS registers no raw-format name), re-encodes the raw
 * signature to minimal DER and verifies through that name instead, the same resolution the library makes for its own
 * signing. A kit that failed with {@code NoSuchAlgorithmException} there would condemn a perfectly conforming signer
 * for a platform reason.
 *
 * <p>Put {@code com.the13haven:push2u-testkit} on the test classpath and extend this class:
 *
 * <pre>{@code
 * class MySignerContractTest extends VapidSignerContractTest {
 *     @Override
 *     protected VapidSigner signer() {
 *         return new MySigner(...);
 *     }
 * }
 * }</pre>
 */
public abstract class VapidSignerContractTest {

    /** For subclasses: the kit is extended, never instantiated on its own. */
    protected VapidSignerContractTest() {}

    /**
     * The signer under test.
     *
     * @return a fully configured {@link VapidSigner}
     */
    protected abstract VapidSigner signer();

    // UnitTestContainsTooManyAsserts: PMD analyses this module's main sources, and this is main
    // source that happens to be a test. Length and prefix are the two halves of one claim — "this
    // is an X9.62 uncompressed point" — and neither half means anything alone.
    @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
    @Test
    void publicKeyIsA65ByteUncompressedPoint() {
        byte[] publicKey = signer().publicKey();
        assertThat(publicKey).hasSize(65);
        assertThat(publicKey[0]).as("X9.62 uncompressed point prefix").isEqualTo((byte) 0x04);
    }

    /**
     * Length and prefix say nothing about the coordinates: the JCA imports a well-framed off-curve point without
     * complaint, and a signer advertising one would publish a VAPID key no push service can verify. So the contract
     * checks the point against P-256 itself — coordinates inside the prime field, then the curve equation {@code y² ≡
     * x³ + ax + b (mod p)}.
     */
    // UnitTestContainsTooManyAsserts: "the point is on P-256" is one claim, and its assertions are
    // a chain rather than a list — the length guard is what makes the coordinate split meaningful,
    // the field bounds are what make the curve equation meaningful. Split across methods they would
    // re-derive the same key and report one broken signer as several unrelated failures.
    @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
    @Test
    void publicKeyIsAPointOnTheP256Curve() throws GeneralSecurityException {
        byte[] publicKey = signer().publicKey();
        assertThat(publicKey).hasSize(65);

        BigInteger x = new BigInteger(1, Arrays.copyOfRange(publicKey, 1, 33));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(publicKey, 33, 65));
        EllipticCurve curve = p256Parameters().getCurve();
        BigInteger p = ((ECFieldFp) curve.getField()).getP();
        assertThat(x).as("x is inside the prime field (x < p)").isLessThan(p);
        assertThat(y).as("y is inside the prime field (y < p)").isLessThan(p);

        BigInteger left = y.multiply(y).mod(p);
        BigInteger right = x.multiply(x)
                .multiply(x)
                .add(curve.getA().multiply(x))
                .add(curve.getB())
                .mod(p);
        assertThat(left)
                .as("the advertised point satisfies the P-256 curve equation (y² = x³ + ax + b mod p)")
                .isEqualTo(right);
    }

    // UnitTestContainsTooManyAsserts: the signature's length and its verification are one claim —
    // raw r||s that verifies — and asserting the length first is what turns a DER signature into
    // "expected 64 bytes" instead of an opaque `verify() == false`.
    @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
    @Test
    void signatureIsRawRsThatVerifiesAgainstTheAdvertisedPublicKey() throws GeneralSecurityException {
        VapidSigner signer = signer();
        byte[] signingInput = "push2u VapidSigner conformance".getBytes(StandardCharsets.US_ASCII);

        byte[] signature = signer.sign(signingInput);
        assertThat(signature).as("raw r||s, not DER").hasSize(64);

        assertThat(verifyEs256(signer.publicKey(), signingInput, signature))
                .as("verifies against the advertised public key")
                .isTrue();
    }

    /**
     * A 65-byte array of the right shape can still be the signer's own state: {@link VapidSigner#publicKey()} requires
     * a fresh copy on every call, because a signer handing out its internal array is corrupted for every later
     * signature by the first caller that writes into the returned bytes — and nothing else would notice, the mutated
     * key still being a well-framed point.
     */
    @Test
    void publicKeyIsAFreshCopyOnEveryCall() {
        VapidSigner signer = signer();
        byte[] returned = signer.publicKey();
        byte[] advertised = returned.clone();
        Arrays.fill(returned, (byte) 0);
        assertThat(signer.publicKey())
                .as("mutating the array publicKey() returned must not change what the next call returns")
                .isEqualTo(advertised);
    }

    /**
     * ES256 verification with the same provider resolution the library makes for its own signing: prefer the native
     * raw-signature form {@code SHA256withECDSAinP1363Format}; where a provider registers only DER-form ECDSA
     * (BouncyCastle FIPS), fall back to {@code SHA256withECDSA} over the raw {@code r || s} re-encoded to minimal DER.
     */
    private static boolean verifyEs256(byte[] uncompressedPublicKey, byte[] signingInput, byte[] rawSignature)
            throws GeneralSecurityException {
        Signature p1363Verifier;
        try {
            p1363Verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
        } catch (NoSuchAlgorithmException p1363NotRegistered) {
            return verifyEs256ViaDerFallback(uncompressedPublicKey, signingInput, rawSignature);
        }
        return verify(p1363Verifier, uncompressedPublicKey, signingInput, rawSignature);
    }

    /**
     * The DER-only branch of {@link #verifyEs256(byte[], byte[], byte[])}, callable on its own: CI has no JVM whose
     * providers lack the P1363 name, so {@code VapidSignerContractSelfTest} drives this path directly instead of hoping
     * some platform reaches it.
     */
    static boolean verifyEs256ViaDerFallback(byte[] uncompressedPublicKey, byte[] signingInput, byte[] rawSignature)
            throws GeneralSecurityException {
        return verify(
                Signature.getInstance("SHA256withECDSA"),
                uncompressedPublicKey,
                signingInput,
                toMinimalDer(rawSignature));
    }

    private static boolean verify(
            Signature verifier, byte[] uncompressedPublicKey, byte[] signingInput, byte[] wireSignature)
            throws GeneralSecurityException {
        verifier.initVerify(decodeP256PublicKey(uncompressedPublicKey));
        verifier.update(signingInput);
        try {
            return verifier.verify(wireSignature);
        } catch (SignatureException invalidSignature) {
            // Some providers report an unparseable or out-of-range signature by throwing rather
            // than returning false. For a conformance check both are the same answer: this byte
            // string is not a valid signature for this key and input.
            return false;
        }
    }

    /**
     * Re-encodes a raw 64-byte {@code r || s} signature as the minimal DER {@code ECDSA-Sig-Value} — {@code SEQUENCE {
     * INTEGER r, INTEGER s }} — that the DER-form verifier consumes. A representation change only: the ECDSA math stays
     * inside the provider. Each INTEGER's content octets are the value's minimal two's-complement encoding, which for a
     * non-negative value is exactly what {@link BigInteger#toByteArray()} produces: leading zero bytes stripped, one
     * {@code 0x00} sign byte exactly when the first magnitude byte has its high bit set, a single {@code 0x00} for
     * zero. A zero {@code r} or {@code s} is not a valid ECDSA signature, but rejecting it is the verifier's job — it
     * can never verify — not the re-encoder's, whose output must simply stay well-formed DER.
     */
    static byte[] toMinimalDer(byte[] rawRs) {
        byte[] r = new BigInteger(1, Arrays.copyOfRange(rawRs, 0, 32)).toByteArray();
        byte[] s = new BigInteger(1, Arrays.copyOfRange(rawRs, 32, 64)).toByteArray();
        // Worst case 2 + 35 + 35 = 72 bytes: the SEQUENCE body always fits a short-form length.
        byte[] der = new byte[2 + 2 + r.length + 2 + s.length];
        der[0] = 0x30; // SEQUENCE
        der[1] = (byte) (der.length - 2);
        der[2] = 0x02; // INTEGER r
        der[3] = (byte) r.length;
        System.arraycopy(r, 0, der, 4, r.length);
        int sTag = 4 + r.length;
        der[sTag] = 0x02; // INTEGER s
        der[sTag + 1] = (byte) s.length;
        System.arraycopy(s, 0, der, sTag + 2, s.length);
        return der;
    }

    private static ECPublicKey decodeP256PublicKey(byte[] uncompressed) throws GeneralSecurityException {
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(uncompressed, 1, 33));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(uncompressed, 33, 65));
        return (ECPublicKey)
                KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), p256Parameters()));
    }

    /**
     * The canonical {@code secp256r1} (NIST P-256) domain parameters, from the platform JCE providers.
     *
     * <p>{@code "EC"} here and in {@link #decodeP256PublicKey(byte[])} needs no FIPS fallback, unlike the signature
     * name: the P1363/DER split is a signature-format concern with no {@code KeyFactory} or {@code AlgorithmParameters}
     * counterpart, {@code "EC"} is the single standard JCA name for both services, and BouncyCastle FIPS registers both
     * — the core's BC-FIPS suite resolves keys and domain parameters through these very names against that provider.
     */
    private static ECParameterSpec p256Parameters() throws GeneralSecurityException {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        return parameters.getParameterSpec(ECParameterSpec.class);
    }
}
