package com.the13haven.push2u;

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;

/**
 * Local ES256 verification of a raw {@code r || s} signature against a 65-byte X9.62 uncompressed P-256 public key —
 * the verifying counterpart of what a {@link VapidSigner} produces.
 *
 * <p>Public because verification is how a caller holding only the {@link VapidSigner} SPI can check a signature end to
 * end: the Spring Boot starter's health indicator uses it to prove the configured signer's output actually verifies
 * against the key the signer advertises, instead of merely being 64 bytes long. It lives in the core, not the starter,
 * because it must mirror the core's ES256 provider resolution exactly: a provider that registers only DER-form ECDSA
 * (BouncyCastle FIPS) signs correctly through {@link Jca}'s fallback, and verification must work on that same platform
 * or it would condemn a perfectly healthy signer — the FIPS test suite here pins that, which no starter-local copy
 * could.
 *
 * <p>Resolution follows {@link Jca#es256()} and is cached the same way (once per underlying {@code Jca}, so once per
 * JVM for the platform entry points below): prefer {@code SHA256withECDSAinP1363Format} and verify the raw signature
 * directly; fall back to {@code SHA256withECDSA} and re-encode the raw signature to minimal DER
 * ({@link EcdsaDer#toDer}) first — a representation change only.
 */
public final class Es256Verifier {

    private static final int SIGNATURE_LENGTH = 64;

    /**
     * The platform-provider resolution, shared so the name lookup happens once per JVM — the same caching discipline as
     * {@link Jca}'s own per-instance resolution, which this reuses.
     */
    private static final Jca PLATFORM_JCA = Jca.platform();

    private Es256Verifier() {}

    /**
     * Whether this JVM's default providers offer an ES256 verification primitive at all — {@code true} on any stock
     * JDK. {@code false} is a platform-capability statement (neither the raw-format nor the DER-form ECDSA name is
     * registered), and callers should treat it as "verification unavailable here", not as evidence against any
     * particular signature: a remote signer on such a platform may still sign perfectly well.
     *
     * @return whether {@link #verify(byte[], byte[], byte[])} can run on this JVM
     */
    public static boolean isSupported() {
        return isSupported(PLATFORM_JCA);
    }

    /**
     * Verifies a raw ES256 signature over {@code signingInput} against the given public key, using the JVM's default
     * providers.
     *
     * @param uncompressedPublicKey the P-256 public key as a 65-byte X9.62 uncompressed point ({@code 0x04 || X || Y})
     * @param signingInput the exact bytes that were signed
     * @param rawSignature the 64-byte raw {@code r || s} signature to check
     * @return {@code true} if the signature is valid for this input and key, {@code false} otherwise
     * @throws IllegalArgumentException if the key or the signature has the wrong length or structure
     * @throws PushCryptoException if the key cannot be imported, or no ES256 primitive is available (see
     *     {@link #isSupported()})
     */
    public static boolean verify(byte[] uncompressedPublicKey, byte[] signingInput, byte[] rawSignature) {
        return verify(PLATFORM_JCA, uncompressedPublicKey, signingInput, rawSignature);
    }

    /** Provider-bound variant — the seam the FIPS suite uses to pin the DER fallback path. */
    static boolean isSupported(Jca jca) {
        try {
            jca.es256();
            return true;
        } catch (PushCryptoException neitherNameRegistered) {
            return false;
        }
    }

    /** Provider-bound variant — the seam the FIPS suite uses to pin the DER fallback path. */
    static boolean verify(Jca jca, byte[] uncompressedPublicKey, byte[] signingInput, byte[] rawSignature) {
        if (rawSignature.length != SIGNATURE_LENGTH) {
            throw new IllegalArgumentException(
                    "Expected a " + SIGNATURE_LENGTH + "-byte raw r||s ES256 signature, got " + rawSignature.length);
        }
        // Capability before inputs: on a platform with no ES256 primitive the failure must name
        // that (the isSupported() contract), not whichever input-processing step happened first.
        Jca.EcdsaSignature es256 = jca.es256();
        ECPublicKey publicKey = EcKeys.decodeP256PublicKey(uncompressedPublicKey, jca);
        // On a DER-only provider the raw signature is re-encoded to the form the provider verifies;
        // on a P1363 provider it is handed over as is. Either way the ECDSA math runs inside the
        // provider — the re-encoding is representation only.
        byte[] wireSignature =
                es256.encoding() == Jca.EcdsaSignature.Encoding.DER ? EcdsaDer.toDer(rawSignature) : rawSignature;
        try {
            Signature verifier = es256.delegate();
            verifier.initVerify(publicKey);
            verifier.update(signingInput);
            return verifier.verify(wireSignature);
        } catch (SignatureException invalidSignature) {
            // Some providers report an unparseable or out-of-range signature by throwing rather
            // than returning false. For a verification API those are the same answer: this byte
            // string is not a valid signature for this key and input.
            return false;
        } catch (GeneralSecurityException e) {
            throw new PushCryptoException("ES256 verification failed before the signature was checked", e);
        }
    }
}
