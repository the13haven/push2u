/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

import org.jspecify.annotations.Nullable;

/**
 * Single point of access to the JCA for the cryptographic pipeline: every {@code getInstance(...)} whose provider a
 * consumer can configure goes through here, optionally bound to a specific {@link Provider}. One lookup deliberately
 * sits outside this seam: the endpoint-redaction fingerprint hashes with the platform's own SHA-256 regardless of any
 * configured provider, because it is diagnostics, not protocol.
 *
 * <p>This is the JCE seam — instead of a bespoke {@code CryptoProvider} SPI, the optional
 * {@code .cryptoProvider(java.security.Provider)} builder option constructs {@link #using(Provider)}; everything else
 * uses {@link #platform()} and resolves against the JVM's default provider chain. Centralizing it here means the
 * encryptor and the local signer never touch a provider directly — they ask this helper.
 *
 * <p>The seam is also where the library's rule for a provider's <em>answers</em> is drawn. A value a provider returns
 * from its own implementation can be degenerately defective — {@code null} where the JDK's types promise nothing — and
 * it is refused by name, as a {@link PushCryptoException}, wherever the value can <em>travel</em>: leave the library as
 * a public method's own (never-{@code null}) answer, outlive the call that obtained it as stored state, or otherwise
 * carry its failure away from the seam it came from. The {@code KeyPair} a generator answers, the key a
 * {@code KeyFactory} answers, the {@code secp256r1} parameters an {@code AlgorithmParameters} lookup answers and the
 * bytes an ES256 {@code Signature} produces all travel that way, and each is refused beside the verification that
 * inspects it. An answer that cannot travel — a MAC's or a cipher's output, the ECDH shared secret — dies in the next
 * step of the same operation whether checked or not: a {@code null} there already fails immediately, loudly and next to
 * its cause, so a refusal would change only the exception's name, and that defensive padding would spread to every
 * provider call without end.
 */
final class Jca {

    /** {@code null} means the JVM default provider search order. */
    @Nullable
    private final Provider provider;

    /**
     * The ES256 algorithm name + output format resolved for this instance, computed lazily on the first
     * {@link #es256()} call (not in the constructor: a {@code Jca} may serve only content encryption — e.g. with an
     * external signer — and must not fail on a missing ECDSA). Volatile + immutable + idempotent computation, so a racy
     * first call at worst resolves twice and both writers store an equal value — safe for the concurrent sends a single
     * {@code PushSender} serves.
     */
    @Nullable
    private volatile Es256Resolution es256Resolution;

    private record Es256Resolution(String algorithm, EcdsaSignature.Encoding encoding) {}

    /**
     * The {@code secp256r1} parameters resolved from this instance's provider and verified against the published NIST
     * P-256 values, computed lazily on the first {@link #p256Parameters()} call. Volatile + immutable + idempotent
     * computation, exactly as {@link #es256Resolution}: a racy first call at worst resolves twice, and each writer has
     * verified its own value before storing it — the cache only saves work, it is never what makes the check hold.
     */
    @Nullable
    private volatile ECParameterSpec p256Parameters;

    private Jca(@Nullable Provider provider) {
        this.provider = provider;
    }

    /** Use the JVM's default JCE provider search order (SunEC / SunJCE on a stock JDK). */
    static Jca platform() {
        return new Jca(null);
    }

    /** Bind every primitive to a specific provider (e.g. BouncyCastle FIPS). */
    static Jca using(Provider provider) {
        return new Jca(Objects.requireNonNull(provider, "provider"));
    }

    Mac hmacSha256() {
        try {
            return provider == null
                    ? Mac.getInstance(Algorithms.HMAC_SHA256)
                    : Mac.getInstance(Algorithms.HMAC_SHA256, provider);
        } catch (GeneralSecurityException e) {
            throw unavailable(Algorithms.HMAC_SHA256, e);
        }
    }

    Cipher aesGcm() {
        try {
            return provider == null
                    ? Cipher.getInstance(Algorithms.AES_GCM_NO_PADDING)
                    : Cipher.getInstance(Algorithms.AES_GCM_NO_PADDING, provider);
        } catch (GeneralSecurityException e) {
            throw unavailable(Algorithms.AES_GCM_NO_PADDING, e);
        }
    }

    KeyAgreement ecdh() {
        try {
            return provider == null
                    ? KeyAgreement.getInstance(Algorithms.ECDH)
                    : KeyAgreement.getInstance(Algorithms.ECDH, provider);
        } catch (GeneralSecurityException e) {
            throw unavailable(Algorithms.ECDH, e);
        }
    }

    KeyFactory ecKeyFactory() {
        try {
            return provider == null
                    ? KeyFactory.getInstance(Algorithms.EC)
                    : KeyFactory.getInstance(Algorithms.EC, provider);
        } catch (GeneralSecurityException e) {
            throw unavailable(Algorithms.EC + " KeyFactory", e);
        }
    }

    KeyPairGenerator ecKeyPairGenerator() {
        try {
            return provider == null
                    ? KeyPairGenerator.getInstance(Algorithms.EC)
                    : KeyPairGenerator.getInstance(Algorithms.EC, provider);
        } catch (GeneralSecurityException e) {
            throw unavailable(Algorithms.EC + " KeyPairGenerator", e);
        }
    }

    /**
     * An ES256 {@link Signature} together with the format its output will be in. The VAPID JWT needs the raw 64-byte
     * {@code r || s} pair (RFC 7518 §3.4); a {@code DER} delegate's output must therefore be converted before use — the
     * caller does that, this record only reports which case it is.
     */
    record EcdsaSignature(Signature delegate, Encoding encoding) {
        enum Encoding {
            P1363,
            DER
        }
    }

    /**
     * The ES256 signature primitive from the configured provider, preferring native P1363 output. Resolution order:
     * first {@code SHA256withECDSAinP1363Format} (raw {@code r || s} directly — registered by SunEC and stock
     * BouncyCastle); if the provider does not register that name, {@code SHA256withECDSA} (standard DER output — the
     * only ECDSA form BouncyCastle FIPS registers) from the <em>same</em> provider. The fallback never widens the
     * provider search: with an explicit provider both lookups are bound to it, so the signature cannot silently escape
     * a compliance boundary to another installed provider.
     *
     * <p>The name/format pair is resolved once per instance and cached; only the (stateful, and therefore per-call)
     * {@link Signature} is created on every invocation — the steady-state path costs one {@code getInstance} and no
     * exception construction, also on the DER fallback.
     */
    EcdsaSignature es256() {
        Es256Resolution resolution = es256Resolution;
        if (resolution == null) {
            resolution = resolveEs256();
            es256Resolution = resolution;
        }
        try {
            return new EcdsaSignature(signature(resolution.algorithm()), resolution.encoding());
        } catch (NoSuchAlgorithmException e) {
            // A provider cannot unlearn an algorithm it resolved moments ago; fail loud anyway.
            throw unavailable(resolution.algorithm(), e);
        }
    }

    private Es256Resolution resolveEs256() {
        try {
            signature(Algorithms.ES256_P1363);
            return new Es256Resolution(Algorithms.ES256_P1363, EcdsaSignature.Encoding.P1363);
        } catch (NoSuchAlgorithmException p1363Missing) {
            try {
                signature(Algorithms.ES256_DER);
                return new Es256Resolution(Algorithms.ES256_DER, EcdsaSignature.Encoding.DER);
            } catch (NoSuchAlgorithmException derMissing) {
                derMissing.addSuppressed(p1363Missing);
                throw new PushCryptoException(
                        "ES256 signing is unavailable from " + providerDescription() + ": neither "
                                + Algorithms.ES256_P1363 + " (raw r||s) nor " + Algorithms.ES256_DER
                                + " (DER) is registered",
                        derMissing);
            }
        }
    }

    private Signature signature(String algorithm) throws NoSuchAlgorithmException {
        return provider == null ? Signature.getInstance(algorithm) : Signature.getInstance(algorithm, provider);
    }

    /**
     * The {@code secp256r1} (NIST P-256) domain parameters used everywhere in Web Push, resolved from the configured
     * provider and verified value for value against the published NIST constants before anything runs on them. The
     * lookup is by name, and the name is all a defective provider needs to honour: an answer carrying some other curve
     * — secp256k1, brainpoolP256r1, or a deliberately weak one — would otherwise silently move the ECDH agreement that
     * protects each payload, and the import of the long-term VAPID private key, onto that curve. This is the one seam
     * where provider-supplied parameters enter the library (both the public-key and the private-key decode take them
     * from here), so verifying here leaves no unverified entry point; the parameters are a per-instance constant, so
     * the verified result is cached and the check is not repaid on every send.
     */
    ECParameterSpec p256Parameters() {
        ECParameterSpec parameters = p256Parameters;
        if (parameters == null) {
            parameters = resolveP256Parameters();
            p256Parameters = parameters;
        }
        return parameters;
    }

    private ECParameterSpec resolveP256Parameters() {
        ECParameterSpec parameters;
        try {
            AlgorithmParameters params = provider == null
                    ? AlgorithmParameters.getInstance(Algorithms.EC)
                    : AlgorithmParameters.getInstance(Algorithms.EC, provider);
            params.init(new ECGenParameterSpec(Algorithms.SECP256R1));
            parameters = params.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) {
            throw unavailable("EC AlgorithmParameters (" + Algorithms.SECP256R1 + ")", e);
        }
        requireNistP256(parameters);
        return parameters;
    }

    /**
     * Refuse a {@code secp256r1} answer that is not, value for value, NIST P-256: prime field modulus {@code p},
     * coefficients {@code a} and {@code b}, generator {@code G}, order {@code n}, cofactor {@code h}. The comparison
     * itself lives with the hard-coded FIPS 186-4 reference values in {@link P256PublicKeys} (which the build pins
     * against two independent providers); this method turns a mismatch into the failure. The message names the
     * component that differs and quotes no values — the component name is what an operator needs. A provider whose
     * {@code AlgorithmParameters} answers the spec lookup with {@code null} is reported the same way — as carrying no
     * domain parameters at all — rather than dereferenced.
     */
    private void requireNistP256(@Nullable ECParameterSpec parameters) {
        String mismatch = P256PublicKeys.nistP256Mismatch(parameters);
        if (mismatch != null) {
            throw new PushCryptoException("The " + Algorithms.SECP256R1 + " parameters from " + providerDescription()
                    + " are not the published NIST P-256 domain parameters (" + mismatch
                    + "), so every EC operation would run on the wrong curve");
        }
    }

    private PushCryptoException unavailable(String algorithm, Throwable cause) {
        return new PushCryptoException(algorithm + " is unavailable from " + providerDescription(), cause);
    }

    private String providerDescription() {
        return provider == null ? "the platform JCE providers" : "provider " + provider.getName();
    }
}
