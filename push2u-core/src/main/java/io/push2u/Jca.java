package io.push2u;

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
 * Single point of access to the JCA: every {@code getInstance(...)} the library makes goes through here, optionally
 * bound to a specific {@link Provider}.
 *
 * <p>This is the JCE seam — instead of a bespoke {@code CryptoProvider} SPI, the optional
 * {@code .cryptoProvider(java.security.Provider)} builder option constructs {@link #using(Provider)}; everything else
 * uses {@link #platform()} and resolves against the JVM's default provider chain. Centralizing it here means the
 * encryptor and the local signer never touch a provider directly — they ask this helper.
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

    /** The {@code secp256r1} (NIST P-256) domain parameters used everywhere in Web Push. */
    ECParameterSpec p256Parameters() {
        try {
            AlgorithmParameters params = provider == null
                    ? AlgorithmParameters.getInstance(Algorithms.EC)
                    : AlgorithmParameters.getInstance(Algorithms.EC, provider);
            params.init(new ECGenParameterSpec(Algorithms.SECP256R1));
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) {
            throw unavailable("EC AlgorithmParameters (" + Algorithms.SECP256R1 + ")", e);
        }
    }

    private PushCryptoException unavailable(String algorithm, Throwable cause) {
        return new PushCryptoException(algorithm + " is unavailable from " + providerDescription(), cause);
    }

    private String providerDescription() {
        return provider == null ? "the platform JCE providers" : "provider " + provider.getName();
    }
}
