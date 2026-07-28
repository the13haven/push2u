package io.push2u;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

/**
 * Single point of access to the JCA: every {@code getInstance(...)} the library makes goes
 * through here, optionally bound to a specific {@link Provider}.
 *
 * <p>This is the seam DESIGN.md §5.1 describes — instead of a bespoke {@code CryptoProvider}
 * SPI, the optional {@code .cryptoProvider(java.security.Provider)} builder option
 * constructs {@link #using(Provider)}; everything else uses {@link #platform()} and resolves
 * against the JVM's default provider chain. Centralizing it here means the encryptor and the
 * local signer never touch a provider directly — they ask this helper.
 */
final class Jca {

    private final Provider provider;

    private Jca(Provider provider) {
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
     * ES256 with the P1363 signature format, i.e. the raw {@code r || s} pair JOSE expects —
     * no DER-to-P1363 conversion, no jose4j (DESIGN.md §4). This algorithm name is registered
     * by SunEC; a non-default provider may spell raw-format ECDSA differently (see README's
     * BouncyCastle caveat), which is why {@code .cryptoProvider(...)} is scoped to the
     * content-encryption primitives, not the VAPID signature.
     */
    Signature es256() {
        try {
            return provider == null
                ? Signature.getInstance(Algorithms.ES256_P1363)
                : Signature.getInstance(Algorithms.ES256_P1363, provider);
        } catch (GeneralSecurityException e) {
            throw unavailable(Algorithms.ES256_P1363, e);
        }
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
        String where = provider == null ? "the platform JCE providers" : "provider " + provider.getName();
        return new PushCryptoException(algorithm + " is unavailable from " + where, cause);
    }
}
