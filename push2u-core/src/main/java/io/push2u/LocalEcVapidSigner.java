package io.push2u;

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.util.Objects;

/**
 * The default {@link VapidSigner}: holds the P-256 private key in memory and signs in-JVM,
 * always producing the raw {@code r || s} pair JOSE wants. When the configured provider
 * registers raw-format ECDSA ({@code SHA256withECDSAinP1363Format}) the signature is used as
 * is; when it registers only the standard DER form ({@code SHA256withECDSA}, e.g. BouncyCastle
 * FIPS), the DER output is strictly re-encoded to {@code r || s} — a representation change
 * only, the signing itself stays inside that provider. Suitable when the key is sourced at
 * rest (e.g. from a secrets manager) and signing in-process is acceptable; for a key that must
 * never touch the heap, use a remote signer instead.
 */
public final class LocalEcVapidSigner implements VapidSigner {

    private final byte[] publicKey;
    private final ECPrivateKey privateKey;
    private final Jca jca;

    /**
     * Creates a signer over the given VAPID key pair, signing in-JVM with the platform JCE provider.
     *
     * @param keys the VAPID key pair
     */
    public LocalEcVapidSigner(VapidKeys keys) {
        this(keys, Jca.platform());
    }

    LocalEcVapidSigner(VapidKeys keys, Jca jca) {
        Objects.requireNonNull(keys, "keys");
        this.jca = Objects.requireNonNull(jca, "jca");
        this.publicKey = keys.publicKey();
        this.privateKey = EcKeys.decodeP256PrivateKey(keys.privateScalar(), jca);
    }

    @Override
    public byte[] sign(byte[] signingInput) {
        Jca.EcdsaSignature es256 = jca.es256();
        try {
            Signature signature = es256.delegate();
            signature.initSign(privateKey);
            signature.update(signingInput);
            byte[] raw = signature.sign();
            return es256.encoding() == Jca.EcdsaSignature.Encoding.DER ? EcdsaDer.toP1363(raw) : raw;
        } catch (GeneralSecurityException e) {
            throw new PushCryptoException("VAPID ES256 signing failed", e);
        }
    }

    @Override
    public byte[] publicKey() {
        return publicKey.clone();
    }
}
