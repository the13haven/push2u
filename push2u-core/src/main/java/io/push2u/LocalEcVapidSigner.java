package io.push2u;

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.util.Objects;

/**
 * The default {@link VapidSigner}: holds the P-256 private key in memory and signs in-JVM via
 * {@code SHA256withECDSAinP1363Format}, which emits the raw {@code r || s} JOSE wants directly
 * (DESIGN.md §4). Suitable when the key is sourced at rest (e.g. from a secrets manager) and
 * signing in-process is acceptable; for a key that must never touch the heap, use a remote
 * signer instead (ADR-010).
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
        try {
            Signature signature = jca.es256();
            signature.initSign(privateKey);
            signature.update(signingInput);
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new PushCryptoException("VAPID ES256 signing failed", e);
        }
    }

    @Override
    public byte[] publicKey() {
        return publicKey.clone();
    }
}
