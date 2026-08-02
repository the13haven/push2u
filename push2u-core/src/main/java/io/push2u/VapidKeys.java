package io.push2u;

import java.util.Objects;

/**
 * A VAPID (RFC 8292) application-server key pair: the P-256 public key in X9.62 uncompressed form (65 bytes — the value
 * advertised as the {@code k} parameter) and the raw 32-byte private scalar. This is pure key material; turning the
 * scalar into a usable signing key is the signer's job (see {@link LocalEcVapidSigner}), so {@code VapidKeys} carries
 * no JCA state.
 *
 * <p>Both halves are commonly distributed as base64url — use {@link #fromBase64}.
 */
public final class VapidKeys {

    private final byte[] publicKey;
    private final byte[] privateScalar;

    private VapidKeys(byte[] publicKey, byte[] privateScalar) {
        if (publicKey.length != EcKeys.UNCOMPRESSED_LENGTH || publicKey[0] != 0x04) {
            throw new IllegalArgumentException("VAPID public key must be a 65-byte uncompressed P-256 point");
        }
        if (privateScalar.length != EcKeys.COORDINATE_LENGTH) {
            throw new IllegalArgumentException("VAPID private key must be a 32-byte P-256 scalar");
        }
        this.publicKey = publicKey.clone();
        this.privateScalar = privateScalar.clone();
    }

    /**
     * Wraps the 65-byte uncompressed public key and the raw 32-byte private scalar.
     *
     * @param publicKey the 65-byte uncompressed P-256 public key
     * @param privateScalar the raw 32-byte private scalar
     * @return the key pair
     */
    public static VapidKeys of(byte[] publicKey, byte[] privateScalar) {
        Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(privateScalar, "privateScalar");
        return new VapidKeys(publicKey, privateScalar);
    }

    /**
     * Decodes the base64url public key and private scalar (the usual VAPID distribution form).
     *
     * @param publicKey the base64url-encoded uncompressed public key
     * @param privateKey the base64url-encoded private scalar
     * @return the key pair
     */
    public static VapidKeys fromBase64(String publicKey, String privateKey) {
        return new VapidKeys(Base64Url.decode(publicKey), Base64Url.decode(privateKey));
    }

    /**
     * The 65-byte uncompressed public key (the VAPID {@code k} value).
     *
     * @return a copy of the public key
     */
    public byte[] publicKey() {
        return publicKey.clone();
    }

    byte[] privateScalar() {
        return privateScalar.clone();
    }
}
