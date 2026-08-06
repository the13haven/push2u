/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

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
        Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(privateKey, "privateKey");
        return new VapidKeys(decode(publicKey, "public"), decode(privateKey, "private"));
    }

    /**
     * Decodes one half, naming it if the decoder refuses. The JDK's message for a bad character is {@code "Illegal
     * base64 character 2b"} and nothing else — the same text for either half, mentioning neither VAPID nor which of the
     * two values was wrong. {@code 2b} is {@code '+'}, and a {@code '+'} or {@code '/'} means the key was encoded with
     * the standard base64 alphabet rather than the URL-safe one Web Push uses: an {@code openssl base64} pipeline, or a
     * language whose default encoder is the standard one, produces exactly that.
     */
    // The cause is kept and only the message replaced, because the decoder's own text says nothing
    // about which of the two values it is refusing.
    private static byte[] decode(String value, String half) {
        try {
            return Base64Url.decode(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "VAPID " + half + " key is not valid base64url (RFC 4648 §5, the URL-safe alphabet with '-' and"
                            + " '_' rather than '+' and '/', padding optional): " + e.getMessage(),
                    e);
        }
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
