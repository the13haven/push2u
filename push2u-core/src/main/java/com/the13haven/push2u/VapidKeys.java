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
 * <p>Both halves are commonly distributed as base64url — use {@link #fromBase64}. The other direction exists for the
 * public half alone: {@link #encodePublicKey} produces the string a browser needs as {@code applicationServerKey}. The
 * private scalar gets no encoder, because handing a secret back as a string is the one direction this library does not
 * provide.
 */
public final class VapidKeys {

    private final byte[] publicKey;
    private final byte[] privateScalar;

    // The public key gets the full on-curve check, not merely the structural one. This is operator
    // configuration rather than attacker input, but a corrupted or transposed value is caught here
    // — at VapidKeys creation, typically config-loading time, with the input named — instead of as
    // LocalEcVapidSigner's later PushCryptoException; and no 65-byte non-point can ever be a valid
    // VAPID key, so nothing legal is refused. The check needs no JCA provider (this type
    // deliberately carries no JCA state).
    private VapidKeys(byte[] publicKey, byte[] privateScalar) {
        P256PublicKeys.requireOnCurve(publicKey, "VAPID public key");
        if (privateScalar.length != EcKeys.COORDINATE_LENGTH) {
            throw new IllegalArgumentException("VAPID private key must be a 32-byte P-256 scalar");
        }
        this.publicKey = publicKey.clone();
        this.privateScalar = privateScalar.clone();
    }

    /**
     * Wraps the 65-byte uncompressed public key and the raw 32-byte private scalar.
     *
     * @param publicKey the 65-byte uncompressed P-256 public key — it must encode a point on the curve
     *     ({@link P256PublicKeys#requireOnCurve}), so a corrupted value fails here rather than at the first send
     * @param privateScalar the raw 32-byte private scalar
     * @return the key pair
     * @throws IllegalArgumentException if the public key does not encode a point on P-256 or the scalar is not 32 bytes
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
     * @throws IllegalArgumentException if either half is not valid base64url, the public key does not encode a point on
     *     P-256, or the scalar is not 32 bytes
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
     * Encodes a VAPID public key into the string a browser takes as the {@code applicationServerKey} option of
     * {@code pushManager.subscribe(...)} — the same spelling {@link #fromBase64} reads back, and the same one the
     * library puts in the {@code k} parameter of every {@code Authorization} header it sends.
     *
     * <p>Three details decide whether the browser accepts it, and all three are applied here. The alphabet is the
     * URL-safe one of <a href="https://datatracker.ietf.org/doc/html/rfc4648#section-5">RFC 4648 §5</a> — {@code '-'}
     * and {@code '_'} where standard base64 has {@code '+'} and {@code '/'}. There is no padding: no trailing
     * {@code '='}, which is what a default {@code java.util.Base64} encoder would add. Those two together are the
     * base64url of <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-2">RFC 7515 §2</a> — what
     * {@code subscribe(...)} reads a string {@code applicationServerKey} as, and what RFC 8292 §3.2 spells the
     * {@code k} parameter as, so neither the alphabet nor the padding is a matter of taste on either side. And the
     * bytes are already the raw 65-byte X9.62 uncompressed point that <a
     * href="https://datatracker.ietf.org/doc/html/rfc8292#section-3.2">RFC 8292 §3.2</a> defines — not a
     * {@code SubjectPublicKeyInfo}, which is what {@code java.security.interfaces.ECPublicKey.getEncoded()} returns (91
     * bytes for P-256) and which the browser has no way to read. The browser reports the two kinds of mistake
     * differently: a string it will not decode is rejected with an {@code InvalidCharacterError}, whereas a
     * {@code SubjectPublicKeyInfo} decodes cleanly and is then refused for not describing a valid point on P-256, with
     * an {@code InvalidAccessError} (steps 10.2 and 10.3 of <a
     * href="https://www.w3.org/TR/push-api/#subscribe-method">the Push API's {@code subscribe()}</a>) — either far from
     * the code that produced the string.
     *
     * <p>To publish the key a {@link VapidSigner} holds — a Vault, KMS or HSM signer that reads it from the custodian
     * and never sees it as configuration — call {@link VapidSigner#publicKeyBase64Url()} instead, which is this
     * encoding of that signer's own key.
     *
     * @param publicKey the 65-byte uncompressed P-256 public key
     * @return the unpadded URL-safe base64 of {@code publicKey}
     * @throws IllegalArgumentException if {@code publicKey} does not encode a point on P-256 — the same standard this
     *     class holds a configured public key to, applied here because these bytes may come from anywhere. An off-curve
     *     key is refused by {@code subscribe(...)} too, with an {@code InvalidAccessError} in a browser console far
     *     from this call
     * @throws NullPointerException if {@code publicKey} is {@code null}
     */
    public static String encodePublicKey(byte[] publicKey) {
        Objects.requireNonNull(publicKey, "publicKey");
        P256PublicKeys.requireOnCurve(publicKey, "VAPID public key");
        return Base64Url.encode(publicKey);
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
