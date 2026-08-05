/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Objects;

/**
 * Builds the VAPID (RFC 8292) JWT and the {@code Authorization: vapid t=<jwt>, k=<key>} header.
 *
 * <p>The JWT JSON is handwritten: the claims are tiny ({@code aud}/{@code exp}/{@code sub}) and fixed-shape, so a JSON
 * library would be dead weight. The header is the constant {@code {"typ":"JWT","alg":"ES256"}}. The ES256 signature is
 * delegated to a {@link VapidSigner}.
 */
final class Vapid {

    private static final byte[] HEADER_JSON = "{\"typ\":\"JWT\",\"alg\":\"ES256\"}".getBytes(StandardCharsets.US_ASCII);

    private Vapid() {}

    /** A P-256 {@code r || s} signature: two 32-octet integers, per RFC 7518 §3.4. */
    private static final int ES256_SIGNATURE_LENGTH = 64;
    /** An X9.62 uncompressed point: the {@code 0x04} tag and two 32-octet coordinates. */
    private static final int UNCOMPRESSED_P256_POINT_LENGTH = 65;

    private static final byte UNCOMPRESSED_POINT_TAG = 0x04;
    /** The ASN.1 SEQUENCE tag a DER-encoded ECDSA signature opens with — recognised only to explain the rejection. */
    private static final byte DER_SEQUENCE_TAG = 0x30;

    /** The full {@code Authorization} header value for the "vapid" scheme. */
    static String authorizationHeader(VapidSigner signer, String audience, String subject, Instant expiry) {
        Objects.requireNonNull(signer, "signer");
        String jwt = jwt(signer, audience, subject, expiry);
        return "vapid t=" + jwt + ", k=" + Base64Url.encode(requireUncompressedPoint(signer.publicKey()));
    }

    /** The signed compact JWT: {@code base64url(header).base64url(claims).base64url(signature)}. */
    static String jwt(VapidSigner signer, String audience, String subject, Instant expiry) {
        Objects.requireNonNull(signer, "signer");
        String signingInput = signingInput(audience, subject, expiry);
        byte[] signature = signer.sign(signingInput.getBytes(StandardCharsets.US_ASCII));
        return signingInput + "." + Base64Url.encode(requireRawEs256Signature(signature));
    }

    /**
     * Check what the {@link VapidSigner} returned before it becomes a JWT nobody can diagnose. A signature of the wrong
     * shape still produces a syntactically valid {@code Authorization} header, so the failure surfaces as an opaque
     * 401/403 from the push service on <em>every</em> send, with nothing in it pointing at the signer. The check costs
     * one comparison per send.
     *
     * <p>DER is called out by name because it is the mistake an implementation actually makes: JCA's
     * {@code SHA256withECDSA} returns DER, RFC 7518 §3.4 requires the raw {@code r || s} pair, and a signer that
     * forwards its provider's output without converting looks correct everywhere except on the wire. The library does
     * that conversion for its own signer (see {@code Jca.es256()}), but cannot do it here: these bytes come from an
     * implementation whose provider and format are unknown, and a valid 64-byte signature may itself begin with
     * {@code 0x30}.
     */
    private static byte[] requireRawEs256Signature(byte[] signature) {
        Objects.requireNonNull(signature, "signature");
        if (signature.length != ES256_SIGNATURE_LENGTH) {
            String der = signature.length > 0 && signature[0] == DER_SEQUENCE_TAG
                    ? " It opens with 0x30, so it looks DER-encoded: convert it to r || s, or ask the provider for"
                            + " \"SHA256withECDSAinP1363Format\"."
                    : "";
            throw new PushCryptoException("VapidSigner.sign returned " + signature.length + " bytes; ES256 needs the"
                    + " raw r || s pair of " + ES256_SIGNATURE_LENGTH + " (RFC 7518 §3.4)." + der);
        }
        return signature;
    }

    /**
     * Check the other half of the {@link VapidSigner} contract, for the same reason: the key travels as the {@code k}
     * parameter, and a malformed one is rejected by the push service exactly like a bad signature — while the signature
     * itself verifies, which makes it the harder of the two to trace back.
     */
    private static byte[] requireUncompressedPoint(byte[] publicKey) {
        Objects.requireNonNull(publicKey, "publicKey");
        if (publicKey.length != UNCOMPRESSED_P256_POINT_LENGTH) {
            throw new PushCryptoException("VapidSigner.publicKey returned " + publicKey.length + " bytes; VAPID needs"
                    + " the X9.62 uncompressed P-256 point of " + UNCOMPRESSED_P256_POINT_LENGTH
                    + " (RFC 8292 §3.2)");
        }
        if (publicKey[0] != UNCOMPRESSED_POINT_TAG) {
            throw new PushCryptoException("VapidSigner.publicKey is not an uncompressed point: it begins with 0x"
                    + String.format("%02x", publicKey[0]) + " where X9.62 requires 0x04 — a compressed point (0x02 or"
                    + " 0x03) or a wrapped encoding such as SubjectPublicKeyInfo has to be reduced to the raw point");
        }
        return publicKey;
    }

    /** The JWS signing input: {@code base64url(header) || "." || base64url(claims)}. */
    static String signingInput(String audience, String subject, Instant expiry) {
        Objects.requireNonNull(audience, "audience");
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(expiry, "expiry");
        return Base64Url.encode(HEADER_JSON) + "."
                + Base64Url.encode(claimsJson(audience, expiry.getEpochSecond(), subject));
    }

    static byte[] claimsJson(String audience, long expirySeconds, String subject) {
        String json = "{\"aud\":\"" + jsonEscape(audience)
                + "\",\"exp\":" + expirySeconds
                + ",\"sub\":\"" + jsonEscape(subject) + "\"}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    private static String jsonEscape(String value) {
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }
}
