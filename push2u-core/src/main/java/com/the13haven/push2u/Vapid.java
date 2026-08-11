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
 *
 * <p>This class also owns the two shape checks applied to what a {@link VapidSigner} returns, because this is where
 * those values go on the wire. The public key's check has a second caller — {@link VapidSigner#publicKeyBase64Url()},
 * which publishes the same value to a browser — so it is shared rather than private: publishing a key and sending with
 * it must accept exactly the same set and say the same thing when they refuse.
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
        return signedAuthorizationHeader(signer, audience, subject, expiry).headerValue();
    }

    /**
     * The full {@code Authorization} header value together with the base64url public key its own {@code k} parameter
     * carries — from one {@link VapidSigner#publicKey()} read, so the two cannot name different keys even against a
     * signer whose answers vary call to call. The caller that files signed headers under their key needs exactly that:
     * a key read separately from the header's could drift from the value actually on the wire, and the header would
     * then be stored under an identity it does not carry.
     */
    static SignedHeader signedAuthorizationHeader(VapidSigner signer, String audience, String subject, Instant expiry) {
        Objects.requireNonNull(signer, "signer");
        String jwt = jwt(signer, audience, subject, expiry);
        String publicKeyBase64Url = Base64Url.encode(requireUncompressedPoint(signer.publicKey()));
        return new SignedHeader("vapid t=" + jwt + ", k=" + publicKeyBase64Url, publicKeyBase64Url);
    }

    /**
     * A signed {@code Authorization} header value paired with the base64url public key that appears as its {@code k}
     * parameter — both produced by {@link #signedAuthorizationHeader} from a single {@code publicKey()} read.
     *
     * @param headerValue the complete {@code vapid t=..., k=...} header value
     * @param publicKeyBase64Url the base64url encoding of the public key bytes the header's {@code k} carries
     */
    record SignedHeader(String headerValue, String publicKeyBase64Url) {
        /** The header value is a bearer credential; only the public half is printable. */
        @Override
        public String toString() {
            return "SignedHeader[headerValue=<redacted>, publicKeyBase64Url=" + publicKeyBase64Url + "]";
        }
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
     *
     * <p>Shared with {@link VapidSigner#publicKeyBase64Url()}, which hands the same value to a browser instead of to a
     * push service. One implementation and one wording is the point: a consumer meeting a broken signer through their
     * own key-publishing endpoint reads what the next send would have told them, and the publication path can never
     * refuse a key delivery would have carried.
     *
     * <p>A {@code null} is a {@link NullPointerException} rather than a {@link PushCryptoException}: the method is
     * declared to return bytes and never {@code null}, so a signer answering {@code null} has broken the type contract
     * rather than failed at a cryptographic operation.
     */
    static byte[] requireUncompressedPoint(byte[] publicKey) {
        Objects.requireNonNull(publicKey, "publicKey");
        if (publicKey.length != UNCOMPRESSED_P256_POINT_LENGTH) {
            String wrapped = publicKey.length > 0 && publicKey[0] == DER_SEQUENCE_TAG
                    ? " It opens with 0x30, so it looks wrapped — a SubjectPublicKeyInfo (what"
                            + " ECPublicKey.getEncoded() returns, 91 bytes for P-256) has to be reduced to the raw"
                            + " point."
                    : "";
            throw new PushCryptoException("VapidSigner.publicKey returned " + publicKey.length + " bytes; VAPID needs"
                    + " the X9.62 uncompressed P-256 point of " + UNCOMPRESSED_P256_POINT_LENGTH
                    + " (RFC 8292 §3.2)." + wrapped);
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
