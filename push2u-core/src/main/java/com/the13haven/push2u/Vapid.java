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

    /** The full {@code Authorization} header value for the "vapid" scheme. */
    static String authorizationHeader(VapidSigner signer, String audience, String subject, Instant expiry) {
        return "vapid t=" + jwt(signer, audience, subject, expiry) + ", k=" + Base64Url.encode(signer.publicKey());
    }

    /** The signed compact JWT: {@code base64url(header).base64url(claims).base64url(signature)}. */
    static String jwt(VapidSigner signer, String audience, String subject, Instant expiry) {
        Objects.requireNonNull(signer, "signer");
        String signingInput = signingInput(audience, subject, expiry);
        byte[] signature = signer.sign(signingInput.getBytes(StandardCharsets.US_ASCII));
        return signingInput + "." + Base64Url.encode(signature);
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
