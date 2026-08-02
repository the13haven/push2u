package io.push2u;

import java.util.Arrays;
import java.util.Objects;

/**
 * A Web Push subscription as handed to the application by the browser: the push endpoint URL plus the user agent's
 * P-256 public key ({@code p256dh}, 65-byte uncompressed point) and the 16-byte authentication secret ({@code auth}).
 *
 * <p>push2u is stateless — the application owns persistence and supplies this record per send. The browser delivers
 * {@code p256dh}/{@code auth} as base64url strings; use {@link #fromBase64} at the REST boundary.
 *
 * <p>The array components are defensively copied in the compact constructor and the accessors, and
 * {@code equals}/{@code hashCode}/{@code toString} are overridden for content-based value semantics with the
 * {@code auth} secret kept out of {@code toString}.
 *
 * <p>The endpoint must be an absolute {@code https} URL (RFC 8030 requires TLS between the application server and the
 * push service). It is a capability URL — whoever holds it can send messages to the subscriber — so it is treated as a
 * secret and never printed verbatim; see {@link Endpoints#redact}.
 *
 * @param endpoint the push service endpoint URL that encrypted messages are POSTed to — an absolute {@code https} URL,
 *     treated as a secret
 * @param p256dh the user agent's P-256 public key — a 65-byte X9.62 uncompressed point
 * @param auth the 16-byte authentication secret (RFC 8291 §3.2)
 */
public record Subscription(String endpoint, byte[] p256dh, byte[] auth) {

    /**
     * Validates the key material (lengths and the {@code 0x04} prefix), requires an absolute {@code https} endpoint,
     * and defensively copies the arrays.
     */
    public Subscription {
        Objects.requireNonNull(endpoint, "endpoint");
        Objects.requireNonNull(p256dh, "p256dh");
        Objects.requireNonNull(auth, "auth");
        if (p256dh.length != EcKeys.UNCOMPRESSED_LENGTH || p256dh[0] != 0x04) {
            throw new IllegalArgumentException("p256dh must be a 65-byte uncompressed P-256 point (0x04 prefix)");
        }
        if (auth.length != 16) {
            throw new IllegalArgumentException("auth must be 16 bytes (RFC 8291 §3.2)");
        }
        Endpoints.requireSecure(endpoint);
        p256dh = p256dh.clone();
        auth = auth.clone();
    }

    /**
     * Returns a defensive copy of the {@code p256dh} public key.
     *
     * @return a copy of the 65-byte uncompressed public key
     */
    @Override
    public byte[] p256dh() {
        return p256dh.clone();
    }

    /**
     * Returns a defensive copy of the {@code auth} secret.
     *
     * @return a copy of the 16-byte authentication secret
     */
    @Override
    public byte[] auth() {
        return auth.clone();
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        return other instanceof Subscription(String otherEndpoint, byte[] otherP256dh, byte[] otherAuth)
                && endpoint.equals(otherEndpoint)
                && Arrays.equals(p256dh, otherP256dh)
                && Arrays.equals(auth, otherAuth);
    }

    @Override
    public int hashCode() {
        return Objects.hash(endpoint, Arrays.hashCode(p256dh), Arrays.hashCode(auth));
    }

    @Override
    public String toString() {
        // Both secrets stay out of logs: auth is the message-encryption secret (RFC 8291 §3.2)
        // and the endpoint is a capability URL (RFC 8030 §8.3) — only its origin + fingerprint show.
        return "Subscription[endpoint=" + Endpoints.redact(endpoint) + ", p256dh=" + p256dh.length
                + " bytes, auth=<redacted>]";
    }

    /**
     * Builds a subscription from the base64url {@code p256dh} and {@code auth} the browser provides.
     *
     * @param endpoint the push service endpoint URL
     * @param p256dh the base64url-encoded user agent public key
     * @param auth the base64url-encoded authentication secret
     * @return the subscription
     */
    public static Subscription fromBase64(String endpoint, String p256dh, String auth) {
        return new Subscription(endpoint, Base64Url.decode(p256dh), Base64Url.decode(auth));
    }
}
