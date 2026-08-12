/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.util.Arrays;
import java.util.Objects;

import org.jspecify.annotations.Nullable;

/**
 * A Web Push subscription as handed to the application by the browser: the push endpoint URL plus the user agent's
 * P-256 public key ({@code p256dh}, 65-byte uncompressed point) and the 16-byte authentication secret ({@code auth}).
 *
 * <p>push2u is stateless — the application owns persistence and supplies this record per send. The browser delivers
 * {@code p256dh}/{@code auth} as base64url strings; use {@link #fromBase64} at the REST boundary.
 *
 * <p>Construction validates what it accepts: {@code p256dh} must encode a point on the P-256 curve (the full
 * {@link P256PublicKeys#requireOnCurve} check — see the constructor), {@code auth} must be exactly 16 bytes, and the
 * endpoint must satisfy {@link Endpoints#requireSecure} and be at most 2048 characters long. A value that cannot ever
 * be sent to is refused here, with an {@link IllegalArgumentException}, rather than at every later send.
 *
 * <p>The array components are defensively copied in the compact constructor and the accessors, and
 * {@code equals}/{@code hashCode}/{@code toString} are overridden for content-based value semantics with the
 * {@code auth} secret kept out of {@code toString}.
 *
 * <p>The endpoint must be an absolute {@code https} URL (RFC 8030 requires TLS between the application server and the
 * push service) of at most 2048 characters. The bound is structural: RFC 1035 §2.3.4 caps a domain name at 255 octets,
 * 253 as a presentation-form hostname, and a capability path needs only enough characters to be unguessable — a 256-bit
 * token is 43 base64url characters — so roughly 1780 characters of headroom remain beyond the longest resolvable host.
 * It is a capability URL — whoever holds it can send messages to the subscriber — so it is treated as a secret and
 * never printed verbatim; see {@link Endpoints#redact}.
 *
 * @param endpoint the push service endpoint URL that encrypted messages are POSTed to — an absolute {@code https} URL
 *     of at most 2048 characters, treated as a secret
 * @param p256dh the user agent's P-256 public key — a 65-byte X9.62 uncompressed point encoding a point on the P-256
 *     curve
 * @param auth the 16-byte authentication secret (RFC 8291 §3.2)
 */
// ArrayRecordComponent: the byte[] components are the wire format this type exists to carry — the
// browser hands over raw key material. The hazards the check warns about are already closed: the
// compact constructor copies both arrays, the accessors return copies, and equals/hashCode/toString
// are overridden to compare by content.
@SuppressWarnings("ArrayRecordComponent")
public record Subscription(String endpoint, byte[] p256dh, byte[] auth) {

    /**
     * The longest endpoint a subscription may carry, in characters: {@value} — a hard ceiling on what an
     * attacker-chosen endpoint can cost, argued structurally rather than from any push service's behaviour. RFC 1035
     * §2.3.4 caps a domain name at 255 octets, 253 as a presentation-form hostname, so beyond the longest resolvable
     * host an endpoint varies only in its capability path and query — and a capability needs only enough characters to
     * be unguessable, 43 base64url characters for a 256-bit token, two orders of magnitude below the ~1780 characters
     * of headroom the bound leaves. Every send derives an {@code Authorization} header that embeds the endpoint's
     * origin, and the sender's token cache retains one such header per origin, so without this bound the party
     * supplying subscriptions would choose both the per-request and the retained cost.
     */
    private static final int MAX_ENDPOINT_LENGTH = 2048;

    /**
     * Validates the key material, requires an absolute {@code https} endpoint of bounded length, and defensively copies
     * the arrays.
     *
     * <p>{@code p256dh} gets the full {@link P256PublicKeys#requireOnCurve} check — shape, coordinates inside the P-256
     * field, curve equation — not merely the structural one. The value is attacker-supplied (a registration endpoint
     * accepts the browser's {@code PushSubscription} JSON verbatim, and nothing upstream enforces RFC 8291 §3.1's
     * requirement that the key be on P-256), and a subscription carrying an off-curve point can never be sent to:
     * accepting it here would persist a value that raises a {@link PushCryptoException} — the "broken deployment"
     * exception — on every later send, far from the request that supplied it. The check needs no JCA provider, so it
     * costs the constructor no new dependency.
     */
    public Subscription {
        Objects.requireNonNull(endpoint, "endpoint");
        Objects.requireNonNull(p256dh, "p256dh");
        Objects.requireNonNull(auth, "auth");
        P256PublicKeys.requireOnCurve(p256dh, "p256dh");
        if (auth.length != 16) {
            throw new IllegalArgumentException("auth must be 16 bytes (RFC 8291 §3.2)");
        }
        // Before requireSecure, so nothing downstream ever works on an unbounded string. The message
        // carries the two lengths and not the endpoint — not even the redacted form, whose origin
        // half contains the host, which is the very part of an oversized endpoint that is oversized.
        if (endpoint.length() > MAX_ENDPOINT_LENGTH) {
            throw new IllegalArgumentException(
                    "endpoint must be at most " + MAX_ENDPOINT_LENGTH + " characters, was " + endpoint.length());
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
    public boolean equals(@Nullable Object other) {
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
        Objects.requireNonNull(p256dh, "p256dh");
        Objects.requireNonNull(auth, "auth");
        return new Subscription(endpoint, decode(p256dh, "p256dh"), decode(auth, "auth"));
    }

    /**
     * Decodes one browser-supplied value, naming it if the decoder refuses. The JDK's message for a bad character is
     * {@code "Illegal base64 character 2b"} and nothing else — the same text for either value, and this pair arrives
     * over the application's own REST boundary, where "which field was malformed" is the whole question.
     *
     * <p>The value itself never reaches the message. It is whatever a client posted, so quoting it would put
     * attacker-chosen text into the application's logs; the decoder's own text names a character code and no content,
     * and is kept as the cause.
     */
    private static byte[] decode(String value, String field) {
        try {
            return Base64Url.decode(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    field + " is not valid base64url (RFC 4648 §5, the URL-safe alphabet with '-' and '_' rather than"
                            + " '+' and '/', padding optional): " + e.getMessage(),
                    e);
        }
    }
}
