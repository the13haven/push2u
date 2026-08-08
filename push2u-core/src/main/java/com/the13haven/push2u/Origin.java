/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.net.IDN;
import java.net.URI;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Serializes the origin of a push endpoint for the VAPID {@code aud} claim. RFC 8292 §2 requires {@code aud} to be the
 * origin of the push resource. RFC 6454 §4 computes that origin with the scheme and host lowercased, and §6.1 pins down
 * its Unicode serialization: the scheme, {@code "://"}, the host with each label converted to Unicode (IDNA A-label →
 * U-label), and the port only when it differs from the scheme's default. {@link java.net.URI} performs none of that
 * normalization — it preserves the scheme/host case and an explicit default port verbatim — so a push service comparing
 * {@code aud} against its canonical origin would reject an otherwise valid JWT.
 *
 * <p><b>Security note:</b> {@link #serialize} is also load-bearing for {@link EndpointPolicies#allowedOrigins}, which
 * compares the allowlist and the endpoint on this method's output. Two properties of the serialization are relied on
 * and pinned in {@code OriginTest}: userinfo never reaches the output (the comparison must see the real host, not an
 * {@code allowed.example@evil.example} impersonation — switching to {@code getAuthority()} would break this), and the
 * {@code unicodeHost} error fallback stays fail-closed for the allowlist (it returns a plain lowercased host, which at
 * worst fails to match and rejects the send — it can never fabricate a host that matches an entry the endpoint's real
 * host would not). An {@code aud}-motivated edit here must keep both, or {@code EndpointPolicies} needs its own
 * normalizer first.
 *
 * <p><b>Label boundaries survive this normalization</b>, which is what lets a suffix rule such as
 * {@link EndpointRule#domain} compare the endpoint's host at a DNS label boundary on the output of {@link #parts}
 * rather than on a host it re-derives for itself. {@link java.net.URI#getHost()} can never hand this class a non-ASCII
 * host: a raw Unicode authority is registry-based, so {@code getHost()} answers {@code null} and the endpoint is
 * rejected as hostless, and the multi-argument {@link java.net.URI} constructor throws rather than accepting one.
 * {@link IDN#toUnicode} therefore only ever sees ASCII here, and decoding a Punycode A-label can only insert code
 * points at or above U+0080 — a U-label can never gain a {@code '.'}. The dots in the normalized host are exactly the
 * dots the endpoint spelled, so a label boundary in the input is a label boundary in the output and no label can be
 * split or merged on the way through.
 */
final class Origin {

    /**
     * An IPv4 dotted-quad, which must bypass IDNA: RFC 6454 §6.1 applies the ToUnicode conversion only to registered
     * names, and RFC 5890 excludes address literals from IDNA entirely. The pattern is deliberately loose about octet
     * ranges — anything {@link java.net.URI} accepted as a host and that matches this shape is an address literal for
     * our purposes, not a registered name.
     */
    private static final Pattern IPV4_LITERAL = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");

    private Origin() {}

    /**
     * The normalized components of one endpoint's origin, produced by a single pass of {@link #parts}. Every allowlist
     * rule reads its answer from one of these rather than calling {@link URI#getHost()} again: two normalizers would
     * mean two answers for one endpoint, and they would diverge exactly in the internationalised cases nobody exercises
     * by hand.
     *
     * @param scheme the lowercased scheme
     * @param host the host lowercased and converted to its Unicode form, with address literals passed through
     * @param port the port as the URI spelled it — {@code -1} when absent, the explicit number otherwise, never the
     *     scheme's default substituted in
     * @param serialized the RFC 6454 §6.1 serialization built from the three above
     */
    record Parts(String scheme, String host, int port, String serialized) {}

    /**
     * The Unicode serialization (RFC 6454 §6.1) of the endpoint's origin, for use as the VAPID {@code aud} claim (RFC
     * 8292 §2).
     *
     * @param endpoint the push endpoint URI
     * @return the serialized origin, e.g. {@code https://push.example} or {@code https://push.example:8443}
     * @throws IllegalArgumentException if the URI has no scheme or host; the message contains only the
     *     {@link Endpoints#redact}ed endpoint, never the raw capability URL
     */
    static String serialize(URI endpoint) {
        return parts(endpoint).serialized();
    }

    /**
     * The endpoint's origin normalized once, as both its components and its RFC 6454 §6.1 serialization. This is the
     * only place either is computed.
     *
     * @param endpoint the push endpoint URI
     * @return the normalized components and the serialized origin
     * @throws IllegalArgumentException if the URI has no scheme or host; the message contains only the
     *     {@link Endpoints#redact}ed endpoint, never the raw capability URL
     */
    static Parts parts(URI endpoint) {
        String scheme = endpoint.getScheme();
        String host = endpoint.getHost();
        // Only structure is checked here — an origin needs a scheme and a host. Enforcing https
        // is Endpoints.requireSecure's job at the Subscription boundary, not this serializer's.
        if (scheme == null || host == null || host.isEmpty()) {
            throw new IllegalArgumentException(
                    "subscription endpoint URI has no scheme or host: " + Endpoints.redact(endpoint.toString()));
        }
        scheme = scheme.toLowerCase(Locale.ROOT);
        host = unicodeHost(host);
        int port = endpoint.getPort();
        boolean defaultPort =
                port == -1 || (port == 443 && "https".equals(scheme)) || (port == 80 && "http".equals(scheme));
        String serialized = defaultPort ? scheme + "://" + host : scheme + "://" + host + ":" + port;
        return new Parts(scheme, host, port, serialized);
    }

    /**
     * Whether the host is an address literal rather than a registered name — a bracketed IPv6 form, or an IPv4
     * dotted-quad. Shared so that everything asking this question asks it of the same pattern.
     *
     * @param host the host, already lowercased
     * @return {@code true} if the host is an address literal
     */
    static boolean isAddressLiteral(String host) {
        return host.startsWith("[") || IPV4_LITERAL.matcher(host).matches();
    }

    /** The host with A-labels converted to U-labels (RFC 6454 §6.1 step 4), lowercased per §4. */
    private static String unicodeHost(String host) {
        // IDN.toUnicode does not lowercase: it returns non-A-label hosts verbatim ("PUSH.EXAMPLE"
        // stays "PUSH.EXAMPLE") and preserves the case of the ASCII part of a decoded label
        // ("XN--BCHER-KVA" becomes "BüCHER"), so the RFC 6454 §4 lowercase step is ours to do.
        String lowered = host.toLowerCase(Locale.ROOT);
        if (isAddressLiteral(lowered)) {
            // Address literals are not registered names, so IDNA does not apply (RFC 5890 §2.3.2.1).
            // The current java.net.IDN happens to pass them through unchanged, but that is an
            // implementation detail, not a contract — bypass it explicitly rather than rely on it.
            return lowered;
        }
        try {
            return IDN.toUnicode(lowered);
        } catch (RuntimeException e) {
            // IDN.toUnicode is documented to return its input unmodified on error, but historically
            // threw unchecked exceptions on malformed A-labels (JDK-8023881). The aud claim must
            // not be the reason a send fails, so fall back to the plain lowercase host — for the
            // all-ASCII hosts real push services use, that is already the correct serialization.
            return lowered;
        }
    }
}
