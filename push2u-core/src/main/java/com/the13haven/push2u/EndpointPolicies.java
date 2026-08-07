/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Standard {@link EndpointPolicy} implementations: an origin allowlist, and the named opt-out from restricting egress
 * at all.
 *
 * <p>The allowlist is the rule nearly every deployment actually wants: the set of browser push services an
 * application's users can arrive from is small and known (FCM, Mozilla autopush, WNS, APNs web push), so "only these
 * origins" closes the attacker-supplied endpoint hole with configuration a reviewer can read. Anything more situational
 * (egress-proxy rules, custom DNS checks) belongs in the deployment's own {@link EndpointPolicy} lambda, not in this
 * class — noting that a policy is fixed per sender when the sender is built and {@code validate} receives only the URI,
 * so a rule that varies by tenant means one sender per tenant, not one policy consulting request context.
 *
 * <p>{@link #unrestricted()} is the other half of the same idea. Every {@link PushSender} is built with a policy, so a
 * deployment that genuinely wants none has to say so — and saying so leaves a token in its own source, visible in a
 * diff, a review and a grep, which an omitted configuration step never was.
 */
public final class EndpointPolicies {

    /**
     * The instance {@link #unrestricted()} hands out. Stateless and immutable, so one shared instance serves every
     * caller and every thread.
     */
    private static final EndpointPolicy UNRESTRICTED = endpoint -> Objects.requireNonNull(endpoint, "endpoint");

    private EndpointPolicies() {}

    /**
     * A policy that permits every endpoint: the explicit, named way for a deployment to state that it applies no egress
     * restriction to push endpoints.
     *
     * <p><b>Security warning.</b> A sender built with this policy POSTs to any endpoint a {@link Subscription} accepts
     * — which means any {@code https} URL with a host, loopback ({@code https://127.0.0.1:8443/…}), private-range
     * ({@code https://10.0.0.5/…}) and cloud-metadata addresses included. The endpoint inside a {@link Subscription} is
     * attacker-influenced wherever subscriptions arrive from clients, which is the ordinary integration: the browser's
     * {@code PushSubscription} JSON is accepted at a public registration endpoint, and nothing stops a client from
     * posting a hand-crafted subscription naming an address inside the application's own network. Every later send then
     * POSTs there from inside that network, and the caller-visible outcome — {@link PushResult#statusCode()} versus
     * {@link PushDeliveryException}, plus how long the attempt took — is a blind server-side request forgery oracle for
     * internal host and port existence. {@link EndpointPolicy} carries the full threat model.
     *
     * <p><b>When it is the right choice.</b> When subscriptions never arrive from untrusted clients: they are entered
     * by operators, imported from a system inside the trust boundary, or fixed in configuration. Also where egress is
     * already pinned somewhere the library cannot see — an egress proxy or firewall that decides what this process may
     * connect to — since a second allowlist there would only be a copy that drifts. In every other case use
     * {@link #allowedOrigins(Collection)}: the push services an application's subscriptions come from are few and
     * known, and naming them costs one configuration line.
     *
     * @return a policy that rejects nothing
     */
    public static EndpointPolicy unrestricted() {
        return UNRESTRICTED;
    }

    /**
     * A policy allowing exactly the given origins; see {@link #allowedOrigins(Collection)}.
     *
     * @param origins the allowed origins, e.g. {@code "https://fcm.googleapis.com"}
     * @return a policy that rejects any endpoint whose origin is not in the set
     * @throws IllegalArgumentException if no origin is given, or any entry is not a well-formed https origin
     */
    public static EndpointPolicy allowedOrigins(String... origins) {
        Objects.requireNonNull(origins, "origins");
        return allowedOrigins(Arrays.asList(origins));
    }

    /**
     * A policy allowing exactly the given origins: a send is permitted only if the endpoint's origin — its
     * {@code scheme://host[:port]}, never the path or query — is in the set.
     *
     * <p>Comparison happens on the RFC 6454 §6.1 serialization of <em>both</em> sides, the same normalization the VAPID
     * {@code aud} claim uses: scheme and host lowercased, IDNA A-labels decoded to Unicode, and an explicit default
     * port ({@code :443}) dropped. {@code https://PUSH.Example:443} in the configuration therefore matches an endpoint
     * on {@code https://push.example}, and an A-label host matches whatever case the endpoint spelled it in. Matching
     * is exact per origin — a subdomain of an allowed origin is <em>not</em> allowed.
     *
     * <p>Each entry must be a bare https origin. A malformed entry — unparseable, non-{@code https} (a
     * {@link Subscription} endpoint is always https, so any other scheme could never match), hostless (spell an
     * internationalised host in its A-label/Punycode form), or carrying a path, query, fragment or userinfo — fails
     * <em>here</em>, at construction: a misconfigured allowlist should fail deployment startup, not silently reject (or
     * worse, silently admit) sends later. A lone trailing {@code "/"} is tolerated, since browsers and RFC 6454 both
     * print origins without one but humans often paste one.
     *
     * <p>On the endpoint side, a URI carrying userinfo ({@code https://allowed.example@evil.example/…}) is rejected
     * outright, before the origin comparison. The comparison itself is not fooled — {@code java.net.URI} resolves the
     * real host, and RFC 6454 excludes userinfo from the origin — but no real push service issues endpoints with
     * userinfo, so its only plausible purpose is to impersonate an allowed origin to <em>some</em> parser: rejecting
     * the shape entirely also protects any custom transport that re-parses the URL string differently. A URI with no
     * scheme or host has no origin to compare and is likewise rejected (reachable only by calling
     * {@link EndpointPolicy#validate} directly — {@link PushSender} never gets that far with one).
     *
     * @param origins the allowed origins, e.g. {@code "https://fcm.googleapis.com"}
     * @return a policy that rejects any endpoint whose origin is not in the set
     * @throws IllegalArgumentException if no origin is given, or any entry is not a well-formed https origin
     */
    public static EndpointPolicy allowedOrigins(Collection<String> origins) {
        Objects.requireNonNull(origins, "origins");
        if (origins.isEmpty()) {
            throw new IllegalArgumentException("allowedOrigins requires at least one origin — an empty allowlist"
                    + " would reject every send, which is far more likely a wiring bug than a policy");
        }
        Set<String> normalized = new LinkedHashSet<>();
        for (String origin : origins) {
            normalized.add(normalize(origin));
        }
        Set<String> allowed = Set.copyOf(normalized);
        return endpoint -> check(allowed, endpoint);
    }

    /** The per-send check behind the policy {@link #allowedOrigins(Collection)} returns. */
    private static void check(Set<String> allowed, URI endpoint) {
        Objects.requireNonNull(endpoint, "endpoint");
        if (endpoint.getRawUserInfo() != null) {
            // Real push services never put userinfo in an endpoint; its only plausible purpose is
            // impersonating an allowed origin to a parser that splits the authority differently.
            throw new EndpointRejectedException("push endpoint carries userinfo, which no push service issues: "
                    + Endpoints.redact(endpoint.toString()));
        }
        String host = endpoint.getHost();
        if (endpoint.getScheme() == null || host == null || host.isEmpty()) {
            // Origin.serialize would throw plain IllegalArgumentException here; validate() promises
            // EndpointRejectedException, and "no origin at all" is certainly not an allowed one.
            throw new EndpointRejectedException("push endpoint has no scheme or host, so no origin to compare: "
                    + Endpoints.redact(endpoint.toString()));
        }
        if (!allowed.contains(Origin.serialize(endpoint))) {
            throw new EndpointRejectedException(
                    "push endpoint origin is not in the allowed set: " + Endpoints.redact(endpoint.toString()));
        }
    }

    /**
     * Validates one configured entry and returns its RFC 6454 serialization — the same normalization
     * {@link Origin#serialize} applies to the endpoint at send time, so the two sides can never disagree on case,
     * default ports or IDNA form. Every rejection message renders the entry through {@link Endpoints#redact}: a
     * configured origin is not supposed to be a capability URL, but the likeliest malformed entry is a pasted full
     * endpoint, which is one.
     */
    // PreserveStackTrace: the cause is dropped on purpose — URISyntaxException's message embeds the
    // raw input, which in the pasted-endpoint failure mode is a capability URL that must not leak.
    @SuppressWarnings("PMD.PreserveStackTrace")
    private static String normalize(String origin) {
        Objects.requireNonNull(origin, "origin");
        URI uri;
        try {
            uri = new URI(origin);
        } catch (URISyntaxException e) {
            // No cause: URISyntaxException's message carries the raw input, which must not leak.
            throw new IllegalArgumentException("allowed origin is not a valid URI: " + Endpoints.redact(origin));
        }
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("allowed origin must be https — Subscription endpoints are https-only"
                    + " (RFC 8030), so any other scheme could never match: " + Endpoints.redact(origin));
        }
        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            throw new IllegalArgumentException("allowed origin has no host (an internationalised host must be given"
                    + " in its A-label/Punycode form): " + Endpoints.redact(origin));
        }
        String path = uri.getPath();
        boolean bareOrigin = (path == null || path.isEmpty() || "/".equals(path))
                && uri.getQuery() == null
                && uri.getFragment() == null
                && uri.getUserInfo() == null;
        if (!bareOrigin) {
            throw new IllegalArgumentException("allowed origin must be a bare scheme://host[:port] — a path, query,"
                    + " fragment or userinfo suggests a pasted endpoint URL, and everything after the origin would be"
                    + " silently ignored: " + Endpoints.redact(origin));
        }
        return Origin.serialize(uri);
    }
}
