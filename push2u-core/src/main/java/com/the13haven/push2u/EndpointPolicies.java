/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Standard {@link EndpointPolicy} implementations: an allowlist of {@link EndpointRule}s, the two string conveniences
 * over it, and the named opt-out from restricting egress at all.
 *
 * <p>The allowlist is the rule nearly every deployment actually wants: the set of browser push services an
 * application's users can arrive from is small and known (FCM, Mozilla autopush, WNS, APNs web push), so "only these"
 * closes the attacker-supplied endpoint hole with configuration a reviewer can read. A service whose operator names one
 * exact host is named back with {@link EndpointRule#origin}; a service whose operator documents that its hostnames vary
 * within one DNS zone — and more than one of the standard four does — is named with {@link EndpointRule#domain}
 * instead. {@link #allowedEndpoints} takes both kinds in one list, and that mixed list is the ordinary cross-browser
 * configuration rather than an edge case. {@link #allowedOrigins} and {@link #allowedDomains} are the single-kind
 * conveniences over it.
 *
 * <p>Anything more situational (egress-proxy rules, custom DNS checks) belongs in the deployment's own
 * {@link EndpointPolicy} lambda, not in this class — noting that a policy is fixed per sender when the sender is built
 * and {@code assess} receives only the URI, so a rule that varies by tenant means one sender per tenant, not one policy
 * consulting request context.
 *
 * <p>{@link #unrestricted()} is the other half of the same idea. Every {@link PushSender} is built with a policy, so a
 * deployment that genuinely wants none has to say so — and saying so leaves a token in its own source, visible in a
 * diff, a review and a grep, which an omitted configuration step never was.
 */
public final class EndpointPolicies {

    /**
     * The single answer every admissible endpoint gets from the policies this class builds. The variant carries no
     * components, so one instance says everything any of them could: all of them are equal to each other, and no caller
     * can be told which it holds. Handing out the same one keeps a question asked on every send from allocating on the
     * answering path, and it commits this class to nothing a caller may read — identity is not part of what the answer
     * means, and a caller comparing two answers with {@code ==} is asking a question the type does not answer.
     */
    private static final EndpointAssessment ALLOWED = new EndpointAssessment.Allowed();

    /**
     * The instance {@link #unrestricted()} hands out. Stateless and immutable, so one shared instance serves every
     * caller and every thread.
     */
    private static final EndpointPolicy UNRESTRICTED = endpoint -> {
        Objects.requireNonNull(endpoint, "endpoint");
        return ALLOWED;
    };

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
     * POSTs there from inside that network, and the caller-visible {@link PushOutcome} — the status code an answered
     * variant carries versus an unanswered {@link PushOutcome.Indeterminate}, plus how long the attempt took — is a
     * blind server-side request forgery oracle for internal host and port existence. {@link EndpointPolicy} carries the
     * full threat model.
     *
     * <p><b>When it is the right choice.</b> When subscriptions never arrive from untrusted clients: they are entered
     * by operators, imported from a system inside the trust boundary, or fixed in configuration. Also where egress is
     * already pinned somewhere the library cannot see — an egress proxy or firewall that decides what this process may
     * connect to — since a second allowlist there would only be a copy that drifts. In every other case name the
     * services instead: {@link #allowedOrigins(Collection)} where each one is a fixed host,
     * {@link #allowedEndpoints(Collection)} where one of them publishes a whole DNS zone whose hostnames vary — which
     * some of them do, and which is the case that most often sends a deployment here by mistake. The push services an
     * application's subscriptions come from are few and known, and naming them costs one configuration line.
     *
     * @return a policy that refuses nothing
     */
    public static EndpointPolicy unrestricted() {
        return UNRESTRICTED;
    }

    /**
     * A policy allowing exactly the given rules; see {@link #allowedEndpoints(Collection)}.
     *
     * @param rules the allowed endpoint rules
     * @return a policy that refuses any endpoint no rule matches
     * @throws IllegalArgumentException if no rule is given
     */
    public static EndpointPolicy allowedEndpoints(EndpointRule... rules) {
        Objects.requireNonNull(rules, "rules");
        return allowedEndpoints(Arrays.asList(rules));
    }

    /**
     * A policy allowing exactly the given rules: a send is permitted only if at least one rule matches the endpoint.
     * This is the primary cross-browser call — {@link EndpointRule#origin} entries for the services named by an exact
     * host, beside a {@link EndpointRule#domain} entry for each service whose hostnames vary within a zone.
     *
     * <p>Each rule validated and normalized its own entry when it was built, so a malformed allowlist has already
     * failed by the time this method is reached. Rules are values: two rules of the same kind with the same normalized
     * entry are equal, so duplicates collapse and the remaining order is the order they were given in. What each kind
     * matches is documented on {@link EndpointRule#origin} and {@link EndpointRule#domain}.
     *
     * <p>Two endpoint-side refusals happen before any rule is consulted, whatever the rules are. A URI carrying
     * userinfo ({@code https://allowed.example@evil.example/…}) is refused outright: {@code java.net.URI} resolves the
     * real host and RFC 6454 excludes userinfo from the origin, so the comparison itself is not fooled, but no real
     * push service issues endpoints with userinfo and its only plausible purpose is to impersonate an allowed host to
     * <em>some</em> parser — refusing the shape entirely also protects any custom transport that re-parses the URL
     * string differently. A URI with no scheme or host has no origin to compare and is likewise refused (reachable only
     * by calling {@link EndpointPolicy#assess} directly — {@link PushSender} never gets that far with one).
     *
     * @param rules the allowed endpoint rules
     * @return a policy that refuses any endpoint no rule matches
     * @throws IllegalArgumentException if no rule is given
     */
    public static EndpointPolicy allowedEndpoints(Collection<? extends EndpointRule> rules) {
        Objects.requireNonNull(rules, "rules");
        if (rules.isEmpty()) {
            throw new IllegalArgumentException("allowedEndpoints requires at least one rule — an empty allowlist"
                    + " would reject every send, which is far more likely a wiring bug than a policy");
        }
        Set<EndpointRule> distinct = new LinkedHashSet<>();
        for (EndpointRule rule : rules) {
            distinct.add(Objects.requireNonNull(rule, "rule"));
        }
        // One list of rules and no second collection beside it: a set of origin strings kept as a
        // fast path would be a second answer to "is this endpoint allowed", and two answers drift.
        List<EndpointRule> allowed = List.copyOf(distinct);
        return endpoint -> check(allowed, endpoint);
    }

    /**
     * A policy allowing each of the given domains <em>and every subdomain of it, at any depth</em>; see
     * {@link #allowedDomains(Collection)}.
     *
     * @param domains the allowed domains, e.g. {@code "notify.windows.com"}
     * @return a policy admitting each listed domain and every host beneath it, and refusing every other endpoint
     * @throws IllegalArgumentException if no domain is given, or any entry is not a well-formed multi-label hostname
     */
    public static EndpointPolicy allowedDomains(String... domains) {
        Objects.requireNonNull(domains, "domains");
        return allowedDomains(Arrays.asList(domains));
    }

    /**
     * A policy allowing each of the given domains <em>and every subdomain of it, at any depth</em>: a send to
     * {@code https://a.b.zone.example/…} is permitted by the entry {@code "zone.example"}. It is deliberately wider
     * than an origin allowlist, and worth exactly what the DNS of each listed zone is worth, so it belongs where the
     * push service operator documents that its hostnames vary within one zone. The match is anchored at a DNS label
     * boundary, and only {@code https} on the default port is admitted; {@link EndpointRule#domain} carries the full
     * rule and the entry grammar.
     *
     * <p>An allowlist mixing both kinds — the usual cross-browser case — is built with
     * {@link #allowedEndpoints(Collection)} instead.
     *
     * @param domains the allowed domains, e.g. {@code "notify.windows.com"}
     * @return a policy admitting each listed domain and every host beneath it, and refusing every other endpoint
     * @throws IllegalArgumentException if no domain is given, or any entry is not a well-formed multi-label hostname
     */
    public static EndpointPolicy allowedDomains(Collection<String> domains) {
        Objects.requireNonNull(domains, "domains");
        // The emptiness refusal is this factory's own, and runs before anything is delegated: each
        // entry point states its own wording, and a shared one would report the wrong parameter.
        if (domains.isEmpty()) {
            throw new IllegalArgumentException("allowedDomains requires at least one domain — an empty allowlist"
                    + " would reject every send, which is far more likely a wiring bug than a policy");
        }
        List<EndpointRule> rules = new ArrayList<>(domains.size());
        for (String domain : domains) {
            rules.add(EndpointRule.domain(domain));
        }
        return allowedEndpoints(rules);
    }

    /**
     * A policy allowing exactly the given origins; see {@link #allowedOrigins(Collection)}.
     *
     * @param origins the allowed origins, e.g. {@code "https://fcm.googleapis.com"}
     * @return a policy that refuses any endpoint whose origin is not in the set
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
     * <em>here</em>, at construction: a misconfigured allowlist should fail deployment startup, not silently refuse (or
     * worse, silently admit) sends later. A lone trailing {@code "/"} is tolerated, since browsers and RFC 6454 both
     * print origins without one but humans often paste one.
     *
     * <p>On the endpoint side, a URI carrying userinfo ({@code https://allowed.example@evil.example/…}) is refused
     * outright, before the origin comparison. The comparison itself is not fooled — {@code java.net.URI} resolves the
     * real host, and RFC 6454 excludes userinfo from the origin — but no real push service issues endpoints with
     * userinfo, so its only plausible purpose is to impersonate an allowed origin to <em>some</em> parser: refusing the
     * shape entirely also protects any custom transport that re-parses the URL string differently. A URI with no scheme
     * or host has no origin to compare and is likewise refused (reachable only by calling {@link EndpointPolicy#assess}
     * directly — {@link PushSender} never gets that far with one).
     *
     * <p>Each entry becomes an {@link EndpointRule#origin}, which is where the entry grammar and its refusals are
     * documented. An allowlist that also has to cover a service whose hostnames vary within a DNS zone is built with
     * {@link #allowedEndpoints(Collection)} instead of enumerating those hostnames here.
     *
     * @param origins the allowed origins, e.g. {@code "https://fcm.googleapis.com"}
     * @return a policy that refuses any endpoint whose origin is not in the set
     * @throws IllegalArgumentException if no origin is given, or any entry is not a well-formed https origin
     */
    public static EndpointPolicy allowedOrigins(Collection<String> origins) {
        Objects.requireNonNull(origins, "origins");
        // The emptiness refusal is this factory's own, and runs before anything is delegated: each
        // entry point states its own wording, and a shared one would report the wrong parameter.
        if (origins.isEmpty()) {
            throw new IllegalArgumentException("allowedOrigins requires at least one origin — an empty allowlist"
                    + " would reject every send, which is far more likely a wiring bug than a policy");
        }
        List<EndpointRule> rules = new ArrayList<>(origins.size());
        for (String origin : origins) {
            rules.add(EndpointRule.origin(origin));
        }
        return allowedEndpoints(rules);
    }

    /** The per-send assessment behind the policy {@link #allowedEndpoints(Collection)} returns. */
    private static EndpointAssessment check(List<EndpointRule> allowed, URI endpoint) {
        Objects.requireNonNull(endpoint, "endpoint");
        if (endpoint.getRawUserInfo() != null) {
            // Real push services never put userinfo in an endpoint; its only plausible purpose is
            // impersonating an allowed origin to a parser that splits the authority differently.
            return new EndpointAssessment.Refused("push endpoint carries userinfo, which no push service issues: "
                    + Endpoints.redact(endpoint.toString()));
        }
        String host = endpoint.getHost();
        if (endpoint.getScheme() == null || host == null || host.isEmpty()) {
            // Origin.parts would throw plain IllegalArgumentException here; assess() answers with a
            // value, and "no origin at all" is certainly not an allowed one.
            return new EndpointAssessment.Refused("push endpoint has no scheme or host, so no origin to compare: "
                    + Endpoints.redact(endpoint.toString()));
        }
        // Normalized once, here, and handed to every rule: a rule that re-derived the host would be
        // a second normalizer, and two normalizers give two answers for one endpoint.
        Origin.Parts parts = Origin.parts(endpoint);
        for (EndpointRule rule : allowed) {
            if (rule.matches(parts)) {
                return ALLOWED;
            }
        }
        // One wording for every factory. Which rule came closest is deliberately not reported: it
        // would describe the allowlist to whoever supplied the endpoint.
        return new EndpointAssessment.Refused("push endpoint is not in the allowed set (no origin or domain rule"
                + " matches it): " + Endpoints.redact(endpoint.toString()));
    }
}
