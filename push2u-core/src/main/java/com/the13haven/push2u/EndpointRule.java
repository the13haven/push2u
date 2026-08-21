/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

import org.jspecify.annotations.Nullable;

/**
 * One entry of the standard endpoint allowlist, as a value that carries its own kind: {@link #origin} names exactly one
 * origin, {@link #domain} names a DNS zone and every host inside it. Build a policy from a list of these with
 * {@link EndpointPolicies#allowedEndpoints}, which is the cross-browser shape — a few origin rules beside one domain
 * rule.
 *
 * <p>The kind travels with the entry rather than with the parameter it was passed in, so two rules of different kinds
 * can sit in one list and neither can be mistaken for the other. Each entry is validated and normalized when the rule
 * is built, which means a misconfigured allowlist fails at deployment startup rather than silently refusing — or
 * silently admitting — sends later. A rule is a value: two rules of the same kind whose entries normalize to the same
 * string are equal, so a list of rules collapses duplicates.
 *
 * <p>The hierarchy is closed. Both implementations are private to this class and the method by which a rule matches an
 * endpoint is not public, so this is an enumeration of the kinds the library supports rather than an extension point. A
 * deployment whose rule is neither of these writes its own {@link EndpointPolicy}, which is the seam this library
 * actually offers.
 *
 * <p>Instances are immutable and safe to share across threads.
 */
// GodClass: the entry validation stays in this class deliberately. The extraction the metric invites
// is a partial one — the shape and label checks move to a class of their own while the parse, the
// no-host branch and the closing read-back equality check stay here, because those three are what
// the factory does with the parser's answer. That split leaves "what a valid allowlist entry is"
// stated in two files, to be kept in step by hand; and because these checks are a security control,
// drift between the halves would be silent rather than loud. Moving the whole body out instead only
// renames the problem, since the class it lands in is this one under another name. The metric itself
// fires for a structural reason rather than a design one: a closed enumeration of rule kinds is two
// static factories plus the refusals behind them, sharing constants and holding no instance fields,
// so cohesion measured by field sharing scores zero however the code is arranged.
@SuppressWarnings("PMD.GodClass")
public abstract sealed class EndpointRule {

    /**
     * A configured domain entry that may be quoted into a rejection message verbatim: a bounded run of ASCII letters,
     * digits, {@code '.'} and {@code '-'}, anchored by {@link java.util.regex.Matcher#matches()}. The bound is there so
     * a hostile entry cannot pad a log line with an unbounded run of characters; a real hostname is far shorter.
     */
    private static final Pattern QUOTABLE_ENTRY = Pattern.compile("[A-Za-z0-9.-]{1,255}");

    /** Whether a configured domain entry is ASCII throughout. */
    private static final Pattern ASCII_ONLY = Pattern.compile("\\p{ASCII}*");

    /** A trailing {@code :} plus digits, stripped from an authority the URI parser declined to split for us. */
    private static final Pattern TRAILING_PORT = Pattern.compile(":\\d+$");

    /**
     * Shared by the two refusals of an address literal, which have one cause: an address has no subdomains for a domain
     * rule to cover, and an operator reading {@code EndpointRule.domain("10.0.0.0")} reads a subnet.
     */
    private static final String NOT_AN_ADDRESS =
            "allowed domain must be a DNS name, not an IP address literal — an address has no subdomains"
                    + " for a domain rule to cover; name an exact address with EndpointRule.origin instead";

    /**
     * The refusal for a control character anywhere in a domain entry. It is its own kind of mistake rather than a
     * variant of the ones below: a configuration line copied out of a terminal drags the escape sequences that coloured
     * it along with it, and a file written on Windows and read as text leaves a carriage return at the end of the
     * value.
     */
    private static final String NOT_A_CONTROL_CHARACTER =
            "allowed domain must not contain a control character — an entry copied out of a terminal can carry the"
                    + " escape sequences that coloured it, and one read from a Windows text file can carry a trailing"
                    + " carriage return; neither can be part of a hostname";

    /** Shared by the three URL delimiters, which have one cause: the entry is a pasted endpoint rather than a host. */
    private static final String NOT_A_URL =
            "allowed domain must be a bare hostname, not a URL — a path, query or fragment suggests a pasted"
                    + " endpoint, and everything after the host would be silently ignored";

    /**
     * The characters that may not appear anywhere in a domain entry, each beside the refusal that says what its
     * presence means. This is a list rather than a chain of conditions because the order is checked in the order
     * written and that order is load-bearing — {@code '['} before {@code ':'}, or an address literal is refused for its
     * colons and the operator is told to remove a port that is not there.
     *
     * <p>The control-character refusal runs before this list rather than inside it, since it is a range of characters
     * rather than one; an ANSI escape sequence carries a {@code '['}, so an entry holding one would otherwise be
     * refused as an address literal.
     */
    private static final List<ForbiddenCharacter> FORBIDDEN_CHARACTERS = List.of(
            new ForbiddenCharacter('[', NOT_AN_ADDRESS),
            new ForbiddenCharacter(
                    ':',
                    "allowed domain must be a bare hostname carrying no scheme and no port — a domain rule matches"
                            + " https on the default port only, and an entry beginning \"https://\" would otherwise be"
                            + " read as the host \"https\""),
            new ForbiddenCharacter('/', NOT_A_URL),
            new ForbiddenCharacter('?', NOT_A_URL),
            new ForbiddenCharacter('#', NOT_A_URL),
            new ForbiddenCharacter(
                    '@',
                    "allowed domain must not carry userinfo — \"zone.example@evil.test\" parses with the host"
                            + " \"evil.test\", so everything written before the @ would be discarded"),
            new ForbiddenCharacter(
                    '*',
                    "allowed domain needs no wildcard and has no pattern syntax — a domain rule already matches the"
                            + " domain itself and every subdomain of it at any depth"));

    private EndpointRule() {}

    /** One forbidden character and the refusal its presence earns. */
    private record ForbiddenCharacter(char marker, String refusal) {}

    /**
     * A rule matching exactly one origin: a send is permitted only if the endpoint's origin — its
     * {@code scheme://host[:port]}, never the path or query — equals this entry. Matching is exact per origin, so a
     * subdomain of an allowed origin is <em>not</em> allowed.
     *
     * <p>Comparison happens on the RFC 6454 §6.1 serialization of <em>both</em> sides, the same normalization the VAPID
     * {@code aud} claim uses: scheme and host lowercased, IDNA A-labels decoded to Unicode, and an explicit default
     * port ({@code :443}) dropped. {@code https://PUSH.Example:443} in the configuration therefore matches an endpoint
     * on {@code https://push.example}, and an A-label host matches whatever case the endpoint spelled it in.
     *
     * <p>The entry must be a bare https origin. An unparseable one, a non-{@code https} one (a {@link Subscription}
     * endpoint is always https, so any other scheme could never match), a hostless one (spell an internationalised host
     * in its A-label/Punycode form), one carrying a path, query, fragment or userinfo, and one using {@code *} where a
     * host label belongs are all refused here. A lone trailing {@code "/"} is tolerated, since browsers and RFC 6454
     * both print origins without one but humans often paste one.
     *
     * <p>Every rejection renders the entry through {@link Endpoints#redact}: a configured origin is not supposed to be
     * a capability URL, but the likeliest malformed entry is a pasted full endpoint, which is one.
     *
     * @param origin the allowed origin, e.g. {@code "https://fcm.googleapis.com"}
     * @return a rule matching that origin and nothing else
     * @throws IllegalArgumentException if the entry is not a well-formed bare https origin
     */
    // PreserveStackTrace: the cause is dropped on purpose — URISyntaxException's message embeds the
    // raw input, which in the pasted-endpoint failure mode is a capability URL that must not leak.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public static EndpointRule origin(String origin) {
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
            if (hasWildcardInHostPosition(uri)) {
                throw new IllegalArgumentException("allowed origin names one host exactly and has no pattern syntax;"
                        + " express a whole DNS zone with EndpointRule.domain(\"zone.example\"), which matches that"
                        + " domain and every subdomain of it at any depth: " + Endpoints.redact(origin));
            }
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
        return new OriginRule(Origin.parts(uri).serialized());
    }

    /**
     * A rule matching a DNS domain and <em>every subdomain of it, at any depth</em>: {@code domain("zone.example")}
     * admits an endpoint on {@code zone.example}, on {@code a.zone.example} and on {@code a.b.c.zone.example} alike. It
     * is not an origin with the scheme left off — it is deliberately wider than that, and it is worth exactly what the
     * DNS of that zone is worth, so a domain rule belongs only where the push service operator documents that its
     * hostnames vary within one zone.
     *
     * <p>The match is anchored at a DNS label boundary, so a domain rule for {@code zone.example} does <em>not</em>
     * admit {@code evilzone.example} or {@code zone.example.evil.test}. It matches only the scheme {@code https} and
     * only the default port — absent or an explicit {@code 443}. A port is a statement about which service on a host is
     * trusted rather than about which names are trusted, and permitting every port across a whole zone would re-create
     * the blind request-forgery oracle an allowlist exists to close; a deployment that genuinely needs
     * {@code https://host.zone:8443} names it exactly with {@link #origin}.
     *
     * <p>The entry is a bare hostname of at least two labels, compared and stored in the same normalized form the
     * endpoint's host arrives in — lowercased, with IDNA A-labels decoded — so {@code domain("NOTIFY.WINDOWS.COM")} and
     * {@code domain("xn--bcher-kva.example")} are live entries rather than dead ones. Refused, in the order the checks
     * run: an empty entry; a control character; a scheme or port; a path, query or fragment; userinfo; a wildcard; a
     * leading dot or an empty label; a trailing root dot; a single label; an IP address literal; and raw Unicode, which
     * must be given in its A-label/Punycode form instead.
     *
     * <p>The library makes no public-suffix judgement, having no authoritative data to make one with: a domain rule
     * over a shared hosting zone permits every tenant of that zone.
     *
     * @param domain the allowed domain, e.g. {@code "notify.windows.com"}
     * @return a rule matching that domain and every subdomain of it over https on the default port
     * @throws IllegalArgumentException if the entry is not a well-formed multi-label hostname
     */
    // PreserveStackTrace: the cause is dropped on purpose — URISyntaxException's message embeds the
    // raw input, which in the pasted-endpoint failure mode is a capability URL that must not leak.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public static EndpointRule domain(String domain) {
        Objects.requireNonNull(domain, "domain");
        requireBareHostnameShape(domain);
        URI uri;
        try {
            // Validation runs through the same parser the endpoint side uses rather than a
            // hand-rolled hostname grammar, so a configured entry can never be a shape an endpoint
            // could never have — a second grammar would be one more thing to keep in step.
            uri = new URI("https://" + domain);
        } catch (URISyntaxException e) {
            // No cause: URISyntaxException's message carries the raw input, which must not leak.
            throw new IllegalArgumentException("allowed domain is not a valid URI host" + quoted(domain));
        }
        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            throw new IllegalArgumentException("allowed domain is not a hostname the URI parser recognises — a label"
                    + " may not start or end with a hyphen, hold an underscore, or be an empty A-label"
                    + quoted(domain));
        }
        if (!host.equalsIgnoreCase(domain)) {
            // The closing defence against the "https://" concatenation reinterpreting the entry:
            // whatever the parser decided the host was, it has to be the entry that was written.
            throw new IllegalArgumentException("allowed domain is not read back as itself once parsed, so it would be"
                    + " reinterpreted rather than matched" + quoted(domain));
        }
        return new DomainRule(Origin.parts(uri).host());
    }

    /**
     * Whether this rule admits the endpoint whose origin normalized to {@code endpoint}.
     *
     * @param endpoint the endpoint's origin, normalized once for every rule in the allowlist
     * @return {@code true} if this rule admits it
     */
    abstract boolean matches(Origin.Parts endpoint);

    /**
     * The shape refusals for a domain entry. Only three of them are load-bearing for the refusal itself: the
     * trailing-root-dot, the single-label and the address-literal checks catch entries the closing equality check in
     * {@link #domain} lets through ({@code "zone.example."}, {@code "com"}, {@code "localhost"}, {@code "1.2.3.4"} and
     * {@code "[::1]"} are all read back as themselves). The rest are redundant for deciding the refusal and exist for
     * their message, which is the point: an operator who pasted an endpoint URL into the domain field is told that,
     * rather than being told the entry is not read back as itself. Do not collapse them into the parse.
     *
     * <p>The order is not free either, and it runs top to bottom through this method and then through
     * {@link #requireLabelStructure}, which is split out only to keep either half readable. The control-character check
     * precedes the bracket check, or an entry carrying an ANSI escape sequence is refused as an address literal for the
     * {@code '['} inside it; the bracket check precedes the colon check, or an IPv6 literal is refused for its colons;
     * the trailing-root-dot check precedes the single-label check, or {@code "com."} is refused for being one label;
     * and the non-ASCII check precedes everything the parser does, or a raw Unicode entry is refused for having no host
     * instead of being told to spell it in its A-label form.
     */
    private static void requireBareHostnameShape(String domain) {
        if (domain.isEmpty()) {
            throw new IllegalArgumentException("allowed domain must not be empty");
        }
        if (domain.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(NOT_A_CONTROL_CHARACTER + quoted(domain));
        }
        for (ForbiddenCharacter forbidden : FORBIDDEN_CHARACTERS) {
            if (domain.indexOf(forbidden.marker()) >= 0) {
                throw new IllegalArgumentException(forbidden.refusal() + quoted(domain));
            }
        }
        requireLabelStructure(domain);
        if (!ASCII_ONLY.matcher(domain).matches()) {
            throw new IllegalArgumentException("allowed domain must be given in its A-label/Punycode form — an"
                    + " endpoint's host is normalized from its A-label spelling, so a raw internationalised entry"
                    + " could never match" + quoted(domain));
        }
    }

    /** The label-level refusals, continuing the ordered list {@link #requireBareHostnameShape} begins. */
    private static void requireLabelStructure(String domain) {
        // Not split on '.': String.split drops trailing empty fields, so "a.b." would pass a
        // check written that way while carrying exactly the empty label this refuses.
        if (domain.startsWith(".") || domain.contains("..")) {
            throw new IllegalArgumentException(
                    "allowed domain must not begin with a dot or hold an empty label" + quoted(domain));
        }
        if (domain.endsWith(".")) {
            throw new IllegalArgumentException("allowed domain must not end with the root dot — an endpoint's host is"
                    + " compared without it, so the entry could never fire and would be dead configuration"
                    + quoted(domain));
        }
        if (domain.indexOf('.') < 0) {
            throw new IllegalArgumentException("allowed domain must have at least two labels — a single label is"
                    + " either a whole public suffix or a name with no global meaning" + quoted(domain));
        }
        if (Origin.isAddressLiteral(domain)) {
            throw new IllegalArgumentException(NOT_AN_ADDRESS + quoted(domain));
        }
    }

    /**
     * Renders a configured domain entry for a rejection message: {@code ": 'zone.example'"} when the entry may be
     * quoted, and a note that it was left out otherwise. The message it is appended to always names the cause on its
     * own, so a refused entry costs the reader nothing but the entry itself.
     *
     * <p>A domain entry is configuration rather than a subscription endpoint, so it is not rendered through
     * {@link Endpoints#redact}: that function is built for capability URLs and answers a bare hostname with an opaque
     * marker and a fingerprint, showing the operator not one character of what they wrote — from a message whose whole
     * job is to point at their typo. Nor is it printed unconditionally, because the domain field is exactly where a
     * pasted endpoint lands, and what arrives there may carry a capability path or query, credentials, or control
     * characters that must not enter a log line.
     */
    private static String quoted(String entry) {
        return isQuotable(entry)
                ? ": '" + entry + "'"
                : " (the entry is left out of this message: it is not a plain host-shaped token, so it may be a pasted"
                        + " endpoint URL or hold characters that must not reach a log)";
    }

    /**
     * Whether an entry may be quoted into a message verbatim: a bounded run of ASCII letters, digits, {@code '.'} and
     * {@code '-'} and nothing else, which leaves out control characters, whitespace and every URI delimiter.
     *
     * <p>This is a strictly weaker and different question from whether the entry is a valid domain — it asks only
     * whether these characters are safe to put in a string a deployment logs, and it decides nothing about what the
     * allowlist accepts. It must never be read or reused as a second hostname grammar beside the validation above:
     * plenty of entries it refuses to quote are refused by that validation anyway, and plenty it happily quotes are
     * still not valid domains.
     */
    private static boolean isQuotable(String entry) {
        return QUOTABLE_ENTRY.matcher(entry).matches();
    }

    /**
     * Whether an origin entry the parser found no host in carries a {@code *} where a host label belongs. The criterion
     * is the host position rather than the character anywhere: {@code https://example.com/*} and
     * {@code https://a*b@example.com} both parse with a real host and are already refused for being more than a bare
     * origin, which is the right thing to tell whoever wrote them.
     */
    private static boolean hasWildcardInHostPosition(URI uri) {
        // getAuthority() rather than getRawAuthority(): the decoded form, so a percent-encoded
        // wildcard ("https://%2A.zone.example") reaches this branch too. Deliberate, and it widens
        // nothing — every entry that gets here has already failed to yield a host and is refused
        // whichever branch it takes, so all that changes is which refusal its author is handed, and
        // "express a zone with a domain rule" diagnoses that entry better than "your origin has no
        // host". Decoding can in principle also move where the strips below cut, when an escaped
        // '@' or ':' appears beside a wildcard; that too only selects a message between two
        // refusals, which is why the decoded form is chosen for the common case rather than the
        // contrived one.
        String authority = uri.getAuthority();
        if (authority == null) {
            // "https:*" parses with no authority at all.
            return false;
        }
        // A registry-based authority — which is what any authority holding a '*' is — is handed back
        // whole: getRawUserInfo() answers null and getPort() answers -1 even for "user@*.zone:8443".
        // So the userinfo and the port are stripped here rather than read off the parsed URI.
        String hostPosition = authority.substring(authority.lastIndexOf('@') + 1);
        return TRAILING_PORT.matcher(hostPosition).replaceFirst("").indexOf('*') >= 0;
    }

    /** A rule matching one RFC 6454 origin serialization exactly. */
    private static final class OriginRule extends EndpointRule {

        private final String origin;

        OriginRule(String origin) {
            super();
            this.origin = origin;
        }

        @Override
        boolean matches(Origin.Parts endpoint) {
            return origin.equals(endpoint.serialized());
        }

        @Override
        public boolean equals(@Nullable Object obj) {
            // Equality is declared per kind and never on the base class: an origin rule and a domain
            // rule carrying the same text are different rules, and a shared instanceof check on the
            // base would quietly let one collapse into the other inside an allowlist.
            return obj instanceof OriginRule other && origin.equals(other.origin);
        }

        @Override
        public int hashCode() {
            return origin.hashCode();
        }

        @Override
        public String toString() {
            return "EndpointRule.origin(" + origin + ")";
        }
    }

    /** A rule matching a domain and every subdomain of it, over https on the default port. */
    private static final class DomainRule extends EndpointRule {

        private final String domain;

        /** The domain with its leading dot, so the boundary test is a plain suffix test. */
        private final String dotSuffix;

        DomainRule(String domain) {
            super();
            this.domain = domain;
            this.dotSuffix = "." + domain;
        }

        @Override
        boolean matches(Origin.Parts endpoint) {
            // The port is tested here rather than inferred from the origin serialization having
            // dropped it: that drop is per scheme and also erases http's :80, and a domain rule
            // that inherited it would inherit a scheme table it does not control.
            if (!"https".equals(endpoint.scheme()) || (endpoint.port() != -1 && endpoint.port() != 443)) {
                return false;
            }
            String host = endpoint.host();
            // The dot belongs to the suffix, not to the host being searched: without it
            // "evilzone.example" ends with "zone.example" and would be admitted.
            return host.equals(domain) || host.endsWith(dotSuffix);
        }

        @Override
        public boolean equals(@Nullable Object obj) {
            // Per kind, for the reason given on the origin rule's equals.
            return obj instanceof DomainRule other && domain.equals(other.domain);
        }

        @Override
        public int hashCode() {
            return domain.hashCode();
        }

        @Override
        public String toString() {
            return "EndpointRule.domain(" + domain + ")";
        }
    }
}
