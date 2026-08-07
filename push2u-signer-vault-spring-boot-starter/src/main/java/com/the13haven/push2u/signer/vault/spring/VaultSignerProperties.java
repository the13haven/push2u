/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault.spring;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;

import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Binds {@code push2u.signer.vault.*} for the Vault Transit signer starter.
 *
 * <p>The transport properties ({@code request-timeout}, {@code connect-timeout}, {@code max-response-bytes}) shape the
 * default {@code JdkVaultHttpTransport} the starter builds. They are ignored when the application supplies its own
 * {@code VaultHttpTransport} bean, and {@code connect-timeout} is additionally ignored when a
 * {@code push2uVaultHttpClient}-qualified {@code HttpClient} bean is supplied (the client owns its connect timeout).
 *
 * @param address the Vault base address, e.g. {@code https://vault.example:8200} — or, for a Vault behind a reverse
 *     proxy or ingress prefix, e.g. {@code https://gw.example/vault}. It must be an absolute URI with a host and no
 *     query or fragment; the path prefix, when present, is preserved in front of every Vault API path. The scheme must
 *     be {@code http} or {@code https}. {@code https} is always accepted; plain {@code http} only towards a literal
 *     loopback host ({@code localhost}, a name under {@code .localhost}, a {@code 127.0.0.0/8} IPv4 dotted-quad in
 *     canonical decimal — so {@code 127.0.0.1}, but neither {@code 127.1} nor {@code 0177.0.0.1} — or a bracketed IP
 *     literal denoting a loopback address, {@code [::1]} in any spelling and the IPv4-mapped writings such as
 *     {@code [::ffff:127.0.0.1]}) — the TLS-terminating Vault Agent or sidecar pattern. Plain {@code http} to any other
 *     host fails startup: the Vault token header would cross the network in clear text, and there is deliberately no
 *     property to permit it — a deployment that accepts that risk defines its own {@code VaultTransitVapidSigner} bean
 *     (built with {@code allowInsecureHttp()}), which this starter yields to
 * @param mount the Transit mount path (default {@code transit})
 * @param namespace the Vault Enterprise/HCP namespace the Transit engine lives in, possibly nested
 *     ({@code team-a/sub}), sent as the {@code X-Vault-Namespace} header on every Vault call; <b>optional</b> — when
 *     unset no such header is sent at all, which is what Vault OSS (no namespaces) expects
 * @param keyName the {@code ecdsa-p256} Transit key name
 * @param token the Vault token authorising {@code sign} on the key (plus {@code read} on {@code transit/keys/<key>}
 *     when {@code publicKey} is omitted)
 * @param publicKey the VAPID public key as base64url (the 65-byte uncompressed point, which must encode a point on the
 *     P-256 curve); <b>optional</b> — when null/blank the signer reads it from Vault at startup
 * @param keyVersion the Transit key version {@code publicKey} belongs to, pinned on every sign request; <b>optional</b>
 *     and only valid together with {@code publicKey} (the fetched mode pins the version it reads from Vault itself).
 *     Without it the explicit mode signs with Vault's latest version, which breaks after a key rotation — set it
 *     whenever the Transit key may ever be rotated
 * @param requestTimeout the per-request timeout for every Vault call (default 30s; must be positive) — bounds the whole
 *     exchange, so a Vault that accepts the connection but never answers cannot hang application startup
 * @param connectTimeout the connect timeout of the default HTTP client (default 10s; must be positive)
 * @param maxResponseBytes the Vault response-size cap in raw bytes (default 1048576 = 1 MiB; must be positive); an
 *     oversized response fails the call instead of being truncated
 *     <p>The three transport defaults restate {@code JdkVaultHttpTransport}'s own ({@code DEFAULT_REQUEST_TIMEOUT},
 *     {@code DEFAULT_CONNECT_TIMEOUT}, {@code DEFAULT_MAX_RESPONSE_BYTES}): {@code @DefaultValue} takes literals, and
 *     those constants are module-private. Keep the two in step when either changes.
 */
@ConfigurationProperties("push2u.signer.vault")
public record VaultSignerProperties(
        @Nullable URI address,
        @DefaultValue("transit") String mount,
        @Nullable String namespace,
        @Nullable String keyName,
        @Nullable String token,
        @Nullable String publicKey,
        @Nullable Integer keyVersion,
        @DefaultValue("30s") Duration requestTimeout,
        @DefaultValue("10s") Duration connectTimeout,
        @DefaultValue("1048576") int maxResponseBytes) {

    /**
     * Rejects non-positive transport settings at binding time — a zero or negative timeout would silently disable the
     * hang protection, and a non-positive cap can never buffer a response.
     */
    public VaultSignerProperties {
        if (requestTimeout == null || requestTimeout.isZero() || requestTimeout.isNegative()) {
            throw new IllegalArgumentException(
                    "push2u.signer.vault.request-timeout must be positive, got " + requestTimeout);
        }
        if (connectTimeout == null || connectTimeout.isZero() || connectTimeout.isNegative()) {
            throw new IllegalArgumentException(
                    "push2u.signer.vault.connect-timeout must be positive, got " + connectTimeout);
        }
        if (maxResponseBytes <= 0) {
            throw new IllegalArgumentException(
                    "push2u.signer.vault.max-response-bytes must be positive, got " + maxResponseBytes);
        }
    }

    /**
     * The record-generated {@code toString()} prints every component, {@code token} included — and while push2u never
     * stringifies this record and the actuator env/configprops endpoints mask values by default, the consuming
     * application is one accidental {@code log.info("{}", properties)} or debugger dump away from its live Vault token
     * in a log line. Two components are therefore rendered rather than printed:
     *
     * <ul>
     *   <li>{@code token} renders as {@code ***} when set, and as {@code null} when not — so the mask never reads as "a
     *       token is configured";
     *   <li>{@code address} renders from its parsed components with its userinfo masked as {@code ***} — or, when it is
     *       not a shape those components can safely rebuild, as a fixed marker carrying none of the original text. The
     *       rendering below states the rule.
     * </ul>
     *
     * Everything else keeps the generated shape.
     */
    @Override
    public String toString() {
        return "VaultSignerProperties[address=" + redactedAddress(address)
                + ", mount=" + mount
                + ", namespace=" + namespace
                + ", keyName=" + keyName
                + ", token=" + (token == null ? null : "***")
                + ", publicKey=" + publicKey
                + ", keyVersion=" + keyVersion
                + ", requestTimeout=" + requestTimeout
                + ", connectTimeout=" + connectTimeout
                + ", maxResponseBytes=" + maxResponseBytes + "]";
    }

    /**
     * The address as it is rendered above, composed from the URI's parsed components — never from its string form. An
     * address Java parsed as {@code scheme://[userinfo@]host[:port][/path]} with no query and no fragment is rebuilt
     * from its scheme, host, port and raw path, with a present, non-empty userinfo masked as {@code ***@}. Userinfo is
     * a supported part of a Vault address — the signer preserves it so a custom transport can use it as basic auth for
     * a proxy in front of Vault — and that password is exactly as secret as the token beside it. It is masked rather
     * than dropped, because a rendering that removed it would tell an operator reading the dump that no proxy
     * credentials are configured; neither half is printed, the user name being the operator's to keep too. An empty
     * userinfo ({@code https://@vault.example:8200}) keeps its {@code @} unmasked: it delimits no credential, and a
     * mask there would claim one that does not exist, exactly as a {@code ***} for an unset token would.
     *
     * <p>Every other shape renders as the fixed marker {@code <unrenderable address>}, with not one character of the
     * original string: once Java has not parsed a server-based authority, a credential can sit anywhere in the text — a
     * password carrying {@code /} or {@code ?}, both ordinary characters in a generated one, dissolves the authority as
     * Java reads it — and no string-level cut can find it without guessing. A parsed authority alone is not enough,
     * which is why a <em>raw</em> path carrying {@code @} routes to the marker too: when the text before a password's
     * first {@code /} happens to parse as {@code host[:port]}
     * ({@code https://u:1971/restOfPassword@vault.example:8200}), Java reads the user name as the host and drops the
     * rest of the credential — its {@code @} and the real host included — into the path. A credential in an authority
     * is always delimited by {@code @}, so a raw path with no {@code @} can hide no tail of one — provided the path is
     * literal text, which is what that argument reasons about. A raw path carrying {@code %} is not literal text: it is
     * an encoding, {@code %40} at any encoding depth spells the delimiter without ever showing it, and decoding to some
     * chosen depth before looking would just move the guessing one level down. So {@code %} routes to the marker as
     * well — an encoded path is refused, not reasoned about. Neither guard swallows anything renderable: the signer's
     * address rule admits neither {@code @} nor {@code %} in an address path. The marker is deliberately distinct from
     * {@code null} (no address configured) and from the token's {@code ***} (a value, hidden): it says an address is
     * configured but its shape cannot be rendered without risking a credential. The shapes it covers — a relative
     * reference, a schemeless {@code user:pass@vault.example:8200} (Java reads {@code user} as the scheme, so there is
     * no host), an address carrying a query, a fragment, or an {@code @} or {@code %} in its raw path — are exactly the
     * shapes that can never be a valid Vault address, so the signer refuses them at startup naming the property; the
     * operator who needs the value has it in their own configuration, and the signer library itself already refuses a
     * bad address without quoting it, which this rendering merely stops departing from. A valid address is unaffected.
     *
     * <p>The built-in Vault transport ({@code JdkVaultHttpTransport}) renders the URIs in its failure messages by the
     * same fail-closed rule. This is a deliberate second copy rather than a shared one: sharing it would mean adding a
     * public member to the signer library that every consumer would then be able to depend on for good, and the two
     * renderings are not the same anyway — the transport drops userinfo outright, keeping its messages a URI an
     * operator can copy, while a configuration dump has to keep saying that something was configured there. Keep the
     * two in step when either changes.
     */
    private static @Nullable String redactedAddress(@Nullable URI address) {
        if (address == null) {
            return null;
        }
        // A URI with a parsed host always carries a path, possibly empty; the fallback only
        // states that in a form the nullness checker can see.
        String rawPath = Objects.requireNonNullElse(address.getRawPath(), "");
        if (address.getScheme() == null
                || address.getHost() == null
                || address.getRawQuery() != null
                || address.getRawFragment() != null
                || rawPath.indexOf('@') >= 0
                || rawPath.indexOf('%') >= 0) {
            return "<unrenderable address>";
        }
        StringBuilder rendered = new StringBuilder(address.getScheme()).append("://");
        String userInfo = address.getUserInfo();
        if (userInfo != null) {
            rendered.append(userInfo.isEmpty() ? "@" : "***@");
        }
        rendered.append(address.getHost());
        if (address.getPort() >= 0) {
            rendered.append(':').append(address.getPort());
        }
        return rendered.append(rawPath).toString();
    }
}
