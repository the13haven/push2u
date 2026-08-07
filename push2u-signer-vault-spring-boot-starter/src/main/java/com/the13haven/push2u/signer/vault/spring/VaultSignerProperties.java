/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault.spring;

import java.net.URI;
import java.time.Duration;

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
 *     query or fragment; the path prefix, when present, is preserved in front of every Vault API path. The scheme is
 *     not restricted to {@code https} (Vault's dev server is plain {@code http}), but a production address must be
 *     {@code https} — on plain HTTP the Vault token header travels in clear text
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
     *   <li>{@code address} renders without its credentials — its userinfo becomes {@code ***}, and a query or a
     *       fragment is dropped. An address may legitimately carry userinfo (basic auth for a proxy in front of Vault,
     *       honoured by a custom transport), and that password is exactly as secret as the token beside it. What is
     *       masked is userinfo as Java parses it, which is not every string an operator may have typed in that
     *       position; the rendering below says where the two part company.
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
     * The address as it is rendered above: the URI's userinfo replaced by {@code ***}, and any query or fragment
     * dropped.
     *
     * <p>Userinfo is a supported part of a Vault address — the signer preserves it so a custom transport can use it as
     * basic auth for a proxy in front of Vault — and a password smuggled into the authority is as secret as the Vault
     * token beside it. It is replaced rather than removed, because a rendering that simply dropped it would tell an
     * operator reading the dump that no proxy credentials are configured; the mask says "configured, not shown" without
     * revealing the user name either, both halves of userinfo being the operator's to keep. A query and a fragment are
     * dropped instead of masked: the signer refuses either in a base address at startup, naming the property, so their
     * presence is a misconfiguration this rendering has no need to report — while a query can name secrets, which is
     * why one that is present anyway (this record binds before the signer validates it) must not be printed.
     *
     * <p>An address typed without a scheme ({@code user:secret@vault.example:8200}) carries its credentials outside any
     * authority — Java reads {@code user} as the scheme — so the same cut is made there, taking the scheme with it. It
     * takes the scheme even where the {@code @} is no credential at all ({@code mailto:ops@example.com} renders as
     * {@code ***@example.com}), which costs a word the operator can reconstruct; the host always survives, the cut
     * being always at an {@code @}.
     *
     * <p>Both cuts end at the first {@code /}, {@code ?} or {@code #}, since userinfo may contain none of the three —
     * so a credential that does contain one is left where it stands. {@code user:PA/SS@vault.example:8200} and
     * {@code https://u:PA/SS@vault.example:8200} render whole, and {@code https://u:PASS?@vault.example} renders as
     * {@code https://u:PASS}; {@code /} in particular is an ordinary character in a generated password. Java reports no
     * userinfo for any of them, which is the honest form of the promise: what is masked is userinfo, not every string
     * typed where userinfo goes. Nor can the rule be widened to reach them — {@code vault.example:8200/a@b} is the same
     * shape as the first, and its {@code @} is an ordinary path character that must stay.
     *
     * <p>The built-in Vault transport ({@code JdkVaultHttpTransport}) applies the same rule to the URIs in its failure
     * messages. This is a deliberate second copy rather than a shared one: sharing it would mean adding a public member
     * to the signer library that every consumer would then be able to depend on for good, and the two renderings are
     * not the same anyway — the transport strips userinfo outright, keeping its messages a URI an operator can copy,
     * while a configuration dump has to keep saying that something was configured there. Keep the two in step when
     * either changes.
     */
    private static @Nullable String redactedAddress(@Nullable URI address) {
        if (address == null) {
            return null;
        }
        String text = address.toString();
        int cut = text.length();
        int query = text.indexOf('?');
        if (query >= 0) {
            cut = query;
        }
        int fragment = text.indexOf('#');
        if (fragment >= 0 && fragment < cut) {
            cut = fragment;
        }
        String stripped = text.substring(0, cut);
        // An authority is the "//" that follows the scheme's colon (or opens a relative reference)
        // and nothing else: a "//" further along is two path segments, whose "@" is an ordinary
        // path character and no credential.
        String scheme = address.getScheme();
        int schemeEnd = scheme == null ? 0 : scheme.length() + 1;
        if (stripped.startsWith("//", schemeEnd)) {
            // Userinfo sits between the "//" and the last "@" of the authority. An "@" at the
            // authority's very first character delimits an empty userinfo — nothing was configured
            // there, and the address is left as it stands.
            int authorityStart = schemeEnd + 2;
            int at = lastAtBeforeThePath(stripped, authorityStart);
            if (at > authorityStart) {
                return stripped.substring(0, authorityStart) + "***@" + stripped.substring(at + 1);
            }
        } else if (scheme != null) {
            // No authority, yet the credentials can still be there: "user:secret@vault:8200" typed
            // without a scheme parses as the scheme "user" with all of "secret@vault:8200" behind
            // it. Everything up to the last "@" before the path goes, the scheme included — it is
            // the user name half of the userinfo.
            int at = lastAtBeforeThePath(stripped, schemeEnd);
            if (at >= schemeEnd) {
                return "***@" + stripped.substring(at + 1);
            }
        }
        return stripped;
    }

    /**
     * The index of the last {@code @} in front of the path, searching from {@code from}, or {@code -1} if there is
     * none. An {@code @} may legally recur inside userinfo, so the last one is the delimiter and everything before it
     * is credential; past the first {@code /} the {@code @} is an ordinary path character.
     */
    private static int lastAtBeforeThePath(String stripped, int from) {
        int pathStart = stripped.indexOf('/', from);
        int end = pathStart >= 0 ? pathStart : stripped.length();
        return stripped.lastIndexOf('@', end - 1);
    }
}
