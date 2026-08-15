/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.spring;

import java.time.Duration;
import java.util.List;

import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Binds {@code push2u.*} configuration for the starter.
 *
 * @param vapid the VAPID identity (keys + subject); always present, its fields may be unset
 * @param jwtExpiry how far ahead the VAPID JWT {@code exp} is set; {@code null} keeps the {@code PushSender} default
 *     (12h). Rejected at startup if not strictly positive or more than 24h (RFC 8292 §2)
 * @param jwtRenewBefore how long before a reused token's {@code exp} a fresh one is signed; {@code null} keeps the
 *     {@code PushSender} default (5m). Rejected at startup if negative. It is deliberately not validated against
 *     {@code push2u.jwt-expiry}: a margin at or above the token's whole life is legal and simply means every send signs
 *     afresh. {@code 0s} is legal too and is <em>not</em> an off switch — zero margin is the most reuse, holding a
 *     token to its last second; {@code push2u.jwt-reuse} is the switch
 * @param jwtReuse whether a signed VAPID token is reused for later sends to the same push-service origin until it nears
 *     expiry; {@code null} keeps the {@code PushSender} default ({@code true}). {@code false} is the declared off
 *     switch, restoring a fresh signature per message
 * @param jwtCacheSize how many signed tokens the sender holds at once, evicting the least recently used; {@code null}
 *     keeps the {@code PushSender} default (64). Rejected at startup if below 1 — the bound is what makes the cache
 *     safe to hold rather than a tuning knob, and it is never a second way to spell {@code push2u.jwt-reuse: false}.
 *     Overflow costs a signature per send, never a delivery
 * @param defaultTtl the push {@code TTL} used when a message sets none; {@code null} keeps the {@code PushSender}
 *     default (24h). Rejected at startup if negative
 * @param maxEncryptedBodyBytes the ceiling on the encrypted HTTP entity body — the sender's one size property, from
 *     which the advertised {@code aes128gcm} record size is derived; {@code null} keeps the {@code PushSender} default
 *     (4096 bytes, the limit RFC 8030 §7.2 lets a push service enforce). Rejected at startup if it is below the fixed
 *     103-byte {@code aes128gcm} overhead, which is the body an empty payload produces
 * @param allowedOrigins the push-service origins the sender may POST to (e.g. {@code https://fcm.googleapis.com}), each
 *     matched exactly — a subdomain of a listed origin is not allowed. Its entries are unioned with those of
 *     {@code push2u.allowed-domains} into one allowlist, so the two are halves of one statement rather than rival
 *     settings. One of the two, or an application-supplied {@code EndpointPolicy} bean, is required: leaving all three
 *     out fails the context, because a sender with no policy POSTs wherever a subscription's endpoint points, which for
 *     client-registered subscriptions is a blind-SSRF surface. Malformed entries are rejected at startup, naming this
 *     property and the index of the entry. A non-empty value is mutually exclusive with an {@code EndpointPolicy} bean;
 *     an explicitly <em>empty</em> value is the escape hatch for a service that inherits this property from shared
 *     configuration it cannot unset, and cedes either to a bean or to the sibling property. Emptying every property
 *     that is set, with no bean, fails the context naming both keys: with nothing left to cede to, the allowlist would
 *     reject every send
 * @param allowedDomains the push-service domains the sender may POST to <em>together with every subdomain of each, at
 *     any depth</em>: {@code notify.windows.com} also admits {@code wns2-ln2p.notify.windows.com}. This is not an
 *     origin with the scheme left off — it is deliberately wider, and worth exactly what the DNS of each listed zone is
 *     worth, so it belongs where the push service operator documents that its hostnames vary within one zone. The match
 *     is anchored at a DNS label boundary ({@code evilnotify.windows.com} is not admitted) and covers only
 *     {@code https} on the default port; an exact host with a port is named under {@code push2u.allowed-origins}
 *     instead. Each entry is a bare hostname of at least two labels, carrying no scheme, port, path or wildcard.
 *     Everything the sibling property says applies here identically: the union, being one of the two ways to express
 *     the decision, startup rejection naming this property and the entry's index, exclusivity with an
 *     {@code EndpointPolicy} bean, and an explicitly empty value as the per-property escape hatch — with every set
 *     property empty and no bean failing the context on both keys at once
 * @param health the Actuator health probe settings; always present, defaults apply when unset
 */
@ConfigurationProperties("push2u")
public record Push2uProperties(
        @DefaultValue Vapid vapid,
        @Nullable Duration jwtExpiry,
        @Nullable Duration jwtRenewBefore,
        // Boolean, not boolean: a primitive would need a @DefaultValue to bind, which would restate
        // the PushSender default here and let the two drift. null means the key was left unset, so
        // the sender's own default stands — the same "one place for the default" rule the nullable
        // siblings above and below follow. It also keeps `false`, the deliberate off switch, a value
        // the operator wrote rather than one the binder supplied.
        @Nullable Boolean jwtReuse,
        @Nullable Integer jwtCacheSize,
        @Nullable Duration defaultTtl,
        @Nullable Integer maxEncryptedBodyBytes,
        @Nullable List<String> allowedOrigins,
        @Nullable List<String> allowedDomains,
        @DefaultValue Health health) {

    /**
     * Snapshots each allowlist into an unmodifiable copy (when set), so the bound configuration cannot drift from the
     * policy the {@code PushSender} was built with.
     *
     * <p>Neither list carries a {@code @DefaultValue}, so an absent key stays {@code null} while a key set to an empty
     * value arrives as an empty list. That difference is load-bearing rather than incidental: an unset property means
     * this deployment has not decided which endpoints it will contact, and an empty one means it deliberately cedes the
     * decision to an {@code EndpointPolicy} bean. A default would collapse the two into one value and the two answers —
     * a context failure listing the ways to decide, against a bean quietly winning — into one.
     */
    public Push2uProperties {
        if (allowedOrigins != null) {
            allowedOrigins = List.copyOf(allowedOrigins);
        }
        if (allowedDomains != null) {
            allowedDomains = List.copyOf(allowedDomains);
        }
    }

    /**
     * The VAPID application-server identity (RFC 8292).
     *
     * @param publicKey the base64url uncompressed P-256 public key (the {@code k} value)
     * @param privateKey the base64url raw 32-byte private scalar
     * @param subject the VAPID {@code sub} — a {@code mailto:} / {@code https:} contact. Optional per RFC 8292 §2.1,
     *     but required by push2u and hence by the autoconfigured {@code PushSender}
     */
    public record Vapid(
            @Nullable String publicKey,
            @Nullable String privateKey,
            @Nullable String subject) {

        /**
         * The record-generated {@code toString()} prints every component, {@code privateKey} included — and while
         * push2u never stringifies this record and the actuator env/configprops endpoints mask values by default, the
         * consuming application is one accidental {@code log.info("{}", properties)} or debugger dump away from its
         * VAPID private key in a log line. The private key renders as {@code ***} when set (and as {@code null} when
         * not, so the mask never reads as "a key is configured"); the public key and subject are published identity and
         * stay readable.
         */
        @Override
        public String toString() {
            return "Vapid[publicKey=" + publicKey
                    + ", privateKey=" + (privateKey == null ? null : "***")
                    + ", subject=" + subject + "]";
        }
    }

    /**
     * The Actuator health probe ({@link Push2uHealthIndicator}). The probe exercises the configured signer, which for a
     * remote signer (Vault Transit) is a full backend round-trip on an endpoint Kubernetes polls every few seconds —
     * hence a result cache, and an off switch for deployments that do not want health tied to the signer at all.
     *
     * @param enabled whether the push2u health indicator is registered. {@code false} removes it entirely, so health
     *     never touches the signer
     * @param cacheTtl how long a successful probe result is served from cache before the signer is exercised again. A
     *     <em>failed</em> result is cached for at most 5 seconds regardless (the shorter of this value and 5s), so
     *     recovery is noticed quickly even under a long TTL. {@code 0s} disables caching; negative values are rejected
     *     at startup
     */
    public record Health(
            @DefaultValue("true") boolean enabled,
            @DefaultValue("30s") Duration cacheTtl) {}
}
