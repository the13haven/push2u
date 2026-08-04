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
 *     (12h)
 * @param defaultTtl the push {@code TTL} used when a message sets none; {@code null} keeps the {@code PushSender}
 *     default (24h)
 * @param recordSize the {@code aes128gcm} record size (RFC 8188 {@code rs}); {@code null} keeps the {@code PushSender}
 *     default (4096 bytes). Rejected at startup if below 18 (RFC 8188 §2); separately, a send fails if the value does
 *     not exceed that particular payload plus 17 bytes (RFC 8291 §4) — a per-payload check this property cannot
 *     pre-empt
 * @param maxEncryptedBodyBytes the ceiling on the encrypted HTTP entity body; {@code null} keeps the {@code PushSender}
 *     default (4096 bytes, the limit RFC 8030 §7.2 lets a push service enforce). Rejected at startup if it is below the
 *     fixed 103-byte {@code aes128gcm} overhead, which is the body an empty payload produces
 * @param allowedOrigins the push-service origins the sender may POST to (e.g. {@code https://fcm.googleapis.com}),
 *     enforced as {@code EndpointPolicies.allowedOrigins}; {@code null} keeps the {@code PushSender} default of no
 *     endpoint policy — any https endpoint is sent to, which for client-registered subscriptions is a blind-SSRF
 *     surface. Malformed entries are rejected at startup, as is an explicitly empty value on its own. A non-empty value
 *     is mutually exclusive with an application-supplied {@code EndpointPolicy} bean; an explicitly <em>empty</em>
 *     value beside a bean cedes to the bean — the escape hatch for a service that inherits this property from shared
 *     configuration it cannot unset
 * @param retry the retry policy
 */
@ConfigurationProperties("push2u")
public record Push2uProperties(
        @DefaultValue Vapid vapid,
        @Nullable Duration jwtExpiry,
        @Nullable Duration defaultTtl,
        @Nullable Integer recordSize,
        @Nullable Integer maxEncryptedBodyBytes,
        @Nullable List<String> allowedOrigins,
        @DefaultValue Retry retry) {

    /**
     * Snapshots {@code allowedOrigins} into an unmodifiable copy (when set), so the bound configuration cannot drift
     * from the policy the {@code PushSender} was built with.
     */
    public Push2uProperties {
        if (allowedOrigins != null) {
            allowedOrigins = List.copyOf(allowedOrigins);
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
            @Nullable String subject) {}

    /**
     * Retry policy, mapped onto {@link com.the13haven.push2u.RetryPolicy}.
     *
     * @param maxAttempts the maximum number of POSTs including the first (≥ 1)
     * @param initialBackoff the backoff before the first retry; doubles on each subsequent retry
     * @param maxBackoff the ceiling for the backoff (and any honoured {@code Retry-After})
     */
    public record Retry(
            @DefaultValue("3") int maxAttempts,
            @DefaultValue("1s") Duration initialBackoff,
            @DefaultValue("60s") Duration maxBackoff) {}
}
