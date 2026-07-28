package io.push2u.spring;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Binds {@code push2u.*} configuration for the starter.
 *
 * @param vapid      the VAPID identity (keys + subject); always present, its fields may be unset
 * @param jwtExpiry  how far ahead the VAPID JWT {@code exp} is set; {@code null} keeps the
 *                   {@code PushSender} default (12h)
 * @param defaultTtl the push {@code TTL} used when a message sets none; {@code null} keeps the
 *                   {@code PushSender} default (24h)
 * @param retry      the retry policy
 */
@ConfigurationProperties("push2u")
public record Push2uProperties(@DefaultValue Vapid vapid, Duration jwtExpiry, Duration defaultTtl,
                               @DefaultValue Retry retry) {

    /**
     * The VAPID application-server identity (RFC 8292).
     *
     * @param publicKey  the base64url uncompressed P-256 public key (the {@code k} value)
     * @param privateKey the base64url raw 32-byte private scalar
     * @param subject    the VAPID {@code sub} — a {@code mailto:} / {@code https:} contact
     */
    public record Vapid(String publicKey, String privateKey, String subject) {
    }

    /**
     * Retry policy, mapped onto {@link io.push2u.RetryPolicy}.
     *
     * @param maxAttempts    the maximum number of POSTs including the first (≥ 1)
     * @param initialBackoff the backoff before the first retry; doubles on each subsequent retry
     * @param maxBackoff     the ceiling for the backoff (and any honoured {@code Retry-After})
     */
    public record Retry(@DefaultValue("3") int maxAttempts,
                        @DefaultValue("1s") Duration initialBackoff,
                        @DefaultValue("60s") Duration maxBackoff) {
    }
}
