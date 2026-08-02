package io.push2u;

import java.time.Duration;
import java.util.Objects;

/**
 * Retry configuration for {@link PushSender}: the maximum number of POST attempts and the exponential-backoff bounds
 * used between retryable failures (429, 5xx). Any retryable response carrying a parseable {@code Retry-After}
 * (delta-seconds or an HTTP-date) overrides the computed backoff (capped at {@link #maxBackoff()}).
 *
 * @param maxAttempts the maximum number of POSTs, including the first (≥ 1)
 * @param initialBackoff the backoff before the first retry; doubles on each subsequent retry
 * @param maxBackoff the ceiling the doubling (and any honoured {@code Retry-After}) is capped at
 */
public record RetryPolicy(int maxAttempts, Duration initialBackoff, Duration maxBackoff) {

    /** Validates the attempt count (≥ 1) and the non-negative backoff bounds. */
    public RetryPolicy {
        if (maxAttempts < 1) {
            throw new IllegalArgumentException("maxAttempts must be >= 1");
        }
        Objects.requireNonNull(initialBackoff, "initialBackoff");
        Objects.requireNonNull(maxBackoff, "maxBackoff");
        if (initialBackoff.isNegative() || maxBackoff.isNegative()) {
            throw new IllegalArgumentException("backoff durations must not be negative");
        }
    }

    /**
     * maxAttempts = 3, backoff starting at 1s and doubling, capped at 60s.
     *
     * @return the default policy
     */
    public static RetryPolicy defaults() {
        return new RetryPolicy(3, Duration.ofSeconds(1), Duration.ofSeconds(60));
    }

    /**
     * A single POST with no retries.
     *
     * @return a no-retry policy
     */
    public static RetryPolicy none() {
        return new RetryPolicy(1, Duration.ZERO, Duration.ZERO);
    }

    /**
     * Backoff before the retry that follows {@code attempt} (1-based): {@code initialBackoff * 2^(attempt-1)}, capped
     * at {@link #maxBackoff()}.
     */
    Duration backoffFor(int attempt) {
        int shift = Math.min(attempt - 1, 30);
        Duration backoff = initialBackoff.multipliedBy(1L << shift);
        return backoff.compareTo(maxBackoff) > 0 ? maxBackoff : backoff;
    }
}
