/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.time.Duration;
import java.util.Objects;

/**
 * Retry configuration for {@link PushSender}: the maximum number of POST attempts and the exponential-backoff bounds
 * used between retryable failures (429, 5xx). Any retryable response carrying a parseable {@code Retry-After}
 * (delta-seconds or an HTTP-date) overrides the computed backoff (capped at {@link #maxBackoff()}).
 *
 * <p>The ceiling holds for every configuration this record accepts: the doubling stops at {@link #maxBackoff()} rather
 * than running past it, so a policy whose backoff would outgrow what a {@link Duration} can hold waits the ceiling
 * instead of failing the send. A {@code maxBackoff} below {@code initialBackoff} is a legal policy — it simply caps
 * from the first retry on.
 *
 * @param maxAttempts the maximum number of POSTs, including the first (≥ 1)
 * @param initialBackoff the backoff before the first retry; doubles on each subsequent retry until the ceiling stops it
 * @param maxBackoff the ceiling the doubling (and any honoured {@code Retry-After}) is capped at; every wait this
 *     policy produces is between zero and this value
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
     * at {@link #maxBackoff()}. Total and saturating — for every accepted policy and every {@code int} it returns a
     * value between zero and {@link #maxBackoff()} and never throws. The cap is applied to the arithmetic rather than
     * to its result: doubling stops the moment another step would pass the ceiling, so a schedule whose uncapped term
     * would not fit in a {@link Duration} still yields the ceiling the caller was promised, and the returned value is
     * the one unbounded arithmetic would give.
     *
     * <p>An attempt below 1 is not on the schedule at all; it is clamped to the first term rather than rejected,
     * because a retry loop must not fail over its own off-by-one. Doubling by shifting a {@code long} cannot express
     * this schedule: the shift distance wraps at 64, which would silently return the schedule to its first term.
     *
     * <p>The loop runs at most once per doubling and not once per attempt, so its cost is bounded whatever the attempt
     * count: a {@link Duration} spans under 2^93 nanoseconds, and each step at least doubles a value of at least one
     * nanosecond, so fewer than a hundred steps are possible before the ceiling ends it.
     */
    Duration backoffFor(int attempt) {
        // A zero initial backoff cannot grow, so every attempt answers zero — and returning here is
        // what keeps the loop below from stepping once per attempt over a value that never changes.
        if (initialBackoff.isZero() || attempt <= 1) {
            return initialBackoff.compareTo(maxBackoff) > 0 ? maxBackoff : initialBackoff;
        }
        // Half the ceiling, rounded down: a value above it is one whose double passes the ceiling.
        // Testing before the multiplication is what makes the doubling below unable to overflow —
        // every value it produces is at most the ceiling, which is itself a representable Duration.
        Duration half = maxBackoff.dividedBy(2);
        Duration backoff = initialBackoff;
        for (int doublings = attempt - 1; doublings > 0; doublings--) {
            if (backoff.compareTo(half) > 0) {
                return maxBackoff;
            }
            backoff = backoff.multipliedBy(2);
        }
        // No cap needed here: the loop ran at least once, and a step it did not turn back only ever
        // doubled a value of at most half the ceiling, so what it left behind is at most the ceiling.
        return backoff;
    }
}
