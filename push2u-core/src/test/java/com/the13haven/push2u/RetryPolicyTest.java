/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.Timeout.ThreadMode;

class RetryPolicyTest {

    /** The largest value a {@link Duration} can hold — the worst case for the doubling arithmetic. */
    private static final Duration DURATION_MAX = Duration.ofSeconds(Long.MAX_VALUE, 999_999_999L);

    @Test
    void exponentialBackoffDoublesAndCapsAtMax() {
        RetryPolicy policy = new RetryPolicy(10, Duration.ofSeconds(1), Duration.ofSeconds(10));
        assertThat(policy.backoffFor(1)).isEqualTo(Duration.ofSeconds(1));
        assertThat(policy.backoffFor(2)).isEqualTo(Duration.ofSeconds(2));
        assertThat(policy.backoffFor(3)).isEqualTo(Duration.ofSeconds(4));
        assertThat(policy.backoffFor(4)).isEqualTo(Duration.ofSeconds(8));
        assertThat(policy.backoffFor(5)).as("16s capped to maxBackoff").isEqualTo(Duration.ofSeconds(10));
        assertThat(policy.backoffFor(40)).as("no overflow, still capped").isEqualTo(Duration.ofSeconds(10));
    }

    @Test
    void defaultsAndNoneArePlausible() {
        assertThat(RetryPolicy.defaults().maxAttempts()).isEqualTo(3);
        assertThat(RetryPolicy.none().maxAttempts()).isEqualTo(1);
    }

    @Test
    void rejectsInvalidConfiguration() {
        assertThatThrownBy(() -> new RetryPolicy(0, Duration.ZERO, Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class);

        Duration negativeBackoff = Duration.ofSeconds(-1);
        assertThatThrownBy(() -> new RetryPolicy(1, negativeBackoff, Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /**
     * The cap is the contract, so a product that cannot be represented at all must still come back as the cap. The
     * constructor accepts this policy — nothing about it is invalid — and {@code Duration.multipliedBy} throws
     * {@code ArithmeticException} on the second attempt unless the ceiling is applied to the arithmetic rather than to
     * its result. Reaching that from {@code PushSender.send} would be an exception outside its documented contract.
     */
    @Test
    void backoffSaturatesWhereTheUncappedProductWouldLeaveDurationsRange() {
        RetryPolicy policy = new RetryPolicy(4, Duration.ofSeconds(Long.MAX_VALUE), Duration.ofSeconds(60));

        assertThat(policy.backoffFor(1)).isEqualTo(Duration.ofSeconds(60));
        assertThat(policy.backoffFor(2)).isEqualTo(Duration.ofSeconds(60));
        assertThat(policy.backoffFor(3)).isEqualTo(Duration.ofSeconds(60));
        assertThat(policy.backoffFor(4)).isEqualTo(Duration.ofSeconds(60));
    }

    /**
     * A ceiling above {@code initialBackoff * 2^30} must still be climbed to. A multiplier frozen at {@code 2^30}
     * stalls the schedule below the ceiling the contract says it reaches, so every term from attempt 32 on is wrong —
     * and a Java shift wide enough to express them wraps at 64, which would collapse the schedule back to
     * {@code initialBackoff}.
     */
    @Test
    void backoffKeepsDoublingPastTheThirtyFirstAttempt() {
        RetryPolicy policy = new RetryPolicy(Integer.MAX_VALUE, Duration.ofSeconds(1), DURATION_MAX);

        assertThat(policy.backoffFor(31)).isEqualTo(Duration.ofSeconds(1L << 30));
        assertThat(policy.backoffFor(32)).isEqualTo(Duration.ofSeconds(1L << 31));
        assertThat(policy.backoffFor(40)).isEqualTo(Duration.ofSeconds(1L << 39));
        assertThat(policy.backoffFor(63)).isEqualTo(Duration.ofSeconds(1L << 62));
    }

    /**
     * The step before the cap is where saturating arithmetic is hardest: at attempt 93 the term is {@code 2^92}
     * nanoseconds, the last one this ceiling admits, and doubling it once more overflows {@link Duration} itself. The
     * result has to be the ceiling, not an exception.
     */
    @Test
    @Timeout(value = 10, threadMode = ThreadMode.SEPARATE_THREAD)
    void backoffClimbsToADurationSizedCeilingWithoutOverflowingOnTheLastStep() {
        RetryPolicy policy = new RetryPolicy(Integer.MAX_VALUE, Duration.ofNanos(1), DURATION_MAX);
        Duration lastRepresentableTerm = Duration.ofNanos(1L << 62).multipliedBy(1L << 30);

        assertThat(policy.backoffFor(92)).isEqualTo(lastRepresentableTerm.dividedBy(2));
        assertThat(policy.backoffFor(93)).isEqualTo(lastRepresentableTerm);
        assertThat(policy.backoffFor(94))
                .as("2^93 ns exceeds both the ceiling and Duration")
                .isEqualTo(DURATION_MAX);
        assertThat(policy.backoffFor(Integer.MAX_VALUE)).isEqualTo(DURATION_MAX);
    }

    /**
     * The schedule is 1-based, and the one caller only ever passes an attempt of at least 1. Anything below that is
     * clamped to the first term rather than rejected or computed: {@code 1L << -1} is {@code 1L << 63}, which turns the
     * multiplier negative and yields a wait the retry loop would treat as no wait at all — or as an exception.
     */
    @Test
    void backoffForAnAttemptBelowOneIsTheFirstTermRatherThanANegativeWait() {
        RetryPolicy policy = new RetryPolicy(3, Duration.ofSeconds(1), Duration.ofSeconds(60));

        assertThat(policy.backoffFor(0)).isEqualTo(Duration.ofSeconds(1));
        assertThat(policy.backoffFor(-1)).isEqualTo(Duration.ofSeconds(1));
        assertThat(policy.backoffFor(Integer.MIN_VALUE))
                .as("attempt - 1 must not be allowed to wrap into a large positive shift")
                .isEqualTo(Duration.ofSeconds(1));
    }

    /** A ceiling below the initial backoff is a legal policy; it simply caps from the first attempt on. */
    @Test
    void aCeilingBelowTheInitialBackoffCapsFromTheFirstAttempt() {
        RetryPolicy policy = new RetryPolicy(5, Duration.ofSeconds(10), Duration.ofSeconds(1));

        assertThat(policy.backoffFor(1)).isEqualTo(Duration.ofSeconds(1));
        assertThat(policy.backoffFor(2)).isEqualTo(Duration.ofSeconds(1));
        assertThat(policy.backoffFor(64)).isEqualTo(Duration.ofSeconds(1));
    }

    /** The exact attempt the doubling crosses the ceiling: the term below it, the one that trips it, and after. */
    @Test
    void theCapTakesEffectAtTheAttemptTheDoublingCrossesIt() {
        RetryPolicy policy = new RetryPolicy(10, Duration.ofSeconds(1), Duration.ofSeconds(60));

        assertThat(policy.backoffFor(6)).isEqualTo(Duration.ofSeconds(32));
        assertThat(policy.backoffFor(7)).as("64s crosses the 60s ceiling").isEqualTo(Duration.ofSeconds(60));
        assertThat(policy.backoffFor(8)).isEqualTo(Duration.ofSeconds(60));
    }

    /** A term landing exactly on the ceiling is not capped early, and an odd ceiling is not rounded into one. */
    @Test
    void aTermLandingExactlyOnTheCeilingIsNotCappedEarly() {
        RetryPolicy exact = new RetryPolicy(10, Duration.ofSeconds(1), Duration.ofSeconds(8));
        assertThat(exact.backoffFor(4)).isEqualTo(Duration.ofSeconds(8));
        assertThat(exact.backoffFor(5)).isEqualTo(Duration.ofSeconds(8));

        RetryPolicy odd = new RetryPolicy(10, Duration.ofNanos(1), Duration.ofNanos(3));
        assertThat(odd.backoffFor(1)).isEqualTo(Duration.ofNanos(1));
        assertThat(odd.backoffFor(2)).isEqualTo(Duration.ofNanos(2));
        assertThat(odd.backoffFor(3)).as("4ns crosses the 3ns ceiling").isEqualTo(Duration.ofNanos(3));
    }

    /**
     * {@link RetryPolicy#none()} has a zero initial backoff and a zero ceiling. A backoff that grows by doubling never
     * leaves zero, so the answer is zero at every attempt — and the timeout is the point of the test: an implementation
     * that steps once per attempt would take an hour on the last one.
     */
    @Test
    @Timeout(value = 10, threadMode = ThreadMode.SEPARATE_THREAD)
    void aZeroBackoffStaysZeroAtEveryAttempt() {
        RetryPolicy none = RetryPolicy.none();

        assertThat(none.backoffFor(1)).isZero();
        assertThat(none.backoffFor(2)).isZero();
        assertThat(none.backoffFor(Integer.MAX_VALUE)).isZero();

        RetryPolicy zeroStartWithACeiling = new RetryPolicy(10, Duration.ZERO, Duration.ofSeconds(60));
        assertThat(zeroStartWithACeiling.backoffFor(Integer.MAX_VALUE)).isZero();
    }

    /**
     * The whole reachable input space, sampled around every power-of-two boundary a shift-based implementation could
     * trip over: the result stays inside {@code [ZERO, maxBackoff]} and never shrinks as the attempt grows. A
     * wrap-around, a collapse back to the first term or a negative wait all show up here as one of the two.
     */
    @Test
    @Timeout(10)
    void backoffIsBoundedAndNonDecreasingAtEveryReachableAttempt() {
        RetryPolicy policy = new RetryPolicy(Integer.MAX_VALUE, Duration.ofNanos(1), DURATION_MAX);
        int[] attempts = {
            Integer.MIN_VALUE,
            -1,
            0,
            1,
            2,
            30,
            31,
            32,
            33,
            62,
            63,
            64,
            65,
            91,
            92,
            93,
            94,
            95,
            1000,
            1_000_000,
            Integer.MAX_VALUE - 1,
            Integer.MAX_VALUE
        };

        Duration previous = Duration.ZERO;
        for (int attempt : attempts) {
            Duration backoff = policy.backoffFor(attempt);
            assertThat(backoff)
                    .as("attempt %d stays within the policy's bounds", attempt)
                    .isBetween(Duration.ZERO, DURATION_MAX);
            assertThat(backoff)
                    .as("attempt %d does not wait less than the attempt before it", attempt)
                    .isGreaterThanOrEqualTo(previous);
            previous = backoff;
        }
    }
}
