/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The production {@link Sleeper} — the one the retry loop uses when nobody substituted a fake.
 *
 * <p>The interesting half is interruption. A thread parked in a retry backoff is a thread an application server is
 * entitled to interrupt during shutdown, and {@code Thread.sleep} answers that by throwing and <em>clearing</em> the
 * interrupt flag. Swallowing the exception would leave the caller sleeping through a shutdown; forgetting to restore
 * the flag would hide the interruption from every layer above.
 */
class SleeperTest {

    @Test
    @Timeout(10)
    void theRealSleeperActuallyWaits() {
        long before = System.nanoTime();

        Sleeper.REAL.sleep(Duration.ofMillis(20));

        assertThat(Duration.ofNanos(System.nanoTime() - before))
                .as("a backoff that returns immediately is not a backoff")
                .isGreaterThanOrEqualTo(Duration.ofMillis(20));
    }

    @Test
    @Timeout(30)
    void interruptionBecomesADeliveryFailureWithTheFlagRestored() throws InterruptedException {
        AtomicReference<Throwable> thrown = new AtomicReference<>();
        AtomicBoolean flagStillSet = new AtomicBoolean();

        Thread worker = new Thread(() -> {
            try {
                Sleeper.REAL.sleep(Duration.ofMinutes(5));
            } catch (RuntimeException e) {
                thrown.set(e);
                flagStillSet.set(Thread.currentThread().isInterrupted());
            }
        });
        worker.start();
        while (worker.getState() != Thread.State.TIMED_WAITING) {
            Thread.onSpinWait();
        }

        worker.interrupt();
        worker.join(Duration.ofSeconds(20).toMillis());

        assertThat(thrown.get())
                .isInstanceOf(PushDeliveryException.class)
                .hasMessageContaining("Interrupted")
                .hasCauseInstanceOf(InterruptedException.class);
        assertThat(flagStillSet)
                .as("Thread.sleep clears the flag; the sleeper has to put it back")
                .isTrue();
    }

    @Test
    void aZeroDurationIsNotAnError() {
        Sleeper.REAL.sleep(Duration.ZERO);
    }

    /**
     * A negative backoff is not an error but a no-op — {@code Thread.sleep(Duration)} clamps it. Worth pinning rather
     * than assuming: a backoff computed from a {@code Retry-After} date already in the past is negative, and the retry
     * loop wants that to mean "retry now", not "throw during a retry".
     */
    @Test
    @Timeout(10)
    void aNegativeDurationReturnsImmediatelyInsteadOfThrowing() {
        long before = System.nanoTime();

        Sleeper.REAL.sleep(Duration.ofSeconds(-5));

        assertThat(Duration.ofNanos(System.nanoTime() - before)).isLessThan(Duration.ofSeconds(1));
    }
}
