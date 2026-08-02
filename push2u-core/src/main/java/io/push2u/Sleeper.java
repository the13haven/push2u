package io.push2u;

import java.time.Duration;

/**
 * Pauses between retry attempts. Indirected behind an interface so a test can drive the {@link PushSender} retry loop
 * deterministically, without real wall-clock delays.
 */
@FunctionalInterface
interface Sleeper {

    void sleep(Duration duration);

    /** The production sleeper — {@link Thread#sleep}, translating interruption into a delivery failure. */
    Sleeper REAL = duration -> {
        try {
            Thread.sleep(duration);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new PushDeliveryException("Interrupted during retry backoff", e);
        }
    };
}
