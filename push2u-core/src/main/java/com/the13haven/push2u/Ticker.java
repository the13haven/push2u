/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

/**
 * Reads the monotonic clock — {@link System#nanoTime()} in production. Indirected behind an interface for the same
 * reason {@link Sleeper} is: the monotonic half of a cached VAPID token's life is judged in elapsed nanoseconds, and a
 * test that could not supply the readings would have to really wait out the spans it models — hours — or pass for the
 * wrong reason. The wall-clock half already has its seam in the sender's {@code Clock}.
 */
@FunctionalInterface
interface Ticker {

    /** The current monotonic reading, meaningful only as a difference between two readings on one JVM. */
    long nanoTime();

    /** The production ticker — the JVM's own monotonic clock. */
    Ticker REAL = System::nanoTime;
}
