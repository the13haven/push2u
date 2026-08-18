/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

/**
 * Records a secondary failure on a primary one as a suppressed exception, without letting the recording displace the
 * primary. Two places convert a seam's exception into a {@link PushOutcome} by reading members a consumer's subclass
 * can override — the {@link PushOutcome.SignerUnavailable} constructor and {@link PushSender}'s interruption test — and
 * both owe the caller the seam's own failure, never a complaint about how its diagnostics were written. The recording
 * form lives once, in a class of its own, because neither of those two is a natural home for the other's need and a
 * second copy of this logic is a second chance to get the one reachable refusal wrong.
 */
final class Suppression {

    private Suppression() {}

    /**
     * Records {@code secondary} on {@code failure} without letting the recording displace it. Exactly one refusal is
     * reachable here, and it is caught: {@code addSuppressed} rejects an exception offered as its own suppressor, which
     * is what an accessor that threw the failure itself hands it. The set is closed rather than assumed — the method is
     * {@code final} on {@code Throwable}, so no consumer type can make it refuse for reasons of its own, and its one
     * other refusal is a {@code null} argument, which no caller here can produce (an exception built with suppression
     * disabled ignores the call silently rather than refusing it). Anything else out of that call is the machine and
     * not the diagnostics, so it is left to leave.
     *
     * @param failure the primary failure, which stays what the caller receives
     * @param secondary the defect worth recording beside it
     */
    static void suppress(Throwable failure, Throwable secondary) {
        try {
            failure.addSuppressed(secondary);
        } catch (IllegalArgumentException selfSuppression) {
            // The failure was offered as its own suppressor, which only its own accessor throwing
            // it can produce. There is nothing to record and nothing to report: the caller is owed
            // the failure the read produced, not a complaint about the exception carrying it.
        }
    }
}
