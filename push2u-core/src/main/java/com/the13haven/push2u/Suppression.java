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
 *
 * <p>Recording mutates the consumer's exception, so the number of recordings one instance can take is bounded here.
 * Preallocating a single exception and throwing it repeatedly is an ordinary thing for a signer to do — a custodian
 * refusing every call while a breaker is open has no reason to build a new instance each time — and the accessors this
 * library guards against are the ones that break on every read. One such signer driving a fan-out over a subscription
 * store would otherwise grow one instance's suppressed list by one entry per send, without limit and for no gain: the
 * hundredth copy of the same diagnostic says nothing the first did not. Neither of the two exception types this is
 * called on can opt out of the accumulation either, since every constructor they offer reaches a superclass constructor
 * that leaves suppression enabled. So the first few recordings are kept and the rest are dropped, which costs a
 * diagnostic nothing and keeps a defective accessor from turning memory into the failure mode.
 */
final class Suppression {

    /**
     * How many suppressed entries an exception may carry before this class stops adding to it. Small on purpose: the
     * recordings made here come in at most a handful of distinct shapes for one failure, so a few of them carry every
     * distinct thing that can be said, and anything beyond that is the same sentence repeated by a defect that repeats.
     * Entries a consumer recorded itself count towards it, which is the conservative direction — an exception already
     * carrying that many diagnostics is not one this library has to add a further one to.
     */
    private static final int RECORDING_CEILING = 8;

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
     * <p>Nothing is recorded once {@code failure} already carries as many suppressed entries as this class allows. The
     * read of that count is safe for the same reason the recording is: {@code getSuppressed} is {@code final} on
     * {@code Throwable} too, so no consumer type can make it throw or lie.
     *
     * @param failure the primary failure, which stays what the caller receives
     * @param secondary the defect worth recording beside it
     */
    static void suppress(Throwable failure, Throwable secondary) {
        if (failure.getSuppressed().length >= RECORDING_CEILING) {
            return;
        }
        try {
            failure.addSuppressed(secondary);
        } catch (IllegalArgumentException selfSuppression) {
            // The failure was offered as its own suppressor, which only its own accessor throwing
            // it can produce. There is nothing to record and nothing to report: the caller is owed
            // the failure the read produced, not a complaint about the exception carrying it.
        }
    }
}
