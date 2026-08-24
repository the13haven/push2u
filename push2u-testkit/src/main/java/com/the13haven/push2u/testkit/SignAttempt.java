/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assumptions;

import com.the13haven.push2u.VapidSigner;
import com.the13haven.push2u.VapidSignerUnavailableException;

/**
 * One {@code sign} call of the signer contract's concurrency check, run under that check's budget, and its outcome: the
 * signature the signer produced, or nothing where the key custodian answered that it cannot sign now. Package-private
 * machinery of {@link VapidSignerContractTest}, never published surface.
 *
 * <p>Two answers are distinguished here and only two, because only two mean anything to the check. A signature is
 * evidence, and the check verifies it against the input its own call handed in. A
 * {@link VapidSignerUnavailableException} is the absence of evidence: a custodian rate-limiting a burst is exactly what
 * that type is for, a burst of concurrent calls is what provokes it, and a call that never signed says nothing about
 * whether the signer weaves state between callers. Everything else thrown is reported as a failure of the check: the
 * contract's other checks sign one call at a time and require that to succeed, so a signer that only fails when several
 * threads are inside it has failed at concurrency and not at signing — and which type it was is left out of the report,
 * this contract asserting no exception types anywhere.
 *
 * <p>Every call runs on a daemon worker, and a call still unanswered when the budget runs out <em>aborts</em> the check
 * rather than failing it. The seam sets no latency requirement, so from outside a signer stuck on a lock and a correct
 * one waiting on a slow custodian are the same observation, and a failure would be a verdict the check has not reached;
 * the budget exists so that a stuck subject ends the check instead of hanging the build it was added to, which is how a
 * contract gets deleted from a build.
 *
 * <p>The budget arrives as an argument, in seconds, and this class holds none of its own: it is the contract instance
 * that owns the number, and it is seconds rather than a computed deadline because the deadline covers the whole batch —
 * a stuck signer costs the check one budget and not one per thread — and because the seconds are what the abort message
 * has to report.
 */
final class SignAttempt {

    private final byte @Nullable [] signature;

    private SignAttempt(byte @Nullable [] signature) {
        this.signature = signature;
    }

    /**
     * One {@code sign} call per element of {@code inputs}, genuinely overlapping: one thread per call on an executor
     * this method creates and shuts down itself — never the platform's shared work-stealing pool, where a rendezvous
     * among tasks deadlocks on a machine with few cores — all held at a start gate until the last one is submitted. One
     * budget for the whole batch. The attempts come back in submission order.
     *
     * @param signer the signer under test
     * @param inputs the signing input of each call, one element per caller and no two alike
     * @param budgetSeconds how long the batch as a whole may go unanswered before the check aborts
     * @return one attempt per caller, in submission order
     * @throws InterruptedException if the check's own thread is interrupted while waiting
     */
    // CloseResource: the executor is shut down in the finally block with shutdownNow rather than
    // close — close waits for termination, so a signer that never answers would hang the suite here
    // after the check had already aborted, which is the one failure mode this machinery exists to
    // prevent. The workers are daemon threads for the wait that interruption cannot end.
    @SuppressWarnings("PMD.CloseResource")
    static List<SignAttempt> concurrently(VapidSigner signer, List<byte[]> inputs, int budgetSeconds)
            throws InterruptedException {
        ExecutorService executor = Executors.newFixedThreadPool(inputs.size(), SignAttempt::worker);
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<SignAttempt>> pending = new ArrayList<>(inputs.size());
            for (byte[] input : inputs) {
                pending.add(executor.submit(() -> {
                    start.await();
                    return of(signer, input);
                }));
            }
            start.countDown();

            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(budgetSeconds);
            List<SignAttempt> attempts = new ArrayList<>(pending.size());
            for (Future<SignAttempt> call : pending) {
                attempts.add(answerOf(call, deadline, budgetSeconds));
            }
            return attempts;
        } finally {
            executor.shutdownNow();
        }
    }

    /**
     * What this call produced.
     *
     * @return the signature, or empty where the custodian answered that it cannot sign now
     */
    Optional<byte[]> signature() {
        return Optional.ofNullable(signature);
    }

    /** One call, with the custodian's own "not now" set apart from every other way of failing. */
    private static SignAttempt of(VapidSigner signer, byte[] input) {
        try {
            return new SignAttempt(signer.sign(input));
        } catch (VapidSignerUnavailableException custodianCannotSignNow) {
            return new SignAttempt(null);
        }
    }

    /**
     * One worker of the concurrency check, and a <em>daemon</em> one deliberately.
     *
     * <p>{@code shutdownNow} interrupts, and interrupting does not end every wait — a thread blocked entering a monitor
     * or inside a native call keeps running whatever the check has already reported. Non-daemon workers would then hold
     * the JVM open after the suite finished, moving the hang from the check to the exit rather than removing it. A
     * daemon thread cannot do that.
     */
    private static Thread worker(Runnable task) {
        Thread thread = new Thread(task, "push2u-vapid-signer-contract");
        thread.setDaemon(true);
        return thread;
    }

    /**
     * Unwraps one call: anything thrown other than the custodian's own unavailability becomes a readable failure, and a
     * call still running when the budget runs out aborts the check instead of failing it. The deadline belongs to the
     * whole batch rather than to this call.
     */
    // PreserveStackTrace: the cause is what the signer actually threw, and it is carried over
    // deliberately in place of the ExecutionException wrapping it — the wrapper's own frames are
    // this method's, and reporting them would bury the frame the implementor has to look at.
    @SuppressWarnings("PMD.PreserveStackTrace")
    private static SignAttempt answerOf(Future<SignAttempt> call, long deadline, int budgetSeconds)
            throws InterruptedException {
        try {
            return call.get(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
        } catch (ExecutionException thrown) {
            throw new AssertionError(
                    "concurrent sign calls failed where the contract's one-call-at-a-time checks pass. Signing from "
                            + "several threads at once is the ordinary case — one sender is shared, and async sends "
                            + "sign in parallel — so a signer keeping state across calls has to guard it. What kind "
                            + "of failure this was is not this contract's judgement to make: it asserts no exception "
                            + "types, and the one answer it does read, the custodian saying it cannot sign now, is "
                            + "counted separately and never brought here.",
                    thrown.getCause());
        } catch (TimeoutException neverAnswered) {
            // Aborted, not failed. The seam sets no latency requirement, so a call still running
            // after the budget may be a custodian that never answers or a correct signer being slow
            // — a cold connection, a loaded machine — and this check cannot tell those apart.
            // Reporting a failure would state a verdict it has not reached; reporting an abort
            // states the truth, that the check did not conclude. The budget exists so that the
            // first case ends the check instead of hanging the suite.
            return Assumptions.abort("the concurrent sign calls had not all answered within " + budgetSeconds
                    + " seconds, so this check stopped waiting without reaching a verdict. That budget is the "
                    + "check's own limit and not a rule about how fast a signer has to answer, so this is neither a "
                    + "pass nor a thread-safety failure. If the calls were merely slow, nothing here is wrong; if one "
                    + "of them never returns, look for a lock held across a call to the custodian.");
        }
    }
}
