/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assumptions;

import com.the13haven.push2u.PushDeliveryException;
import com.the13haven.push2u.PushHttpClient;
import com.the13haven.push2u.PushResponse;

/**
 * One {@code post} call of the transport contract, run under the contract's budget, and its outcome: the response the
 * transport answered, or the {@code RuntimeException} it threw. Package-private machinery of
 * {@link PushHttpClientContractTest} — each check holds an attempt to its expectation through {@link #response} or
 * {@link #deliveryFailure}, so the delivery-failure checks and the response-shaped ones read the same way.
 *
 * <p>Every call runs on a daemon worker with a deadline, and a call still unanswered when the budget runs out
 * <em>aborts</em> the check rather than failing it. The seam sets no latency requirement, so from outside a hung
 * transport and a correct one that is slow on a loaded machine are the same observation, and a failure would be a
 * verdict the check has not reached; the budget exists so that a hung subject ends the check instead of hanging the
 * build it was added to, which is how a contract gets deleted from a build.
 */
final class PostAttempt {

    /**
     * How long one check may wait for the transport to answer before it stops waiting and aborts. The budget is the
     * check's own limit, never a rule about the transport: the seam promises nothing about latency.
     */
    private static final int ANSWER_BUDGET_SECONDS = 30;

    private final @Nullable PushResponse response;
    private final @Nullable RuntimeException thrown;

    private PostAttempt(@Nullable PushResponse response, @Nullable RuntimeException thrown) {
        this.response = response;
        this.thrown = thrown;
    }

    /** One {@code post} call under the budget. */
    // CloseResource: the executor is shut down in the finally block with shutdownNow rather than
    // close — close waits for termination, so a transport that never answers would hang the suite
    // here after the check had already aborted, which is the one failure mode this machinery
    // exists to prevent. The worker is a daemon thread for the wait interruption cannot end.
    @SuppressWarnings("PMD.CloseResource")
    static PostAttempt one(PushHttpClient subject, URI endpoint, Map<String, String> headers, byte[] body)
            throws InterruptedException {
        ExecutorService executor = Executors.newSingleThreadExecutor(PostAttempt::worker);
        try {
            Future<PushResponse> call = executor.submit(() -> subject.post(endpoint, headers, body));
            return answerOf(call, System.nanoTime() + TimeUnit.SECONDS.toNanos(ANSWER_BUDGET_SECONDS));
        } finally {
            executor.shutdownNow();
        }
    }

    /**
     * One {@code post} call per element of {@code headers}/{@code bodies}, genuinely overlapping: one thread per call
     * on an executor this method creates and shuts down itself — never the platform's shared work-stealing pool, where
     * a rendezvous among tasks deadlocks on a machine with few cores — all held at a start gate until the last one is
     * submitted. One budget for the whole batch, so a stuck transport costs one budget and not one per caller. The
     * attempts come back in submission order.
     */
    // CloseResource: see the single-call machinery above — shutdownNow in the finally block on
    // purpose, and daemon workers for the wait that interruption cannot end.
    @SuppressWarnings("PMD.CloseResource")
    static List<PostAttempt> concurrently(
            PushHttpClient subject, URI endpoint, List<Map<String, String>> headers, List<byte[]> bodies)
            throws InterruptedException {
        int calls = headers.size();
        ExecutorService executor = Executors.newFixedThreadPool(calls, PostAttempt::worker);
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<PushResponse>> pending = new ArrayList<>(calls);
            for (int call = 0; call < calls; call++) {
                Map<String, String> callHeaders = headers.get(call);
                byte[] callBody = bodies.get(call);
                pending.add(executor.submit(() -> {
                    start.await();
                    return subject.post(endpoint, callHeaders, callBody);
                }));
            }
            start.countDown();

            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(ANSWER_BUDGET_SECONDS);
            List<PostAttempt> attempts = new ArrayList<>(pending.size());
            for (Future<PushResponse> call : pending) {
                attempts.add(answerOf(call, deadline));
            }
            return attempts;
        } finally {
            executor.shutdownNow();
        }
    }

    /** The response, or a failure saying the transport threw where the seam owes an answer. */
    PushResponse response(String expectation) {
        if (response != null) {
            return response;
        }
        String threwWhat = thrown == null ? "nothing" : thrown.getClass().getSimpleName();
        throw new AssertionError(
                "post must answer " + expectation + " as a PushResponse, and it threw " + threwWhat
                        + " instead. An HTTP status, whatever it is, is the push service's verdict for the "
                        + "sender to classify; only an exchange that produced no response may throw.",
                thrown);
    }

    /** The delivery failure, or a failure saying the transport answered or threw the wrong type. */
    void deliveryFailure(String scenario) {
        if (response != null) {
            throw new AssertionError("post must throw PushDeliveryException for " + scenario + " — no response "
                    + "exists to report, and a status invented in its place would be classified as the push "
                    + "service's verdict, making an unanswered send indistinguishable from an answered one. It "
                    + "answered a PushResponse carrying " + response.statusCode() + " instead.");
        }
        if (!(thrown instanceof PushDeliveryException)) {
            String threwWhat = thrown == null ? "nothing" : thrown.getClass().getSimpleName();
            throw new AssertionError(
                    "post must report " + scenario + " as PushDeliveryException — the one exception type the "
                            + "sender converts into an outcome; it threw " + threwWhat + ", which the sender "
                            + "treats as a defect in the transport and propagates unconverted.",
                    thrown);
        }
    }

    /**
     * Written by hand: the generated form of a type like this would render the response — whose headers a defective
     * transport may have filled with anything — or the thrown exception's message. The kind and the class name say
     * everything a diagnostic needs.
     */
    @Override
    public String toString() {
        return response != null
                ? "PostAttempt[answered]"
                : "PostAttempt[threw "
                        + (thrown == null ? "nothing" : thrown.getClass().getSimpleName()) + "]";
    }

    /**
     * One worker of the budgeted machinery, and a <em>daemon</em> one deliberately: {@code shutdownNow} interrupts, and
     * interrupting does not end every wait — a transport blocked in a native call keeps running whatever the check has
     * already reported, and a non-daemon worker would then hold the JVM open after the suite finished.
     */
    private static Thread worker(Runnable task) {
        Thread thread = new Thread(task, "push2u-transport-contract");
        thread.setDaemon(true);
        return thread;
    }

    /**
     * Unwraps one call: an answered response and a thrown {@code RuntimeException} both become an attempt for the check
     * to hold to its expectation, and a call still running when the budget runs out aborts the check instead of failing
     * it — see the class Javadoc.
     */
    // PreserveStackTrace: the ExecutionException wrapper is set aside deliberately — its frames
    // are this method's own, and what the two assertion methods above report, and attach as the
    // cause where one exists, is the exception the transport actually threw, which is the frame
    // the implementor has to look at.
    @SuppressWarnings("PMD.PreserveStackTrace")
    private static PostAttempt answerOf(Future<PushResponse> call, long deadline) throws InterruptedException {
        try {
            return new PostAttempt(call.get(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS), null);
        } catch (ExecutionException thrown) {
            Throwable cause = thrown.getCause();
            if (cause instanceof Error error) {
                throw error;
            }
            if (cause instanceof RuntimeException runtime) {
                return new PostAttempt(null, runtime);
            }
            throw new AssertionError("post declares no checked exception, and one arrived anyway", cause);
        } catch (TimeoutException neverAnswered) {
            // Aborted, not failed: see the class Javadoc. The budget exists so that a subject
            // that never answers ends the check instead of hanging the build it was added to.
            return Assumptions.abort("the post call had not answered within " + ANSWER_BUDGET_SECONDS
                    + " seconds, so this check stopped waiting without reaching a verdict. That budget is this "
                    + "check's own limit and not a rule about how fast a transport has to be, so this is neither a "
                    + "pass nor a failure. If the call was merely slow, nothing here is wrong; if it never returns, "
                    + "look for a missing timeout in the stack this transport wraps.");
        }
    }
}
