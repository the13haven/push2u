/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

/**
 * Thrown when a send is stopped because the thread carrying it was interrupted. Nothing failed: the caller asked to
 * stop. So the action is to let the cancellation propagate — clear nothing, repeat nothing, and page nobody, because an
 * alarm raised over a shutdown is an alarm about the shutdown.
 *
 * <p>It is a type of its own rather than the type of whichever seam happened to be blocked, so that a caller reads the
 * cancellation from the type instead of inferring it from a transport failure, a signing failure or a message. Where a
 * request may already have gone out, that is a fact about this send and not a verdict to act on: an interrupted send is
 * reported as an interruption, never as something worth trying again.
 *
 * <p><b>The promise differs between the two send methods, because an interrupt status cannot cross a
 * {@link java.util.concurrent.CompletableFuture}.</b> Both are stated rather than one being left to be discovered in a
 * {@code catch} block.
 *
 * <p><b>On a synchronous send</b>, the full promise: the interrupt status is re-set on the calling thread before this
 * exception is thrown, so a caller finds its own thread interrupted whether or not it ever looks at the cause chain,
 * and an {@link InterruptedException} is in that chain wherever one was raised. An interruption may also surface as a
 * {@link java.nio.channels.ClosedByInterruptException} or an {@link java.io.InterruptedIOException} with no
 * {@code InterruptedException} beneath it, which is why the flag is promised and the cause is promised only where one
 * exists.
 *
 * <p><b>On an asynchronous send</b>, the future completes exceptionally with this exception, and the interrupt status
 * on whatever thread reads that future is explicitly <b>not</b> promised — that thread was never interrupted, and
 * nobody can promise otherwise. What travels is the type and its cause chain, which is all a future can carry. The
 * interrupted worker re-sets its own flag before completing the future, which is owed to the executor and to whatever
 * that thread runs next, not to the caller.
 *
 * <p><b>The future completes exceptionally; it is not cancelled.</b> {@code isCancelled()} answers {@code false},
 * {@code join()} raises a {@link java.util.concurrent.CompletionException} wrapping this exception, and {@code get()}
 * an {@link java.util.concurrent.ExecutionException} with the same cause.
 *
 * <p><b>A {@link java.util.concurrent.CancellationException} is deliberately not used for this</b>, and the reason is
 * that the two events are not the same event. That type is the JDK's word for a result that cannot be retrieved because
 * the task was cancelled, and {@code CompletableFuture.cancel} is documented as having the same effect as completing
 * exceptionally with one — so borrowing it would deliver a caller's own {@code cancel} and a worker stopped mid-flight
 * into one {@code catch} clause, indistinguishable. They differ in what happened to the send: cancelling a future does
 * not interrupt the task running behind it, so a cancelled future leaves the send running, while a send that was
 * interrupted was cancelled by nobody's {@code cancel}. A caller that has to tell "I cancelled this" from "the sender
 * was stopped mid-flight" is exactly the caller this type exists for.
 *
 * <p>Unchecked, like every exception this library owns, and extending {@code RuntimeException} directly.
 */
public class PushInterruptedException extends RuntimeException {

    /**
     * Creates an exception reporting the interruption, where nothing was thrown to carry along.
     *
     * @param message the detail message, which must not contain a push endpoint verbatim — render one with
     *     {@link Endpoints#redact}
     */
    public PushInterruptedException(String message) {
        super(message);
    }

    /**
     * Creates an exception reporting the interruption, wrapping whatever was raised where the send was stopped — the
     * {@link InterruptedException} itself wherever one was raised, and otherwise the exception that carried the
     * interruption out of whichever seam was blocked.
     *
     * @param message the detail message, which must not contain a push endpoint verbatim — render one with
     *     {@link Endpoints#redact}
     * @param cause what was raised where the send was stopped
     */
    public PushInterruptedException(String message, Throwable cause) {
        super(message, cause);
    }
}
