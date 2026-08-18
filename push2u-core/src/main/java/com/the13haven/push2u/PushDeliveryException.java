/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.io.Serial;

/**
 * Thrown by a {@link PushHttpClient} whose exchange produced no response — a connection failure, a timeout, an
 * interrupted send. A push service <em>answering</em>, whatever the status, is never this: an HTTP status is a
 * {@link PushOutcome} for the sender to classify. This type is the transport seam's vocabulary rather than anything
 * {@link PushSender#send} reports: the facade recognises exactly this type as the unanswered exchange and reports the
 * send as {@link PushOutcome.Indeterminate} — whether the push service received the message is unknown — while any
 * other {@code RuntimeException} out of a transport is a defect in that implementation and propagates unchanged.
 *
 * <p><b>The interrupted send in that list is what a transport signals, not what a caller reads.</b> A
 * {@link PushHttpClient} reports an interruption this way like any other exchange that produced no response, and its
 * contract is deliberately left that way so that no transport has to recognise a cancellation; what a caller receives
 * for one is {@link PushInterruptedException}, which promises the interrupt status and the cause chain this type
 * promises nothing about. So an implementation of the transport seam reads this sentence as its own, and an application
 * catching a cancellation reads the other type.
 *
 * <p><b>{@link #getCause()} must not throw.</b> It is the one member {@link PushSender#send} reads while converting
 * this exception — walking the cause chain for the interruption test — and the contract names that single method
 * deliberately, asking nothing of accessors the library never reads. A subclass whose {@code getCause()} throws a
 * {@code RuntimeException} does not cost the caller the classification: the walk stops, the defect is recorded on this
 * exception as a suppressed one, and the send stays {@link PushOutcome.Indeterminate} unless the thread's interrupt
 * status says otherwise — but an {@link InterruptedException} sitting beyond the break can then no longer be seen.
 */
public class PushDeliveryException extends RuntimeException {

    // Declared rather than computed. A computed identifier is derived from every non-private
    // constructor and method as well as from the fields, so adding either would move it and make an
    // instance already written to a stream unreadable after an otherwise compatible release.
    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * Creates an exception describing the delivery failure.
     *
     * @param message the detail message
     */
    public PushDeliveryException(String message) {
        super(message);
    }

    /**
     * Creates an exception describing the delivery failure, wrapping the underlying cause.
     *
     * @param message the detail message
     * @param cause the underlying cause
     */
    public PushDeliveryException(String message, Throwable cause) {
        super(message, cause);
    }
}
