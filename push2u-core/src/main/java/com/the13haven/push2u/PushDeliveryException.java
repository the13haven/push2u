/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

/**
 * Thrown when a push message cannot be delivered for a transport-level reason that is not a normal HTTP outcome — a
 * connection failure, a timeout, an interrupted send. A push service <em>rejecting</em> the message (4xx) or reporting
 * a dead subscription (404/410) is NOT this: those are normal {@link PushResult}s. Exceptions are reserved for the
 * genuine I/O errors a caller cannot interpret as a push-service verdict.
 *
 * <p><b>The interrupted send in that list is what a transport signals, not what a caller reads.</b> A
 * {@link PushHttpClient} reports an interruption this way like any other exchange that produced no response, and its
 * contract is deliberately left that way so that no transport has to recognise a cancellation; what a caller receives
 * for one is {@link PushInterruptedException}, which promises the interrupt status and the cause chain this type
 * promises nothing about. So an implementation of the transport seam reads this sentence as its own, and an application
 * catching a cancellation reads the other type.
 */
public class PushDeliveryException extends RuntimeException {

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
