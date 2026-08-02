package io.push2u;

/**
 * Thrown when a push message cannot be delivered for a transport-level reason that is not a normal HTTP outcome — a
 * connection failure, a timeout, an interrupted send. A push service <em>rejecting</em> the message (4xx) or reporting
 * a dead subscription (404/410) is NOT this: those are normal {@link PushResult}s. Exceptions are reserved for the
 * genuine I/O errors a caller cannot interpret as a push-service verdict.
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
