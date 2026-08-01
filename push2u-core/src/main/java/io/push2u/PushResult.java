package io.push2u;

/**
 * The outcome of a send. A dead subscription is a normal result here, not an exception:
 * callers prune their store on {@link #isSubscriptionExpired()} without exception-driven
 * control flow.
 *
 * @param status     the interpreted outcome
 * @param statusCode the final HTTP status from the push service (0 if none was obtained)
 * @param attempts   how many POSTs were made, including retries (≥ 1)
 */
public record PushResult(Status status, int statusCode, int attempts) {

    /** The interpreted outcome category of a send. */
    public enum Status {
        /** 201 Created — the push service accepted the message. */
        DELIVERED,
        /** 404 / 410 — the subscription is gone; the caller should delete it. */
        SUBSCRIPTION_EXPIRED,
        /** A non-retryable rejection (4xx other than 404/410) or exhausted retries. */
        FAILED
    }

    /**
     * Whether the push service accepted the message ({@link Status#DELIVERED}).
     *
     * @return {@code true} if delivered
     */
    public boolean delivered() {
        return status == Status.DELIVERED;
    }

    /**
     * Whether the subscription is gone and the caller should delete it ({@link Status#SUBSCRIPTION_EXPIRED}).
     *
     * @return {@code true} if the subscription is expired
     */
    public boolean isSubscriptionExpired() {
        return status == Status.SUBSCRIPTION_EXPIRED;
    }
}
