/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.util.Objects;

/**
 * The outcome of a send. A dead subscription is a normal result here, not an exception: callers prune their store on
 * {@link #isSubscriptionExpired()} without exception-driven control flow.
 *
 * <p>The record is public and so is its canonical constructor — callers construct one in tests and fakes — so the
 * contract the fields document is enforced rather than merely stated: a {@code null} status, a negative status code or
 * an attempt count below one would each describe a send that cannot have happened.
 *
 * @param status the interpreted outcome; never {@code null}
 * @param statusCode the final HTTP status from the push service (0 if none was obtained); never negative
 * @param attempts how many POSTs were made, including retries (≥ 1)
 */
public record PushResult(Status status, int statusCode, int attempts) {

    /**
     * Validates the field contract documented on the record; see there for why it is enforced.
     *
     * @throws NullPointerException if {@code status} is {@code null}
     * @throws IllegalArgumentException if {@code statusCode} is negative or {@code attempts} is below 1
     */
    public PushResult {
        Objects.requireNonNull(status, "status");
        if (statusCode < 0) {
            throw new IllegalArgumentException(
                    "statusCode must not be negative (0 means none was obtained), was " + statusCode);
        }
        if (attempts < 1) {
            throw new IllegalArgumentException(
                    "attempts must be at least 1 — a result exists only after a POST, was " + attempts);
        }
    }

    /** The interpreted outcome category of a send. */
    public enum Status {
        /**
         * A 2xx — the push service accepted the message. RFC 8030 §5 has a push service answer a successful send with
         * {@code 201 Created}, and that is what the major services return, but the whole 2xx class is accepted: the
         * RFC's own retry advice keys off 4xx/5xx, and a service answering {@code 200} or {@code 202} has accepted the
         * message just the same. The precise code is in {@link PushResult#statusCode()} for a caller that needs to tell
         * them apart.
         */
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
    public boolean isDelivered() {
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
