/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

/**
 * The answer to {@link PushSender#assessPayloadSize(byte[])}: whether a serialized payload fits the sender's
 * configuration, asked <em>before</em> a send so an application that renders a notification can shorten it rather than
 * discover the limit by outcome. The concrete case is translation — the same notification fits in one language and not
 * in another, and which one overflows is otherwise discovered in production.
 *
 * <p>This type is deliberately the only way to the budget: the sender publishes no bare numeric maximum, so the first
 * question about a payload is always answered by the library, over the serialized octets themselves. A hand-written
 * comparison such as {@code notificationString.length() <= maximum} compiles, reads correctly, and compares UTF-16 code
 * units against octets — any non-ASCII notification then passes a check it should have failed, and nothing downstream
 * can detect that. {@link ExceedsLimit#maximumPayloadBytes()} is published for the render that follows a refusal, which
 * is the moment the number is needed and the moment its unit has just been demonstrated.
 *
 * <p>An assessment is a question, not a send, and it replaces nothing: {@link PushSender#send} checks the payload again
 * and reports an oversized one as {@link PushOutcome.PayloadRejected}, carrying the same two numbers in the same unit.
 * Asking is optional; being told is not.
 */
public sealed interface PayloadSizeAssessment {

    /**
     * The payload fits this sender's configuration; the action is to send it. Deliberately no components: a payload
     * that fits needs no number to act on, and a record component added later would change the canonical constructor
     * and every pattern match — a breaking change, unlike the compatible addition of a method — so the empty shape is a
     * commitment rather than an omission. Not a singleton: the canonical constructor is public, all instances are
     * equal, and nothing distinguishes one from another.
     */
    record WithinLimit() implements PayloadSizeAssessment {}

    /**
     * The payload does not fit this sender's configuration. The action is to render the notification smaller — against
     * {@code maximumPayloadBytes}, serialize, and ask again: the relation between source text and serialized octets is
     * non-linear under JSON and UTF-8, so shortening by the difference of the two numbers is not a shortcut this type
     * suggests, and the difference itself is a subtraction the caller can perform where a log line wants it.
     *
     * <p>Both numbers are plaintext octets — the unit the caller can act in, and the same pair, in the same unit, that
     * {@link PushOutcome.PayloadRejected} reports when a send is refused for size.
     *
     * @param payloadBytes the serialized payload the caller handed over, in octets
     * @param maximumPayloadBytes the largest payload this sender's configuration carries, in octets — the budget for
     *     the next render
     */
    record ExceedsLimit(int payloadBytes, int maximumPayloadBytes) implements PayloadSizeAssessment {

        /**
         * Enforces what the name asserts: neither number is negative, which no payload and no configuration can have
         * produced, and the payload is strictly greater than the maximum — a variant that says a payload exceeds a
         * limit may not be constructed to say the opposite.
         *
         * @param payloadBytes the serialized payload the caller handed over, in octets
         * @param maximumPayloadBytes the largest payload this sender's configuration carries, in octets
         * @throws IllegalArgumentException if either size is negative, or if {@code payloadBytes} does not exceed
         *     {@code maximumPayloadBytes}
         */
        public ExceedsLimit {
            if (payloadBytes < 0) {
                throw new IllegalArgumentException("payloadBytes must not be negative, was " + payloadBytes);
            }
            if (maximumPayloadBytes < 0) {
                throw new IllegalArgumentException(
                        "maximumPayloadBytes must not be negative, was " + maximumPayloadBytes);
            }
            if (payloadBytes <= maximumPayloadBytes) {
                throw new IllegalArgumentException("ExceedsLimit asserts that the payload exceeds the maximum, so"
                        + " payloadBytes (" + payloadBytes + ") must be strictly greater than maximumPayloadBytes ("
                        + maximumPayloadBytes + ")");
            }
        }
    }
}
