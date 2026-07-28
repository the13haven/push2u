package io.push2u;

import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;

/**
 * An immutable push message: the payload plus the optional RFC 8030 delivery headers
 * ({@code TTL}, {@code Urgency}, {@code Topic}). The payload is encrypted (RFC 8291) before
 * transport; the headers travel in clear and are applied by the send pipeline.
 *
 * <p>A record — a pure value with no identity. Unset headers are {@code null} (a record
 * accessor must return its component type, so {@code ttl()}/{@code urgency()}/{@code topic()}
 * are nullable rather than {@code Optional}). Build it with the {@link Builder} for the common
 * "payload plus a header or two" shape, with {@link #of} for a payload alone, or via the
 * canonical constructor. {@code equals}/{@code hashCode}/{@code toString} are overridden so the
 * {@code byte[]} payload compares by content (and {@code toString} logs its size, not its bytes).
 *
 * @param payload the cleartext message body (encrypted before transport)
 * @param ttl     how long the push service retains the message if undelivered, or {@code null} for the sender default
 * @param urgency the delivery urgency (RFC 8030 §5.3), or {@code null} to leave it unset
 * @param topic   collapses an earlier undelivered message of the same topic, or {@code null}
 */
public record PushMessage(byte[] payload, Duration ttl, Urgency urgency, String topic) {

    /** Validates the TTL (non-negative if present) and defensively copies the payload. */
    public PushMessage {
        Objects.requireNonNull(payload, "payload");
        if (ttl != null && ttl.isNegative()) {
            throw new IllegalArgumentException("ttl must not be negative");
        }
        payload = payload.clone();
    }

    /**
     * A message carrying only a payload — no {@code TTL}/{@code Urgency}/{@code Topic} headers.
     *
     * @param payload the message payload
     * @return the message
     */
    public static PushMessage of(byte[] payload) {
        return new PushMessage(payload, null, null, null);
    }

    /**
     * A {@link Builder} seeded with the payload, for adding optional headers.
     *
     * @param payload the message payload
     * @return a new builder
     */
    public static Builder builder(byte[] payload) {
        return new Builder(payload);
    }

    /**
     * Returns a defensive copy of the payload.
     *
     * @return a copy of the payload
     */
    @Override
    public byte[] payload() {
        return payload.clone();
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        return other instanceof PushMessage(var otherPayload, var otherTtl, var otherUrgency, var otherTopic)
            && Arrays.equals(payload, otherPayload)
            && Objects.equals(ttl, otherTtl)
            && urgency == otherUrgency
            && Objects.equals(topic, otherTopic);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(payload), ttl, urgency, topic);
    }

    @Override
    public String toString() {
        // payload may carry user content — log its size, not its bytes.
        return "PushMessage[payload=" + payload.length + " bytes, ttl=" + ttl
            + ", urgency=" + urgency + ", topic=" + topic + "]";
    }

    /** Fluent builder over the optional headers; a single {@link PushMessage} is built at {@link #build()}. */
    public static final class Builder {

        private final byte[] payload;
        private Duration ttl;
        private Urgency urgency;
        private String topic;

        private Builder(byte[] payload) {
            this.payload = Objects.requireNonNull(payload, "payload");
        }

        /**
         * Sets the {@code TTL} (retention); must be non-negative. {@code null} leaves it to the sender default.
         *
         * @param ttl the retention duration, or {@code null}
         * @return this builder
         */
        public Builder ttl(Duration ttl) {
            this.ttl = ttl;
            return this;
        }

        /**
         * Sets the {@code Urgency} header; {@code null} leaves it unset.
         *
         * @param urgency the urgency, or {@code null}
         * @return this builder
         */
        public Builder urgency(Urgency urgency) {
            this.urgency = urgency;
            return this;
        }

        /**
         * Sets the {@code Topic} header; {@code null} leaves it unset.
         *
         * @param topic the topic, or {@code null}
         * @return this builder
         */
        public Builder topic(String topic) {
            this.topic = topic;
            return this;
        }

        /**
         * Builds the immutable {@link PushMessage}.
         *
         * @return the message
         */
        public PushMessage build() {
            return new PushMessage(payload, ttl, urgency, topic);
        }
    }
}
