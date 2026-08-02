package io.push2u;

import java.time.Duration;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;

/**
 * An immutable push message: the payload plus the optional RFC 8030 delivery headers ({@code TTL}, {@code Urgency},
 * {@code Topic}). The payload is encrypted (RFC 8291) before transport; the headers travel in clear and are applied by
 * the send pipeline.
 *
 * <p>A record — a pure value with no identity. Unset headers are {@code null} (a record accessor must return its
 * component type, so {@code ttl()}/{@code urgency()}/{@code topic()} are nullable rather than {@code Optional}). Build
 * it with the {@link Builder} for the common "payload plus a header or two" shape, with {@link #of} for a payload
 * alone, or via the canonical constructor. {@code equals}/{@code hashCode}/{@code toString} are overridden so the
 * {@code byte[]} payload compares by content (and {@code toString} logs its size, not its bytes).
 *
 * @param payload the cleartext message body (encrypted before transport)
 * @param ttl how long the push service retains the message if undelivered, or {@code null} for the sender default
 * @param urgency the delivery urgency (RFC 8030 §5.3), or {@code null} to leave it unset
 * @param topic collapses an earlier undelivered message of the same topic, or {@code null}; per RFC 8030 §5.4 1 to 32
 *     characters from the URL-safe Base64 alphabet ({@code A-Z a-z 0-9 - _}) — the lower bound is the {@code Topic =
 *     token} grammar, a token being at least one character
 */
// ArrayRecordComponent: same rationale as Subscription — the payload is bytes by definition, and
// the constructor, the accessor and equals/hashCode all treat the array by value.
@SuppressWarnings("ArrayRecordComponent")
public record PushMessage(byte[] payload, Duration ttl, Urgency urgency, String topic) {

    private static final int TOPIC_MAX_LENGTH = 32;

    /** How much of a rejected topic the exception message echoes back. */
    private static final int TOPIC_ECHO_LIMIT = 40;

    /**
     * Validates the TTL (non-negative if present) and the topic (RFC 8030 §5.4 shape if present), and defensively
     * copies the payload.
     */
    public PushMessage {
        Objects.requireNonNull(payload, "payload");
        if (ttl != null && ttl.isNegative()) {
            throw new IllegalArgumentException("ttl must not be negative");
        }
        validateTopic(topic);
        payload = payload.clone();
    }

    /**
     * RFC 8030 §5.4: a topic is 1 to 32 characters from the URL and filename-safe Base64 alphabet (RFC 4648 §5); the
     * lower bound of 1 is the {@code Topic = token} grammar rather than a house rule. Enforced locally rather than
     * waiting for a remote HTTP 400 — and because a third-party {@code PushHttpClient} may not reject header values
     * containing CR/LF the way the JDK client does.
     */
    private static void validateTopic(String topic) {
        if (topic == null) {
            return;
        }
        if (topic.isEmpty() || topic.length() > TOPIC_MAX_LENGTH || !isUrlSafeBase64Alphabet(topic)) {
            throw new IllegalArgumentException(
                    "topic must be 1-" + TOPIC_MAX_LENGTH + " characters from the URL-safe Base64 alphabet"
                            + " (A-Z a-z 0-9 - _), got " + topic.length() + " characters: \""
                            + renderForMessage(topic) + "\"");
        }
    }

    /**
     * The rejected topic, rendered safe to log: characters outside printable US-ASCII escaped, and the whole thing
     * truncated. A topic is developer-supplied and not secret, so echoing it keeps the diagnostic value — but echoing
     * it <em>raw</em> would move a CR/LF injection out of the HTTP header and into the log file, and an oversized topic
     * would be retained whole on the throwable. The caller states the real length separately.
     */
    private static String renderForMessage(String topic) {
        int shown = Math.min(topic.length(), TOPIC_ECHO_LIMIT);
        StringBuilder rendered = new StringBuilder(shown);
        for (int i = 0; i < shown; i++) {
            char c = topic.charAt(i);
            if (c == '\\') {
                rendered.append("\\\\");
            } else if (c >= 0x20 && c < 0x7f) {
                rendered.append(c);
            } else {
                rendered.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
            }
        }
        if (topic.length() > shown) {
            rendered.append("...");
        }
        return rendered.toString();
    }

    private static boolean isUrlSafeBase64Alphabet(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean allowed =
                    (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!allowed) {
                return false;
            }
        }
        return true;
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
        return "PushMessage[payload=" + payload.length + " bytes, ttl=" + ttl + ", urgency=" + urgency + ", topic="
                + topic + "]";
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
         * Sets the {@code Topic} header; {@code null} leaves it unset. A non-null topic must be 1 to 32 characters from
         * the URL-safe Base64 alphabet (RFC 8030 §5.4); validated at {@link #build()}.
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
