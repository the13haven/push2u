package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

import org.junit.jupiter.api.Test;

/**
 * {@code Topic} is caller-supplied and, when it is rejected, quoted back in the exception message. That message goes to
 * a log, so the value has to be rendered rather than pasted: a topic carrying a newline could otherwise forge a log
 * line, and one carrying a terminal escape could rewrite what an operator sees.
 *
 * <p>Also covers value equality, which matters because {@link PushMessage} holds a mutable byte array and copies it.
 */
class PushMessageTopicTest {

    /** A raw control character in a literal is invisible in a diff and in review; name it instead. */
    private static final char BELL = 0x07;

    private static final byte[] PAYLOAD = "hello".getBytes(StandardCharsets.UTF_8);

    @Test
    void aTopicOutsideTheUrlSafeAlphabetIsRejected() {
        assertThatThrownBy(() ->
                        PushMessage.builder(PAYLOAD).topic("not+base64/url").build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aRejectedTopicIsEchoedWithControlCharactersEscaped() {
        assertThatThrownBy(
                        () -> PushMessage.builder(PAYLOAD).topic("a\nb" + BELL).build())
                .isInstanceOf(IllegalArgumentException.class)
                .satisfies(thrown -> assertThat(thrown.getMessage())
                        .as("a topic must not be able to forge a log line")
                        .doesNotContain("\n")
                        .contains("\\u000a")
                        .contains("\\u0007"));
    }

    @Test
    void aRejectedTopicHasItsBackslashesDoubledSoTheEscapesAreUnambiguous() {
        assertThatThrownBy(() -> PushMessage.builder(PAYLOAD).topic("a\\u0041b").build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("a\\\\u0041b");
    }

    @Test
    void anOverlongRejectedTopicIsTruncatedRatherThanEchoedInFull() {
        String huge = "A".repeat(4096) + "!";

        assertThatThrownBy(() -> PushMessage.builder(PAYLOAD).topic(huge).build())
                .isInstanceOf(IllegalArgumentException.class)
                .satisfies(thrown -> {
                    assertThat(thrown.getMessage()).contains("...");
                    assertThat(thrown.getMessage().length())
                            .as("the whole topic is not pasted into the message")
                            .isLessThan(huge.length());
                });
    }

    @Test
    void aValidTopicSurvivesUnchanged() {
        PushMessage message = PushMessage.builder(PAYLOAD).topic("abc-DEF_123").build();

        assertThat(message.topic()).isEqualTo("abc-DEF_123");
    }

    // ---- value semantics ------------------------------------------------------------------------

    @Test
    void equalityIsByValueAcrossEveryComponent() {
        PushMessage base = PushMessage.builder(PAYLOAD)
                .ttl(Duration.ofHours(1))
                .urgency(Urgency.HIGH)
                .topic("topic")
                .build();
        PushMessage same = PushMessage.builder("hello".getBytes(StandardCharsets.UTF_8))
                .ttl(Duration.ofHours(1))
                .urgency(Urgency.HIGH)
                .topic("topic")
                .build();

        assertThat(base.equals(base)).as("equals is reflexive").isTrue();
        assertThat(base).isEqualTo(same).hasSameHashCodeAs(same);
        assertThat(base).isNotEqualTo(null).isNotEqualTo("not a message");

        assertThat(base)
                .isNotEqualTo(PushMessage.builder("other".getBytes(StandardCharsets.UTF_8))
                        .ttl(Duration.ofHours(1))
                        .urgency(Urgency.HIGH)
                        .topic("topic")
                        .build());
        assertThat(base)
                .isNotEqualTo(PushMessage.builder(PAYLOAD)
                        .ttl(Duration.ofHours(2))
                        .urgency(Urgency.HIGH)
                        .topic("topic")
                        .build());
        assertThat(base)
                .isNotEqualTo(PushMessage.builder(PAYLOAD)
                        .ttl(Duration.ofHours(1))
                        .urgency(Urgency.LOW)
                        .topic("topic")
                        .build());
        assertThat(base)
                .isNotEqualTo(PushMessage.builder(PAYLOAD)
                        .ttl(Duration.ofHours(1))
                        .urgency(Urgency.HIGH)
                        .topic("other")
                        .build());
    }

    @Test
    void thePayloadIsCopiedOnTheWayInAndOut() {
        byte[] mutable = "hello".getBytes(StandardCharsets.UTF_8);
        PushMessage message = PushMessage.builder(mutable).build();

        mutable[0] = 'X';
        assertThat(message.payload()).startsWith((byte) 'h');

        message.payload()[0] = 'Y';
        assertThat(message.payload()).startsWith((byte) 'h');
    }
}
