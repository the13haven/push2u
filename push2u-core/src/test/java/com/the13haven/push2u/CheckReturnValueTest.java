/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.net.URI;

import org.junit.jupiter.api.Test;

/**
 * The two questions whose answer is the whole of the answer carry {@link CheckReturnValue}, which is what turns a bare
 * {@code policy.assess(uri);} or {@code sender.assessPayloadSize(payload);} into a compile error for a consumer running
 * an analyser that matches such a mark by its simple name.
 *
 * <p>This is insurance against a refactoring dropping the annotation in silence — nothing in this build compiles worse
 * without it, and the analyser that reads it runs in someone else's build. It is not a test of Error Prone: what it
 * pins is that the mark is on those methods, that it survives into the class file, and that it keeps the simple name
 * the matching is done by.
 *
 * <p>{@link PushSender#send} and {@link PushSender#sendAsync} are deliberately not marked, and that is asserted here so
 * the omission reads as a decision rather than as one more method somebody forgot. Discarding a {@link PushOutcome}
 * loses real information — an expired subscription above all — but fire-and-forget is a legitimate way to send, and it
 * is the ordinary shape of a discarded {@code CompletableFuture}; marking either would break a correct consumer's
 * build.
 */
class CheckReturnValueTest {

    @Test
    void theAnswersThatMustBeReadAreMarked() throws NoSuchMethodException {
        assertThat(EndpointPolicy.class.getMethod("assess", URI.class).getAnnotation(CheckReturnValue.class))
                .isNotNull();
        assertThat(PushSender.class.getMethod("assessPayloadSize", byte[].class).getAnnotation(CheckReturnValue.class))
                .isNotNull();
    }

    @Test
    void sendingIsNotMarked() throws NoSuchMethodException {
        assertThat(PushSender.class
                        .getMethod("send", Subscription.class, PushMessage.class)
                        .getAnnotation(CheckReturnValue.class))
                .isNull();
        assertThat(PushSender.class
                        .getMethod("sendAsync", Subscription.class, PushMessage.class)
                        .getAnnotation(CheckReturnValue.class))
                .isNull();
    }

    @Test
    void theMarkKeepsTheNameAndTheRetentionTheMatchingNeeds() {
        // The analysers this exists for match on the simple name alone, and they read it out of the class file: a
        // rename, or a retention of SOURCE, would leave every call site above unchecked in a consumer's build with
        // nothing here to say so.
        assertThat(CheckReturnValue.class.getSimpleName()).isEqualTo("CheckReturnValue");
        assertThat(CheckReturnValue.class.getAnnotation(Retention.class).value())
                .isEqualTo(RetentionPolicy.RUNTIME);
        assertThat(CheckReturnValue.class.getAnnotation(Target.class).value())
                .containsExactlyInAnyOrder(ElementType.METHOD, ElementType.TYPE);
    }
}
