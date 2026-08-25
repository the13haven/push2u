/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.net.URI;

import org.junit.jupiter.api.Test;

/**
 * The methods whose returned value is the whole of their answer carry {@link CheckReturnValue}, which is what turns a
 * bare {@code policy.assess(uri);} — or the same shape on {@code assessPayloadSize} or {@code Es256Verifier.verify} —
 * into a compile error for a consumer running an analyser that matches such a mark by its simple name.
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
        assertThat(Es256Verifier.class
                        .getMethod("verify", byte[].class, byte[].class, byte[].class)
                        .getAnnotation(CheckReturnValue.class))
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
        // The analyser this exists for matches on the simple name alone and reads the mark out of the class file, so
        // a rename leaves every call site above unchecked in a consumer's build. RUNTIME rather than CLASS is what
        // lets this test read it at all; SOURCE would not reach the artifact a consumer compiles against, which is
        // the only place any of this has to work.
        assertThat(CheckReturnValue.class.getSimpleName()).isEqualTo("CheckReturnValue");
        assertThat(CheckReturnValue.class.getAnnotation(Retention.class).value())
                .isEqualTo(RetentionPolicy.RUNTIME);
    }
}
