/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.InterruptedIOException;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;

import org.junit.jupiter.api.Test;

/**
 * The cancellation type ADR-022 pins. What a send does with it is the facade's, but the promises the type itself makes
 * — the cause chain it carries, and how it travels through a {@link CompletableFuture} — are checkable here.
 */
class PushInterruptedExceptionTest {

    @Test
    void itCarriesTheInterruptedExceptionWhereOneWasRaised() {
        InterruptedException interrupted = new InterruptedException("sleep interrupted");

        PushInterruptedException e = new PushInterruptedException("send interrupted", interrupted);

        assertThat(e).hasMessage("send interrupted").hasCause(interrupted);
    }

    /**
     * An interruption can surface without an {@code InterruptedException} beneath it, which is why the type promises
     * the flag on the synchronous path and the cause only where one exists.
     */
    @Test
    void itCarriesWhateverTheBlockedSeamRaisedWhereThatIsNotAnInterruptedException() {
        InterruptedIOException raised = new InterruptedIOException("closed");

        PushInterruptedException e = new PushInterruptedException("send interrupted", raised);

        assertThat(e).hasCause(raised);
        assertThat(e.getCause()).isNotInstanceOf(InterruptedException.class);
    }

    @Test
    void itCanReportAnInterruptionSeenOnlyAsAFlag() {
        PushInterruptedException e = new PushInterruptedException("send interrupted");

        assertThat(e).hasMessage("send interrupted");
        assertThat(e.getCause()).isNull();
    }

    /**
     * The asynchronous contract: the future completes exceptionally with this type and is not cancelled, so a caller
     * can tell its own {@code cancel} from a worker stopped mid-flight.
     */
    @Test
    void aFutureCompletedWithItIsExceptionalRatherThanCancelled() {
        CompletableFuture<String> future = new CompletableFuture<>();

        future.completeExceptionally(new PushInterruptedException("send interrupted", new InterruptedException()));

        assertThat(future.isCancelled()).isFalse();
        assertThat(future.isCompletedExceptionally()).isTrue();
        assertThatThrownBy(future::join)
                .isInstanceOf(CompletionException.class)
                .cause()
                .isInstanceOf(PushInterruptedException.class)
                .cause()
                .isInstanceOf(InterruptedException.class);
        assertThatThrownBy(future::get)
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(PushInterruptedException.class);
    }

    /** A cancelled future is the other event, and the two must not arrive in one {@code catch} clause. */
    @Test
    void aCancelledFutureIsTheOtherEventEntirely() {
        CompletableFuture<String> cancelled = new CompletableFuture<>();
        cancelled.cancel(true);

        assertThat(cancelled.isCancelled()).isTrue();
        assertThatThrownBy(cancelled::join).isInstanceOf(CancellationException.class);
        assertThat(CancellationException.class.isAssignableFrom(PushInterruptedException.class))
                .as("borrowing the JDK's cancellation type would make the two indistinguishable")
                .isFalse();
    }

    /** ADR-022 rules out a library exception that does not extend {@code RuntimeException} directly. */
    @Test
    void itExtendsRuntimeExceptionDirectly() {
        assertThat(PushInterruptedException.class.getSuperclass()).isEqualTo(RuntimeException.class);
    }

    /**
     * A cancellation is not a delivery failure, a crypto failure or an outage, and no catch of those may swallow it.
     */
    @Test
    void itIsNoneOfTheOperationalTypes() {
        assertThat(PushDeliveryException.class.isAssignableFrom(PushInterruptedException.class))
                .isFalse();
        assertThat(PushCryptoException.class.isAssignableFrom(PushInterruptedException.class))
                .isFalse();
        assertThat(VapidSignerUnavailableException.class.isAssignableFrom(PushInterruptedException.class))
                .isFalse();
    }
}
