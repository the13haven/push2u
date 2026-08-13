/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.time.Duration;

import org.junit.jupiter.api.Test;

/**
 * The seam vocabulary ADR-022 pins for a key custodian that cannot sign now: one type over both halves of an outage,
 * carrying a cause, an optional custodian status and an optional retry hint.
 */
class VapidSignerUnavailableExceptionTest {

    @Test
    void unansweredHalfCarriesTheCauseAndDeclaresNothingElse() {
        IOException cause = new IOException("Connection refused");

        VapidSignerUnavailableException e = new VapidSignerUnavailableException("vault is unreachable", cause);

        assertThat(e).hasMessage("vault is unreachable").hasCause(cause);
        assertThat(e.status())
                .as("nothing answered, so nothing answered a number")
                .isEmpty();
        assertThat(e.retryAfter())
                .as("nothing answered, so nothing declared a moment")
                .isEmpty();
    }

    @Test
    void unansweredHalfAcceptsNoCauseAtAll() {
        VapidSignerUnavailableException e = new VapidSignerUnavailableException("no key custodian configured", null);

        assertThat(e.getCause()).isNull();
        assertThat(e.status()).isEmpty();
        assertThat(e.retryAfter()).isEmpty();
    }

    @Test
    void answeredHalfCarriesTheStatusAndTheDeclaredMoment() {
        VapidSignerUnavailableException e =
                new VapidSignerUnavailableException("vault is rate-limiting", 429, Duration.ofSeconds(30), null);

        assertThat(e.status()).hasValue(429);
        assertThat(e.retryAfter()).contains(Duration.ofSeconds(30));
        assertThat(e.getCause()).isNull();
    }

    @Test
    void aCustodianThatAnswersWithoutDeclaringAMomentLeavesTheHintEmpty() {
        VapidSignerUnavailableException e = new VapidSignerUnavailableException("vault is sealed", 503, null, null);

        assertThat(e.status()).hasValue(503);
        assertThat(e.retryAfter())
                .as("empty is the ordinary reading, not a defect")
                .isEmpty();
    }

    @Test
    void aStatusAndACauseTravelTogetherWhereBothExist() {
        IllegalStateException cause = new IllegalStateException("throttled");

        VapidSignerUnavailableException e =
                new VapidSignerUnavailableException("kms refused on quota", 429, Duration.ofMinutes(1), cause);

        assertThat(e.status()).hasValue(429);
        assertThat(e.retryAfter()).contains(Duration.ofMinutes(1));
        assertThat(e.getCause()).isSameAs(cause);
    }

    @Test
    void aZeroHintIsADeclarationAndSurvives() {
        VapidSignerUnavailableException e =
                new VapidSignerUnavailableException("come back now", 429, Duration.ZERO, null);

        assertThat(e.retryAfter()).contains(Duration.ZERO);
    }

    @Test
    void theHintIsReportedWithNoCeilingApplied() {
        Duration hours = Duration.ofHours(9);

        VapidSignerUnavailableException e = new VapidSignerUnavailableException("standby", 429, hours, null);

        assertThat(e.retryAfter())
                .as("the caller's own ceiling is the only one")
                .contains(hours);
    }

    /**
     * The unanswered half must stay tellable from an answered zero, which is why the absence is a flag rather than a
     * sentinel number: a custodian that is not reached over HTTP may answer in numbers of its own.
     */
    @Test
    void anAnsweredZeroIsStillAnAnswer() {
        assertThat(new VapidSignerUnavailableException("odd but answered", 0, null, null).status())
                .hasValue(0);
        assertThat(new VapidSignerUnavailableException("nothing answered", null).status())
                .isEmpty();
    }

    /**
     * Reporting an outage must not be able to fail: a constructor that validated would answer a defect in how the
     * report was written by destroying the report, and the report is the only thing that says the custodian is down.
     */
    @Test
    void constructingOneNeverThrows() {
        VapidSignerUnavailableException e =
                new VapidSignerUnavailableException("odd values", -1, Duration.ofSeconds(-1), null);

        assertThat(e.status()).hasValue(-1);
        assertThat(e.retryAfter()).contains(Duration.ofSeconds(-1));
    }

    /** ADR-022 rules out a library exception that does not extend {@code RuntimeException} directly. */
    @Test
    void itExtendsRuntimeExceptionDirectly() {
        assertThat(VapidSignerUnavailableException.class.getSuperclass()).isEqualTo(RuntimeException.class);
    }

    /**
     * The narrowing is the point: a custodian's outage must not arrive as the type that means "a person has to change
     * something", or a caller that catches the second one swallows the first.
     */
    @Test
    void itIsNotAPushCryptoException() {
        assertThat(PushCryptoException.class.isAssignableFrom(VapidSignerUnavailableException.class))
                .isFalse();
        assertThat(PushDeliveryException.class.isAssignableFrom(VapidSignerUnavailableException.class))
                .as("a signing call delivers nothing, so it does not wear the delivery type either")
                .isFalse();
    }
}
