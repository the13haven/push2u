/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.time.Duration;
import java.util.Optional;
import java.util.OptionalInt;

import org.junit.jupiter.api.Test;

/**
 * The {@link PushOutcome} hierarchy's own contract: the validation each variant applies, the {@code NotAttempted}
 * grouping a caller may switch on, the identity equality of the two class-shaped variants, and — the invariant with
 * security weight — that no outcome's default rendering discloses a capability URL, however the underlying cause chain
 * embeds one.
 */
class PushOutcomeTest {

    private static final String CAPABILITY_URL = "https://push.example/wpush/v2/SECRET-subscriber-token";

    @Test
    void statusCarryingVariantsRejectANegativeStatusCode() {
        assertThatThrownBy(() -> new PushOutcome.Accepted(-1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new PushOutcome.SubscriptionExpired(-1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new PushOutcome.RetryableFailure(-1, Optional.empty()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new PushOutcome.NonRetryableFailure(-1)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void retryableFailureRejectsANullOrNegativeHint() {
        assertThatThrownBy(() -> new PushOutcome.RetryableFailure(429, null)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new PushOutcome.RetryableFailure(429, Optional.of(Duration.ofSeconds(-1))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("retryAfter");
    }

    @Test
    void payloadRejectedRejectsNegativeSizes() {
        assertThatThrownBy(() -> new PushOutcome.PayloadRejected(-1, 100))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("payloadBytes");
        assertThatThrownBy(() -> new PushOutcome.PayloadRejected(100, -1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maximumPayloadBytes");
    }

    @Test
    void endpointRejectedRejectsNulls() {
        assertThatThrownBy(() -> new PushOutcome.EndpointRejected(null, "reason"))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new PushOutcome.EndpointRejected("https://push.example/…#abc", null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void theClassShapedVariantsRejectANullCause() {
        assertThatThrownBy(() -> new PushOutcome.Indeterminate(null)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new PushOutcome.SignerUnavailable(null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void theNotAttemptedLeavesAreSwitchableAsAGroup() {
        // The marker is what lets a caller take "no POST was made, a repeat cannot duplicate" in
        // one case — every leaf must actually be under it, and no answered variant may be.
        assertThat(new PushOutcome.PayloadRejected(5000, 3993)).isInstanceOf(PushOutcome.NotAttempted.class);
        assertThat(new PushOutcome.EndpointRejected("https://push.example/…#abc", "no rule matches"))
                .isInstanceOf(PushOutcome.NotAttempted.class);
        assertThat(new PushOutcome.SignerUnavailable(new VapidSignerUnavailableException("sealed")))
                .isInstanceOf(PushOutcome.NotAttempted.class);

        assertThat(new PushOutcome.Accepted(201)).isNotInstanceOf(PushOutcome.NotAttempted.class);
        assertThat(new PushOutcome.RetryableFailure(503, Optional.empty()))
                .isNotInstanceOf(PushOutcome.NotAttempted.class);
        assertThat(new PushOutcome.NonRetryableFailure(400)).isNotInstanceOf(PushOutcome.NotAttempted.class);
        assertThat(new PushOutcome.Indeterminate(new PushDeliveryException("x")))
                .isNotInstanceOf(PushOutcome.NotAttempted.class);
    }

    /**
     * Two values describing the same timeout are unequal: the class-shaped variants carry a {@link Throwable} and
     * compare by identity. Outcomes are switched on rather than compared, so this is the accepted reading — pinned here
     * so nobody keys a map or a deduplication on one and discovers it in production.
     */
    @Test
    void theClassShapedVariantsCompareByIdentity() {
        PushDeliveryException cause = new PushDeliveryException("timeout");
        assertThat(new PushOutcome.Indeterminate(cause)).isNotEqualTo(new PushOutcome.Indeterminate(cause));

        VapidSignerUnavailableException unavailable = new VapidSignerUnavailableException("sealed");
        assertThat(new PushOutcome.SignerUnavailable(unavailable))
                .isNotEqualTo(new PushOutcome.SignerUnavailable(unavailable));
    }

    @Test
    void indeterminateToStringNeverPrintsTheCauseChain() {
        // A JDK transport exception's message embeds the request URI, which is the capability URL.
        // The written toString prints class names only; the chain is reachable through cause() and
        // through nothing else.
        PushDeliveryException transport = new PushDeliveryException(
                "POST failed", new IOException("connect to " + CAPABILITY_URL + " timed out"));

        PushOutcome.Indeterminate outcome = new PushOutcome.Indeterminate(transport);

        assertThat(outcome.toString())
                .doesNotContain(CAPABILITY_URL)
                .doesNotContain("SECRET")
                .contains("PushDeliveryException");
        assertThat(outcome.cause()).isSameAs(transport);
    }

    @Test
    void signerUnavailableToStringPrintsTheCustodiansDeclarationsAndNothingElse() {
        VapidSignerUnavailableException withBoth = new VapidSignerUnavailableException(
                "custodian sealed", 503, Duration.ofSeconds(30), new IOException("dial " + CAPABILITY_URL));

        PushOutcome.SignerUnavailable outcome = new PushOutcome.SignerUnavailable(withBoth);

        assertThat(outcome.toString())
                .contains("custodian status 503")
                .contains("retry after PT30S")
                .doesNotContain(CAPABILITY_URL)
                .doesNotContain("sealed");

        PushOutcome.SignerUnavailable bare =
                new PushOutcome.SignerUnavailable(new VapidSignerUnavailableException("nothing answered"));
        assertThat(bare.toString()).isEqualTo("SignerUnavailable[]");
    }

    @Test
    void signerUnavailableReportsTheExceptionsStatusAndHint() {
        VapidSignerUnavailableException cause =
                new VapidSignerUnavailableException("standby", 473, Duration.ofSeconds(5), null);

        PushOutcome.SignerUnavailable outcome = new PushOutcome.SignerUnavailable(cause);

        assertThat(outcome.status()).hasValue(473);
        assertThat(outcome.retryAfter()).contains(Duration.ofSeconds(5));
        assertThat(outcome.cause()).isSameAs(cause);
    }

    /**
     * {@link VapidSignerUnavailableException} is extensible and its accessors are not final, so a third-party subtype
     * can answer differently on every call. The outcome snapshots the status and the hint once, at construction —
     * ADR-021 has them "copied across", not delegated — so what the same outcome answers can never move afterwards, on
     * the accessors or in the rendering. Pinned by a subtype whose answers shift after the first read.
     */
    @Test
    void signerUnavailableAnswersDoNotMoveWhenTheExceptionsDo() {
        VapidSignerUnavailableException shifting =
                new VapidSignerUnavailableException("standby", 473, Duration.ofSeconds(5), null) {
                    private int statusReads;
                    private int hintReads;

                    @Override
                    public OptionalInt status() {
                        return statusReads++ == 0 ? super.status() : OptionalInt.of(200);
                    }

                    @Override
                    public Optional<Duration> retryAfter() {
                        return hintReads++ == 0 ? super.retryAfter() : Optional.of(Duration.ofDays(365));
                    }
                };

        PushOutcome.SignerUnavailable outcome = new PushOutcome.SignerUnavailable(shifting);

        // The subtype has genuinely moved on: every read after the construction-time one answers differently.
        assertThat(shifting.status()).hasValue(200);
        assertThat(shifting.retryAfter()).contains(Duration.ofDays(365));

        // The outcome's answers are the construction-time ones — repeatedly, and in toString() too.
        assertThat(outcome.status()).hasValue(473);
        assertThat(outcome.status()).hasValue(473);
        assertThat(outcome.retryAfter()).contains(Duration.ofSeconds(5));
        assertThat(outcome.retryAfter()).contains(Duration.ofSeconds(5));
        assertThat(outcome.toString()).contains("custodian status 473").contains("retry after PT5S");
    }

    // ---- the guarded reads: a broken accessor costs a component, never the outcome -------------
    //
    // Every test below calls the public constructor directly, which is what proves the guard lives
    // in the constructor rather than only on PushSender's conversion path: a consumer building the
    // outcome themselves gets the same protection.

    @Test
    void signerUnavailableSurvivesAThrowingStatusAndKeepsTheHint() {
        IllegalStateException defect = new IllegalStateException("status accessor broke");
        VapidSignerUnavailableException cause =
                new VapidSignerUnavailableException("standby", 473, Duration.ofSeconds(5), null) {
                    @Override
                    public OptionalInt status() {
                        throw defect;
                    }
                };

        PushOutcome.SignerUnavailable outcome = new PushOutcome.SignerUnavailable(cause);

        assertThat(outcome.status()).isEmpty();
        assertThat(outcome.retryAfter())
                .as("the two reads are guarded independently: retryAfter() answered, and its answer is kept")
                .contains(Duration.ofSeconds(5));
        assertThat(cause.getSuppressed())
                .as("the defect is recorded on the cause, so an empty component with a broken accessor"
                        + " never reads as a custodian that declared nothing")
                .containsExactly(defect);
    }

    @Test
    void signerUnavailableSurvivesAThrowingHintAndKeepsTheStatus() {
        IllegalStateException defect = new IllegalStateException("retryAfter accessor broke");
        VapidSignerUnavailableException cause =
                new VapidSignerUnavailableException("standby", 473, Duration.ofSeconds(5), null) {
                    @Override
                    public Optional<Duration> retryAfter() {
                        throw defect;
                    }
                };

        PushOutcome.SignerUnavailable outcome = new PushOutcome.SignerUnavailable(cause);

        assertThat(outcome.status())
                .as("the mirror of the independence claim: status() was read first and its answer survives"
                        + " the later read breaking")
                .hasValue(473);
        assertThat(outcome.retryAfter()).isEmpty();
        assertThat(cause.getSuppressed()).containsExactly(defect);
    }

    @Test
    void signerUnavailableTreatsANullStatusAsTheSameBreachAsAThrow() {
        // The accessor's declared way of saying "nothing declared" is the empty optional; null is
        // a contract breach that would otherwise sit in an OptionalInt-typed field and break later,
        // somewhere with nothing left to name the culprit.
        VapidSignerUnavailableException cause =
                new VapidSignerUnavailableException("standby", 473, Duration.ofSeconds(5), null) {
                    @Override
                    public OptionalInt status() {
                        return null;
                    }
                };

        PushOutcome.SignerUnavailable outcome = new PushOutcome.SignerUnavailable(cause);

        assertThat(outcome.status()).isEmpty();
        assertThat(outcome.retryAfter()).contains(Duration.ofSeconds(5));
        assertThat(cause.getSuppressed()).hasSize(1);
        assertThat(cause.getSuppressed()[0])
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("status()");
    }

    @Test
    void signerUnavailableTreatsANullHintAsTheSameBreachAsAThrow() {
        VapidSignerUnavailableException cause =
                new VapidSignerUnavailableException("standby", 473, Duration.ofSeconds(5), null) {
                    @Override
                    public Optional<Duration> retryAfter() {
                        return null;
                    }
                };

        PushOutcome.SignerUnavailable outcome = new PushOutcome.SignerUnavailable(cause);

        assertThat(outcome.status()).hasValue(473);
        assertThat(outcome.retryAfter()).isEmpty();
        assertThat(cause.getSuppressed()).hasSize(1);
        assertThat(cause.getSuppressed()[0])
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("retryAfter()");
    }

    @Test
    void signerUnavailableSurvivesAnAccessorThrowingTheExceptionItself() {
        // The one refusal recording a defect can meet: an accessor that throws the exception
        // carrying it hands addSuppressed its own argument, which the platform rejects as
        // self-suppression. The guard swallows that rejection — the outcome still exists, the
        // component is still empty, and nothing is recorded, because nothing can be.
        VapidSignerUnavailableException cause = new VapidSignerUnavailableException("self-throwing", 473, null, null) {
            @Override
            public OptionalInt status() {
                throw this;
            }
        };

        PushOutcome.SignerUnavailable outcome = new PushOutcome.SignerUnavailable(cause);

        assertThat(outcome.status()).isEmpty();
        assertThat(outcome.retryAfter()).isEmpty();
        assertThat(outcome.cause()).isSameAs(cause);
        assertThat(cause.getSuppressed()).isEmpty();
    }

    @Test
    void signerUnavailableLetsAnErrorOutOfAnAccessorPropagate() {
        // The guard's boundary is RuntimeException, pinned here as a boundary rather than an
        // untested preference: an AssertionError is a failed invariant, not a diagnostic to
        // survive, and laundering it into an outcome would hide it.
        VapidSignerUnavailableException cause = new VapidSignerUnavailableException("standby", 473, null, null) {
            @Override
            public OptionalInt status() {
                throw new AssertionError("invariant failed inside an accessor");
            }
        };

        assertThatThrownBy(() -> new PushOutcome.SignerUnavailable(cause))
                .isInstanceOf(AssertionError.class)
                .hasMessage("invariant failed inside an accessor");
    }

    @Test
    void oneReusedExceptionDoesNotGrowItsSuppressedListWithEveryOutcome() {
        // Preallocating one exception and throwing it for every call is an ordinary thing for a
        // signer to do — a custodian refusing everything while a breaker is open builds nothing
        // per call — so a fan-out over a subscription store hands the same instance to this
        // constructor over and over. With a broken accessor on it, an unbounded recording would
        // turn one defect into a list that grows for as long as the fan-out runs.
        VapidSignerUnavailableException reused = new VapidSignerUnavailableException("sealed", 503, null, null) {
            @Override
            public OptionalInt status() {
                return null;
            }
        };

        for (int i = 0; i < 1000; i++) {
            assertThat(new PushOutcome.SignerUnavailable(reused).status()).isEmpty();
        }

        assertThat(reused.getSuppressed())
                .as("the recording is bounded, and every outcome still answered from a guarded read")
                .hasSizeLessThanOrEqualTo(8);
        assertThat(reused.getSuppressed()[0])
                .as("what was recorded is still the diagnostic, not something the ceiling substituted")
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("status()");
    }
}
