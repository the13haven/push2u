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
}
