/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import org.junit.jupiter.api.Test;

/**
 * The value the {@link EndpointPolicy} seam answers with (ADR-027). The load-bearing property is that constructing a
 * refusal can never fail: a policy translating its own failure writes {@code new Refused(e.getMessage())} in one line,
 * and {@code getMessage()} is {@code null} for every exception built without a message — a constructor refusing that
 * would send the one-line slip out of the seam as a defect, and a defect stops the fan-out this value exists to keep
 * running. So {@code Refused} normalises {@code null} to {@code ""} and permits a blank reason, exactly what
 * {@link PushOutcome.EndpointRejected} permits — one refusal may not be legal in one of the two types describing it and
 * illegal in the other. {@code Allowed} carries nothing and is not a singleton; both are pinned here so a later
 * "obvious" validation or component does not arrive by accident.
 */
class EndpointAssessmentTest {

    @Test
    void refusedNormalisesANullReasonToTheEmptyString() {
        // The explicit canonical constructor's whole reason to exist: the parameter is nullable,
        // the component is not, and no policy can make constructing a refusal throw.
        EndpointAssessment.Refused refused = new EndpointAssessment.Refused(null);

        assertThat(refused.reason()).isEmpty();
    }

    @Test
    void refusedPermitsAnEmptyAndABlankReason() {
        // Refusing what the name does not contradict would be a defect, not rigour: nothing
        // branches on the reason, so a blank one breaks nothing — and throwing here would stop a
        // fan-out on the first row whose policy wrote no message.
        assertThatCode(() -> {
                    new EndpointAssessment.Refused("");
                    new EndpointAssessment.Refused("   ");
                })
                .doesNotThrowAnyException();
        assertThat(new EndpointAssessment.Refused("   ").reason()).isEqualTo("   ");
    }

    @Test
    void refusedKeepsTheReasonItWasGiven() {
        assertThat(new EndpointAssessment.Refused("egress denied by corporate rule").reason())
                .isEqualTo("egress denied by corporate rule");
    }

    @Test
    void aNullReasonAndAnEmptyReasonAreTheSameValue() {
        // The normalisation is to a value, not to a marker: a caller cannot tell "no account" from
        // "an empty account", which is the deliberate price of a constructor that cannot fail.
        assertThat(new EndpointAssessment.Refused(null)).isEqualTo(new EndpointAssessment.Refused(""));
    }

    @Test
    void allowedCarriesNothingAndAllInstancesAreEqual() {
        // No components, so all instances are equal and interchangeable — and the public canonical
        // constructor means it is not a singleton: identity is not part of what the answer means.
        assertThat(new EndpointAssessment.Allowed()).isEqualTo(new EndpointAssessment.Allowed());
    }
}
