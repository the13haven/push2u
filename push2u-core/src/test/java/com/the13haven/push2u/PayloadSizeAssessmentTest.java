/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/**
 * The assessment's own contract: {@code ExceedsLimit}'s compact constructor enforces what its name asserts, and
 * {@code WithinLimit} is an empty record whose instances are all equal — not a singleton, and carrying nothing.
 */
class PayloadSizeAssessmentTest {

    @Test
    void exceedsLimitRefusesNegativeSizes() {
        assertThatThrownBy(() -> new PayloadSizeAssessment.ExceedsLimit(-1, -2))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("payloadBytes must not be negative");
        assertThatThrownBy(() -> new PayloadSizeAssessment.ExceedsLimit(1, -1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maximumPayloadBytes must not be negative");
    }

    @Test
    void exceedsLimitRefusesToSayAPayloadDoesNotExceedTheLimit() {
        // The variant's name is an assertion, and a value constructed to contradict it would be a
        // lie every switch downstream believes. Equality is the boundary: the sender's comparison
        // is inclusive, so a payload equal to the maximum fits and is WithinLimit's case.
        assertThatThrownBy(() -> new PayloadSizeAssessment.ExceedsLimit(5, 5))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("strictly greater");
        assertThatThrownBy(() -> new PayloadSizeAssessment.ExceedsLimit(5, 6))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("strictly greater");
        assertThatThrownBy(() -> new PayloadSizeAssessment.ExceedsLimit(0, 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("strictly greater");
    }

    @Test
    void exceedsLimitCarriesExactlyTheTwoNumbersItWasGiven() {
        PayloadSizeAssessment.ExceedsLimit assessment = new PayloadSizeAssessment.ExceedsLimit(3994, 3993);

        assertThat(assessment.payloadBytes()).isEqualTo(3994);
        assertThat(assessment.maximumPayloadBytes()).isEqualTo(3993);
        // A payload one octet over a zero budget is the smallest constructible refusal.
        assertThat(new PayloadSizeAssessment.ExceedsLimit(1, 0)).isNotNull();
    }

    @Test
    void withinLimitInstancesAreAllEqualAndCarryNothing() {
        // A record with no components: the canonical constructor is public, a caller may create as
        // many instances as it likes, and equality is the whole of what the variant carries.
        assertThat(new PayloadSizeAssessment.WithinLimit())
                .isEqualTo(new PayloadSizeAssessment.WithinLimit())
                .hasSameHashCodeAs(new PayloadSizeAssessment.WithinLimit());
    }
}
