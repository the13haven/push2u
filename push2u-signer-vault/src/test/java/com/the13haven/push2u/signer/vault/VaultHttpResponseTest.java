/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.Optional;

import org.junit.jupiter.api.Test;

/**
 * {@link VaultHttpResponse}'s own guarantees: the two-argument constructor reports no hint (the ordinary case, and the
 * whole constructor for a transport that does not read the {@code Retry-After} header), and the hint's floor — a
 * negative delay reads to a scheduler as "repeat immediately" against a Vault that just declared it cannot serve, so a
 * transport passing one is refused at this boundary rather than believed.
 */
class VaultHttpResponseTest {

    @Test
    void theTwoArgumentConstructorReportsNoHint() {
        assertThat(new VaultHttpResponse(200, "{}").retryAfter()).isEmpty();
    }

    @Test
    void aZeroHintIsLegalItDeclaresNow() {
        assertThat(new VaultHttpResponse(429, "{}", Optional.of(Duration.ZERO)).retryAfter())
                .contains(Duration.ZERO);
    }

    @Test
    void aNegativeHintIsRefusedAtTheBoundaryThatTookIt() {
        assertThatThrownBy(() -> new VaultHttpResponse(429, "{}", Optional.of(Duration.ofSeconds(-1))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("retryAfter must not be negative");
    }

    @Test
    void aNullBodyIsRefusedABodylessReplyIsTheEmptyString() {
        assertThatThrownBy(() -> new VaultHttpResponse(204, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("body");
    }
}
