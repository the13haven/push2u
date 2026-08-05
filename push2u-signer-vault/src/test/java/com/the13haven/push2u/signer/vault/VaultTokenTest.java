/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/**
 * {@link VaultToken} is valid by construction — the whole reason the signer's factory methods can take it instead of a
 * {@code String} and never re-validate. Two properties carry the security weight: an invalid token is rejected without
 * any part of its value reaching the exception message, and {@code toString()} never prints the value at all.
 */
class VaultTokenTest {

    private static final String TOKEN = "s.push2u-test-vault-token";

    @Test
    void aHeaderSafeTokenIsAccepted() {
        // HTAB and obs-text (0x80–0xFF) are legal in an HTTP field value per RFC 9110 — the
        // validation must not be stricter than the header grammar it protects.
        for (String value : new String[] {TOKEN, "hvs.CAESIJ", "with\ttab", "obs-text-ÿ"}) {
            assertThat(new VaultToken(value).value()).isEqualTo(value);
        }
    }

    @Test
    void aTokenWithACharacterIllegalInAHeaderIsRejectedWithoutEchoingTheValue() {
        // A token with a trailing newline is exactly how it arrives from `kubectl create secret
        // --from-file`, a Vault Agent sidecar file, or a YAML block scalar. Sent as-is, the JDK
        // header validation rejects it with the WHOLE token in the exception message — in the
        // signer's fetched mode from inside build(), i.e. in the application's startup stack
        // trace. The misconfiguration must instead fail at construction, before the value can
        // reach any transport, with a message that names the problem and no part of the value.
        for (String value : new String[] {TOKEN + "\n", TOKEN + "\r", "hvs.embedded\0nul", "beyond-Ā"}) {
            assertThatThrownBy(() -> new VaultToken(value))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("token")
                    .satisfies(e ->
                            assertThat(e.getMessage()).doesNotContain(TOKEN).doesNotContain("hvs.embedded"));
        }
    }

    @Test
    void aNullTokenIsRejected() {
        assertThatThrownBy(() -> new VaultToken(null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void toStringNeverContainsTheValue() {
        // The record-generated toString() prints every component — for this type that would be
        // the live Vault token, one log.info("{}", token) away from a log line. The override must
        // hold whatever the value is.
        VaultToken token = new VaultToken(TOKEN);

        assertThat(token).hasToString("VaultToken[REDACTED]");
        assertThat(token.toString()).doesNotContain(TOKEN);
    }
}
