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
 * {@link TransitKeyName} is valid by construction: any instance can stand as the final path segment of the Transit
 * {@code keys}/{@code sign} URLs without altering which URL the signer calls. Vault itself refuses {@code /} in a
 * Transit key name, so the validation refuses no name a Transit key can actually carry.
 */
class TransitKeyNameTest {

    @Test
    void aPlainKeyNameIsAccepted() {
        for (String value : new String[] {"vapid", "vapid-rotation", "team_a.vapid", "K1"}) {
            assertThat(new TransitKeyName(value).value()).isEqualTo(value);
        }
    }

    @Test
    void aNullKeyNameIsRejected() {
        assertThatThrownBy(() -> new TransitKeyName(null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void aBlankKeyNameIsRejected() {
        for (String value : new String[] {"", "   "}) {
            assertThatThrownBy(() -> new TransitKeyName(value))
                    .as("value '%s'", value)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("blank");
        }
    }

    @Test
    void aCharacterThatWouldAlterTheRequestPathIsRejected() {
        // '/' adds a path segment, '?' starts a query, '#' a fragment, and a space is not valid
        // in a URI at all — any of them would make the signer call a URL other than
        // /v1/<mount>/keys/<name>. Each failure names the offending character; the key name is
        // not a secret (it already travels in request paths and error messages).
        for (String value : new String[] {"a/b", "sign/../other", "name?x=1", "name#frag", "two words"}) {
            assertThatThrownBy(() -> new TransitKeyName(value))
                    .as("value '%s'", value)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("request path");
        }
    }
}
