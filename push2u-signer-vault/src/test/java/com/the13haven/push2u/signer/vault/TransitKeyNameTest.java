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
 * {@link TransitKeyName} enforces Vault's own Transit key-name rule — {@code GenericNameRegex("name")},
 * {@code ^\w(([\w-.]+)?\w)?$} with Go's {@code \w} being {@code [0-9A-Za-z_]}. Matching Vault's rule exactly means no
 * name Vault would accept is refused, while every URL-breaking character ({@code /}, {@code ?}, {@code #}, {@code %},
 * whitespace, non-ASCII) is refused without being enumerated.
 */
class TransitKeyNameTest {

    @Test
    void aNameVaultWouldAcceptIsAccepted() {
        // Word characters at both ends; '-' and '.' inside; a single word character is the
        // regex's minimal match; digits may lead.
        for (String value : new String[] {"vapid", "vapid-rotation", "team_a.vapid", "K1", "a", "0key", "_x_"}) {
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
    void aNameOutsideVaultsRuleIsRejected() {
        // The names that motivated the type — path-altering characters ('/', '?', '#', space),
        // percent-escapes ('%'), the '-'/'.' edge positions the regex forbids, and non-word
        // characters generally. Vault would refuse each of these too, so nothing usable is lost.
        for (String value : new String[] {
            "a/b",
            "sign/../other",
            "name?x=1",
            "name#frag",
            "two words",
            "key%2Fname",
            "%",
            "-leading",
            "trailing-",
            ".leading",
            "trailing.",
            "café"
        }) {
            assertThatThrownBy(() -> new TransitKeyName(value))
                    .as("value '%s'", value)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Transit key-name rule");
        }
    }
}
