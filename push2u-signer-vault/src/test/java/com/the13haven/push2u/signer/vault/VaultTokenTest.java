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
 * {@code String} and never re-validate. The rule is the token's character set (non-empty, visible ASCII, no
 * whitespace), never its format: dev-mode Vault accepts an arbitrary root token, so a prefix check would reject working
 * configurations. Two properties carry the security weight: an invalid token is rejected without any part of its value
 * reaching the exception message, and {@code toString()} never prints the value at all.
 */
class VaultTokenTest {

    private static final String TOKEN = "s.push2u-test-vault-token";

    @Test
    void aVisibleAsciiTokenIsAcceptedWhateverItsFormat() {
        // Every Vault token era plus the dev-mode arbitrary string: hvs./hvb./hvr. (current),
        // s./b. (pre-1.10), and plain values like `root` or the `push2u-test-root` this
        // repository's Testcontainers-backed test runs Vault with. The format is deliberately not
        // validated — only the character set is.
        for (String value :
                new String[] {TOKEN, "hvs.CAESIJ", "hvb.AAAAAQ", "hvr.abc", "b.legacy", "root", "push2u-test-root"}) {
            assertThat(new VaultToken(value).value()).isEqualTo(value);
        }
    }

    @Test
    void aTokenWithACharacterOutsideVisibleAsciiIsRejectedWithoutEchoingTheValue() {
        // A Vault-issued token contains none of these, so each is the signature of a transfer
        // accident: the trailing newline from `kubectl create secret --from-file` or a YAML block
        // scalar, the `Bearer ` prefix pasted along with the value, control characters, non-ASCII
        // mojibake. The interior space is the one deliberate over-reach — a space is legal in a
        // header and `vault token create -id='has space'` works, but no self-generated token has
        // one, so in configuration it is overwhelmingly a paste accident. Sent as-is, the JDK
        // header validation would echo the WHOLE value into the exception message — or Vault
        // would answer 403 per request, far from the cause.
        for (String value : new String[] {
            TOKEN + "\n",
            TOKEN + "\r",
            "hvs.embedded\0nul",
            "Bearer " + TOKEN,
            "with space",
            "with\ttab",
            "obs-text-ÿ",
            "токен"
        }) {
            assertThatThrownBy(() -> new VaultToken(value))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("token")
                    .satisfies(e ->
                            assertThat(e.getMessage()).doesNotContain(TOKEN).doesNotContain("hvs.embedded"));
        }
    }

    @Test
    void anEmptyOrBlankTokenIsRejected() {
        assertThatThrownBy(() -> new VaultToken("")).isInstanceOf(IllegalArgumentException.class);
        // Blank-but-not-empty falls to the character rule: a space is not visible ASCII.
        assertThatThrownBy(() -> new VaultToken("   ")).isInstanceOf(IllegalArgumentException.class);
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
