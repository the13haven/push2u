/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import java.util.Objects;

/**
 * A Vault token, valid by construction: any instance is non-empty, visible ASCII with no whitespace — and can therefore
 * always travel in an {@code X-Vault-Token} HTTP header. Taking this type — rather than a bare {@code String} — at
 * {@link VaultTransitVapidSigner}'s factory methods is what lets the signer skip re-validating the token on every path
 * that offers it to a transport.
 *
 * <p>The constructor checks the token's <em>character set</em>, not its format: the value must not be empty, and every
 * character must be visible ASCII excluding the space (0x21–0x7E). Every token Vault issues on its own satisfies this,
 * so the rule rejects a Vault-issued token exactly when it was damaged in transfer — the trailing newline picked up
 * from {@code kubectl create secret --from-file}, a Vault Agent sidecar file or a YAML block scalar; the {@code Bearer
 * } prefix pasted along with the value; control characters; non-ASCII mojibake. It is deliberately a little stricter
 * than "what would break": a space is a legal HTTP field-value character, and {@code vault token create -id='has
 * space'} does produce a working token containing one — but no token Vault generates itself contains a space, so an
 * interior space in configuration is overwhelmingly a transfer accident, and refusing the space-bearing custom-ID token
 * (which production setups do not use) is the accepted cost of catching the accident. Left to the HTTP client, a
 * damaged token is either rejected by the JDK's own header validation with the WHOLE value in the
 * {@code IllegalArgumentException} message — in the signer's fetched mode from inside {@code build()}, i.e. straight
 * into the application's startup stack trace and logs — or sent as-is and refused by Vault as a per-request 403, far
 * from the misconfiguration. Failing here makes it fail at construction with a message that names the problem and no
 * part of the value.
 *
 * <p>The token's <em>format</em> is deliberately not validated. Vault issues {@code hvs.}/{@code hvb.}/{@code hvr.}
 * prefixes today, issued {@code s.}/{@code b.} before Vault 1.10, and a dev-mode server accepts an arbitrary string as
 * its root token ({@code -dev-root-token-id=root}) — the Testcontainers-backed test in this repository runs Vault with
 * {@code push2u-test-root}. A prefix or shape check would break all of those while catching no real mistake the
 * character-set check does not already catch.
 *
 * <p>{@link #toString()} is overridden to never print the value — the record-generated form would put the live token
 * into any log line or debugger dump that renders this object.
 *
 * @param value the token value, e.g. {@code hvs.…}
 */
public record VaultToken(String value) {

    /**
     * Validates the token.
     *
     * @throws NullPointerException if {@code value} is {@code null}
     * @throws IllegalArgumentException if {@code value} is empty or contains a character outside visible ASCII
     *     (0x21–0x7E) — whitespace included; the message deliberately does not echo the value
     */
    public VaultToken {
        Objects.requireNonNull(value, "token");
        if (value.isEmpty()) {
            throw new IllegalArgumentException("token must not be empty");
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x21 || c > 0x7E) {
                throw new IllegalArgumentException("token contains a character (at index " + i + " of "
                        + value.length() + ") outside visible ASCII (0x21-0x7E) — a token sourced from a file or a"
                        + " YAML block scalar commonly carries a trailing newline, and one pasted with its"
                        + " 'Bearer ' prefix carries a space. The value itself is deliberately not echoed");
            }
        }
    }

    /**
     * A redacted form that never contains the token — the record-generated {@code toString()} would print it.
     *
     * @return the literal {@code VaultToken[REDACTED]}
     */
    @Override
    public String toString() {
        return "VaultToken[REDACTED]";
    }
}
