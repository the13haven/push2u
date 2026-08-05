/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import java.util.Objects;

/**
 * A Vault token, valid by construction: any instance can travel in an {@code X-Vault-Token} HTTP header. Taking this
 * type — rather than a bare {@code String} — at {@link VaultTransitVapidSigner}'s factory methods is what lets the
 * signer skip re-validating the token on every path that offers it to a transport.
 *
 * <p>The constructor validates that the value can appear in an HTTP header before it is ever offered to a transport.
 * RFC 9110 limits a field value to HTAB, SP, visible ASCII and obs-text (0x80–0xFF); the character actually seen in the
 * wild is the trailing newline a token picks up from {@code kubectl create secret --from-file}, a Vault Agent sidecar
 * file, or a YAML block scalar. Left to the HTTP client, that token is rejected by the JDK's own header validation with
 * the WHOLE value in the {@code IllegalArgumentException} message — in the signer's fetched mode from inside
 * {@code build()}, i.e. straight into the application's startup stack trace and logs. Failing here makes the
 * misconfiguration fail at construction with a message that names the problem and no part of the value.
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
     * @throws IllegalArgumentException if {@code value} contains a character that cannot appear in an HTTP header
     *     value; the message deliberately does not echo the value
     */
    public VaultToken {
        Objects.requireNonNull(value, "token");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c != '\t' && (c < 0x20 || c == 0x7F || c > 0xFF)) {
                throw new IllegalArgumentException("token contains a character (at index " + i + " of "
                        + value.length() + ") that cannot appear in an HTTP header value — a token sourced from a"
                        + " file or a YAML block scalar commonly carries a trailing newline. The value itself is"
                        + " deliberately not echoed");
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
