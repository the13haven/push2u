/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * A Vault Transit key name, valid by construction: any instance satisfies the rule Vault itself applies to a Transit
 * key name, and can therefore stand as the final path segment of {@code /v1/<mount>/sign/<name>} and
 * {@code /v1/<mount>/keys/<name>} without altering the request path. Taking this type — rather than a bare
 * {@code String} — at {@link VaultTransitVapidSigner}'s factory methods also makes the name impossible to swap with the
 * token in the positional argument list: the compiler tells them apart.
 *
 * <p>The rule is Vault's own, not a blacklist of this module's invention: Transit validates the {@code name} path field
 * against {@code GenericNameRegex("name")} — {@code ^\w(([\w-.]+)?\w)?$} in
 * {@code builtin/logical/transit/path_keys.go}, where Go's {@code \w} is {@code [0-9A-Za-z_]}. So a name is letters,
 * digits, {@code _}, {@code -} and {@code .}, beginning and ending with a word character. Matching Vault's rule exactly
 * means no name Vault would accept is refused here, and everything URL-breaking — {@code /}, {@code ?}, {@code #},
 * {@code %}, whitespace, non-ASCII — is refused without having to be enumerated.
 *
 * @param value the Transit key name, e.g. {@code vapid}
 */
public record TransitKeyName(String value) {

    /**
     * Vault's {@code GenericNameRegex("name")} for the Transit {@code name} path field, transcribed for Java's
     * {@link Pattern}: the anchors are implied by {@code matches()}, and the character class is reordered to
     * {@code [\w.-]} so the {@code -} is unambiguously literal.
     */
    private static final Pattern VAULT_TRANSIT_NAME = Pattern.compile("\\w(([\\w.-]+)?\\w)?");

    /**
     * Validates the key name against Vault's own Transit key-name rule.
     *
     * @throws NullPointerException if {@code value} is {@code null}
     * @throws IllegalArgumentException if {@code value} is blank or does not match Vault's Transit key-name rule
     */
    public TransitKeyName {
        Objects.requireNonNull(value, "keyName");
        if (value.isBlank()) {
            throw new IllegalArgumentException("keyName must not be blank");
        }
        if (!VAULT_TRANSIT_NAME.matcher(value).matches()) {
            throw new IllegalArgumentException("keyName does not satisfy Vault's own Transit key-name rule"
                    + " (letters, digits, '_', '-' and '.', beginning and ending with a letter, digit or '_' —"
                    + " GenericNameRegex in Vault's path_keys.go). A conforming name can never alter the"
                    + " /v1/<mount>/keys/<name> and /v1/<mount>/sign/<name> request paths");
        }
    }
}
