/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import java.util.Objects;

/**
 * A Vault Transit key name, valid by construction: any instance can stand as the final path segment of
 * {@code /v1/<mount>/sign/<name>} and {@code /v1/<mount>/keys/<name>} without altering the request path. Taking this
 * type — rather than a bare {@code String} — at {@link VaultTransitVapidSigner}'s factory methods also makes the name
 * impossible to swap with the token in the positional argument list: the compiler tells them apart.
 *
 * <p>The constructor rejects a blank name and the characters that would change which URL the signer calls — {@code /}
 * (a further path segment), {@code ?} (a query), {@code #} (a fragment) and the space (not valid in a URI at all).
 * Vault itself does not allow {@code /} in a Transit key name, so this refuses no name a Transit key can actually
 * carry.
 *
 * @param value the Transit key name, e.g. {@code vapid}
 */
public record TransitKeyName(String value) {

    /**
     * Validates the key name.
     *
     * @throws NullPointerException if {@code value} is {@code null}
     * @throws IllegalArgumentException if {@code value} is blank or contains {@code /}, {@code ?}, {@code #} or a space
     */
    public TransitKeyName {
        Objects.requireNonNull(value, "keyName");
        if (value.isBlank()) {
            throw new IllegalArgumentException("keyName must not be blank");
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '/' || c == '?' || c == '#' || c == ' ') {
                throw new IllegalArgumentException("keyName contains '" + c + "' (at index " + i
                        + "), which would alter the /v1/<mount>/keys/<name> and /v1/<mount>/sign/<name> request"
                        + " paths — Vault Transit key names cannot contain it");
            }
        }
    }
}
