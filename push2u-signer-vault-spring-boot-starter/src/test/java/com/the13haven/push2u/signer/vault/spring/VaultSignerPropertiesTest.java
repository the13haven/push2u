/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.time.Duration;

import org.junit.jupiter.api.Test;

/**
 * {@link VaultSignerProperties} renders no secret in {@code toString()}. Records generate a {@code toString()} that
 * prints every component, so without an override the bound Vault token would ride into any accidental
 * {@code log.info("{}", properties)} or debugger dump in the consuming application — push2u itself never stringifies
 * the record, but the hazard is handed to whoever does.
 */
class VaultSignerPropertiesTest {

    @Test
    void toStringMasksTheToken() {
        VaultSignerProperties properties = new VaultSignerProperties(
                URI.create("https://vault.example:8200"),
                "transit",
                "vapid",
                "hvs.SECRET-TOKEN-MARKER",
                "BPublicKeyMarker",
                3,
                Duration.ofSeconds(30),
                Duration.ofSeconds(10),
                1024 * 1024);

        assertThat(properties.toString())
                .doesNotContain("hvs.SECRET-TOKEN-MARKER")
                .contains("***")
                .as("non-secret components stay readable")
                .contains("https://vault.example:8200")
                .contains("vapid")
                .contains("BPublicKeyMarker");
    }

    @Test
    void anUnsetTokenIsRenderedAsNullNotAsAMask() {
        // "***" for an unset token would read as "a token is configured" — the mask must only
        // stand in for an actual value.
        VaultSignerProperties properties = new VaultSignerProperties(
                null, "transit", null, null, null, null, Duration.ofSeconds(30), Duration.ofSeconds(10), 1024);

        assertThat(properties.toString()).contains("token=null");
    }
}
