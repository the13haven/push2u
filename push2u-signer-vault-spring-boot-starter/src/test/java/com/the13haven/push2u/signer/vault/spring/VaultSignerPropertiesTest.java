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
 * prints every component, so without an override the bound Vault token — and any credentials carried in the address —
 * would ride into any accidental {@code log.info("{}", properties)} or debugger dump in the consuming application;
 * push2u itself never stringifies the record, but the hazard is handed to whoever does.
 */
class VaultSignerPropertiesTest {

    @Test
    void toStringMasksTheToken() {
        VaultSignerProperties properties = properties(URI.create("https://vault.example:8200"));

        assertThat(properties.toString())
                .doesNotContain("hvs.SECRET-TOKEN-MARKER")
                .contains("***")
                .as("non-secret components stay readable")
                .contains("https://vault.example:8200")
                .contains("team-a/sub")
                .contains("vapid")
                .contains("BPublicKeyMarker");
    }

    @Test
    void anUnsetTokenIsRenderedAsNullNotAsAMask() {
        // "***" for an unset token would read as "a token is configured" — the mask must only
        // stand in for an actual value.
        VaultSignerProperties properties = new VaultSignerProperties(
                null, "transit", null, null, null, null, null, Duration.ofSeconds(30), Duration.ofSeconds(10), 1024);

        assertThat(properties.toString()).contains("token=null");
    }

    @Test
    void toStringMasksUserinfoInTheAddress() {
        // The address may legitimately carry userinfo — basic auth for a proxy in front of Vault,
        // preserved by the signer for a custom transport to honour — and that password is exactly
        // as secret as the token. Neither half of the userinfo is printed: the user name is the
        // operator's too.
        VaultSignerProperties properties =
                properties(URI.create("https://proxy-user:PROXY-PASSWORD-MARKER@vault.example:8200/vault"));

        assertThat(properties.toString())
                .doesNotContain("PROXY-PASSWORD-MARKER")
                .doesNotContain("proxy-user")
                .as("the mask must not read as \"no credentials configured\", and the rest stays diagnosable")
                .contains("address=https://***@vault.example:8200/vault");
    }

    @Test
    void anAddressWithoutUserinfoCarriesNoCredentialMarker() {
        // The mirror of the token's null: a mask on an address that has no credentials would claim
        // credentials are configured.
        VaultSignerProperties properties = properties(URI.create("https://vault.example:8200/vault"));

        assertThat(properties.toString())
                .contains("address=https://vault.example:8200/vault")
                .doesNotContain("***@");
    }

    @Test
    void toStringMasksUserinfoUpToItsLastAtSign() {
        // An "@" may recur inside the userinfo (Java parses such an authority as registry-based, so
        // the signer refuses the address at startup — but this record binds before that, and holds
        // whatever was configured). The last "@" before the path is the delimiter, so masking up to
        // it leaves no part of the credential behind.
        VaultSignerProperties properties =
                properties(URI.create("https://user@name:PASSWORD-MARKER@vault.example:8200"));

        assertThat(properties.toString())
                .doesNotContain("PASSWORD-MARKER")
                .doesNotContain("user@name")
                .contains("address=https://***@vault.example:8200");
    }

    @Test
    void toStringMasksCredentialsInAnAddressThatHasNoAuthority() {
        // "user:secret@vault.example:8200" — the address as an operator types a host:port, without
        // a scheme — is a valid URI whose scheme is "user" and whose whole scheme-specific part is
        // "secret@vault.example:8200": no "//", so URI.getUserInfo() is null and an authority-only
        // rule would print the password verbatim. The signer refuses such an address (no host), but
        // this record binds before any signer exists, and holds it either way.
        VaultSignerProperties properties =
                properties(URI.create("proxy-user:PROXY-PASSWORD-MARKER@vault.example:8200"));

        assertThat(properties.toString())
                .doesNotContain("PROXY-PASSWORD-MARKER")
                .doesNotContain("proxy-user")
                .contains("address=***@vault.example:8200");
    }

    @Test
    void anEmptyUserinfoIsNotMasked() {
        // "https://@vault.example:8200" delimits a userinfo that is empty — no credential was
        // configured, so a mask here would claim one exactly as a "***" for an unset token would.
        VaultSignerProperties properties = properties(URI.create("https://@vault.example:8200"));

        assertThat(properties.toString())
                .contains("address=https://@vault.example:8200")
                .doesNotContain("***@");
    }

    @Test
    void aDoubleSlashInThePathIsNotAnAuthority() {
        // An authority is the "//" right after the scheme's colon and nothing else. A "//" further
        // along is an empty path segment, and the "@" behind it is an ordinary path character —
        // masking there would both claim credentials that do not exist and mangle the address.
        VaultSignerProperties properties = properties(URI.create("/vault//a@b"));

        assertThat(properties.toString()).contains("address=/vault//a@b").doesNotContain("***@");
    }

    @Test
    void toStringDropsAQueryAndFragmentFromTheAddress() {
        // A base address may carry neither — the signer refuses one at startup, naming the property
        // — but the binding that fills this record happens first, and a Vault query can name
        // secrets, so a value that is present anyway must not be printed on the way there.
        VaultSignerProperties properties =
                properties(URI.create("https://vault.example:8200?token=QUERY-MARKER#FRAGMENT-MARKER"));

        assertThat(properties.toString())
                .doesNotContain("QUERY-MARKER")
                .doesNotContain("FRAGMENT-MARKER")
                .contains("address=https://vault.example:8200");
    }

    /** The record with everything but the address fixed, so a test names only what it is about. */
    private static VaultSignerProperties properties(URI address) {
        return new VaultSignerProperties(
                address,
                "transit",
                "team-a/sub",
                "vapid",
                "hvs.SECRET-TOKEN-MARKER",
                "BPublicKeyMarker",
                3,
                Duration.ofSeconds(30),
                Duration.ofSeconds(10),
                1024 * 1024);
    }
}
