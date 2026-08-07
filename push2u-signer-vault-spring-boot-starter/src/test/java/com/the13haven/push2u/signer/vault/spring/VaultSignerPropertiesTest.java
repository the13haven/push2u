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
        // stand in for an actual value. The unset address prints null for the same reason: it must
        // stay distinguishable from the marker an unrenderable-but-configured address gets.
        VaultSignerProperties properties = new VaultSignerProperties(
                null, "transit", null, null, null, null, null, Duration.ofSeconds(30), Duration.ofSeconds(10), 1024);

        assertThat(properties.toString()).contains("token=null").contains("address=null");
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
    void anAuthorityWithASecondAtSignRendersAsTheMarker() {
        // Java parses "user@name:PASSWORD-MARKER@vault.example:8200" as a registry-based authority
        // — getHost() is null — so no component says where a credential ends and the host begins.
        // The host is not shown either, deliberately: an address of this shape can never be a valid
        // Vault address, the signer refuses it at startup naming the property, and reconstructing
        // "the host part" from the string would be exactly the guessing that used to leak.
        VaultSignerProperties properties =
                properties(URI.create("https://user@name:PASSWORD-MARKER@vault.example:8200"));

        assertThat(properties.toString())
                .doesNotContain("PASSWORD-MARKER")
                .doesNotContain("user@name")
                .doesNotContain("vault.example")
                .contains("address=<unrenderable address>");
    }

    @Test
    void aSchemelessAddressRendersAsTheMarker() {
        // "proxy-user:PROXY-PASSWORD-MARKER@vault.example:8200" — a host:port typed without a
        // scheme — parses as the scheme "proxy-user" with everything else opaque behind it: no
        // host, and the password sits outside any userinfo Java reports. Under the old string-level
        // cut the host was kept; it no longer is, because an address with no parsed host can never
        // be a valid Vault address (the signer refuses it at startup, naming the property), and
        // only a parse-level authority says which characters are safely printable.
        VaultSignerProperties properties =
                properties(URI.create("proxy-user:PROXY-PASSWORD-MARKER@vault.example:8200"));

        assertThat(properties.toString())
                .doesNotContain("PROXY-PASSWORD-MARKER")
                .doesNotContain("proxy-user")
                .doesNotContain("vault.example")
                .contains("address=<unrenderable address>");
    }

    @Test
    void anEmptyUserinfoIsNotMasked() {
        // "https://@vault.example:8200" delimits a userinfo that is empty — Java reports "" rather
        // than null — so no credential was configured, and a mask here would claim one exactly as
        // a "***" for an unset token would. The address is valid apart from the stray "@" and
        // renders as configured.
        assertThat(URI.create("https://@vault.example:8200").getUserInfo()).isEmpty();
        VaultSignerProperties properties = properties(URI.create("https://@vault.example:8200"));

        assertThat(properties.toString())
                .contains("address=https://@vault.example:8200")
                .doesNotContain("***@");
    }

    @Test
    void aRelativeReferenceRendersAsTheMarker() {
        // "/vault//a@b" has no scheme and no authority at all — nothing but path. Its "@" is an
        // ordinary path character, but the rendering no longer reasons about characters: an address
        // without a parsed scheme://host can never be a valid Vault address, so it is withheld
        // whole rather than echoed on the strength of a guess about which parts are safe.
        VaultSignerProperties properties = properties(URI.create("/vault//a@b"));

        assertThat(properties.toString())
                .contains("address=<unrenderable address>")
                .doesNotContain("/vault//a@b");
    }

    @Test
    void aCredentialCarryingASlashRendersAsTheMarker() {
        // Previously the leak this fix closes: "/" ends the authority as Java reads it, so both
        // addresses parse with no host and no userinfo, and the old string-level cut — anchored on
        // an "@" it could no longer find — printed the password whole. "/" is an ordinary character
        // in a generated password. Fail-closed, the whole address is withheld: no parsed host means
        // no component is known to be credential-free.
        assertThat(URI.create("user:PA/SS@vault.example:8200").getUserInfo()).isNull();
        assertThat(properties(URI.create("user:PA/SS@vault.example:8200")).toString())
                .doesNotContain("PA/SS")
                .doesNotContain("vault.example")
                .contains("address=<unrenderable address>");

        assertThat(URI.create("https://u:PA/SS@vault.example:8200").getUserInfo())
                .isNull();
        assertThat(properties(URI.create("https://u:PA/SS@vault.example:8200")).toString())
                .doesNotContain("PA/SS")
                .doesNotContain("vault.example")
                .contains("address=<unrenderable address>");
    }

    @Test
    void aCredentialAheadOfAQueryOrPathRendersAsTheMarker() {
        // The other previously pinned leak: "?" ends the authority before the "@", so
        // "https://u:PASS?@vault.example" parses with no host and the old query cut rendered it as
        // "https://u:PASS" — the password standing alone. The "/" variant parses hostless the same
        // way. Both are withheld whole now: no parsed host, nothing safely printable.
        assertThat(URI.create("https://u:PASS?@vault.example").getUserInfo()).isNull();
        assertThat(properties(URI.create("https://u:PASS?@vault.example")).toString())
                .doesNotContain("PASS")
                .doesNotContain("vault.example")
                .contains("address=<unrenderable address>");

        assertThat(URI.create("https://u:PASS/@vault.example").getUserInfo()).isNull();
        assertThat(properties(URI.create("https://u:PASS/@vault.example")).toString())
                .doesNotContain("PASS")
                .doesNotContain("vault.example")
                .contains("address=<unrenderable address>");
    }

    @Test
    void aCredentialWhoseHeadParsesAsHostAndPortRendersAsTheMarker() {
        // The subtlest of the leak class: when the text before a password's first "/" happens to
        // parse as host[:port], Java produces a perfectly server-based authority — user name as
        // the host, digits as the port — and drops the rest of the credential, "@" and real host
        // included, into the path. A host check alone passes these, so the guard keys on the "@"
        // in the parsed path: a credential in an authority is always delimited by "@", and a valid
        // Vault address path never carries one.
        assertThat(properties(URI.create("https://u:1971/restOfPassword@vault.example:8200"))
                        .toString())
                .doesNotContain("restOfPassword")
                .doesNotContain("1971")
                .doesNotContain("vault.example")
                .contains("address=<unrenderable address>");

        assertThat(properties(URI.create("https://u:/PASS@vault.example:8200")).toString())
                .doesNotContain("PASS")
                .doesNotContain("vault.example")
                .contains("address=<unrenderable address>");

        assertThat(properties(URI.create("https://user.name:443/secret@vault.example"))
                        .toString())
                .doesNotContain("secret")
                .doesNotContain("user.name")
                .doesNotContain("vault.example")
                .contains("address=<unrenderable address>");
    }

    @Test
    void aPercentEncodedPathRendersAsTheMarker() {
        // The encoded sliver of the same class: "%40" is "@" spelt without the literal character,
        // so a literal-"@" guard alone would render "https://u:1971/rest%40vault.example:8200"
        // whole. The "@"-delimiter argument reasons about literal text; an encoded path is not
        // literal text, so any "%" routes to the marker rather than being decoded to some depth
        // and reasoned about — which is also what closes the double-encoded "%2540", one decode
        // away from "%40" and two from "@". A valid Vault address path admits neither "@" nor "%",
        // so no renderable address is lost.
        assertThat(properties(URI.create("https://u:1971/rest%40vault.example:8200"))
                        .toString())
                .doesNotContain("rest%40vault")
                .doesNotContain("vault.example")
                .contains("address=<unrenderable address>");

        // An encoded "@" beside a literal one: already caught by the literal guard, pinned so the
        // pair of guards cannot regress independently.
        assertThat(properties(URI.create("https://u:1971/re%40st@vault.example:8200"))
                        .toString())
                .doesNotContain("re%40st")
                .doesNotContain("vault.example")
                .contains("address=<unrenderable address>");

        assertThat(properties(URI.create("https://u:1971/rest%2540vault.example:8200"))
                        .toString())
                .doesNotContain("rest%2540vault")
                .doesNotContain("vault.example")
                .contains("address=<unrenderable address>");
    }

    @Test
    void anAddressCarryingAQueryOrFragmentRendersAsTheMarker() {
        // A base address may carry neither — the signer refuses one at startup, naming the property
        // — but the binding that fills this record happens first, and a Vault query can name
        // secrets. The address used to render truncated at the "?"; that truncation is what left
        // "https://u:PASS?@vault.example" printing a password, so a query or fragment now withholds
        // the address whole rather than trusting a cut.
        VaultSignerProperties properties =
                properties(URI.create("https://vault.example:8200?token=QUERY-MARKER#FRAGMENT-MARKER"));

        assertThat(properties.toString())
                .doesNotContain("QUERY-MARKER")
                .doesNotContain("FRAGMENT-MARKER")
                .doesNotContain("vault.example")
                .contains("address=<unrenderable address>");
    }

    @Test
    void validAddressShapesRenderAsConfigured() {
        // The marker must never swallow an address the signer would accept: every shape here passes
        // the signer's validation and renders exactly as configured (userinfo aside, masked above).
        assertThat(properties(URI.create("https://vault.example")).toString())
                .contains("address=https://vault.example,");
        assertThat(properties(URI.create("https://vault.example:8200")).toString())
                .contains("address=https://vault.example:8200,");
        assertThat(properties(URI.create("https://gw.example/vault")).toString())
                .contains("address=https://gw.example/vault,");
        assertThat(properties(URI.create("https://[::1]:8200")).toString()).contains("address=https://[::1]:8200,");
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
