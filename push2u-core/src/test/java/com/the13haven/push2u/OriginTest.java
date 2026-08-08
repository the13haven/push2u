/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;

import org.junit.jupiter.api.Test;

/**
 * Tests for the RFC 6454 §6.1 Unicode origin serialization used as the VAPID {@code aud} claim (RFC 8292 §2).
 * {@code java.net.URI} does none of this normalization itself — it preserves scheme/host case and explicit default
 * ports — so each rule is pinned here.
 */
class OriginTest {

    @Test
    void lowercasesSchemeAndHost() {
        assertThat(Origin.serialize(URI.create("HTTPS://PUSH.Example/subscriber-token")))
                .isEqualTo("https://push.example");
    }

    @Test
    void dropsAnExplicitDefaultHttpsPort() {
        assertThat(Origin.serialize(URI.create("https://push.example:443/subscriber-token")))
                .isEqualTo("https://push.example");
    }

    @Test
    void dropsAnExplicitDefaultHttpPort() {
        assertThat(Origin.serialize(URI.create("http://push.example:80/subscriber-token")))
                .isEqualTo("http://push.example");
    }

    @Test
    void keepsANonDefaultPort() {
        assertThat(Origin.serialize(URI.create("https://push.example:8443/subscriber-token")))
                .isEqualTo("https://push.example:8443");
    }

    @Test
    void defaultPortsBelongToTheirScheme() {
        // 80 is http's default, not https's — RFC 6454 §6.1 only drops the port of *this* scheme.
        assertThat(Origin.serialize(URI.create("https://push.example:80/subscriber-token")))
                .isEqualTo("https://push.example:80");
    }

    @Test
    void convertsIdnaALabelsToUnicode() {
        assertThat(Origin.serialize(URI.create("https://xn--e1afmkfd.xn--80akhbyknj4f/subscriber-token")))
                .isEqualTo("https://пример.испытание");
    }

    @Test
    void convertsUppercaseALabels() {
        // An uppercase A-label must come out as a lowercase U-label — RFC 6454 §6.1 converts the
        // host to Unicode and §4 lowercases it, whatever case the endpoint used.
        assertThat(Origin.serialize(URI.create("https://XN--E1AFMKFD.XN--80AKHBYKNJ4F:443/subscriber-token")))
                .isEqualTo("https://пример.испытание");
    }

    @Test
    void keepsAnIpv6LiteralWithItsBrackets() {
        assertThat(Origin.serialize(URI.create("https://[::1]/subscriber-token")))
                .isEqualTo("https://[::1]");
        assertThat(Origin.serialize(URI.create("https://[::1]:8443/subscriber-token")))
                .isEqualTo("https://[::1]:8443");
        assertThat(Origin.serialize(URI.create("https://[::1]:443/subscriber-token")))
                .as("the default port is dropped for address literals too")
                .isEqualTo("https://[::1]");
    }

    @Test
    void keepsAnIpv4Literal() {
        assertThat(Origin.serialize(URI.create("https://127.0.0.1/subscriber-token")))
                .isEqualTo("https://127.0.0.1");
        assertThat(Origin.serialize(URI.create("https://127.0.0.1:8443/subscriber-token")))
                .isEqualTo("https://127.0.0.1:8443");
    }

    @Test
    void hostWithATrailingDotDoesNotBreakTheSerialization() {
        // The trailing dot leaves an empty final DNS label, which IDNA processing may reject;
        // the origin must still serialize rather than fail the send.
        assertThat(Origin.serialize(URI.create("https://example.com./subscriber-token")))
                .isEqualTo("https://example.com.");
    }

    @Test
    void userinfoNeverAppearsInTheOrigin() {
        // The endpoint is a capability URL; whatever credentials sit in its authority must not
        // leak into the aud claim — RFC 6454 §6.1 serializes only scheme, host, and port.
        assertThat(Origin.serialize(URI.create("https://user:pass@push.example/subscriber-token")))
                .isEqualTo("https://push.example");
    }

    @Test
    void userinfoShapedLikeAnAllowedHostCannotDisplaceTheRealHost() {
        // Security-load-bearing beyond the aud claim (see the class Javadoc): EndpointPolicies
        // compares allowlist entries against this output, so an endpoint whose userinfo spells an
        // allowed host must still serialize to the REAL host. Rewriting serialize() around
        // URI.getAuthority() — which includes userinfo — would fail here before it ships.
        assertThat(Origin.serialize(URI.create("https://fcm.googleapis.com@evil.example/subscriber-token")))
                .isEqualTo("https://evil.example");
    }

    @Test
    void schemelessUriIsRejectedWithoutEchoingIt() {
        assertThatThrownBy(() -> Origin.serialize(URI.create("/relative/secret-path")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("no scheme or host")
                .hasMessageNotContaining("secret-path");
    }

    @Test
    void hostlessUriIsRejectedWithoutEchoingIt() {
        assertThatThrownBy(() -> Origin.serialize(URI.create("mailto:someone@example.com")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("no scheme or host")
                .hasMessageNotContaining("someone@example.com");
    }

    @Test
    void rawUnicodeHostNeverReachesTheSerializer() {
        // java.net.URI parses a non-ASCII authority as registry-based and returns
        // getHost() == null, so an already-Unicode host is rejected as hostless — the U-label
        // form only ever appears in aud as the output of our own A-label conversion. Pinned so
        // this stays deliberate.
        assertThat(URI.create("https://пример.испытание/subscriber-token").getHost())
                .isNull();
        assertThatThrownBy(() -> Origin.serialize(URI.create("https://пример.испытание/subscriber-token")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageNotContaining("subscriber-token");
    }

    @Test
    void serializeIsExactlyThePartsSerialization() {
        // serialize() is a projection of parts(): the allowlist reads the components while the aud
        // claim reads the string, and one endpoint must never get two answers. Every case pinned
        // above is replayed here, so a change that moved one and not the other fails.
        for (String endpoint : new String[] {
            "HTTPS://PUSH.Example/subscriber-token",
            "https://push.example:443/subscriber-token",
            "http://push.example:80/subscriber-token",
            "https://push.example:8443/subscriber-token",
            "https://push.example:80/subscriber-token",
            "https://xn--e1afmkfd.xn--80akhbyknj4f/subscriber-token",
            "https://XN--E1AFMKFD.XN--80AKHBYKNJ4F:443/subscriber-token",
            "https://[::1]:8443/subscriber-token",
            "https://127.0.0.1:8443/subscriber-token",
            "https://example.com./subscriber-token",
            "https://user:pass@push.example/subscriber-token",
            "https://fcm.googleapis.com@evil.example/subscriber-token"
        }) {
            URI uri = URI.create(endpoint);
            assertThat(Origin.parts(uri).serialized()).as("%s", endpoint).isEqualTo(Origin.serialize(uri));
        }
    }

    @Test
    void partsExposeTheSchemeHostAndRawPort() {
        // The port is the URI's own: absent stays -1 rather than being replaced by the scheme's
        // default, and an explicit 443 stays 443 even though the serialization drops it. A rule
        // testing the port itself needs the raw value, not the serialization's per-scheme drop.
        Origin.Parts noPort = Origin.parts(URI.create("HTTPS://PUSH.Example/subscriber-token"));
        assertThat(noPort.scheme()).isEqualTo("https");
        assertThat(noPort.host()).isEqualTo("push.example");
        assertThat(noPort.port()).isEqualTo(-1);
        assertThat(noPort.serialized()).isEqualTo("https://push.example");

        Origin.Parts defaultPort = Origin.parts(URI.create("https://push.example:443/subscriber-token"));
        assertThat(defaultPort.port()).isEqualTo(443);
        assertThat(defaultPort.serialized()).isEqualTo("https://push.example");

        Origin.Parts otherPort = Origin.parts(URI.create("https://push.example:8443/subscriber-token"));
        assertThat(otherPort.port()).isEqualTo(8443);
        assertThat(otherPort.serialized()).isEqualTo("https://push.example:8443");
    }

    @Test
    void normalizationNeverMovesALabelBoundary() {
        // Load-bearing for suffix matching: decoding an A-label can only insert code points at or
        // above U+0080, so a U-label can never gain a '.'. The label count therefore survives
        // normalization and a boundary in the input is a boundary in the output.
        Origin.Parts parts = Origin.parts(URI.create("https://UPPER.xn--BCHER-KVA.example/subscriber-token"));

        assertThat(parts.host()).isEqualTo("upper.bücher.example");
        assertThat(parts.host().split("\\.", -1)).hasSize(3);
        assertThat(parts.host().chars().filter(c -> c == '.').count())
                .as("no dot is created or destroyed by decoding")
                .isEqualTo(2);
    }
}
