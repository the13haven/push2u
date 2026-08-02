package io.push2u;

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
}
