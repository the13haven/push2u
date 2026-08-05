/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class EndpointsTest {

    private static final String ENDPOINT =
            "https://fcm.googleapis.com/fcm/send/dCbWEKuAbCk:APA91bEXAMPLE?auth=secret-token";

    @Test
    void redactKeepsOriginAndFingerprintButNeverThePathOrQuery() {
        String redacted = Endpoints.redact(ENDPOINT);

        assertThat(redacted)
                .startsWith("https://fcm.googleapis.com/…#")
                .doesNotContain("fcm/send")
                .doesNotContain("dCbWEKuAbCk")
                .doesNotContain("APA91bEXAMPLE")
                .doesNotContain("auth=secret-token");
        assertThat(redacted.substring(redacted.indexOf('#') + 1))
                .as("fingerprint is 16 lowercase hex characters")
                .hasSize(16)
                .matches("[0-9a-f]{16}");
    }

    @Test
    void redactIsDeterministic() {
        assertThat(Endpoints.redact(ENDPOINT)).isEqualTo(Endpoints.redact(ENDPOINT));
    }

    @Test
    void redactPreservesAnExplicitPort() {
        assertThat(Endpoints.redact("https://push.example.net:8443/token-path"))
                .startsWith("https://push.example.net:8443/…#");
    }

    @Test
    void redactDistinguishesEndpointsWithSameOriginButDifferentPaths() {
        String a = Endpoints.redact("https://push.example.net/subscriber-a");
        String b = Endpoints.redact("https://push.example.net/subscriber-b");

        assertThat(a).startsWith("https://push.example.net/…#");
        assertThat(b).startsWith("https://push.example.net/…#");
        assertThat(a).isNotEqualTo(b);
    }

    @Test
    void redactDistinguishesEndpointsDifferingOnlyInQuery() {
        String a = Endpoints.redact("https://push.example.net/send?token=alpha");
        String b = Endpoints.redact("https://push.example.net/send?token=beta");

        assertThat(a).isNotEqualTo(b);
        assertThat(a).doesNotContain("token=alpha");
        assertThat(b).doesNotContain("token=beta");
    }

    @Test
    void redactNeverThrowsAndNeverEchoesUnparseableInput() {
        assertThat(Endpoints.redact(null)).isEqualTo("<null endpoint>");

        String garbage = "ht!tp:// not a uri at all";
        assertThatCode(() -> Endpoints.redact(garbage)).doesNotThrowAnyException();
        assertThat(Endpoints.redact(garbage)).startsWith("<opaque endpoint>#").doesNotContain("not a uri");
    }

    @Test
    void redactTreatsSchemelessOrHostlessUriAsOpaque() {
        assertThat(Endpoints.redact("/relative/path-only"))
                .startsWith("<opaque endpoint>#")
                .doesNotContain("relative");
        assertThat(Endpoints.redact("mailto:someone@example.com"))
                .startsWith("<opaque endpoint>#")
                .doesNotContain("someone@example.com");
    }

    @Test
    void redactNeverEchoesUserinfoCredentials() {
        String redacted = Endpoints.redact("https://user:pass@push.example/p");

        assertThat(redacted).doesNotContain("user").doesNotContain("pass").doesNotContain("/p#");
        assertThat(redacted).startsWith("https://push.example/…#");
    }

    @Test
    void emptyEndpointIsRedactableButNotAcceptable() {
        assertThatCode(() -> Endpoints.redact("")).doesNotThrowAnyException();
        assertThat(Endpoints.redact("")).startsWith("<opaque endpoint>#");

        assertThatThrownBy(() -> Endpoints.requireSecure("")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void requireSecureAcceptsHttps() {
        assertThatCode(() -> Endpoints.requireSecure("https://push.example.net/subscriber-token"))
                .doesNotThrowAnyException();
    }

    @Test
    void requireSecureRejectsHttp() {
        assertThatThrownBy(() -> Endpoints.requireSecure("http://push.example.net/subscriber-token"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("https")
                .hasMessageNotContaining("subscriber-token");
    }

    @Test
    void requireSecureRejectsRelativeUriAndUriWithoutHost() {
        assertThatThrownBy(() -> Endpoints.requireSecure("/just/a/path"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageNotContaining("/just/a/path");
        assertThatThrownBy(() -> Endpoints.requireSecure("https:///no-host-here"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageNotContaining("no-host-here");
    }

    @Test
    void requireSecureRejectsHostnameWithUnderscore() {
        // java.net.URI parses "exa_mple.com" as a registry-based authority (an underscore is
        // invalid in a hostname per RFC 1123) and returns getHost() == null, so the null-host
        // check rejects it. Deliberate behavior, pinned here so it does not read as a bug.
        assertThatThrownBy(() -> Endpoints.requireSecure("https://exa_mple.com/subscriber-token"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("absolute https URL")
                .hasMessageNotContaining("subscriber-token");
    }

    @Test
    void requireSecureRejectsUnparseableUriWithoutEchoingIt() {
        assertThatThrownBy(() -> Endpoints.requireSecure("http://exa mple.com/secret-path"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("subscription endpoint is not a valid URI")
                .hasNoCause();
    }

    @Test
    void requireSecureRejectsPlaintextLoopbackLikeAnyOtherHttpEndpoint() {
        // RFC 8030 requires TLS between the application server and the push service, and this
        // library grants no loopback exception — not even for its own tests, which run their
        // in-process receiver over real TLS (MockPushReceiver + LoopbackTls). Pinned so a
        // "harmless" localhost carve-out cannot quietly reintroduce a plaintext escape hatch.
        for (String plaintextLoopback :
                new String[] {"http://127.0.0.1/push", "http://127.0.0.1:8443/push", "http://localhost:8443/push"}) {
            assertThatThrownBy(() -> Endpoints.requireSecure(plaintextLoopback))
                    .as("%s", plaintextLoopback)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("absolute https URL");
        }
    }
}
