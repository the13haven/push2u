/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * What the recorded call refuses to print, and what it refuses to share. The endpoint is a capability URL and the
 * {@code Authorization} header carries a VAPID token; both may be real in a consumer's integration test, and a failed
 * assertion's message is exactly how such a value would reach a CI log — so the rendering is asserted negatively, on
 * the absence of the secret halves, not only positively on what it keeps.
 */
final class SentPushTest {

    private static final String CAPABILITY_PATH = "wp/eHl6LXNlY3JldC1jYXBhYmlsaXR5";
    private static final URI ENDPOINT = URI.create("https://push.example.net/" + CAPABILITY_PATH);
    private static final String VAPID_TOKEN = "vapid t=eyJhbGciOiJFUzI1NiJ9.secret.signature, k=BFakePublicKey";

    /** Distinctive on purpose: no substring of it can occur in an origin or a hex fingerprint by accident. */
    private static final String TTL_VALUE = "TTL-VALUE-MUST-NOT-PRINT";

    @Test
    void toStringCarriesNeitherTheCapabilityPathNorAnyHeaderValue() {
        SentPush sent = new SentPush(ENDPOINT, Map.of("Authorization", VAPID_TOKEN, "TTL", TTL_VALUE), 120);

        String rendered = sent.toString();

        assertThat(rendered).doesNotContain(CAPABILITY_PATH);
        assertThat(rendered).doesNotContain(VAPID_TOKEN);
        assertThat(rendered).doesNotContain(TTL_VALUE);
        assertThat(rendered)
                .as("the origin survives redaction, so a failure still names the service")
                .contains("push.example.net");
        assertThat(rendered).as("header names are printed without their values").contains("Authorization");
        assertThat(rendered).contains("TTL");
        assertThat(rendered).contains("bodyBytes=120");
    }

    @Test
    void headersAreAnImmutableCopyOfWhatWasPassed() {
        Map<String, String> mutable = new HashMap<>();
        mutable.put("TTL", "60");
        SentPush sent = new SentPush(ENDPOINT, mutable, 1);

        mutable.put("TTL", "0");

        assertThat(sent.headers())
                .as("a later change to the caller's map does not reach the record")
                .containsEntry("TTL", "60");
        assertThatThrownBy(() -> sent.headers().put("TTL", "0")).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void aNegativeBodyLengthIsRefused() {
        assertThatThrownBy(() -> new SentPush(ENDPOINT, Map.of(), -1)).isInstanceOf(IllegalArgumentException.class);
    }
}
