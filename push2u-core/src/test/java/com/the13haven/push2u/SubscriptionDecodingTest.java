/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Base64;

import org.junit.jupiter.api.Test;

/**
 * What {@link Subscription#fromBase64} says when it refuses. Unlike the VAPID pair, these two values arrive from a
 * browser through the application's own REST boundary, so the failure lands on a developer holding a request body — and
 * "which of the two fields was malformed" is the entire question.
 *
 * <p>The JDK decoder's message is {@code "Illegal base64 character 2b"} and nothing else: identical for either field,
 * naming neither. {@code 2b} is {@code '+'}, which means the value was encoded with the standard base64 alphabet rather
 * than the URL-safe one the Push API uses.
 *
 * <p>The other half of this is what must <em>not</em> be in the message. Both values are whatever a client posted, so
 * quoting one would put attacker-chosen text into the application's logs.
 */
class SubscriptionDecodingTest {

    private static final String ENDPOINT = "https://push.example.net/subscriber-token";
    private static final String AUTH = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[16]);

    private static String p256dh() {
        return TestVectors.UA_PUBLIC;
    }

    /**
     * A {@code '+'} spliced in at a fixed position rather than substituted for a {@code '-'}: the value may contain no
     * {@code '-'} at all, and a mutation that sometimes does nothing is a test that sometimes asserts nothing.
     */
    private static String withStandardAlphabetCharacter(String base64url) {
        return "+" + base64url.substring(1);
    }

    @Test
    void aMalformedP256dhNamesThatFieldAndNotTheOther() {
        assertThatThrownBy(() -> Subscription.fromBase64(ENDPOINT, withStandardAlphabetCharacter(p256dh()), AUTH))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("p256dh is not valid base64url")
                .hasMessageContaining("'-' and '_'")
                .hasMessageNotContaining("auth");
    }

    @Test
    void aMalformedAuthNamesThatFieldRatherThanTheKey() {
        assertThatThrownBy(() -> Subscription.fromBase64(ENDPOINT, p256dh(), withStandardAlphabetCharacter(AUTH)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("auth is not valid base64url")
                .hasMessageNotContaining("p256dh");
    }

    /** The value is client-supplied, so it must not travel into a log line by way of the exception. */
    @Test
    void theRejectedValueIsNotQuotedBack() {
        String hostile = withStandardAlphabetCharacter(p256dh());

        assertThatThrownBy(() -> Subscription.fromBase64(ENDPOINT, hostile, AUTH))
                .hasMessageNotContaining(hostile)
                .hasMessageNotContaining(hostile.substring(1, 20))
                .hasMessageContaining("Illegal base64 character");
    }

    /**
     * Well-formed base64url of the wrong length is a different failure, and the compact constructor already named the
     * field. Pinned so the decode message added here does not swallow it.
     */
    @Test
    void aWellFormedButShortKeyStillFailsOnItsLength() {
        assertThatThrownBy(() -> Subscription.fromBase64(ENDPOINT, p256dh().substring(0, 40), AUTH))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("p256dh must be a 65-byte uncompressed P-256 point");
    }

    @Test
    void aNullValueIsNamedRatherThanFailingInsideTheDecoder() {
        assertThatThrownBy(() -> Subscription.fromBase64(ENDPOINT, null, AUTH))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("p256dh");
        assertThatThrownBy(() -> Subscription.fromBase64(ENDPOINT, p256dh(), null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("auth");
    }

    /** The vector the rest of the suite uses must keep decoding, so the checks above cannot pass vacuously. */
    @Test
    void aWellFormedPairStillDecodes() {
        Subscription subscription = Subscription.fromBase64(ENDPOINT, p256dh(), AUTH);

        assertThat(subscription.p256dh()).hasSize(65).startsWith((byte) 0x04);
        assertThat(subscription.auth()).hasSize(16);
    }

    /** An empty value decodes to zero bytes, so it is a length failure and must stay one. */
    @Test
    void anEmptyValueIsALengthFailureRatherThanADecodeFailure() {
        assertThatThrownBy(() -> Subscription.fromBase64(ENDPOINT, "", AUTH))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("p256dh must be a 65-byte")
                .hasMessageNotContaining("base64url");
    }
}
