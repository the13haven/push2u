/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Base64;

import org.junit.jupiter.api.Test;

/**
 * What {@link VapidKeys#fromBase64} says when it refuses. The pair is the first thing anyone configures and the last
 * thing they can debug from the inside, so every refusal has to name the half it is about.
 *
 * <p>The decode failure is the one worth its own test. The JDK decoder's message is {@code "Illegal base64 character
 * 2b"} and nothing else — identical for either argument, mentioning neither VAPID nor which value was wrong. {@code 2b}
 * is {@code '+'}: a key carrying one was encoded with the standard base64 alphabet rather than the URL-safe one, which
 * is what an {@code openssl base64} pipeline or a default encoder in another language produces.
 */
class VapidKeysDecodingTest {

    /** A well-formed pair, so each case below is wrong in exactly one way. */
    private static final VapidKeys VALID = PushTestSupport.generateVapidKeys();

    private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();

    private static String publicKey() {
        return BASE64URL.encodeToString(VALID.publicKey());
    }

    private static String privateKey() {
        // privateScalar() is package-private and this test shares the package — the point is to encode
        // exactly what fromBase64 will be asked to decode back.
        return BASE64URL.encodeToString(VALID.privateScalar());
    }

    /**
     * A {@code '+'} spliced in at a fixed position rather than substituted for a {@code '-'}: a random key contains no
     * {@code '-'} about half the time, so substituting would be a test that sometimes asserts nothing.
     */
    private static String withStandardAlphabetCharacter(String base64url) {
        return "+" + base64url.substring(1);
    }

    @Test
    void aPublicKeyThatIsNotBase64urlNamesThePublicHalf() {
        assertThatThrownBy(() -> VapidKeys.fromBase64(withStandardAlphabetCharacter(publicKey()), privateKey()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("VAPID public key is not valid base64url")
                .hasMessageContaining("'-' and '_'")
                .hasMessageNotContaining("private");
    }

    @Test
    void aPrivateKeyThatIsNotBase64urlNamesThePrivateHalf() {
        assertThatThrownBy(() -> VapidKeys.fromBase64(publicKey(), withStandardAlphabetCharacter(privateKey())))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("VAPID private key is not valid base64url");
    }

    /** The decoder's own text is kept as the cause, so the offending character is still recoverable. */
    @Test
    void theDecodersOwnMessageSurvivesAsTheCause() {
        assertThatThrownBy(() -> VapidKeys.fromBase64(withStandardAlphabetCharacter(publicKey()), privateKey()))
                .hasMessageContaining("Illegal base64 character 2b")
                .cause()
                .isInstanceOf(IllegalArgumentException.class);
    }

    /**
     * Well-formed base64url of the wrong length is a different failure, and one the constructor already named. Pinned
     * so the decode message added here does not swallow it.
     */
    @Test
    void aWellFormedButShortKeyStillFailsOnItsLength() {
        assertThatThrownBy(() -> VapidKeys.fromBase64(publicKey().substring(0, 40), privateKey()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("VAPID public key must be a 65-byte uncompressed P-256 point");
    }
}
