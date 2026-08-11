/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static com.the13haven.push2u.TestVectors.b64;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Base64;

import org.junit.jupiter.api.Test;

/**
 * {@link VapidKeys#encodePublicKey}, the direction {@link VapidKeys#fromBase64} does not have: the 65-byte X9.62 point
 * as the string a browser takes as its {@code applicationServerKey}. Three details decide whether the browser accepts
 * it — the URL-safe alphabet of RFC 4648 §5, the absence of padding, and the bytes being the raw point rather than a
 * SubjectPublicKeyInfo — and each is pinned below, because each fails at {@code subscribe(...)} rather than here.
 *
 * <p>The vector is RFC 8292 §2.4's own application-server key, so the expected string is published rather than whatever
 * this encoder currently produces.
 */
class VapidKeysEncodingTest {

    private static final byte[] RFC8292_PUBLIC_KEY = b64(TestVectors.VAPID_PUBLIC_K);

    @Test
    void encodesTheRfc8292ExampleKeyToTheStringTheRfcPublishes() {
        assertThat(VapidKeys.encodePublicKey(RFC8292_PUBLIC_KEY)).isEqualTo(TestVectors.VAPID_PUBLIC_K);
    }

    /**
     * The alphabet and the padding are pinned against the same bytes in the standard alphabet — what a default
     * {@code java.util.Base64} encoder produces, and the mistake {@link VapidKeys#fromBase64} already has to name when
     * it refuses a key. This vector happens to exercise both substituted characters, which the first assertion states
     * rather than assumes: on a key containing neither, the comparison would hold for an encoder using either alphabet.
     */
    @Test
    void spellsTheKeyInTheUrlSafeAlphabetWithoutPadding() {
        String standard = Base64.getEncoder().encodeToString(RFC8292_PUBLIC_KEY);
        assertThat(standard)
                .as("the vector exercises both characters the URL-safe alphabet substitutes, and the padding")
                .contains("+")
                .contains("/")
                .endsWith("=");

        assertThat(VapidKeys.encodePublicKey(RFC8292_PUBLIC_KEY))
                .doesNotContain("+")
                .doesNotContain("/")
                .doesNotContain("=")
                .isEqualTo(standard.replace('+', '-').replace('/', '_').replace("=", ""));
    }

    /**
     * The local-keys mode: whatever string {@link VapidKeys#fromBase64} was configured with comes back out of the
     * encoder unchanged, so an application serving it to its frontend need keep no second copy beside the pair.
     */
    @Test
    void returnsTheStringFromBase64WasConfiguredWith() {
        VapidKeys generated = PushTestSupport.generateVapidKeys();
        Base64.Encoder base64url = Base64.getUrlEncoder().withoutPadding();
        String publicKey = base64url.encodeToString(generated.publicKey());

        VapidKeys configured = VapidKeys.fromBase64(publicKey, base64url.encodeToString(generated.privateScalar()));

        assertThat(VapidKeys.encodePublicKey(configured.publicKey())).isEqualTo(publicKey);
    }

    /**
     * The full on-curve check, not the structural one: a {@code VapidKeys} static encoding what a {@code VapidKeys}
     * constructor refuses would hold one value to two standards, and the string it would produce is one
     * {@code pushManager.subscribe(...)} rejects anyway — in a browser console, far from this call.
     */
    @Test
    void refusesAWellFramedPointThatIsNotOnTheCurve() {
        byte[] offCurve = RFC8292_PUBLIC_KEY.clone();
        offCurve[offCurve.length - 1] ^= 0x01;

        assertThatThrownBy(() -> VapidKeys.encodePublicKey(offCurve))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("VAPID public key")
                .hasMessageContaining("curve equation");
    }

    @Test
    void refusesAKeyOfTheWrongLength() {
        byte[] truncated = new byte[64];
        System.arraycopy(RFC8292_PUBLIC_KEY, 0, truncated, 0, truncated.length);

        assertThatThrownBy(() -> VapidKeys.encodePublicKey(truncated))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("VAPID public key must be a 65-byte uncompressed P-256 point");
    }

    /**
     * The realistic wrong input: {@code ECPublicKey.getEncoded()} returns a SubjectPublicKeyInfo, 91 bytes for P-256,
     * and encoding one produces a string the browser cannot read.
     */
    @Test
    void refusesASubjectPublicKeyInfoEncoding() {
        byte[] spki = new byte[91];
        spki[0] = 0x30;

        assertThatThrownBy(() -> VapidKeys.encodePublicKey(spki))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("VAPID public key must be a 65-byte uncompressed P-256 point");
    }

    @Test
    void refusesNull() {
        assertThatThrownBy(() -> VapidKeys.encodePublicKey(null)).isInstanceOf(NullPointerException.class);
    }
}
