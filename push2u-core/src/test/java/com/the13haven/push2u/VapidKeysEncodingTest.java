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
 * SubjectPublicKeyInfo — and each is pinned below, because none of them is decided here. The first two are RFC 7515 §2
 * base64url, which is both what {@code subscribe(...)} reads a string {@code applicationServerKey} as and what RFC 8292
 * §3.2 spells {@code k} as, so a padded or standard-alphabet string breaks the browser and the header alike. The
 * browser reports the two kinds of mistake differently: a string it will not decode gets an
 * {@code InvalidCharacterError}, whereas a SubjectPublicKeyInfo decodes and then fails the P-256 point check with an
 * {@code InvalidAccessError} (steps 10.2 and 10.3 of {@code subscribe()}).
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
     * The local-keys mode: a string {@link VapidKeys#fromBase64} accepted comes back out of the encoder in the form the
     * browser and the {@code k} parameter want, so an application serving it to its frontend need keep no second copy
     * beside the pair. Canonical rather than identical, and the difference is the padding: {@code fromBase64} takes it
     * or leaves it — a 65-byte key always carries exactly one {@code '='} from a padded encoder — while the encoder
     * never emits it, so a padded input round-trips to the unpadded spelling rather than to itself.
     */
    @Test
    void returnsTheConfiguredKeyInTheCanonicalUnpaddedForm() {
        VapidKeys generated = PushTestSupport.generateVapidKeys();
        String unpadded = Base64.getUrlEncoder().withoutPadding().encodeToString(generated.publicKey());
        String padded = Base64.getUrlEncoder().encodeToString(generated.publicKey());
        String privateScalar = Base64.getUrlEncoder().withoutPadding().encodeToString(generated.privateScalar());

        assertThat(padded)
                .as("a padded encoder does pad a 65-byte key, so the case below is real")
                .endsWith("=");
        assertThat(VapidKeys.encodePublicKey(
                        VapidKeys.fromBase64(unpadded, privateScalar).publicKey()))
                .as("an unpadded input comes back as itself")
                .isEqualTo(unpadded);
        assertThat(VapidKeys.encodePublicKey(
                        VapidKeys.fromBase64(padded, privateScalar).publicKey()))
                .as("a padded input comes back canonical, with the '=' gone")
                .isEqualTo(unpadded);
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
