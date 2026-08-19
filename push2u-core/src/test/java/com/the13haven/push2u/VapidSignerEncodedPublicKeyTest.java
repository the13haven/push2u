/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;

import org.junit.jupiter.api.Test;

/**
 * {@link VapidSigner#publicKeyBase64Url()} — the {@code default} method that publishes a signer's own key as the
 * browser's {@code applicationServerKey}. Its whole contract is agreement: with {@link VapidSigner#publicKey()} on the
 * value, and with the send path on what it refuses and what it says when it does.
 *
 * <p>That second agreement is why this method applies the send path's structural check and not the fuller one
 * {@link VapidKeys#encodePublicKey} applies to a caller's own bytes: a key this method publishes is a key the next send
 * carries, and a consumer meeting a broken signer through their own key-publishing endpoint reads exactly what delivery
 * would have told them.
 */
class VapidSignerEncodedPublicKeyTest {

    private static final Instant EXPIRY = Instant.ofEpochSecond(TestVectors.VAPID_EXP);

    @Test
    void agreesWithTheStaticEncoderForARealSigner() {
        VapidKeys keys = PushTestSupport.generateVapidKeys();
        VapidSigner signer = new LocalEcVapidSigner(keys);

        assertThat(signer.publicKeyBase64Url())
                .isEqualTo(VapidKeys.encodePublicKey(signer.publicKey()))
                .isEqualTo(VapidKeys.encodePublicKey(keys.publicKey()));
    }

    /** The same string the send path puts in the {@code k} parameter — one value, two places it is published. */
    @Test
    void isTheSameStringTheAuthorizationHeaderCarriesAsK() {
        VapidSigner signer = new LocalEcVapidSigner(PushTestSupport.generateVapidKeys());

        String header =
                Vapid.authorizationHeader(signer, TestVectors.VAPID_AUDIENCE, TestVectors.VAPID_SUBJECT, EXPIRY);

        assertThat(header).endsWith(", k=" + signer.publicKeyBase64Url());
    }

    @Test
    void aKeyOfTheWrongShapeFailsWithTheSendPathsExceptionAndWording() {
        assertThatThrownBy(() -> signerReturning(new byte[64]).publicKeyBase64Url())
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("VapidSigner.publicKey returned 64 bytes")
                .hasMessageContaining("RFC 8292");

        byte[] compressed = new byte[65];
        compressed[0] = 0x02;
        assertThatThrownBy(() -> signerReturning(compressed).publicKeyBase64Url())
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("begins with 0x02")
                .hasMessageContaining("0x04");
    }

    /**
     * The mistake this call actually invites: a signer publishing {@code ECPublicKey.getEncoded()}, which is a
     * SubjectPublicKeyInfo. The send path names that case specifically, and publication has to name it identically —
     * the consumer hitting it through a {@code /public-key} endpoint is the one furthest from the send that would
     * otherwise have explained it.
     */
    @Test
    void anSpkiWrappedKeySaysSoJustAsASendWould() {
        byte[] spki = new byte[91];
        spki[0] = 0x30;

        assertThatThrownBy(() -> signerReturning(spki).publicKeyBase64Url())
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("looks wrapped")
                .hasMessageContaining("SubjectPublicKeyInfo");
    }

    /**
     * A {@code null} is the type contract broken, not a cryptographic operation failed: {@code publicKey()} is declared
     * to return bytes. Converting it to a {@link PushCryptoException} here would split this method from the send path
     * it precedes, which reports the same defect the same way.
     */
    @Test
    void aNullKeyIsANullPointerExceptionExactlyAsASendMakesIt() {
        VapidSigner signer = signerReturning(null);

        assertThatThrownBy(signer::publicKeyBase64Url).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> Vapid.authorizationHeader(
                        signer, TestVectors.VAPID_AUDIENCE, TestVectors.VAPID_SUBJECT, EXPIRY))
                .isInstanceOf(NullPointerException.class);
    }

    /**
     * Publication is as strict as the send it precedes and no stricter. What the send path checks on the VAPID key is
     * the structure alone, so a well-framed point that is off the curve is published here exactly as it would be
     * carried — an encoder refusing what delivery would send is a second, later opinion about a key the library was
     * already handed, and the defect belongs where a signer is built and where the conformance kit runs.
     */
    @Test
    void publishesWhateverASendWouldCarry() {
        byte[] offCurve = new byte[65];
        offCurve[0] = 0x04;
        VapidSigner signer = signerReturning(offCurve);

        assertThatCode(() -> Vapid.authorizationHeader(
                        signer, TestVectors.VAPID_AUDIENCE, TestVectors.VAPID_SUBJECT, EXPIRY))
                .doesNotThrowAnyException();
        assertThat(signer.publicKeyBase64Url()).isEqualTo(Base64Url.encode(offCurve));
        assertThatThrownBy(() -> VapidKeys.encodePublicKey(offCurve))
                .as("the static's caller-supplied bytes get the full check instead")
                .isInstanceOf(IllegalArgumentException.class);
    }

    /** A signer whose signature half is valid, so only what it advertises as a public key is under test. */
    private static VapidSigner signerReturning(byte[] publicKey) {
        return new VapidSigner() {
            @Override
            public byte[] sign(byte[] signingInput) {
                return new byte[64];
            }

            @Override
            public byte[] publicKey() {
                return publicKey;
            }
        };
    }
}
