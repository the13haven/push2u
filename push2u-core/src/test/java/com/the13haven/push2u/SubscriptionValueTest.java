/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static com.the13haven.push2u.TestVectors.b64;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * {@link Subscription} is the library's only mutable-carrying value type: two byte arrays it copies on the way in and
 * on the way out. Equality therefore has to be by content — an application storing subscriptions in a {@code Set} or
 * keying a map by them would otherwise get duplicates that look identical in a log and behave as distinct entries.
 */
class SubscriptionValueTest {

    private static final String ENDPOINT = "https://push.example.net/wpush/v1/token";

    private static byte[] key() {
        return b64(TestVectors.UA_PUBLIC);
    }

    private static byte[] auth() {
        return b64(TestVectors.AUTH_SECRET);
    }

    @Test
    void equalityAndHashingAreByContentNotByArrayIdentity() {
        Subscription first = new Subscription(ENDPOINT, key(), auth());
        Subscription second = new Subscription(ENDPOINT, key(), auth());

        assertThat(first.equals(first)).as("equals is reflexive").isTrue();
        assertThat(first)
                .isEqualTo(second)
                .hasSameHashCodeAs(second)
                .isNotEqualTo(null)
                .isNotEqualTo("not a subscription");
    }

    @Test
    void eachComponentParticipatesInEquality() {
        Subscription base = new Subscription(ENDPOINT, key(), auth());

        assertThat(base).isNotEqualTo(new Subscription(ENDPOINT + "2", key(), auth()));

        // A different genuine point (the RFC 8291 application-server key): a flipped byte would no
        // longer construct, since the constructor validates the point against the curve.
        byte[] otherKey = b64(TestVectors.AS_PUBLIC);
        assertThat(base).isNotEqualTo(new Subscription(ENDPOINT, otherKey, auth()));

        byte[] otherAuth = auth();
        otherAuth[0] ^= 0x01;
        assertThat(base).isNotEqualTo(new Subscription(ENDPOINT, key(), otherAuth));
    }

    @Test
    void theKeyMaterialIsCopiedInBothDirections() {
        byte[] mutableKey = key();
        byte[] mutableAuth = auth();
        Subscription subscription = new Subscription(ENDPOINT, mutableKey, mutableAuth);

        mutableKey[1] ^= 0xFF;
        mutableAuth[1] ^= 0xFF;
        assertThat(subscription.p256dh()).isEqualTo(key());
        assertThat(subscription.auth()).isEqualTo(auth());

        subscription.p256dh()[1] ^= 0xFF;
        subscription.auth()[1] ^= 0xFF;
        assertThat(subscription.p256dh()).isEqualTo(key());
        assertThat(subscription.auth()).isEqualTo(auth());
    }

    /**
     * A 65-byte key with the wrong first octet is the interesting rejection: the length check alone would pass it, and
     * what arrives is then a compressed point or a raw coordinate pair that ECDH would interpret as something else
     * entirely.
     */
    @Test
    void aKeyOfTheRightLengthWithTheWrongPrefixIsRejected() {
        byte[] wrongPrefix = key();
        wrongPrefix[0] = 0x03;

        assertThatThrownBy(() -> new Subscription(ENDPOINT, wrongPrefix, auth()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("0x04");
    }

    /**
     * The hostile case the constructor's full check exists for: a value with the right shape whose point is not on
     * P-256. {@code p256dh} arrives from whoever posts to the application's registration endpoint, and accepting an
     * off-curve point here would store a subscription that raises {@link PushCryptoException} — the "broken deployment"
     * exception — on every later send, far from the request that supplied it.
     */
    @Test
    void aKeyOfTheRightShapeWhosePointIsOffTheCurveIsRejectedAtConstruction() {
        byte[] offCurve = key();
        offCurve[64] ^= 0x01; // Y is no longer a square root of x³ - 3x + b

        assertThatThrownBy(() -> new Subscription(ENDPOINT, offCurve, auth()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("p256dh")
                .hasMessageContaining("curve equation");
    }

    @Test
    void aKeyWithACoordinateOutsideTheFieldIsRejectedAtConstruction() {
        byte[] outOfField = new byte[65];
        outOfField[0] = 0x04;
        Arrays.fill(outOfField, 1, 65, (byte) 0xFF); // X = Y = 2^256 - 1 > p

        assertThatThrownBy(() -> new Subscription(ENDPOINT, outOfField, auth()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("p256dh")
                .hasMessageContaining("outside the P-256 field");
    }

    /** The same refusal through {@link Subscription#fromBase64}, the path a browser-posted value actually takes. */
    @Test
    void anOffCurveKeyIsRejectedOnTheFromBase64Path() {
        byte[] offCurve = key();
        offCurve[64] ^= 0x01;
        String encoded = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(offCurve);

        assertThatThrownBy(() -> Subscription.fromBase64(
                        ENDPOINT, encoded, java.util.Base64.getUrlEncoder().encodeToString(auth())))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("p256dh");
    }

    @Test
    void theAuthSecretMustBeExactlyTheSixteenBytesRfc8291Requires() {
        for (int length : new int[] {0, 15, 17, 32}) {
            assertThatThrownBy(() -> new Subscription(ENDPOINT, key(), new byte[length]))
                    .as("auth of %d bytes", length)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("16 bytes");
        }
    }

    @Test
    void aPlaintextEndpointIsRejected() {
        assertThatThrownBy(() -> new Subscription("http://push.example.net/x", key(), auth()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void anEndpointOfExactlyTheMaximumLengthIsAccepted() {
        String prefix = "https://push.example.net/wpush/v1/";
        String endpoint = prefix + "t".repeat(2048 - prefix.length());

        Subscription subscription = new Subscription(endpoint, key(), auth());

        assertThat(subscription.endpoint()).hasSize(2048);
    }

    /**
     * The endpoint is attacker-influenced (a registration endpoint accepts whatever a client posts), its origin is
     * embedded in every {@code Authorization} header, and the sender's token cache retains one such header per origin —
     * so an unbounded endpoint would let the party supplying subscriptions choose both the per-request and the retained
     * cost. No resolvable host can come near the bound: RFC 1035 caps a hostname at 253 characters.
     */
    @Test
    void anEndpointOverTheMaximumLengthIsRejectedAtConstruction() {
        String host = "h".repeat(4000) + ".example.net";
        String endpoint = "https://" + host + "/wpush/v1/token";

        assertThatThrownBy(() -> new Subscription(endpoint, key(), auth()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("2048")
                .hasMessageContaining(String.valueOf(endpoint.length()))
                // Not the endpoint, and not even its redacted form: the redaction's origin half
                // carries the host, which is exactly where the oversized part lives.
                .hasMessageNotContaining("hhhh")
                .hasMessageNotContaining("example.net");
    }

    /** One character over, so the boundary itself is pinned rather than only a value far beyond it. */
    @Test
    void theEndpointLengthBoundaryIsExact() {
        String prefix = "https://push.example.net/wpush/v1/";
        String oneOver = prefix + "t".repeat(2049 - prefix.length());

        assertThatThrownBy(() -> new Subscription(oneOver, key(), auth()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("2048")
                .hasMessageContaining("2049");
    }

    /** The same refusal through {@link Subscription#fromBase64} — no construction path evades the bound. */
    @Test
    void anOversizedEndpointIsRejectedOnTheFromBase64Path() {
        String endpoint = "https://push.example.net/" + "t".repeat(3000);

        assertThatThrownBy(() -> Subscription.fromBase64(
                        endpoint,
                        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(key()),
                        java.util.Base64.getUrlEncoder().encodeToString(auth())))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("2048");
    }

    @Test
    void toStringDoesNotLeakTheSubscriptionToken() {
        String rendered = new Subscription(ENDPOINT, key(), auth()).toString();

        assertThat(rendered).doesNotContain("token");
        assertThat(rendered).doesNotContain(Arrays.toString(auth()));
    }
}
