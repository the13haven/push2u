/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;

import java.net.URI;
import java.util.Base64;
import java.util.function.Predicate;

import org.junit.jupiter.api.Test;

import com.the13haven.push2u.Subscription;

/**
 * The subscription fixture's honesty checks: the typed form and the browser-form strings describe one subscription, the
 * byte shapes are the contracted ones, and each {@code at(...)} makes a fresh coherent set.
 */
final class SubscriptionFixtureTest {

    private static final URI ENDPOINT = URI.create("https://push.example.net/wp/subscription-token");

    @Test
    void theStringsAndTheSubscriptionDescribeTheSameSubscription() {
        SubscriptionFixture fixture = SubscriptionFixture.at(ENDPOINT);

        Subscription rebuilt =
                Subscription.fromBase64(fixture.endpoint(), fixture.p256dhBase64Url(), fixture.authBase64Url());

        assertThat(rebuilt).isEqualTo(fixture.subscription());
    }

    @Test
    void theEndpointIsTheOneAskedFor() {
        SubscriptionFixture fixture = SubscriptionFixture.at(ENDPOINT);

        assertThat(fixture.endpoint()).isEqualTo(ENDPOINT.toString());
        assertThat(fixture.subscription().endpoint()).isEqualTo(ENDPOINT.toString());
    }

    @Test
    void theDecodedBytesHaveTheContractedShapes() {
        SubscriptionFixture fixture = SubscriptionFixture.at(ENDPOINT);

        byte[] p256dh = Base64.getUrlDecoder().decode(fixture.p256dhBase64Url());
        assertThat(p256dh).hasSize(65);
        assertThat(p256dh[0]).as("X9.62 uncompressed point prefix").isEqualTo((byte) 0x04);
        assertThat(Base64.getUrlDecoder().decode(fixture.authBase64Url())).hasSize(16);
    }

    /** Pinned on the strings themselves, so the claim does not lean on any decoder's leniency. */
    @Test
    void theStringsUseTheUrlSafeAlphabetWithoutPadding() {
        SubscriptionFixture fixture = SubscriptionFixture.at(ENDPOINT);

        assertThat(fixture.p256dhBase64Url()).matches("[A-Za-z0-9_-]+");
        assertThat(fixture.authBase64Url()).matches("[A-Za-z0-9_-]+");
    }

    @Test
    void everyCallMakesAFreshSet() {
        SubscriptionFixture first = SubscriptionFixture.at(ENDPOINT);
        SubscriptionFixture second = SubscriptionFixture.at(ENDPOINT);

        assertThat(second.p256dhBase64Url()).isNotEqualTo(first.p256dhBase64Url());
        assertThat(second.authBase64Url()).isNotEqualTo(first.authBase64Url());
    }

    /**
     * The boundary shape of the point writer, hunted for rather than sampled: a coordinate below 2<sup>248</sup> comes
     * out of {@code BigInteger.toByteArray()} short of 32 bytes and must be left-padded inside the 65-byte point —
     * roughly one {@code at(...)} call in 128 across the two coordinates, so a writer padding the wrong side keeps an
     * ordinary run green while failing consumers intermittently. A mis-padded coordinate shifts every following byte
     * and encodes a different point, which the on-curve check inside {@code Subscription.fromBase64} refuses — so
     * surviving generation on this shape is most of the assertion, and the coherence check closes it.
     */
    @Test
    void aP256dhWhoseXCoordinateHasLeadingZeroBytesIsStillWellFormed() {
        assertShapesAndCoherence(atUntil(fixture -> decodedP256dh(fixture)[1] == 0));
    }

    /** The same hunt on the Y coordinate, whose bytes sit at a different offset in the point. */
    @Test
    void aP256dhWhoseYCoordinateHasLeadingZeroBytesIsStillWellFormed() {
        assertShapesAndCoherence(atUntil(fixture -> decodedP256dh(fixture)[33] == 0));
    }

    /** The fixture inherits the library's endpoint contract instead of relaxing it for tests. */
    @Test
    void anEndpointTheLibraryRefusesIsRefusedHereToo() {
        assertThatThrownBy(() -> SubscriptionFixture.at(URI.create("http://push.example.net/wp/insecure")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static void assertShapesAndCoherence(SubscriptionFixture fixture) {
        byte[] p256dh = decodedP256dh(fixture);
        assertThat(p256dh).hasSize(65);
        assertThat(p256dh[0]).as("X9.62 uncompressed point prefix").isEqualTo((byte) 0x04);
        assertThat(Subscription.fromBase64(fixture.endpoint(), fixture.p256dhBase64Url(), fixture.authBase64Url()))
                .as("the strings still rebuild the very subscription the fixture holds")
                .isEqualTo(fixture.subscription());
    }

    /**
     * Draws fixtures until one matches the wanted byte shape. Enough attempts that missing a 1-in-256 shape has
     * probability below 1e-13 — and under a broken point writer the draw itself goes red long before the cap, since the
     * library's on-curve check refuses a shifted coordinate inside {@code at(...)}.
     */
    private static SubscriptionFixture atUntil(Predicate<SubscriptionFixture> shape) {
        for (int attempt = 0; attempt < 8192; attempt++) {
            SubscriptionFixture fixture = SubscriptionFixture.at(ENDPOINT);
            if (shape.test(fixture)) {
                return fixture;
            }
        }
        return fail("no generated subscription matched the wanted byte shape in 8192 attempts — statistically"
                + " impossible for the shapes hunted here");
    }

    private static byte[] decodedP256dh(SubscriptionFixture fixture) {
        return Base64.getUrlDecoder().decode(fixture.p256dhBase64Url());
    }
}
