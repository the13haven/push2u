/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.util.Base64;

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

    /** The fixture inherits the library's endpoint contract instead of relaxing it for tests. */
    @Test
    void anEndpointTheLibraryRefusesIsRefusedHereToo() {
        assertThatThrownBy(() -> SubscriptionFixture.at(URI.create("http://push.example.net/wp/insecure")))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
