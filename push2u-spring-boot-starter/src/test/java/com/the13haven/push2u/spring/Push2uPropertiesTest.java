/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.spring;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * {@link Push2uProperties} renders no secret in {@code toString()}. Records generate a {@code toString()} that prints
 * every component, so without an override the bound VAPID private key would ride into any accidental
 * {@code log.info("{}", properties)} or debugger dump in the consuming application — push2u itself never stringifies
 * the record, but the hazard is handed to whoever does.
 */
class Push2uPropertiesTest {

    @Test
    void toStringMasksThePrivateKey() {
        Push2uProperties.Vapid vapid =
                new Push2uProperties.Vapid("BPublicKeyMarker", "raw-private-scalar-marker", "mailto:ops@example.com");
        Push2uProperties properties = new Push2uProperties(
                vapid,
                null,
                null,
                null,
                null,
                null,
                null,
                // allowedOrigins and allowedDomains: unset, which is what the binder produces when
                // the properties are absent. The autoconfiguration then requires an EndpointPolicy
                // bean instead, or fails the context — but that is its business; this record only
                // carries the values.
                null,
                null);

        // Directly and through the enclosing record — the outer toString() embeds the inner one.
        for (String rendered : new String[] {vapid.toString(), properties.toString()}) {
            assertThat(rendered)
                    .doesNotContain("raw-private-scalar-marker")
                    .contains("***")
                    .as("non-secret components stay readable")
                    .contains("BPublicKeyMarker")
                    .contains("mailto:ops@example.com");
        }
    }

    @Test
    void anUnsetPrivateKeyIsRenderedAsNullNotAsAMask() {
        // "***" for an unset key would read as "a key is configured" — the mask must only stand
        // in for an actual value.
        Push2uProperties.Vapid vapid = new Push2uProperties.Vapid("BPublicKeyMarker", null, null);

        assertThat(vapid.toString()).contains("privateKey=null");
    }
}
