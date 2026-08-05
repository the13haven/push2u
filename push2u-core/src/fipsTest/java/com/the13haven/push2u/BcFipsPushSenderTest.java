/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static com.the13haven.push2u.PushTestSupport.generateVapidKeys;
import static com.the13haven.push2u.PushTestSupport.subscription;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.time.Duration;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.junit.jupiter.api.Test;

/**
 * The full send pipeline — RFC 8291 encryption, VAPID ES256, HTTP POST — with BC-FIPS as the scoped
 * {@code .cryptoProvider(...)}, exercising the DER → P1363 signature fallback end to end against the in-process
 * {@link MockPushReceiver}. Runs in the fipsTest source set (bc-fips and stock bcprov cannot share a classpath); the
 * receiver and the subscription/key helpers are reused from the regular test source set's compiled output.
 */
class BcFipsPushSenderTest {

    @Test
    void deliversWithBcFipsCryptoProviderViaTheDerFallback() throws IOException {
        Provider bcFips = new BouncyCastleFipsProvider();
        // Guard the premise: BC-FIPS must actually lack raw-format ECDSA — this FAILS (not
        // skips) if a future version starts registering it, so the test cannot silently stop
        // covering the DER fallback.
        assertThat(Jca.using(bcFips).es256().encoding()).isEqualTo(Jca.EcdsaSignature.Encoding.DER);

        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushSender pusher = PushSender.builder(generateVapidKeys(), "mailto:ops@example.com")
                    .cryptoProvider(bcFips)
                    // No-op sleeper: the happy path never retries, but if this scenario ever grows a
                    // retry the test must not fall back to real wall-clock backoff.
                    .sleeper(duration -> {})
                    .build();

            PushResult result = pusher.send(
                    subscription(receiver),
                    PushMessage.builder("hello".getBytes(StandardCharsets.UTF_8))
                            .ttl(Duration.ofHours(1))
                            .build());

            assertThat(result.isDelivered()).isTrue();
            assertThat(result.attempts()).isEqualTo(1);

            assertThat(receiver.requests()).hasSize(1);
            MockPushReceiver.RecordedRequest request = receiver.requests().getFirst();
            assertThat(request.headers()).containsEntry("content-encoding", "aes128gcm");
            assertThat(request.headers().get("authorization")).startsWith("vapid t=");
            // Same aes128gcm framing as the platform-provider path: 86-byte header + plaintext(5)
            // + delimiter(1) + GCM tag(16) — the provider swap changes no wire bytes.
            assertThat(request.bodyLength()).isEqualTo(86 + 5 + 1 + 16);
        }
    }
}
