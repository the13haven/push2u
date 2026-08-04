/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static com.the13haven.push2u.TestVectors.b64;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Shared helpers for the send-pipeline tests. A plain class (not JUnit lifecycle) so both test source sets can use it:
 * the regular {@code test} set and the bcprov-free {@code fipsTest} set, which reuses this compiled output instead of
 * duplicating the receiver/subscription plumbing.
 *
 * <p><b>Invariant: keep this class provider-free.</b> It is loaded on two deliberately disjoint classpaths —
 * {@code test} carries only bcprov, {@code fipsTest} carries only bc-fips — so any reference to either BouncyCastle
 * provider here breaks one of the two source sets. Platform (SunEC) primitives only.
 */
final class PushTestSupport {

    private PushTestSupport() {}

    /** A {@link Subscription} pointing at the in-process receiver, through the plaintext test seam. */
    static Subscription subscription(MockPushReceiver receiver) {
        // The in-process receiver listens on plain http://127.0.0.1 — allowed only through the
        // package-private test seam; the public Subscription contract stays https-only.
        // try-with-resources, not a finally that throws: if the Subscription construction below
        // fails, a close() failure must be attached as suppressed rather than replace it.
        try (AutoCloseable plaintextSeam = Endpoints.allowPlaintextEndpointsForTests()) {
            return new Subscription(
                    receiver.endpoint().toString(), b64(TestVectors.UA_PUBLIC), b64(TestVectors.AUTH_SECRET));
        } catch (RuntimeException e) {
            // Rethrown unchanged: if Subscription validation ever regresses, its
            // IllegalArgumentException must surface as itself, not be renamed to a seam failure.
            throw e;
        } catch (Exception e) {
            // Only close() can get here — it merely restores a ThreadLocal (AutoCloseable forces
            // the checked signature), so a throw is a broken test fixture.
            throw new IllegalStateException("plaintext endpoint seam failed to close", e);
        }
    }

    /** A fresh VAPID key pair, generated with the platform provider. */
    static VapidKeys generateVapidKeys() {
        KeyPair keyPair = EcKeys.generateP256(Jca.platform());
        return VapidKeys.of(
                EcKeys.encodeUncompressed((ECPublicKey) keyPair.getPublic()),
                TestVectors.scalar32((ECPrivateKey) keyPair.getPrivate()));
    }

    /** Records backoff durations instead of sleeping, so the retry tests run instantly. */
    static final class RecordingSleeper implements Sleeper {
        final List<Duration> sleeps = new ArrayList<>();

        @Override
        public void sleep(Duration duration) {
            sleeps.add(duration);
        }
    }
}
