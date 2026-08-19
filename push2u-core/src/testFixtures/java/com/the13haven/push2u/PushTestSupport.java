/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static com.the13haven.push2u.TestVectors.b64;

import java.net.http.HttpClient;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;

/**
 * Shared helpers for the send-pipeline tests. A plain class (not JUnit lifecycle) so both test source sets can use it:
 * the regular {@code test} set and the bcprov-free {@code fipsTest} set, each depending on these fixtures as an
 * ordinary consumer instead of duplicating the receiver/subscription plumbing.
 *
 * <p><b>Invariant: keep this class provider-free.</b> It is loaded on two deliberately disjoint classpaths —
 * {@code test} carries only bcprov, {@code fipsTest} carries only bc-fips — so any reference to either BouncyCastle
 * provider here breaks one of the two source sets. Platform (SunEC) primitives only.
 */
final class PushTestSupport {

    private PushTestSupport() {}

    /**
     * A {@link Subscription} pointing at the in-process receiver. An ordinary construction: the receiver serves TLS, so
     * its {@code https://127.0.0.1:<port>/push} endpoint satisfies the same {@link Endpoints#requireSecure} contract a
     * production endpoint does — no seam, no special case.
     */
    static Subscription subscription(MockPushReceiver receiver) {
        return new Subscription(
                receiver.endpoint().toString(), b64(TestVectors.UA_PUBLIC), b64(TestVectors.AUTH_SECRET));
    }

    /**
     * A {@code java.net.http} client that trusts exactly the {@link LoopbackTls} certificate the receiver presents (via
     * {@link LoopbackTls#clientContext()} — no trust-all manager, no relaxed hostname verification) and never follows
     * redirects, which {@link JdkPushHttpClient} requires of any supplied client.
     */
    static HttpClient trustingJavaHttpClient() {
        return HttpClient.newBuilder()
                .sslContext(LoopbackTls.clientContext())
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    /**
     * The production transport, {@link JdkPushHttpClient}, wired through its public constructor to trust the receiver's
     * certificate. Tests that send through a {@link MockPushReceiver} pass this to
     * {@code PushSender.Builder.httpClient(...)}; the sender's default client rightly refuses a certificate no CA
     * vouches for.
     */
    static JdkPushHttpClient trustingPushHttpClient() {
        return new JdkPushHttpClient(trustingJavaHttpClient(), Duration.ofSeconds(30));
    }

    /** A fresh VAPID key pair, generated with the platform provider. */
    static VapidKeys generateVapidKeys() {
        KeyPair keyPair = EcKeys.generateP256(Jca.platform());
        return VapidKeys.of(
                EcKeys.encodeUncompressed((ECPublicKey) keyPair.getPublic()),
                TestVectors.scalar32((ECPrivateKey) keyPair.getPrivate()));
    }
}
