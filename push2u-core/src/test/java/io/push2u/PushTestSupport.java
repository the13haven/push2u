package io.push2u;

import static io.push2u.TestVectors.b64;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

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
        AutoCloseable plaintextSeam = Endpoints.allowPlaintextEndpointsForTests();
        try {
            // Deliberately NOT inside a catch: if Subscription validation ever regresses, its
            // IllegalArgumentException must surface as itself, not be renamed to a seam failure.
            return new Subscription(
                    receiver.endpoint().toString(), b64(TestVectors.UA_PUBLIC), b64(TestVectors.AUTH_SECRET));
        } finally {
            try {
                plaintextSeam.close();
            } catch (Exception e) {
                // Only close() is wrapped: it merely restores a ThreadLocal (AutoCloseable
                // forces the checked signature), so a throw here is a broken test fixture.
                throw new IllegalStateException("plaintext endpoint seam failed to close", e);
            }
        }
    }

    /** A fresh VAPID key pair, generated with the platform provider. */
    static VapidKeys generateVapidKeys() {
        KeyPair keyPair = EcKeys.generateP256(Jca.platform());
        return VapidKeys.of(
                EcKeys.encodeUncompressed((ECPublicKey) keyPair.getPublic()),
                TestVectors.scalar32((ECPrivateKey) keyPair.getPrivate()));
    }
}
