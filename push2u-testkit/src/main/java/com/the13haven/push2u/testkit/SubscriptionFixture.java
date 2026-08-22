/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.util.Base64;
import java.util.Objects;

import com.the13haven.push2u.PushCryptoException;
import com.the13haven.push2u.Subscription;

/**
 * One valid browser subscription at a chosen endpoint, published in the two forms a test reads it: as
 * {@link Subscription} for a send, and as the base64url strings a browser's {@code PushSubscription} JSON carries — so
 * a registration or controller test can post them and a send test can send to them, and both describe the <em>same</em>
 * subscription.
 *
 * <p>The three components are one coherent set on one instance, deliberately not three separate factories: an endpoint
 * combined with the {@code p256dh} of one subscription and the {@code auth} of another is a subscription no browser
 * ever produced, and the mismatch has no symptom until decryption fails at the receiver. Each {@link #at(URI)} call
 * makes a fresh set — a new P-256 key and 16 new random bytes — valid by construction against whatever the current
 * {@link Subscription} contract requires, which is the point of taking the fixture from the library instead of pasting
 * values that were valid on the day they were written.
 *
 * <p>The endpoint is a required argument with no default, because it has to agree with the {@code EndpointPolicy} the
 * test configures beside it — an egress decision the application owns, kept visible in the same block rather than
 * buried in a fixture. It must be an absolute {@code https} URL, like every endpoint this library accepts.
 *
 * <p>The string forms are unpadded URL-safe base64, and publishing them pre-encoded closes a trap worth naming:
 * {@code java.util.Base64.getEncoder()} in their place uses the {@code +}/{@code /} alphabet, which
 * {@link Subscription#fromBase64} refuses — almost always for the 65-byte {@code p256dh}, but only on some runs for the
 * 16-byte {@code auth}, whose encoding is short enough to land in the shared alphabet about half the time. A test
 * hand-encoding these values therefore fails intermittently, in a value whose only downstream symptom is a subscription
 * the browser cannot decrypt for.
 */
public final class SubscriptionFixture {

    /**
     * Shared across calls: {@code SecureRandom} is thread-safe, and one well-seeded instance serving every fixture is
     * both cheaper and stronger than seeding a fresh generator per 16-byte secret.
     */
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Subscription subscription;
    private final String p256dhBase64Url;
    private final String authBase64Url;

    private SubscriptionFixture(String endpoint, String p256dhBase64Url, String authBase64Url) {
        this.p256dhBase64Url = p256dhBase64Url;
        this.authBase64Url = authBase64Url;
        // Decoding through the public boundary is the fixture's own acceptance test: the library
        // checks the point against the curve, the auth length and the endpoint's form here, so a
        // defect in this fixture fails the at(...) call instead of a send far from it.
        this.subscription = Subscription.fromBase64(endpoint, p256dhBase64Url, authBase64Url);
    }

    /**
     * A fresh subscription at the given endpoint: a new P-256 key as {@code p256dh} and 16 new random bytes as
     * {@code auth}, generated with whatever provider the environment offers for the standard algorithm names.
     *
     * @param endpoint the push endpoint this subscription points at — an absolute {@code https} URL, chosen by the test
     *     so it can agree with the endpoint policy configured beside it
     * @return a new fixture holding one coherent subscription
     * @throws IllegalArgumentException if the endpoint is not one {@link Subscription} accepts
     * @throws NullPointerException if {@code endpoint} is {@code null}
     * @throws PushCryptoException if this JVM's providers offer no P-256 key generation — a platform on which the
     *     library under test cannot run either
     */
    public static SubscriptionFixture at(URI endpoint) {
        Objects.requireNonNull(endpoint, "endpoint");
        byte[] auth = new byte[16];
        RANDOM.nextBytes(auth);
        Base64.Encoder base64Url = Base64.getUrlEncoder().withoutPadding();
        return new SubscriptionFixture(
                endpoint.toString(),
                base64Url.encodeToString(uncompressedPoint(generateP256PublicKey())),
                base64Url.encodeToString(auth));
    }

    /**
     * The subscription as the library's type, for {@code PushSender.send(...)}.
     *
     * @return the decoded form of exactly the endpoint and strings this fixture publishes
     */
    public Subscription subscription() {
        return subscription;
    }

    /**
     * The endpoint, exactly as {@link #subscription()} carries it.
     *
     * @return the push endpoint URL
     */
    public String endpoint() {
        return subscription.endpoint();
    }

    /**
     * The user agent public key as a browser sends it: unpadded URL-safe base64 of the 65-byte uncompressed point.
     *
     * @return the base64url {@code p256dh} value
     */
    public String p256dhBase64Url() {
        return p256dhBase64Url;
    }

    /**
     * The authentication secret as a browser sends it: unpadded URL-safe base64 of the 16 raw bytes.
     *
     * @return the base64url {@code auth} value
     */
    public String authBase64Url() {
        return authBase64Url;
    }

    private static ECPublicKey generateP256PublicKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return (ECPublicKey) generator.generateKeyPair().getPublic();
        } catch (GeneralSecurityException e) {
            throw new PushCryptoException("this JVM's providers offer no P-256 (secp256r1) key generation", e);
        }
    }

    /**
     * The X9.62 uncompressed encoding: {@code 0x04}, then X and Y as fixed 32-byte big-endian values, each written by
     * {@link FixedWidth} — the same single writer the key-pair fixture encodes through, never the variable-width form
     * {@code BigInteger.toByteArray()} produces, whose shifted bytes would encode a different point.
     */
    private static byte[] uncompressedPoint(ECPublicKey publicKey) {
        ECPoint point = publicKey.getW();
        byte[] encoded = new byte[65];
        encoded[0] = 0x04;
        System.arraycopy(FixedWidth.of(point.getAffineX()), 0, encoded, 1, 32);
        System.arraycopy(FixedWidth.of(point.getAffineY()), 0, encoded, 33, 32);
        return encoded;
    }
}
