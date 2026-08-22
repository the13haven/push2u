/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.util.Base64;

import com.the13haven.push2u.PushCryptoException;
import com.the13haven.push2u.VapidKeys;

/**
 * A freshly generated VAPID key pair, in the two forms a test needs it: as {@link VapidKeys} for
 * {@code PushSender.builder(...)}, and as the base64url strings a configuration file or a {@code push2u.vapid.*}
 * property binds.
 *
 * <p><b>Every call to {@link #generate()} makes new key material, and there is deliberately no fixed pair.</b> A
 * published private scalar would be copied out of test code into a real {@code application.yml}, and the copy would
 * outlive every warning attached to the original. The same consequence is worth knowing when writing the application
 * itself: a pair generated at deployment start is replaced by a different pair at the next restart, and every browser
 * subscription taken under the old application server key becomes unusable from that moment. A deployment's real pair
 * is generated once, out of band, and configured; this fixture is for tests, where a fresh pair per test is exactly
 * right. Where a test needs the same key twice, it needs it within one run — hold one generated fixture in a field.
 *
 * <p>The strings are the primary form and {@link #vapidKeys()} is {@link VapidKeys#fromBase64} applied to them, so a
 * pair whose public half is mis-encoded fails inside {@code generate()} — loudly, in the test that asked for it —
 * rather than surviving into an assertion. The encodings are the ones every VAPID consumer reads: the public key as a
 * 65-byte X9.62 uncompressed point ({@code 0x04 || X || Y}, each coordinate exactly 32 bytes) and the private key as
 * the raw 32-byte scalar, both in unpadded URL-safe base64. The private-key string names a secret that did not exist
 * until the caller asked for it; nothing here (or anywhere in this library) takes key material a caller already holds
 * and hands its secret back as text.
 *
 * <p>The pair comes from the JCA's standard {@code "EC"} / {@code secp256r1} names with no provider selected, named or
 * inspected: the environment chooses, exactly as it does for the code under test, so the fixture works on whatever
 * provider set the test JVM runs — a pinned provider would produce keys through a provider the library under test is
 * not using, or fail outright on a JVM that does not carry it.
 */
public final class VapidKeyPairFixture {

    /**
     * P-256 coordinates and scalars serialize as exactly this many big-endian bytes, left-padded with zeros — never the
     * minimal length {@link BigInteger#toByteArray()} produces. A value quietly shortened or padded on the wrong side
     * still decodes as <em>some</em> key, just not this one, and the mismatch surfaces only when a push service rejects
     * the JWT.
     */
    private static final int COORDINATE_LENGTH = 32;

    private final String publicKeyBase64Url;
    private final String privateKeyBase64Url;
    private final VapidKeys vapidKeys;

    private VapidKeyPairFixture(String publicKeyBase64Url, String privateKeyBase64Url) {
        this.publicKeyBase64Url = publicKeyBase64Url;
        this.privateKeyBase64Url = privateKeyBase64Url;
        // Decoding through the public constructor is the fixture's own acceptance test: the library
        // applies its on-curve check to the public half and its length check to the scalar, so an
        // encoding defect fails the generate() call instead of the assertion three lines later.
        this.vapidKeys = VapidKeys.fromBase64(publicKeyBase64Url, privateKeyBase64Url);
    }

    /**
     * Generates a fresh P-256 pair with whatever provider the environment offers for the standard {@code "EC"} name.
     *
     * @return a new fixture over key material that exists nowhere else
     * @throws PushCryptoException if this JVM's providers offer no EC key generation for {@code secp256r1} — a platform
     *     on which the library under test cannot sign either
     */
    public static VapidKeyPairFixture generate() {
        KeyPair keyPair = generateP256KeyPair();
        Base64.Encoder base64Url = Base64.getUrlEncoder().withoutPadding();
        return new VapidKeyPairFixture(
                base64Url.encodeToString(uncompressedPoint((ECPublicKey) keyPair.getPublic())),
                base64Url.encodeToString(fixedWidthScalar(((ECPrivateKey) keyPair.getPrivate()).getS())));
    }

    /**
     * The pair as the library's key type, for {@code PushSender.builder(keys, contact, endpointPolicy)} or
     * {@code LocalEcVapidSigner}.
     *
     * @return the decoded form of exactly the two strings this fixture publishes
     */
    public VapidKeys vapidKeys() {
        return vapidKeys;
    }

    /**
     * The public key as unpadded URL-safe base64 of the 65-byte uncompressed point — the form
     * {@code push2u.vapid.public-key} binds and a browser takes as {@code applicationServerKey}.
     *
     * @return the base64url public key
     */
    public String publicKeyBase64Url() {
        return publicKeyBase64Url;
    }

    /**
     * The private key as unpadded URL-safe base64 of the raw 32-byte scalar — the form {@code push2u.vapid.private-key}
     * binds.
     *
     * <p>This is a secret, but one this fixture just created: it configures nothing real, and a fresh one replaces it
     * on the next {@link #generate()}. Treat any pair that does configure a deployment the opposite way — it is
     * generated once and never regenerated, because subscriptions are bound to the public half.
     *
     * @return the base64url private scalar
     */
    public String privateKeyBase64Url() {
        return privateKeyBase64Url;
    }

    private static KeyPair generateP256KeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new PushCryptoException("this JVM's providers offer no P-256 (secp256r1) key generation", e);
        }
    }

    /**
     * The X9.62 uncompressed encoding: {@code 0x04}, then X and Y as fixed 32-byte big-endian values. Both coordinates
     * go through the same fixed-width writer as the scalar — a coordinate that kept {@link BigInteger#toByteArray()}'s
     * variable length would shift every byte after it and encode a different point.
     */
    private static byte[] uncompressedPoint(ECPublicKey publicKey) {
        ECPoint point = publicKey.getW();
        byte[] encoded = new byte[1 + 2 * COORDINATE_LENGTH];
        encoded[0] = 0x04;
        System.arraycopy(fixedWidthScalar(point.getAffineX()), 0, encoded, 1, COORDINATE_LENGTH);
        System.arraycopy(fixedWidthScalar(point.getAffineY()), 0, encoded, 1 + COORDINATE_LENGTH, COORDINATE_LENGTH);
        return encoded;
    }

    /**
     * A non-negative value below 2<sup>256</sup> as exactly 32 big-endian bytes. {@link BigInteger#toByteArray()}
     * answers the <em>minimal</em> two's-complement form, which is almost never 32 bytes: a value whose top bit is set
     * gets a 33rd leading {@code 0x00} sign byte, and a value with leading zero bytes comes back short. The sign byte
     * is dropped and the value is left-padded — each roughly a coin flip per key, so an encoder that skipped either
     * case would produce working pairs most of the time and unusable ones on a schedule no test suite keeps.
     */
    private static byte[] fixedWidthScalar(BigInteger value) {
        byte[] minimal = value.toByteArray();
        byte[] fixed = new byte[COORDINATE_LENGTH];
        int length = Math.min(minimal.length, COORDINATE_LENGTH);
        System.arraycopy(minimal, minimal.length - length, fixed, COORDINATE_LENGTH - length, length);
        return fixed;
    }
}
