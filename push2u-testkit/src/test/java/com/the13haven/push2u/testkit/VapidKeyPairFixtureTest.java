/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.fail;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.function.Predicate;

import org.junit.jupiter.api.Test;

import com.the13haven.push2u.Es256Verifier;
import com.the13haven.push2u.LocalEcVapidSigner;
import com.the13haven.push2u.VapidKeys;

/**
 * The fixture's own honesty checks. The one that matters most is the scalar/point correspondence: the fixture writes
 * both encodings itself (the core's writers are package-private and out of its reach), {@code VapidKeys.fromBase64}
 * checks only that the point is on the curve and the scalar is 32 bytes, and nothing anywhere else verifies that the
 * scalar is the one belonging to that point. A mis-padded scalar therefore produces a fixture that looks coherent
 * everywhere except in a signature verification — so a signature made from the scalar is verified against the public
 * half here, through {@link Es256Verifier}, and deliberately on the pairs where {@code BigInteger.toByteArray()}
 * disagrees with the fixed 32-byte form: a scalar carrying a leading sign byte (about half of all pairs) and a scalar
 * short of 32 bytes (about one pair in 256, hunted for explicitly because an ordinary run would sample it rarely).
 */
final class VapidKeyPairFixtureTest {

    private static final byte[] SIGNING_INPUT =
            "push2u VapidKeyPairFixture correspondence".getBytes(StandardCharsets.US_ASCII);

    /** Enough draws that missing a 1-in-256 shape has probability below 1e-13. */
    private static final int MAX_GENERATION_ATTEMPTS = 8192;

    @Test
    void aSignatureMadeFromTheScalarVerifiesAgainstThePublicKey() {
        assertScalarBelongsToPoint(VapidKeyPairFixture.generate());
    }

    /**
     * The sign-byte half of the padding rule: a scalar whose top bit is set comes out of {@code toByteArray()} as 33
     * bytes, and the fixture must drop exactly the leading zero. Kept as its own test although roughly every second
     * generated pair has this shape, so that a padding regression is named rather than flaking.
     */
    @Test
    void aScalarWithItsHighBitSetStillBelongsToThePublicKey() {
        assertScalarBelongsToPoint(generateUntil(fixture -> (decodedScalar(fixture)[0] & 0x80) != 0));
    }

    /**
     * The left-padding half: a scalar below 2<sup>248</sup> comes out of {@code toByteArray()} short of 32 bytes, and
     * the fixture must left-pad it. This is the shape a wrong writer survives longest on — one pair in 256 — so it is
     * hunted for rather than sampled.
     */
    @Test
    void aScalarWithLeadingZeroBytesStillBelongsToThePublicKey() {
        VapidKeyPairFixture fixture = generateUntil(candidate -> decodedScalar(candidate)[0] == 0);
        assertThat(decodedScalar(fixture)).hasSize(32);
        assertScalarBelongsToPoint(fixture);
    }

    /**
     * The same hunt on the public half: an X coordinate short of 32 bytes must be left-padded inside the 65-byte point.
     * A mis-padded coordinate shifts every following byte and encodes a different point, which the on-curve check
     * inside {@code generate()} refuses — so surviving generation is most of the assertion, and the correspondence
     * check closes it.
     */
    @Test
    void aPublicKeyWhoseXCoordinateHasLeadingZeroBytesIsStillWellFormed() {
        VapidKeyPairFixture fixture = generateUntil(candidate -> decodedPublicKey(candidate)[1] == 0);
        assertThat(decodedPublicKey(fixture)).hasSize(65);
        assertScalarBelongsToPoint(fixture);
    }

    @Test
    void everyGenerateMakesNewKeyMaterial() {
        VapidKeyPairFixture first = VapidKeyPairFixture.generate();
        VapidKeyPairFixture second = VapidKeyPairFixture.generate();

        assertThat(second.publicKeyBase64Url()).isNotEqualTo(first.publicKeyBase64Url());
        assertThat(second.privateKeyBase64Url()).isNotEqualTo(first.privateKeyBase64Url());
    }

    @Test
    void theLibraryAcceptsExactlyWhatTheStringsSay() {
        VapidKeyPairFixture fixture = VapidKeyPairFixture.generate();

        assertThatCode(() -> VapidKeys.fromBase64(fixture.publicKeyBase64Url(), fixture.privateKeyBase64Url()))
                .doesNotThrowAnyException();
    }

    @Test
    void thePublicKeyStringRoundTripsThroughTheLibrarysOwnEncoder() {
        VapidKeyPairFixture fixture = VapidKeyPairFixture.generate();

        assertThat(VapidKeys.encodePublicKey(fixture.vapidKeys().publicKey())).isEqualTo(fixture.publicKeyBase64Url());
    }

    @Test
    void theDecodedBytesHaveTheContractedShapes() {
        VapidKeyPairFixture fixture = VapidKeyPairFixture.generate();

        byte[] publicKey = decodedPublicKey(fixture);
        assertThat(publicKey).hasSize(65);
        assertThat(publicKey[0]).as("X9.62 uncompressed point prefix").isEqualTo((byte) 0x04);
        assertThat(decodedScalar(fixture)).hasSize(32);
    }

    /**
     * The URL-safe alphabet without padding, asserted character by character rather than by decoding: the URL decoder
     * used elsewhere in these tests happens to reject the standard alphabet, but pinning the property on the string
     * itself keeps the claim independent of any decoder's leniency.
     */
    @Test
    void theStringsUseTheUrlSafeAlphabetWithoutPadding() {
        VapidKeyPairFixture fixture = VapidKeyPairFixture.generate();

        assertThat(fixture.publicKeyBase64Url()).matches("[A-Za-z0-9_-]+");
        assertThat(fixture.privateKeyBase64Url()).matches("[A-Za-z0-9_-]+");
    }

    /**
     * Signs with the library's own signer built from {@code vapidKeys()} — the production path a consumer's test takes
     * — and verifies through {@link Es256Verifier} against the bytes the <em>string</em> names, so the check covers the
     * encoded forms and not merely the in-memory pair.
     */
    private static void assertScalarBelongsToPoint(VapidKeyPairFixture fixture) {
        assertThat(Es256Verifier.isSupported())
                .as("this build's JVM offers ES256 verification")
                .isTrue();

        byte[] signature = new LocalEcVapidSigner(fixture.vapidKeys()).sign(SIGNING_INPUT);

        assertThat(Es256Verifier.verify(decodedPublicKey(fixture), SIGNING_INPUT, signature))
                .as("a signature made from the private scalar verifies against the advertised public key")
                .isTrue();
    }

    private static VapidKeyPairFixture generateUntil(Predicate<VapidKeyPairFixture> shape) {
        for (int attempt = 0; attempt < MAX_GENERATION_ATTEMPTS; attempt++) {
            VapidKeyPairFixture fixture = VapidKeyPairFixture.generate();
            if (shape.test(fixture)) {
                return fixture;
            }
        }
        return fail("no generated pair matched the wanted byte shape in " + MAX_GENERATION_ATTEMPTS
                + " attempts — statistically impossible for the shapes hunted here");
    }

    private static byte[] decodedPublicKey(VapidKeyPairFixture fixture) {
        return Base64.getUrlDecoder().decode(fixture.publicKeyBase64Url());
    }

    private static byte[] decodedScalar(VapidKeyPairFixture fixture) {
        return Base64.getUrlDecoder().decode(fixture.privateKeyBase64Url());
    }
}
