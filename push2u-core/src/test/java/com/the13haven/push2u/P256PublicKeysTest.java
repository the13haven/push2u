/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static com.the13haven.push2u.TestVectors.b64;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.EllipticCurve;
import java.util.Arrays;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;

/**
 * {@link P256PublicKeys} — the public validator for the 65-byte uncompressed key material Web Push carries
 * ({@code p256dh}, the VAPID {@code k} value). The full check runs on hard-coded FIPS 186-4 domain parameters so it
 * needs no JCA provider; {@link #everyHardCodedConstantMatchesTheProvider} is what keeps those constants honest, and
 * the rejection cases mirror the invalid-curve shapes {@link EcKeysUntrustedInputTest} pins for the decode-time check.
 */
class P256PublicKeysTest {

    /** A valid point, from the RFC 8291 worked example, used as the base for each corruption below. */
    private static byte[] validPoint() {
        return b64(TestVectors.UA_PUBLIC);
    }

    // ---- the hard-coded FIPS 186-4 constants ---------------------------------------------------

    /**
     * Every hard-coded P-256 constant must equal what the platform provider answers for {@code secp256r1} — the guard
     * against a transcription error in the FIPS 186-4 values, which no other test would catch (a wrong {@code b} would
     * just reject every genuine key, or accept a family of wrong ones). The BC-FIPS twin of this test lives in the
     * {@code fipsTest} source set.
     */
    @Test
    void everyHardCodedConstantMatchesTheProvider() {
        EllipticCurve curve = Jca.platform().p256Parameters().getCurve();

        assertThat(curve.getField()).isInstanceOf(ECFieldFp.class);
        assertThat(P256PublicKeys.P).as("field prime p").isEqualTo(((ECFieldFp) curve.getField()).getP());
        assertThat(P256PublicKeys.A).as("curve coefficient a").isEqualTo(curve.getA());
        assertThat(P256PublicKeys.B).as("curve coefficient b").isEqualTo(curve.getB());
        assertThat(P256PublicKeys.COORDINATE_LENGTH)
                .as("coordinate width follows the field size")
                .isEqualTo((curve.getField().getFieldSize() + 7) / 8);
        assertThat(P256PublicKeys.UNCOMPRESSED_LENGTH)
                .as("uncompressed point: tag plus two coordinates")
                .isEqualTo(1 + 2 * P256PublicKeys.COORDINATE_LENGTH);
    }

    // ---- the structural check ------------------------------------------------------------------

    @Test
    void theStructuralCheckAcceptsTheRfc8291WorkedExamplePoint() {
        assertThatCode(() -> P256PublicKeys.requireUncompressedPoint(validPoint(), "p256dh"))
                .doesNotThrowAnyException();
    }

    @Test
    void theStructuralCheckRejectsWrongLengthsNamingTheValueAndTheLength() {
        assertThatThrownBy(() -> P256PublicKeys.requireUncompressedPoint(new byte[64], "p256dh"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("p256dh")
                .hasMessageContaining("65-byte uncompressed")
                .hasMessageContaining("64 bytes");

        byte[] compressed = new byte[33];
        compressed[0] = 0x03; // a valid X9.62 compressed point — just not the form Web Push uses
        assertThatThrownBy(() -> P256PublicKeys.requireUncompressedPoint(compressed, "p256dh"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("33 bytes");
    }

    @Test
    void theStructuralCheckRejectsTheWrongLeadingTag() {
        byte[] wrongTag = validPoint();
        wrongTag[0] = 0x03;

        assertThatThrownBy(() -> P256PublicKeys.requireUncompressedPoint(wrongTag, "publicKey"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("publicKey")
                .hasMessageContaining("0x04");
    }

    @Test
    void theStructuralCheckDoesNotInspectTheCoordinates() {
        // Structural only, by contract: all-zero coordinates are not a point on the curve, but
        // they have the right shape — the case the Vault signer's supplied-key mode relies on.
        byte[] zeroCoordinates = new byte[P256PublicKeys.UNCOMPRESSED_LENGTH];
        zeroCoordinates[0] = 0x04;

        assertThatCode(() -> P256PublicKeys.requireUncompressedPoint(zeroCoordinates, "publicKey"))
                .doesNotThrowAnyException();
    }

    // ---- the full check ------------------------------------------------------------------------

    @Test
    void theFullCheckAcceptsThePublishedRfcVectors() {
        assertThatCode(() -> {
                    P256PublicKeys.requireOnCurve(b64(TestVectors.UA_PUBLIC), "p256dh");
                    P256PublicKeys.requireOnCurve(b64(TestVectors.AS_PUBLIC), "p256dh");
                    P256PublicKeys.requireOnCurve(b64(TestVectors.VAPID_PUBLIC_K), "VAPID public key");
                })
                .doesNotThrowAnyException();
    }

    @Test
    void everyGeneratedKeyPassesTheFullCheck() {
        for (int i = 0; i < 16; i++) {
            byte[] encoded = EcKeys.encodeUncompressed(
                    (ECPublicKey) EcKeys.generateP256(Jca.platform()).getPublic());
            int attempt = i;
            assertThatCode(() -> P256PublicKeys.requireOnCurve(encoded, "p256dh"))
                    .as("attempt %d", attempt)
                    .doesNotThrowAnyException();
        }
    }

    @Test
    void aPointOffTheCurveIsRejected() {
        byte[] offCurve = validPoint();
        offCurve[offCurve.length - 1] ^= 0x01; // Y is no longer a square root of x³ - 3x + b

        assertThatThrownBy(() -> P256PublicKeys.requireOnCurve(offCurve, "p256dh"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("p256dh")
                .hasMessageContaining("curve equation");
    }

    /** All-zero coordinates are the affine point {@code (0, 0)} — off the curve because P-256's {@code b} is not 0. */
    @Test
    void allZeroCoordinatesAreRejectedAsOffCurve() {
        byte[] zeros = new byte[P256PublicKeys.UNCOMPRESSED_LENGTH];
        zeros[0] = 0x04;

        assertThatThrownBy(() -> P256PublicKeys.requireOnCurve(zeros, "p256dh"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("curve equation");
    }

    @Test
    void coordinatesOutsideTheFieldAreRejected() {
        byte[] outOfRange = new byte[P256PublicKeys.UNCOMPRESSED_LENGTH];
        outOfRange[0] = 0x04;
        Arrays.fill(outOfRange, 1, P256PublicKeys.UNCOMPRESSED_LENGTH, (byte) 0xFF); // X = Y = 2^256 - 1 > p

        assertThatThrownBy(() -> P256PublicKeys.requireOnCurve(outOfRange, "p256dh"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("outside the P-256 field");
    }

    /**
     * {@code x = p} is one past the last representable field element and congruent to zero mod p. The pinned message is
     * what distinguishes a raw comparison from an implementation that reduced before comparing — the same boundary
     * {@link EcKeysUntrustedInputTest} pins for the decode-time check.
     */
    @Test
    void aCoordinateAtExactlyTheFieldPrimeIsRejectedByTheFieldCheck() {
        byte[] atPrime = validPoint();
        byte[] primeBytes = toFixed32(P256PublicKeys.P);
        System.arraycopy(primeBytes, 0, atPrime, 1, P256PublicKeys.COORDINATE_LENGTH); // X = p, Y kept valid

        assertThatThrownBy(() -> P256PublicKeys.requireOnCurve(atPrime, "p256dh"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("outside the P-256 field");
    }

    /**
     * The value is attacker-reachable, so a rejection must not copy its bytes into the log line that reports it — only
     * the name and the structural reason.
     */
    @Test
    void rejectionMessagesQuoteNoCoordinateMaterial() {
        byte[] offCurve = validPoint();
        offCurve[offCurve.length - 1] ^= 0x01;
        String coordinateHex = HexFormat.of().formatHex(Arrays.copyOfRange(offCurve, 1, 33));

        assertThatThrownBy(() -> P256PublicKeys.requireOnCurve(offCurve, "p256dh"))
                .satisfies(e -> {
                    String message = e.getMessage().toLowerCase(java.util.Locale.ROOT);
                    assertThat(message).doesNotContain(coordinateHex.substring(0, 8));
                    assertThat(e.getMessage()).hasSizeLessThan(200);
                });
    }

    @Test
    void theStructuralCheckRunsFirstInTheFullCheck() {
        assertThatThrownBy(() -> P256PublicKeys.requireOnCurve(new byte[10], "p256dh"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("65-byte uncompressed");
    }

    private static byte[] toFixed32(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[32];
        int length = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - length, out, 32 - length, length);
        return out;
    }
}
