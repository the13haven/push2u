/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static com.the13haven.push2u.TestVectors.b64;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * The {@code p256dh} key travels from a browser through the application's own storage before reaching this library, so
 * it is attacker-reachable input in the same sense a request body is. These are the shapes an invalid-curve attack
 * arrives in — a point off the curve, the point at infinity, coordinates outside the field — modelled on the classes of
 * case Project Wycheproof enumerates for {@code ecdh_secp256r1}.
 *
 * <p>What is being pinned is that each one is refused before it can reach ECDH, and refused as a
 * {@link PushCryptoException} rather than as whatever the provider happened to throw.
 */
class EcKeysUntrustedInputTest {

    private final Jca jca = Jca.platform();

    /** A valid point, from the RFC 8291 worked example, used as the base for each corruption below. */
    private byte[] validPoint() {
        return b64(TestVectors.UA_PUBLIC);
    }

    /**
     * Where the refusal happens, measured rather than assumed: the JDK's {@code KeyFactory} imports these points
     * without complaint — {@code ECPublicKeySpec} is a container, not a validator — and {@code KeyAgreement.doPhase} is
     * what rejects them, with an {@code InvalidKeyException} this library reports as a {@link PushCryptoException}.
     *
     * <p>So the guarantee these tests pin is "no later than ECDH", which is early enough that no shared secret is ever
     * derived from an attacker-chosen point. Note what it rests on: the provider. A provider configured through
     * {@code Jca.using(...)} that skips point validation in {@code doPhase} would move the boundary, and nothing in
     * this library would notice.
     */
    @Test
    void aPointOffTheCurveIsRefusedNoLaterThanEcdh() {
        byte[] offCurve = validPoint();
        offCurve[offCurve.length - 1] ^= 0x01; // Y is no longer a square root of x^3 - 3x + b

        assertThatThrownBy(() -> agreeWith(offCurve))
                .as("an off-curve point is the entry ticket for an invalid-curve attack")
                .isInstanceOf(PushCryptoException.class)
                .satisfies(thrown -> assertThat(thrown.getMessage())
                        .as("either refusal point satisfies the contract; which one is the provider's choice")
                        .containsAnyOf("Invalid P-256 public key", "ECDH key agreement failed"));
    }

    @Test
    void thePointAtInfinityEncodedAsZeroesIsRefusedNoLaterThanEcdh() {
        byte[] infinity = new byte[EcKeys.UNCOMPRESSED_LENGTH];
        infinity[0] = 0x04; // 0x04 || 0^32 || 0^32

        assertThatThrownBy(() -> agreeWith(infinity)).isInstanceOf(PushCryptoException.class);
    }

    @Test
    void coordinatesOutsideTheFieldAreRefusedNoLaterThanEcdh() {
        byte[] outOfRange = new byte[EcKeys.UNCOMPRESSED_LENGTH];
        outOfRange[0] = 0x04;
        Arrays.fill(outOfRange, 1, EcKeys.UNCOMPRESSED_LENGTH, (byte) 0xFF); // X = Y = 2^256 - 1 > p

        assertThatThrownBy(() -> agreeWith(outOfRange)).isInstanceOf(PushCryptoException.class);
    }

    /** Decodes the point and runs the agreement it would feed — the full path a subscription key takes. */
    private byte[] agreeWith(byte[] uaPublicKey) {
        return EcKeys.ecdh(
                EcKeys.decodeP256PrivateKey(b64(TestVectors.AS_PRIVATE), jca),
                EcKeys.decodeP256PublicKey(uaPublicKey, jca),
                jca);
    }

    @Test
    void aCompressedPointIsRefusedEvenThoughItIsAValidEncodingElsewhere() {
        byte[] compressed = new byte[33];
        compressed[0] = 0x03; // valid X9.62 compressed form — just not the form Web Push specifies

        assertThatThrownBy(() -> EcKeys.decodeP256PublicKey(compressed, jca))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("65-byte uncompressed");
    }

    @Test
    void aPrivateScalarOfTheWrongLengthIsRefusedBeforeReachingTheProvider() {
        assertThatThrownBy(() -> EcKeys.decodeP256PrivateKey(new byte[31], jca))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32-byte");
    }

    /**
     * Zero is not a valid P-256 private scalar: the group has no element of order 1, so {@code d = 0} has no matching
     * public key. Whether the provider notices at import time or only on first use, the library's job is to surface it
     * as a crypto failure rather than as a class-cast or a null.
     */
    @Test
    void aZeroPrivateScalarDoesNotProduceAUsableKey() {
        byte[] zero = new byte[EcKeys.COORDINATE_LENGTH];

        assertThatThrownBy(() -> {
                    var key = EcKeys.decodeP256PrivateKey(zero, jca);
                    // If the import itself is permissive, the failure must still arrive before anything is signed.
                    EcKeys.ecdh(key, EcKeys.decodeP256PublicKey(b64(TestVectors.UA_PUBLIC), jca), jca);
                })
                .isInstanceOf(PushCryptoException.class);
    }

    // ---- a provider that cannot do the job ------------------------------------------------------

    /**
     * Every {@link EcKeys} entry point wraps its provider failure as a {@link PushCryptoException}. Worth covering
     * separately from {@link JcaUnavailableAlgorithmTest}: that one pins what {@code Jca} reports, this one pins that
     * the wrapping does not get lost on the way through the key handling — a raw {@code GeneralSecurityException}
     * escaping here would be a checked exception the public API never declares.
     */
    @Test
    void everyKeyOperationReportsAProviderFailureAsACryptoException() {
        Jca crippled = Jca.using(new java.security.Provider("push2u-empty", "1.0", "registers no algorithms") {});

        assertThatThrownBy(() -> EcKeys.decodeP256PublicKey(validPoint(), crippled))
                .isInstanceOf(PushCryptoException.class);
        assertThatThrownBy(() -> EcKeys.decodeP256PrivateKey(b64(TestVectors.AS_PRIVATE), crippled))
                .isInstanceOf(PushCryptoException.class);
        assertThatThrownBy(() -> EcKeys.generateP256(crippled)).isInstanceOf(PushCryptoException.class);
        assertThatThrownBy(() -> EcKeys.ecdh(
                        EcKeys.decodeP256PrivateKey(b64(TestVectors.AS_PRIVATE), jca),
                        EcKeys.decodeP256PublicKey(validPoint(), jca),
                        crippled))
                .isInstanceOf(PushCryptoException.class);
    }

    // ---- fixed-width coordinate serialisation --------------------------------------------------

    /**
     * {@code BigInteger.toByteArray()} is variable-width: it drops leading zero bytes and prepends a sign byte when the
     * top bit is set. A P-256 X coordinate below 2^248 therefore serialises to 31 bytes — roughly one key in 256 — and
     * one at or above 2^255 to 33. Copying either straight into the output would shift every following byte and produce
     * a {@code p256dh} the user agent cannot match, for a minority of keys and never in a way a round-trip over
     * generated keys would reliably catch.
     */
    @Test
    void shortAndSignPaddedCoordinatesAreBothNormalisedToThirtyTwoBytes() {
        ECParameterSpec p256 = jca.p256Parameters();

        byte[] shortCoordinate = EcKeys.encodeUncompressed(pointAt(BigInteger.ONE, BigInteger.TWO, p256));
        assertThat(shortCoordinate).hasSize(EcKeys.UNCOMPRESSED_LENGTH);
        assertThat(Arrays.copyOfRange(shortCoordinate, 1, 33))
                .as("X = 1 is right-aligned in 32 bytes, not left-aligned")
                .isEqualTo(rightAligned(BigInteger.ONE));
        assertThat(Arrays.copyOfRange(shortCoordinate, 33, 65)).isEqualTo(rightAligned(BigInteger.TWO));

        // 2^255: toByteArray() returns 33 bytes, the first of them a 0x00 sign byte that must be dropped.
        BigInteger signPadded = BigInteger.ONE.shiftLeft(255);
        byte[] highBit = EcKeys.encodeUncompressed(pointAt(signPadded, signPadded, p256));
        assertThat(highBit).hasSize(EcKeys.UNCOMPRESSED_LENGTH);
        assertThat(Arrays.copyOfRange(highBit, 1, 33))
                .as("the sign byte is dropped, the value keeps its position")
                .isEqualTo(rightAligned(signPadded));
    }

    @Test
    void everyGeneratedKeyRoundTripsThroughTheWireFormat() {
        for (int i = 0; i < 64; i++) {
            ECPublicKey generated = (ECPublicKey) EcKeys.generateP256(jca).getPublic();

            byte[] encoded = EcKeys.encodeUncompressed(generated);

            assertThat(encoded).hasSize(EcKeys.UNCOMPRESSED_LENGTH);
            assertThat(EcKeys.decodeP256PublicKey(encoded, jca).getW())
                    .as("attempt %d", i)
                    .isEqualTo(generated.getW());
        }
    }

    /** The 32-byte big-endian form the wire format requires. */
    private static byte[] rightAligned(BigInteger value) {
        byte[] out = new byte[EcKeys.COORDINATE_LENGTH];
        byte[] raw = value.toByteArray();
        int length = Math.min(raw.length, EcKeys.COORDINATE_LENGTH);
        System.arraycopy(raw, raw.length - length, out, EcKeys.COORDINATE_LENGTH - length, length);
        return out;
    }

    /**
     * A public key carrying an arbitrary point. {@code encodeUncompressed} serialises whatever {@code getW()} reports —
     * it is not a validation step — which is what makes the coordinate widths above testable without hunting for a
     * generated key whose X happens to be small.
     */
    private static ECPublicKey pointAt(BigInteger x, BigInteger y, ECParameterSpec params) {
        return new ECPublicKey() {
            @java.io.Serial
            private static final long serialVersionUID = 1L;

            @Override
            public ECPoint getW() {
                return new ECPoint(x, y);
            }

            @Override
            public ECParameterSpec getParams() {
                return params;
            }

            @Override
            public String getAlgorithm() {
                return Algorithms.EC;
            }

            @Override
            public String getFormat() {
                return "X.509";
            }

            @Override
            public byte[] getEncoded() {
                return new byte[0];
            }
        };
    }
}
