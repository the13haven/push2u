/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

import org.junit.jupiter.api.Test;

import com.the13haven.push2u.VapidSigner;

/**
 * The kit checking itself. {@link VapidSignerContractTest} is published so that a signer implementation finds out it
 * encodes something wrong before a push service silently rejects its JWT — which is worth exactly as much as the
 * contract's ability to fail. So each of the three checks is run twice here: once against a signer that satisfies the
 * contract, and once against one that breaks precisely what that check is about.
 *
 * <p>The signers are built on the JDK alone rather than on {@code LocalEcVapidSigner}: the kit's correctness must not
 * depend on the correctness of the implementation shipped beside it.
 */
final class VapidSignerContractSelfTest {

    /** Drives one contract instance over a supplied signer, since the kit takes its subject from an abstract method. */
    private static final class Contract extends VapidSignerContractTest {

        private final VapidSigner signer;

        Contract(VapidSigner signer) {
            this.signer = signer;
        }

        @Override
        protected VapidSigner signer() {
            return signer;
        }
    }

    @Test
    void conformingSignerSatisfiesEveryCheck() throws Exception {
        Contract contract = new Contract(new JdkP256Signer(keyPair(), Encoding.RAW, PointDamage.NONE));

        assertThatCode(contract::publicKeyIsA65ByteUncompressedPoint).doesNotThrowAnyException();
        assertThatCode(contract::publicKeyIsAPointOnTheP256Curve).doesNotThrowAnyException();
        assertThatCode(contract::signatureIsRawRsThatVerifiesAgainstTheAdvertisedPublicKey)
                .doesNotThrowAnyException();
    }

    @Test
    void derSignatureFailsTheRawRsCheck() throws Exception {
        Contract contract = new Contract(new JdkP256Signer(keyPair(), Encoding.DER, PointDamage.NONE));

        assertThatThrownBy(contract::signatureIsRawRsThatVerifiesAgainstTheAdvertisedPublicKey)
                .as("a DER signature is the failure this contract exists to catch")
                .isInstanceOf(AssertionError.class);
    }

    @Test
    void compressedPublicKeyFailsTheEncodingCheck() throws Exception {
        Contract contract = new Contract(new JdkP256Signer(keyPair(), Encoding.RAW, PointDamage.COMPRESSED));

        assertThatThrownBy(contract::publicKeyIsA65ByteUncompressedPoint)
                .as("a compressed point is 33 bytes, not 65")
                .isInstanceOf(AssertionError.class);
    }

    @Test
    void offCurvePublicKeyFailsTheCurveCheck() throws Exception {
        Contract contract = new Contract(new JdkP256Signer(keyPair(), Encoding.RAW, PointDamage.OFF_CURVE));

        assertThatCode(contract::publicKeyIsA65ByteUncompressedPoint)
                .as("well-framed: 65 bytes behind the uncompressed prefix, which is why length alone proves nothing")
                .doesNotThrowAnyException();
        assertThatThrownBy(contract::publicKeyIsAPointOnTheP256Curve)
                .as("the coordinates do not satisfy the curve equation")
                .isInstanceOf(AssertionError.class);
    }

    private static KeyPair keyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    /** How the signer encodes its signature: the contract requires {@link #RAW}. */
    private enum Encoding {
        RAW,
        DER
    }

    /** What the signer advertises as its public point: the contract requires {@link #NONE}. */
    private enum PointDamage {
        NONE,
        COMPRESSED,
        OFF_CURVE
    }

    /** A P-256 signer on platform primitives only, able to break each half of the contract on request. */
    private static final class JdkP256Signer implements VapidSigner {

        private final KeyPair keyPair;
        private final Encoding encoding;
        private final PointDamage damage;

        JdkP256Signer(KeyPair keyPair, Encoding encoding, PointDamage damage) {
            this.keyPair = keyPair;
            this.encoding = encoding;
            this.damage = damage;
        }

        @Override
        public byte[] sign(byte[] signingInput) {
            String algorithm = encoding == Encoding.RAW ? "SHA256withECDSAinP1363Format" : "SHA256withECDSA";
            try {
                Signature signature = Signature.getInstance(algorithm);
                signature.initSign(keyPair.getPrivate());
                signature.update(signingInput);
                return signature.sign();
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("signing the conformance probe failed", e);
            }
        }

        @Override
        public byte[] publicKey() {
            ECPublicKey key = (ECPublicKey) keyPair.getPublic();
            BigInteger x = key.getW().getAffineX();
            BigInteger y = key.getW().getAffineY();

            if (damage == PointDamage.COMPRESSED) {
                byte[] compressed = new byte[33];
                compressed[0] = (byte) (y.testBit(0) ? 0x03 : 0x02);
                copyCoordinate(x, compressed, 1);
                return compressed;
            }

            byte[] uncompressed = new byte[65];
            uncompressed[0] = 0x04;
            copyCoordinate(x, uncompressed, 1);
            // Flipping the lowest bit of y keeps the coordinate inside the prime field and well
            // below p, so only the curve equation can tell the point apart from a valid one — which
            // is exactly the check under test.
            copyCoordinate(damage == PointDamage.OFF_CURVE ? y.flipBit(0) : y, uncompressed, 33);
            return uncompressed;
        }

        /** Writes a coordinate right-aligned into 32 bytes, dropping the sign byte {@link BigInteger} may prepend. */
        private static void copyCoordinate(BigInteger coordinate, byte[] target, int offset) {
            byte[] magnitude = coordinate.toByteArray();
            int length = Math.min(magnitude.length, 32);
            System.arraycopy(magnitude, magnitude.length - length, target, offset + 32 - length, length);
        }
    }
}
