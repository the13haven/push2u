/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import com.the13haven.push2u.VapidSigner;

/**
 * The conformance contract every {@link VapidSigner} must satisfy: the advertised public key is a 65-byte uncompressed
 * point that actually lies on NIST P-256, and signing produces a raw {@code r || s} ES256 signature (64 bytes) that
 * verifies against it. Each implementation extends this and supplies a configured signer via {@link #signer()} — the
 * local signer's unit test and every remote signer's integration test.
 *
 * <p>Verification uses only the JDK and the public {@link VapidSigner} surface, so the contract is self-contained and
 * carries no push2u-internal dependency.
 */
public abstract class VapidSignerContractTest {

    /**
     * The signer under test.
     *
     * @return a fully configured {@link VapidSigner}
     */
    protected abstract VapidSigner signer();

    @Test
    void publicKeyIsA65ByteUncompressedPoint() {
        byte[] publicKey = signer().publicKey();
        assertThat(publicKey).hasSize(65);
        assertThat(publicKey[0]).as("X9.62 uncompressed point prefix").isEqualTo((byte) 0x04);
    }

    /**
     * Length and prefix say nothing about the coordinates: the JCA imports a well-framed off-curve point without
     * complaint, and a signer advertising one would publish a VAPID key no push service can verify. So the contract
     * checks the point against P-256 itself — coordinates inside the prime field, then the curve equation {@code y² ≡
     * x³ + ax + b (mod p)}.
     */
    @Test
    void publicKeyIsAPointOnTheP256Curve() throws Exception {
        byte[] publicKey = signer().publicKey();
        assertThat(publicKey).hasSize(65);

        BigInteger x = new BigInteger(1, Arrays.copyOfRange(publicKey, 1, 33));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(publicKey, 33, 65));
        EllipticCurve curve = p256Parameters().getCurve();
        BigInteger p = ((ECFieldFp) curve.getField()).getP();
        assertThat(x).as("x is inside the prime field (x < p)").isLessThan(p);
        assertThat(y).as("y is inside the prime field (y < p)").isLessThan(p);

        BigInteger left = y.multiply(y).mod(p);
        BigInteger right = x.multiply(x)
                .multiply(x)
                .add(curve.getA().multiply(x))
                .add(curve.getB())
                .mod(p);
        assertThat(left)
                .as("the advertised point satisfies the P-256 curve equation (y² = x³ + ax + b mod p)")
                .isEqualTo(right);
    }

    @Test
    void signatureIsRawRsThatVerifiesAgainstTheAdvertisedPublicKey() throws Exception {
        VapidSigner signer = signer();
        byte[] signingInput = "push2u VapidSigner conformance".getBytes(StandardCharsets.US_ASCII);

        byte[] signature = signer.sign(signingInput);
        assertThat(signature).as("raw r||s, not DER").hasSize(64);

        Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
        verifier.initVerify(decodeP256PublicKey(signer.publicKey()));
        verifier.update(signingInput);
        assertThat(verifier.verify(signature))
                .as("verifies against the advertised public key")
                .isTrue();
    }

    private static ECPublicKey decodeP256PublicKey(byte[] uncompressed) throws Exception {
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(uncompressed, 1, 33));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(uncompressed, 33, 65));
        return (ECPublicKey)
                KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), p256Parameters()));
    }

    /** The canonical {@code secp256r1} (NIST P-256) domain parameters, from the platform JCE providers. */
    private static ECParameterSpec p256Parameters() throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        return parameters.getParameterSpec(ECParameterSpec.class);
    }
}
