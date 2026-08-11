/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import com.the13haven.push2u.VapidSigner;

/**
 * The kit checking itself. {@link VapidSignerContractTest} is published so that a signer implementation finds out it
 * encodes something wrong before a push service silently rejects its JWT — which is worth exactly as much as the
 * contract's ability to fail. So each of the kit's checks is run twice here: once against a signer that satisfies the
 * contract, and once against one that breaks precisely what that check is about.
 *
 * <p>The contract's ES256 verification also carries a branch no CI platform reaches on its own: on a JVM whose
 * providers register only DER-form ECDSA (BouncyCastle FIPS), the kit re-encodes the raw signature to minimal DER and
 * verifies through {@code SHA256withECDSA}. That fallback is pinned here directly — its positive and negative
 * verification outcomes, and the minimal-DER re-encoding itself against hand-written expected bytes.
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
        assertThatCode(contract::publicKeyBase64UrlIsTheEncodingOfTheAdvertisedPublicKey)
                .doesNotThrowAnyException();
        assertThatCode(contract::publicKeyIsAFreshCopyOnEveryCall).doesNotThrowAnyException();
        assertThatCode(contract::signHandsOutAFreshArrayOnEveryCall).doesNotThrowAnyException();
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
    void sharedInternalKeyArrayFailsTheFreshCopyCheck() throws Exception {
        Contract contract =
                new Contract(new SharedArrayKeySigner(new JdkP256Signer(keyPair(), Encoding.RAW, PointDamage.NONE)));

        assertThatCode(contract::publicKeyIsA65ByteUncompressedPoint)
                .as("the shared array is a perfectly valid key — only aliasing is wrong with it")
                .doesNotThrowAnyException();
        assertThatThrownBy(contract::publicKeyIsAFreshCopyOnEveryCall)
                .as("a signer handing out its internal array is what the fresh-copy check exists to catch")
                .isInstanceOf(AssertionError.class);
    }

    /**
     * The aliasing a mutation probe cannot see. This signer hands out one buffer and refills it with the key on every
     * call, so writing into what it returned is undone before the next call — yet two callers still hold the same
     * object, which is exactly what the contract forbids. Checking identity rather than consequences is what makes it
     * catchable, and this is the case that decided that choice.
     */
    @Test
    void aRefilledSharedBufferAlsoFailsTheFreshCopyCheck() throws Exception {
        Contract contract = new Contract(
                new RefillingBufferKeySigner(new JdkP256Signer(keyPair(), Encoding.RAW, PointDamage.NONE)));

        assertThatCode(contract::publicKeyIsA65ByteUncompressedPoint)
                .as("every call reports the right key — the refill sees to that")
                .doesNotThrowAnyException();
        assertThatThrownBy(contract::publicKeyIsAFreshCopyOnEveryCall)
                .as("one buffer handed to two callers is aliasing however faithfully it is refilled")
                .isInstanceOf(AssertionError.class);
    }

    @Test
    void aReusedSignatureBufferFailsTheSignOwnershipCheck() throws Exception {
        Contract contract = new Contract(
                new ReusedSignatureBufferSigner(new JdkP256Signer(keyPair(), Encoding.RAW, PointDamage.NONE)));

        assertThatCode(contract::signatureIsRawRsThatVerifiesAgainstTheAdvertisedPublicKey)
                .as("each signature is genuine and verifies — only the buffer is shared")
                .doesNotThrowAnyException();
        assertThatThrownBy(contract::signHandsOutAFreshArrayOnEveryCall)
                .as("a signer reusing one signature buffer is what the ownership check exists to catch")
                .isInstanceOf(AssertionError.class);
    }

    // CI never runs on a JVM whose providers lack the P1363 signature name, so the contract's DER
    // fallback — the branch a FIPS-only consumer platform takes — is exercised directly here
    // through the kit's package-private seam rather than hoped for.
    @Test
    void rawSignatureVerifiesThroughTheDerFallback() throws Exception {
        VapidSigner signer = new JdkP256Signer(keyPair(), Encoding.RAW, PointDamage.NONE);
        byte[] input = "push2u DER fallback probe".getBytes(StandardCharsets.US_ASCII);
        byte[] signature = signer.sign(input);

        assertThat(VapidSignerContractTest.verifyEs256ViaDerFallback(signer.publicKey(), input, signature))
                .as("a genuine raw signature verifies after the minimal-DER re-encode")
                .isTrue();
    }

    @Test
    void derFallbackStillRejectsWhatItShould() throws Exception {
        VapidSigner signer = new JdkP256Signer(keyPair(), Encoding.RAW, PointDamage.NONE);
        byte[] input = "push2u DER fallback probe".getBytes(StandardCharsets.US_ASCII);
        byte[] signature = signer.sign(input);

        assertThat(VapidSignerContractTest.verifyEs256ViaDerFallback(
                        signer.publicKey(), "a different input".getBytes(StandardCharsets.US_ASCII), signature))
                .as("the fallback must not verify vacuously")
                .isFalse();
        byte[] garbage = new byte[64];
        Arrays.fill(garbage, (byte) 0x42);
        assertThat(VapidSignerContractTest.verifyEs256ViaDerFallback(signer.publicKey(), input, garbage))
                .as("out-of-range garbage of the right length is invalid, not an error")
                .isFalse();
    }

    @Test
    void minimalDerStripsLeadingZeroBytes() {
        // r = 1 and s = 2: the 31 leading zero bytes of each coordinate must go, leaving
        // one-byte INTEGERs — DER admits exactly one encoding, and strict (FIPS) verifiers
        // reject a padded one.
        byte[] der = VapidSignerContractTest.toMinimalDer(concat(coordinate(0x01), coordinate(0x02)));

        assertThat(der).containsExactly(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02);
    }

    @Test
    void minimalDerAddsTheSignByteAHighBitCoordinateNeeds() {
        // A full 32-byte coordinate whose first byte has the high bit set would read as negative
        // in two's complement; DER requires one leading 0x00 to keep it positive — and no more.
        byte[] r = new byte[32];
        r[0] = (byte) 0x80;

        byte[] der = VapidSignerContractTest.toMinimalDer(concat(r, coordinate(0x01)));

        byte[] expected = concat(bytes(0x30, 0x26, 0x02, 0x21, 0x00, 0x80), new byte[31], bytes(0x02, 0x01, 0x01));
        assertThat(der).isEqualTo(expected);
    }

    @Test
    void minimalDerEncodesAZeroCoordinateAsTheMinimalZeroInteger() {
        // A zero r or s can never verify, and it is the verifier's job to say so: the re-encoding
        // must stay well-formed DER (02 01 00) so the rejection is cryptographic, not a parsing
        // accident.
        byte[] der = VapidSignerContractTest.toMinimalDer(concat(new byte[32], coordinate(0x01)));

        assertThat(der).containsExactly(0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01);
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

    /**
     * The check exists for an override, so the override is what has to fail it. This one encodes the right key in the
     * standard alphabet with padding — a plausible mistake rather than a contrived one, and the reason the contract
     * compares strings instead of decoding both sides: a decoder would accept these characters and report agreement.
     */
    @Test
    void anOverrideEncodingTheKeyDifferentlyFailsTheEncodingCheck() throws Exception {
        Contract contract = new Contract(
                new StandardAlphabetEncodingSigner(new JdkP256Signer(keyPair(), Encoding.RAW, PointDamage.NONE)));

        assertThatCode(contract::publicKeyIsA65ByteUncompressedPoint)
                .as("the key itself is beyond reproach — only its published spelling is wrong")
                .doesNotThrowAnyException();
        assertThatThrownBy(contract::publicKeyBase64UrlIsTheEncodingOfTheAdvertisedPublicKey)
                .as("the browser cannot read a standard-alphabet, padded applicationServerKey")
                .isInstanceOf(AssertionError.class);
    }

    /**
     * An override publishing a different key altogether: the drift the check is really about, since a signer whose
     * advertised key is not the one it signs with invalidates every subscription taken against it.
     */
    @Test
    void anOverridePublishingAnotherKeyFailsTheEncodingCheck() throws Exception {
        Contract contract = new Contract(
                new ForeignKeySigner(new JdkP256Signer(keyPair(), Encoding.RAW, PointDamage.NONE), keyPair()));

        assertThatThrownBy(contract::publicKeyBase64UrlIsTheEncodingOfTheAdvertisedPublicKey)
                .as("advertising one key while signing with another is invisible until a push service rejects the JWT")
                .isInstanceOf(AssertionError.class);
    }

    private static KeyPair keyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    /** A 32-byte big-endian coordinate holding a single-byte value. */
    private static byte[] coordinate(int lastByte) {
        byte[] c = new byte[32];
        c[31] = (byte) lastByte;
        return c;
    }

    private static byte[] bytes(int... values) {
        byte[] out = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            out[i] = (byte) values[i];
        }
        return out;
    }

    private static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] out = new byte[length];
        int at = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, at, part.length);
            at += part.length;
        }
        return out;
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

    /**
     * A signer handing out its internal key array instead of a copy — otherwise fully conforming, which is exactly why
     * only the fresh-copy check may catch it.
     */
    private static final class SharedArrayKeySigner implements VapidSigner {

        private final VapidSigner delegate;
        private final byte[] publicKey;

        SharedArrayKeySigner(VapidSigner delegate) {
            this.delegate = delegate;
            this.publicKey = delegate.publicKey();
        }

        @Override
        public byte[] sign(byte[] signingInput) {
            return delegate.sign(signingInput);
        }

        @Override
        public byte[] publicKey() {
            return publicKey;
        }
    }

    /**
     * Hands out one buffer, refilled with the key on every call. Conforming by content and by every observable
     * consequence of a mutation, aliasing all the same — see {@link #aRefilledSharedBufferAlsoFailsTheFreshCopyCheck}.
     */
    private static final class RefillingBufferKeySigner implements VapidSigner {

        private final VapidSigner delegate;
        private final byte[] buffer;

        RefillingBufferKeySigner(VapidSigner delegate) {
            this.delegate = delegate;
            this.buffer = new byte[delegate.publicKey().length];
        }

        @Override
        public byte[] sign(byte[] signingInput) {
            return delegate.sign(signingInput);
        }

        @Override
        public byte[] publicKey() {
            byte[] current = delegate.publicKey();
            System.arraycopy(current, 0, buffer, 0, current.length);
            return buffer;
        }
    }

    /** Signs correctly but returns the same array every time — the {@code sign()} half of the ownership rule. */
    private static final class ReusedSignatureBufferSigner implements VapidSigner {

        private final VapidSigner delegate;
        private final byte[] buffer = new byte[64];

        ReusedSignatureBufferSigner(VapidSigner delegate) {
            this.delegate = delegate;
        }

        @Override
        public byte[] sign(byte[] signingInput) {
            byte[] signature = delegate.sign(signingInput);
            System.arraycopy(signature, 0, buffer, 0, signature.length);
            return buffer;
        }

        @Override
        public byte[] publicKey() {
            return delegate.publicKey();
        }
    }

    /** Overrides the published spelling with the standard base64 alphabet and padding, over the correct key. */
    private static final class StandardAlphabetEncodingSigner implements VapidSigner {

        private final VapidSigner delegate;

        StandardAlphabetEncodingSigner(VapidSigner delegate) {
            this.delegate = delegate;
        }

        @Override
        public byte[] sign(byte[] signingInput) {
            return delegate.sign(signingInput);
        }

        @Override
        public byte[] publicKey() {
            return delegate.publicKey();
        }

        @Override
        public String publicKeyBase64Url() {
            return Base64.getEncoder().encodeToString(delegate.publicKey());
        }
    }

    /** Signs with one key and publishes another — the drift that only a comparison of the two answers can catch. */
    private static final class ForeignKeySigner implements VapidSigner {

        private final VapidSigner delegate;
        private final VapidSigner other;

        ForeignKeySigner(VapidSigner delegate, KeyPair otherKeyPair) {
            this.delegate = delegate;
            this.other = new JdkP256Signer(otherKeyPair, Encoding.RAW, PointDamage.NONE);
        }

        @Override
        public byte[] sign(byte[] signingInput) {
            return delegate.sign(signingInput);
        }

        @Override
        public byte[] publicKey() {
            return delegate.publicKey();
        }

        @Override
        public String publicKeyBase64Url() {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(other.publicKey());
        }
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
