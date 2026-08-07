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
import java.security.AlgorithmParametersSpi;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Arrays;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The {@code p256dh} key travels from a browser through the application's own storage before reaching this library, so
 * it is attacker-reachable input in the same sense a request body is. These are the shapes an invalid-curve attack
 * arrives in — a point off the curve, the point at infinity, coordinates outside the field — modelled on the classes of
 * case Project Wycheproof enumerates for {@code ecdh_secp256r1}.
 *
 * <p>What is being pinned is that each one is refused at decode time, by the library's own check in
 * {@code EcKeys.decodeP256PublicKey}, as a {@link PushCryptoException} — before the point ever reaches the provider's
 * {@code KeyFactory}, and therefore independently of whether the provider would have caught it in
 * {@code KeyAgreement.doPhase}.
 */
class EcKeysUntrustedInputTest {

    private final Jca jca = Jca.platform();

    /** A valid point, from the RFC 8291 worked example, used as the base for each corruption below. */
    private byte[] validPoint() {
        return b64(TestVectors.UA_PUBLIC);
    }

    /**
     * The boundary these tests pin: {@code decodeP256PublicKey} itself checks the curve equation and refuses the point
     * before the provider's {@code KeyFactory} sees it. The messages are asserted exactly because they are the evidence
     * the refusal is the library's own — the old guarantee was "no later than ECDH", and that one rested on the
     * provider: {@code ECPublicKeySpec} is a container, not a validator, so a provider configured through
     * {@code Jca.using(...)} that skipped point validation in {@code doPhase} would silently have accepted the point.
     */
    @Test
    void aPointOffTheCurveIsRefusedAtDecodeTime() {
        byte[] offCurve = validPoint();
        offCurve[offCurve.length - 1] ^= 0x01; // Y is no longer a square root of x^3 - 3x + b

        assertThatThrownBy(() -> EcKeys.decodeP256PublicKey(offCurve, jca))
                .as("an off-curve point is the entry ticket for an invalid-curve attack")
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("does not satisfy the curve equation");
    }

    /**
     * The X9.62 wire format cannot express the point at infinity — it encodes infinity as a single {@code 0x00} byte,
     * which fails the length check — so all-zero coordinates are merely the affine point {@code (0, 0)}, off the curve
     * like any other because P-256's {@code b} is non-zero. Hence the same refusal, not a special one.
     */
    @Test
    void thePointAtInfinityEncodedAsZeroesIsRefusedAtDecodeTime() {
        byte[] infinity = new byte[EcKeys.UNCOMPRESSED_LENGTH];
        infinity[0] = 0x04; // 0x04 || 0^32 || 0^32

        assertThatThrownBy(() -> EcKeys.decodeP256PublicKey(infinity, jca))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("does not satisfy the curve equation");
    }

    @Test
    void coordinatesOutsideTheFieldAreRefusedAtDecodeTime() {
        byte[] outOfRange = new byte[EcKeys.UNCOMPRESSED_LENGTH];
        outOfRange[0] = 0x04;
        Arrays.fill(outOfRange, 1, EcKeys.UNCOMPRESSED_LENGTH, (byte) 0xFF); // X = Y = 2^256 - 1 > p

        assertThatThrownBy(() -> EcKeys.decodeP256PublicKey(outOfRange, jca))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("coordinate outside the field");
    }

    /**
     * The exact boundary of the field check: {@code x = p} is one past the last representable field element, and
     * congruent to zero mod p. What is pinned is the <em>message</em>: an implementation that reduced before comparing
     * would also refuse this point, but through the curve equation rather than through the field check, so only the
     * message distinguishes a raw comparison from a reducing one. The case such an implementation would genuinely
     * accept — {@code x = p + x₀} with {@code (x₀, y)} on the curve — needs an {@code x₀} below 2^224 and cannot be
     * built from the RFC 8291 point, which makes {@code x = p} the practical proxy for "the raw coordinate is what is
     * compared".
     */
    @Test
    void aCoordinateAtExactlyTheFieldPrimeIsRefusedAtDecodeTime() {
        byte[] atPrime = validPoint();
        System.arraycopy(rightAligned(fieldPrime()), 0, atPrime, 1, EcKeys.COORDINATE_LENGTH); // X = p, Y kept valid

        assertThatThrownBy(() -> EcKeys.decodeP256PublicKey(atPrime, jca))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("coordinate outside the field");
    }

    /**
     * {@code Jca.using(...)} means the {@code secp256r1} parameters come from an arbitrary provider, and a provider
     * answering that lookup with a binary-field ({@code ECFieldF2m}) parameter set is defective — the pinned behaviour
     * is failing closed at the parameter seam, before any key is imported on those parameters.
     */
    @Test
    void parametersOverANonPrimeFieldFailClosedInsteadOfSkippingTheCheck() {
        assertThatThrownBy(() -> EcKeys.decodeP256PublicKey(validPoint(), Jca.using(new BinaryFieldProvider())))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("non-prime field");
    }

    // ---- a provider answering secp256r1 with some other curve ----------------------------------

    /**
     * The {@code secp256r1} lookup is by name, and the name is all a defective provider needs to honour: before the
     * value-wise verification, a provider could answer it with any other 256-bit prime-field curve — secp256k1,
     * brainpoolP256r1, or a deliberately weak one — and ECDH, the VAPID private key import and the ephemeral key
     * generation would all silently run on that curve. Each canonical component (field prime, both coefficients,
     * generator, order, cofactor) must be compared, so each is falsified on its own here, with the message naming it —
     * the messages quote no parameter values, only which component is off.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("substitutedP256Components")
    void parametersDifferingFromNistP256InAnyComponentFailClosed(
            String component, ECParameterSpec substituted, String expectedFragment) {
        assertThatThrownBy(
                        () -> EcKeys.decodeP256PublicKey(validPoint(), Jca.using(new ParametersProvider(substituted))))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining(expectedFragment)
                .hasMessageContaining("NIST P-256");
    }

    /**
     * The private-scalar decode imports the VAPID private key on the same provider parameters, and a weak curve there
     * leaks the long-term key through the signatures made with it — so the wrong-curve refusal must cover this path
     * too, not only the public-key one.
     */
    @Test
    void thePrivateKeyDecodeGoesThroughTheSameParameterVerification() {
        Jca secp256k1 =
                Jca.using(new ParametersProvider(withCurve(SECP256K1_P, BigInteger.ZERO, BigInteger.valueOf(7))));

        assertThatThrownBy(() -> EcKeys.decodeP256PrivateKey(b64(TestVectors.AS_PRIVATE), secp256k1))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("NIST P-256");
    }

    /** secp256k1's field prime — the 256-bit prime-field curve most likely to be confused with P-256. */
    private static final BigInteger SECP256K1_P =
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);

    private static Stream<Arguments> substitutedP256Components() {
        return Stream.of(
                Arguments.of("wrong field prime (secp256k1's p)", withField(SECP256K1_P), "prime field modulus"),
                Arguments.of("wrong coefficient a", withA(BigInteger.ZERO), "coefficient a"),
                Arguments.of("wrong coefficient b (secp256k1's b)", withB(BigInteger.valueOf(7)), "coefficient b"),
                Arguments.of(
                        "wrong generator", withGenerator(new ECPoint(BigInteger.ONE, BigInteger.TWO)), "generator"),
                Arguments.of("wrong order", withOrder(P256PublicKeys.N.subtract(BigInteger.ONE)), "order"),
                Arguments.of("wrong cofactor", withCofactor(4), "cofactor"));
    }

    private static ECParameterSpec withField(BigInteger p) {
        return spec(p, P256PublicKeys.A, P256PublicKeys.B, canonicalGenerator(), P256PublicKeys.N, 1);
    }

    private static ECParameterSpec withA(BigInteger a) {
        return spec(P256PublicKeys.P, a, P256PublicKeys.B, canonicalGenerator(), P256PublicKeys.N, 1);
    }

    private static ECParameterSpec withB(BigInteger b) {
        return spec(P256PublicKeys.P, P256PublicKeys.A, b, canonicalGenerator(), P256PublicKeys.N, 1);
    }

    private static ECParameterSpec withCurve(BigInteger p, BigInteger a, BigInteger b) {
        return spec(p, a, b, canonicalGenerator(), P256PublicKeys.N, 1);
    }

    private static ECParameterSpec withGenerator(ECPoint generator) {
        return spec(P256PublicKeys.P, P256PublicKeys.A, P256PublicKeys.B, generator, P256PublicKeys.N, 1);
    }

    private static ECParameterSpec withOrder(BigInteger order) {
        return spec(P256PublicKeys.P, P256PublicKeys.A, P256PublicKeys.B, canonicalGenerator(), order, 1);
    }

    private static ECParameterSpec withCofactor(int cofactor) {
        return spec(
                P256PublicKeys.P, P256PublicKeys.A, P256PublicKeys.B, canonicalGenerator(), P256PublicKeys.N, cofactor);
    }

    private static ECPoint canonicalGenerator() {
        return new ECPoint(P256PublicKeys.GX, P256PublicKeys.GY);
    }

    private static ECParameterSpec spec(
            BigInteger p, BigInteger a, BigInteger b, ECPoint generator, BigInteger order, int cofactor) {
        return new ECParameterSpec(new EllipticCurve(new ECFieldFp(p), a, b), generator, order, cofactor);
    }

    /** A valid point still decodes and feeds ECDH — the RFC 8291 vector in {@link EcKeysTest} pins the exact secret. */
    @Test
    void theRfc8291WorkedExamplePointPassesTheDecodeTimeCheck() {
        assertThat(agreeWith(validPoint())).hasSize(32);
    }

    /** Decodes the point and runs the agreement it would feed — the full path a subscription key takes. */
    private byte[] agreeWith(byte[] uaPublicKey) {
        return EcKeys.ecdh(
                EcKeys.decodeP256PrivateKey(b64(TestVectors.AS_PRIVATE), jca),
                EcKeys.decodeP256PublicKey(uaPublicKey, jca),
                jca);
    }

    /** P-256's field prime, taken from the platform parameters the production check reads it from. */
    private BigInteger fieldPrime() {
        return ((ECFieldFp) jca.p256Parameters().getCurve().getField()).getP();
    }

    /**
     * A provider whose only registration answers the {@code secp256r1} {@code AlgorithmParameters} lookup with
     * parameters over a binary field — the defective-provider shape the fail-closed test above needs.
     * {@code Service.newInstance} is overridden, so the SPI needs no reflective access.
     */
    private static final class BinaryFieldProvider extends Provider {

        @java.io.Serial
        private static final long serialVersionUID = 1L;

        BinaryFieldProvider() {
            super("push2u-binary-field", "1.0", "answers secp256r1 with a binary field");
            putService(
                    new Service(
                            this,
                            "AlgorithmParameters",
                            Algorithms.EC,
                            BinaryFieldParameters.class.getName(),
                            null,
                            null) {
                        @Override
                        public Object newInstance(Object constructorParameter) {
                            return new BinaryFieldParameters();
                        }
                    });
        }
    }

    /**
     * An {@code AlgorithmParameters} SPI reporting a binary-field ({@code ECFieldF2m}) parameter set —
     * {@code sect163}-shaped, the details are irrelevant, only the field type matters.
     */
    public static final class BinaryFieldParameters extends AlgorithmParametersSpi {

        @Override
        protected void engineInit(AlgorithmParameterSpec paramSpec) {
            // Accept the ECGenParameterSpec("secp256r1") init and misreport the parameters anyway.
        }

        @Override
        protected void engineInit(byte[] params) {
            // Unused by Jca.p256Parameters().
        }

        @Override
        protected void engineInit(byte[] params, String format) {
            // Unused by Jca.p256Parameters().
        }

        @Override
        protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec) {
            EllipticCurve binaryCurve =
                    new EllipticCurve(new ECFieldF2m(163, new int[] {7, 6, 3}), BigInteger.ONE, BigInteger.ONE);
            return paramSpec.cast(new ECParameterSpec(
                    binaryCurve, new ECPoint(BigInteger.ONE, BigInteger.ONE), BigInteger.valueOf(2), 1));
        }

        @Override
        protected byte[] engineGetEncoded() {
            return new byte[0];
        }

        @Override
        protected byte[] engineGetEncoded(String format) {
            return new byte[0];
        }

        @Override
        protected String engineToString() {
            return "binary-field parameters";
        }
    }

    /**
     * A provider answering the {@code secp256r1} {@code AlgorithmParameters} lookup with a fixed parameter set — the
     * wrong-curve-provider shape the value-wise verification tests need. Its {@code KeyFactory} is real (delegated to
     * the stock provider), because a genuinely defective provider offers a working key import too — the pinned
     * behaviour is that the parameters are refused before that import is ever asked to run.
     */
    private static final class ParametersProvider extends Provider {

        @java.io.Serial
        private static final long serialVersionUID = 1L;

        ParametersProvider(ECParameterSpec parameters) {
            super("push2u-fixed-parameters", "1.0", "answers secp256r1 with a fixed parameter set");
            putService(
                    new Service(
                            this, "AlgorithmParameters", Algorithms.EC, FixedParameters.class.getName(), null, null) {
                        @Override
                        public Object newInstance(Object constructorParameter) {
                            return new FixedParameters(parameters);
                        }
                    });
            Provider.Service source =
                    java.security.Security.getProvider("SunEC").getService("KeyFactory", Algorithms.EC);
            putService(new Service(this, "KeyFactory", Algorithms.EC, source.getClassName(), null, null) {
                @Override
                public Object newInstance(Object constructorParameter) throws java.security.NoSuchAlgorithmException {
                    return source.newInstance(constructorParameter);
                }
            });
        }
    }

    /** An {@code AlgorithmParameters} SPI reporting whatever parameter set it was built with. */
    public static final class FixedParameters extends AlgorithmParametersSpi {

        private final ECParameterSpec parameters;

        FixedParameters(ECParameterSpec parameters) {
            this.parameters = parameters;
        }

        @Override
        protected void engineInit(AlgorithmParameterSpec paramSpec) {
            // Accept the ECGenParameterSpec("secp256r1") init and report the fixed parameters anyway.
        }

        @Override
        protected void engineInit(byte[] params) {
            // Unused by Jca.p256Parameters().
        }

        @Override
        protected void engineInit(byte[] params, String format) {
            // Unused by Jca.p256Parameters().
        }

        @Override
        protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec) {
            return paramSpec.cast(parameters);
        }

        @Override
        protected byte[] engineGetEncoded() {
            return new byte[0];
        }

        @Override
        protected byte[] engineGetEncoded(String format) {
            return new byte[0];
        }

        @Override
        protected String engineToString() {
            return "fixed parameters";
        }
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
        Jca crippled = Jca.using(new Provider("push2u-empty", "1.0", "registers no algorithms") {});

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

    // ---- the ephemeral key generator -----------------------------------------------------------

    /**
     * {@code generateP256} asks the provider's {@code KeyPairGenerator} for {@code secp256r1} by name, and the
     * parameter verification at the {@code AlgorithmParameters} lookup does not reach this path — the generator
     * resolves the curve name itself. The generated public point drives ECDH and is published in the {@code aes128gcm}
     * header, so a generator answering the name with another curve's key must fail closed. secp256k1's generator point
     * is the probe: a genuine EC point, just not on P-256.
     */
    @Test
    void aGeneratedKeyPairOffTheP256CurveFailsClosed() {
        BigInteger k1x = new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
        BigInteger k1y = new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
        Jca dishonest = Jca.using(new FixedKeyPairProvider(pointAt(k1x, k1y, jca.p256Parameters())));

        assertThatThrownBy(() -> EcKeys.generateP256(dishonest))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("not on NIST P-256");
    }

    @Test
    void aGeneratedKeyThatIsNotAnEcKeyFailsClosedInsteadOfClassCasting() {
        Jca dishonest = Jca.using(new FixedKeyPairProvider(new PublicKey() {
            @java.io.Serial
            private static final long serialVersionUID = 1L;

            @Override
            public String getAlgorithm() {
                return "XDH";
            }

            @Override
            public String getFormat() {
                return "X.509";
            }

            @Override
            public byte[] getEncoded() {
                return new byte[0];
            }
        }));

        assertThatThrownBy(() -> EcKeys.generateP256(dishonest))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("not an EC");
    }

    /** {@code getAffineX()} on the point at infinity is {@code null}, so it needs refusing before the curve check. */
    @Test
    void aGeneratedKeyAtThePointAtInfinityFailsClosed() {
        Jca dishonest = Jca.using(new FixedKeyPairProvider(keyAt(ECPoint.POINT_INFINITY, jca.p256Parameters())));

        assertThatThrownBy(() -> EcKeys.generateP256(dishonest))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("point at infinity");
    }

    /**
     * The sharper defective-generator shape: the returned public <em>point</em> genuinely lies on P-256 — the curve
     * equation cannot refuse it — while the key's declared domain parameters differ from NIST P-256 in a component the
     * equation never looks at. The order {@code n} is the case that matters most: {@code n} bounds the private scalar,
     * so a generator configured with a small order draws a guessable {@code d} whose public point {@code d·G} is still
     * a perfectly good P-256 point. Pinned: the value-wise parameter comparison, not the equation, is what refuses the
     * pair, with the message naming the mismatched component.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("substitutedGeneratedKeyParameters")
    void aGeneratedKeyOnP256WithSubstitutedParametersFailsClosed(
            String component, ECParameterSpec substituted, String expectedFragment) {
        Jca dishonest = Jca.using(new FixedKeyPairProvider(keyAt(genuineP256Point(), substituted)));

        assertThatThrownBy(() -> EcKeys.generateP256(dishonest))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining(expectedFragment)
                .hasMessageContaining("NIST P-256");
    }

    private static Stream<Arguments> substitutedGeneratedKeyParameters() {
        return Stream.of(
                Arguments.of("wrong (small) order", withOrder(BigInteger.valueOf(65_537)), "wrong order n"),
                Arguments.of(
                        "wrong generator",
                        withGenerator(new ECPoint(BigInteger.ONE, BigInteger.TWO)),
                        "wrong generator"),
                Arguments.of("wrong cofactor", withCofactor(4), "wrong cofactor h"));
    }

    /** The private half drives ECDH directly, so a non-EC private key must fail closed, not class-cast later. */
    @Test
    void aGeneratedPrivateHalfThatIsNotAnEcKeyFailsClosedInsteadOfClassCasting() {
        ECPublicKey genuine = EcKeys.decodeP256PublicKey(validPoint(), jca);
        Jca dishonest = Jca.using(new FixedKeyPairProvider(genuine, nonEcPrivateKey()));

        assertThatThrownBy(() -> EcKeys.generateP256(dishonest))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("private key, not an EC");
    }

    /**
     * The private half carries its own parameter set, and it is the scalar's parameters — not the public point's — that
     * the ECDH agreement runs on, so they get the same value-wise verification as the public half's.
     */
    @Test
    void aGeneratedPrivateHalfWithNonP256ParametersFailsClosed() {
        ECPublicKey genuine = EcKeys.decodeP256PublicKey(validPoint(), jca);
        ECParameterSpec secp256k1 = withCurve(SECP256K1_P, BigInteger.ZERO, BigInteger.valueOf(7));
        Jca dishonest = Jca.using(new FixedKeyPairProvider(genuine, privateKeyOn(secp256k1)));

        assertThatThrownBy(() -> EcKeys.generateP256(dishonest))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("private")
                .hasMessageContaining("NIST P-256");
    }

    /**
     * The maximally degenerate generator: {@code KeyPair} stores whatever references its constructor was handed,
     * {@code null} included, and the refusal must still arrive as the library's own {@link PushCryptoException} — a
     * {@link NullPointerException} escaping from the diagnostic itself would be a crypto failure surfacing outside the
     * library's stated exception taxonomy.
     */
    @Test
    void aGeneratedPairWithANullPublicHalfFailsClosedAsACryptoException() {
        Jca dishonest = Jca.using(new FixedKeyPairProvider(null));

        assertThatThrownBy(() -> EcKeys.generateP256(dishonest))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("no public key");
    }

    @Test
    void aGeneratedPairWithANullPrivateHalfFailsClosedAsACryptoException() {
        ECPublicKey genuine = EcKeys.decodeP256PublicKey(validPoint(), jca);
        Jca dishonest = Jca.using(new FixedKeyPairProvider(genuine, null));

        assertThatThrownBy(() -> EcKeys.generateP256(dishonest))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("no private key");
    }

    /**
     * One step less degenerate than a null half: the half is an EC key, but its {@code getParams()} — the provider's
     * own key implementation answering, with nothing in the JDK promising the answer is non-null — reports no domain
     * parameters. The refusal must be the library's own {@link PushCryptoException}, naming the half and what is
     * missing, not a {@link NullPointerException} escaping from inside the parameter comparison.
     */
    @Test
    void aGeneratedPublicHalfWithNullParametersFailsClosedAsACryptoException() {
        Jca dishonest = Jca.using(new FixedKeyPairProvider(keyAt(genuineP256Point(), null)));

        assertThatThrownBy(() -> EcKeys.generateP256(dishonest))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("public")
                .hasMessageContaining("no domain parameters at all");
    }

    @Test
    void aGeneratedPrivateHalfWithNullParametersFailsClosedAsACryptoException() {
        ECPublicKey genuine = EcKeys.decodeP256PublicKey(validPoint(), jca);
        Jca dishonest = Jca.using(new FixedKeyPairProvider(genuine, privateKeyOn(null)));

        assertThatThrownBy(() -> EcKeys.generateP256(dishonest))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("private")
                .hasMessageContaining("no domain parameters at all");
    }

    /**
     * {@code ECPoint.POINT_INFINITY.equals(null)} is {@code false} — the infinity guard quietly waves a null point
     * through — so a {@code getW()} of {@code null} must be refused by name, before that comparison, or it dereferences
     * on the affine coordinates one line later.
     */
    @Test
    void aGeneratedPublicHalfWithANullPointFailsClosedAsACryptoException() {
        Jca dishonest = Jca.using(new FixedKeyPairProvider(keyAt(null, jca.p256Parameters())));

        assertThatThrownBy(() -> EcKeys.generateP256(dishonest))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("no point at all");
    }

    /**
     * The same degenerate answer at the other provider seam: {@code AlgorithmParameters.getParameterSpec} from a custom
     * provider can return {@code null}, and the value-wise parameter verification must then fail closed as the
     * library's crypto exception instead of dereferencing the spec.
     */
    @Test
    void aProviderAnsweringTheParameterLookupWithNullFailsClosed() {
        assertThatThrownBy(() -> EcKeys.decodeP256PublicKey(validPoint(), Jca.using(new ParametersProvider(null))))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("no domain parameters at all");
    }

    /** A genuine P-256 point (the RFC 8291 worked example's {@code ua_public}) to pair with substituted parameters. */
    private ECPoint genuineP256Point() {
        return EcKeys.decodeP256PublicKey(validPoint(), jca).getW();
    }

    /** A private key that is not an EC key at all — the shape an unguarded cast would explode on. */
    private static PrivateKey nonEcPrivateKey() {
        return new PrivateKey() {
            @java.io.Serial
            private static final long serialVersionUID = 1L;

            @Override
            public String getAlgorithm() {
                return "XDH";
            }

            @Override
            public String getFormat() {
                return "PKCS#8";
            }

            @Override
            public byte[] getEncoded() {
                return new byte[0];
            }
        };
    }

    /** An EC private key reporting the given parameter set — the wrong-curve private half the tests above need. */
    private static ECPrivateKey privateKeyOn(ECParameterSpec params) {
        return new ECPrivateKey() {
            @java.io.Serial
            private static final long serialVersionUID = 1L;

            @Override
            public BigInteger getS() {
                return BigInteger.TWO;
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
                return "PKCS#8";
            }

            @Override
            public byte[] getEncoded() {
                return new byte[0];
            }
        };
    }

    /**
     * A provider whose only registration answers the EC {@code KeyPairGenerator} lookup with a generator returning a
     * fixed key pair — the defective-generator shape the fail-closed tests above need. The one-argument form pairs the
     * given public key with a genuine platform-derived private half, for the tests that probe the public side only.
     */
    private static final class FixedKeyPairProvider extends Provider {

        @java.io.Serial
        private static final long serialVersionUID = 1L;

        FixedKeyPairProvider(PublicKey publicKey) {
            this(publicKey, EcKeys.decodeP256PrivateKey(b64(TestVectors.AS_PRIVATE), Jca.platform()));
        }

        FixedKeyPairProvider(PublicKey publicKey, PrivateKey privateKey) {
            super("push2u-fixed-keypair", "1.0", "answers EC key-pair generation with a fixed key pair");
            putService(
                    new Service(
                            this,
                            "KeyPairGenerator",
                            Algorithms.EC,
                            FixedKeyPairGenerator.class.getName(),
                            null,
                            null) {
                        @Override
                        public Object newInstance(Object constructorParameter) {
                            return new FixedKeyPairGenerator(publicKey, privateKey);
                        }
                    });
        }
    }

    /** A {@code KeyPairGenerator} SPI returning the fixed key pair it was built with. */
    public static final class FixedKeyPairGenerator extends KeyPairGeneratorSpi {

        private final PublicKey publicKey;
        private final PrivateKey privateKey;

        FixedKeyPairGenerator(PublicKey publicKey, PrivateKey privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        @Override
        public void initialize(int keysize, SecureRandom random) {
            // Unused by EcKeys.generateP256.
        }

        @Override
        public void initialize(AlgorithmParameterSpec params, SecureRandom random) {
            // Accept the ECGenParameterSpec("secp256r1") init and return the fixed pair anyway.
        }

        @Override
        public KeyPair generateKeyPair() {
            return new KeyPair(publicKey, privateKey);
        }
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

    /**
     * A coordinate above one leading {@code 0x00} sign byte's worth of padding is <em>significant</em> width — a
     * 257-bit value is not a P-256 field element, and copying its low 32 bytes would publish a plausible-looking but
     * wrong point. The bit count is quoted (a length is not content); the digits are not.
     */
    @Test
    void anOverWideCoordinateIsRefusedInsteadOfBeingTruncated() {
        BigInteger overWide =
                BigInteger.ONE.shiftLeft(256); // 257 bits: toByteArray() is 33 bytes, none of them padding

        assertThatThrownBy(() -> EcKeys.encodeUncompressed(pointAt(overWide, BigInteger.TWO, jca.p256Parameters())))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("257 bits")
                .hasMessageContaining("at most 256");
    }

    /**
     * A negative coordinate is refused with its own message: {@code BigInteger.bitLength()} excludes the sign bit and
     * is 0 for −1, so folding this case into the width complaint would report a nonsensical bit count.
     */
    @Test
    void aNegativeCoordinateIsRefusedNotSerialisedInTwosComplement() {
        assertThatThrownBy(() -> EcKeys.encodeUncompressed(
                        pointAt(BigInteger.valueOf(-1), BigInteger.TWO, jca.p256Parameters())))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("negative");
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
     * A public key carrying an arbitrary point. {@code encodeUncompressed} serialises whatever {@code getW()} reports
     * as long as each coordinate fits a 32-byte field element — anything negative or wider is refused, pinned above —
     * which is what makes the coordinate widths testable without hunting for a generated key whose X happens to be
     * small.
     */
    private static ECPublicKey pointAt(BigInteger x, BigInteger y, ECParameterSpec params) {
        return keyAt(new ECPoint(x, y), params);
    }

    /**
     * A public key reporting exactly {@code w} — including {@link ECPoint#POINT_INFINITY}, which has no affine form.
     */
    private static ECPublicKey keyAt(ECPoint w, ECParameterSpec params) {
        return new ECPublicKey() {
            @java.io.Serial
            private static final long serialVersionUID = 1L;

            @Override
            public ECPoint getW() {
                return w;
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
