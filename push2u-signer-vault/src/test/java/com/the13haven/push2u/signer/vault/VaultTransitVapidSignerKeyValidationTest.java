/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import java.net.URI;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.the13haven.push2u.PushCryptoException;

/**
 * The fetched mode must establish that the Transit key really is a P-256 <em>point</em> at construction. Before this, a
 * misconfigured {@code ecdsa-p384} key sailed through: the P-384 coordinates were silently cut to 32 bytes and
 * published as a 65-byte "VAPID public key" that no push service could ever verify, so the misconfiguration surfaced
 * only at the first send, as an opaque rejection.
 *
 * <p>Three independent things are exercised separately, because none implies another: the advertised {@code data.type}
 * (Vault's claim about the key), the key's domain parameters, and the point itself. The JCA validates none of them —
 * SunEC happily builds and encodes a key whose point is {@code (1, 2)} or whose coordinate sits at the field prime.
 */
class VaultTransitVapidSignerKeyValidationTest {

    private static final String TOKEN = "s.push2u-test-vault-token";
    private static final URI VAULT = URI.create("http://vault.test:8200");

    /**
     * A real P-256 public key that hits both fixed-width encoding corner cases at once. {@code X.toByteArray()} is 31
     * bytes, so X must be zero-padded on the left into the 32-byte field; {@code Y.toByteArray()} is 33 bytes — a
     * 256-bit value whose leading {@code 0x00} is a two's-complement sign byte that must be dropped rather than
     * mistaken for an over-wide coordinate. Fixed rather than generated: a 31-byte X turns up in roughly one key in
     * 250, so a generated fixture would exercise the padding branch only occasionally.
     */
    private static final String SHORT_COORDINATE_PEM = """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAC0/GQgDhPy8g/jyn7qlcT8jPojC
        PnGVOxDI55Ha8t6oK+wARampblpJ9RsNpQhl4ibvl92CCDaDb8jllhT1+A==
        -----END PUBLIC KEY-----
        """;

    private static final BigInteger SECP256K1_P =
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    private static final BigInteger SECP256K1_N =
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    private static final BigInteger SECP256K1_GX =
            new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    private static final BigInteger SECP256K1_GY =
            new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);

    /** Serves one canned {@code transit/keys/<name>} body; signing is never reached in these tests. */
    private record MetadataTransport(String body) implements VaultHttpTransport {

        @Override
        public VaultHttpResponse get(URI uri, Map<String, String> headers) {
            return new VaultHttpResponse(200, body);
        }

        @Override
        public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] requestBody) {
            throw new AssertionError("a rejected key must never reach the sign endpoint");
        }
    }

    @Test
    void rejectsATransitKeyWhoseTypeIsNotP256() throws Exception {
        // The realistic misconfiguration: `vault write transit/keys/vapid type=ecdsa-p384`.
        String body = metadataBody(pem(generate("secp384r1")), "ecdsa-p384");

        assertThatThrownBy(() -> signerFor(body))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("ecdsa-p384")
                .hasMessageContaining("ecdsa-p256");
    }

    @Test
    void rejectsAKeyOffP256EvenWhenTheAdvertisedTypeClaimsP256() throws Exception {
        // The type is only Vault's claim about the key; the curve check must stand on its own, so a
        // response whose metadata says ecdsa-p256 while the PEM carries a P-384 key still fails.
        String body = metadataBody(pem(generate("secp384r1")), "ecdsa-p256");

        assertThatThrownBy(() -> signerFor(body))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("not on NIST P-256")
                .hasMessageContaining("384-bit");
    }

    @Test
    void rejectsA256BitCurveThatIsNotP256() throws Exception {
        // secp256k1 has the same field size as P-256, so a check on the bit width alone would wave
        // it through. SunEC cannot generate it, so the domain parameters are spelled out and the
        // curve's own generator serves as a genuinely on-curve point.
        String body = metadataBody(pem(keyAt(SECP256K1_GX, SECP256K1_GY, secp256k1())), "ecdsa-p256");

        assertThatThrownBy(() -> signerFor(body))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("not on NIST P-256")
                // The discriminator that makes the message usable: both curves are 256-bit prime-field
                // curves, so only b tells them apart (secp256k1: b = 7).
                .hasMessageContaining("b=0x7,");
    }

    @Test
    void acceptsAKeyWhoseP256ParametersAreExplicitRatherThanNamed() throws Exception {
        // A key carrying explicit (rebuilt) domain parameters is still a P-256 key. This is the only
        // reason the comparison is written out value by value: ECParameterSpec has no equals, so
        // `actual.equals(expected)` is identity here and false for these equal parameters —
        // simplifying sameCurve() would pass the rest of this suite and break in production.
        ECPublicKey named = generate("secp256r1");
        ECPublicKey explicit = keyAt(named.getW().getAffineX(), named.getW().getAffineY(), rebuilt(p256()));
        assertThat(explicit.getParams().equals(p256()))
                .as("precondition: equal parameter values, unequal spec objects")
                .isFalse();

        VaultTransitVapidSigner signer = signerFor(metadataBody(pem(explicit), "ecdsa-p256"));

        assertThat(signer.publicKey()).isEqualTo(expectedUncompressed(named));
    }

    @Test
    void rejectsAPointThatIsNotOnTheCurve() throws Exception {
        // (1, 2) carries P-256's own domain parameters but satisfies no curve equation. SunEC builds
        // and encodes such a key without complaint and never validates it at verification time
        // either, so only an explicit check keeps it out of the published VAPID key.
        String body = metadataBody(pem(keyAt(BigInteger.ONE, BigInteger.TWO, p256())), "ecdsa-p256");

        assertThatThrownBy(() -> signerFor(body))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("does not satisfy the NIST P-256 curve equation");
    }

    @Test
    void rejectsACoordinateAtTheFieldPrime() throws Exception {
        // x = p is not a field element (0 <= x < p), yet it fits the 32-byte wire field and survives
        // the DER round trip intact, so it reaches the check unchanged.
        String body = metadataBody(pem(keyAt(fieldPrime(), BigInteger.TWO, p256())), "ecdsa-p256");

        assertThatThrownBy(() -> signerFor(body))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("coordinate outside the P-256 field");
    }

    @Test
    void rejectsANegativeCoordinate() throws Exception {
        // DER encodes EC coordinates unsigned, so a negative coordinate cannot survive the wire: -1
        // arrives as 0xff. It is still rejected — as the off-curve point it now is — which is what
        // matters here. The signum() guards in the code proper are defence in depth against a
        // provider handing back a negative affine coordinate, not something Vault can send.
        String body = metadataBody(pem(keyAt(BigInteger.valueOf(-1), BigInteger.TWO, p256())), "ecdsa-p256");

        assertThatThrownBy(() -> signerFor(body))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("curve equation");
    }

    @Test
    void missingTypeFieldIsRejectedInsteadOfSilentlyAccepted() throws Exception {
        String body = "{\"data\":{\"keys\":{\"1\":{\"public_key\":\"" + escaped(pem(generate("secp256r1")))
                + "\"}},\"latest_version\":1}}";

        assertThatThrownBy(() -> signerFor(body))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("no 'type' field");
    }

    @Test
    void acceptsAManagedKeyTypeOnTheStrengthOfTheCurveCheck() throws Exception {
        // Vault Enterprise reports HSM/KMS-backed keys as type "managed_key", which describes the
        // wrapper and says nothing about the curve. Accepting it is safe only because the curve
        // check is authoritative — the next test pins that this relaxes the metadata check alone.
        ECPublicKey key = generate("secp256r1");

        VaultTransitVapidSigner signer = signerFor(metadataBody(pem(key), "managed_key"));

        assertThat(signer.publicKey()).isEqualTo(expectedUncompressed(key));
    }

    @Test
    void aManagedKeyOffP256IsStillRejected() throws Exception {
        String body = metadataBody(pem(generate("secp384r1")), "managed_key");

        assertThatThrownBy(() -> signerFor(body))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("not on NIST P-256");
    }

    @Test
    void aMalformedPemFailsAsThisModulesExceptionNotAsAnIllegalArgument() {
        // sign() already converts a Base64 failure into a PushCryptoException; the constructor must
        // follow the same convention rather than leaking a raw IllegalArgumentException out of a
        // public API whose documented failure mode is PushCryptoException.
        String body = metadataBody(
                "-----BEGIN PUBLIC KEY-----\nnot base64 at all $$$\n-----END PUBLIC KEY-----\n", "ecdsa-p256");

        assertThatThrownBy(() -> signerFor(body))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("not valid base64");
    }

    @Test
    void acceptsAP256KeyAndPublishesItsUncompressedPoint() throws Exception {
        ECPublicKey key = generate("secp256r1");

        VaultTransitVapidSigner signer = signerFor(metadataBody(pem(key), "ecdsa-p256"));

        assertThat(signer.publicKey()).isEqualTo(expectedUncompressed(key));
    }

    @Test
    void rightAlignsACoordinateNarrowerThanTheFieldWidth() throws Exception {
        ECPublicKey key = parse(SHORT_COORDINATE_PEM);
        assertThat(key.getW().getAffineX().toByteArray())
                .as("fixture precondition: X is one byte short of the field width and needs left padding")
                .hasSize(31);
        assertThat(key.getW().getAffineY().toByteArray())
                .as("fixture precondition: Y carries a two's-complement sign byte")
                .hasSize(33);

        byte[] point =
                signerFor(metadataBody(SHORT_COORDINATE_PEM, "ecdsa-p256")).publicKey();

        assertThat(point).isEqualTo(expectedUncompressed(key));
        assertThat(point[1])
                .as("the short X is padded on the left, not shifted into the tag")
                .isZero();
        assertThat(point[2]).as("X's own leading byte follows the padding").isNotZero();
        assertThat(point[33])
                .as("Y's leading sign byte is dropped, not written into the field")
                .isNotZero();
    }

    private static VaultTransitVapidSigner signerFor(String metadataBody) {
        return VaultTransitVapidSigner.builderWithFetchedPublicKey()
                .address(VAULT)
                .mount("transit")
                .keyName("vapid")
                .token(TOKEN)
                .transport(new MetadataTransport(metadataBody))
                .build();
    }

    /** A minimal {@code transit/keys/<name>} response carrying {@code pem} as version 1. */
    private static String metadataBody(String pem, String type) {
        return "{\"data\":{\"keys\":{\"1\":{\"public_key\":\"" + escaped(pem)
                + "\"}},\"latest_version\":1,\"name\":\"vapid\",\"type\":\"" + type + "\"}}";
    }

    private static String escaped(String pem) {
        return pem.replace("\n", "\\n");
    }

    private static ECPublicKey generate(String curve) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve));
        KeyPair keyPair = generator.generateKeyPair();
        return (ECPublicKey) keyPair.getPublic();
    }

    /** A public key at an arbitrary — possibly invalid — point of the given domain parameters. */
    private static ECPublicKey keyAt(BigInteger x, BigInteger y, ECParameterSpec parameters) throws Exception {
        return (ECPublicKey)
                KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), parameters));
    }

    private static ECParameterSpec p256() throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        return parameters.getParameterSpec(ECParameterSpec.class);
    }

    private static BigInteger fieldPrime() throws Exception {
        return ((ECFieldFp) p256().getCurve().getField()).getP();
    }

    /** The same domain parameters rebuilt from their values — equal, but not the named instance. */
    private static ECParameterSpec rebuilt(ECParameterSpec source) {
        EllipticCurve curve = new EllipticCurve(
                new ECFieldFp(((ECFieldFp) source.getCurve().getField()).getP()),
                source.getCurve().getA(),
                source.getCurve().getB());
        ECPoint generator = new ECPoint(
                source.getGenerator().getAffineX(), source.getGenerator().getAffineY());
        return new ECParameterSpec(curve, generator, source.getOrder(), source.getCofactor());
    }

    /** SEC 2 secp256k1: {@code y² = x³ + 7} over a 256-bit prime field — the same width as P-256. */
    private static ECParameterSpec secp256k1() {
        EllipticCurve curve = new EllipticCurve(new ECFieldFp(SECP256K1_P), BigInteger.ZERO, BigInteger.valueOf(7));
        return new ECParameterSpec(curve, new ECPoint(SECP256K1_GX, SECP256K1_GY), SECP256K1_N, 1);
    }

    private static String pem(PublicKey key) {
        return "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(key.getEncoded())
                + "\n-----END PUBLIC KEY-----\n";
    }

    private static ECPublicKey parse(String pem) throws Exception {
        byte[] der = Base64.getMimeDecoder()
                .decode(pem.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", ""));
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
    }

    /** {@code 0x04 || X || Y}, computed independently of the signer's own encoder. */
    private static byte[] expectedUncompressed(ECPublicKey key) {
        byte[] out = new byte[65];
        out[0] = 0x04;
        System.arraycopy(toFixed32(key.getW().getAffineX()), 0, out, 1, 32);
        System.arraycopy(toFixed32(key.getW().getAffineY()), 0, out, 33, 32);
        return out;
    }

    private static byte[] toFixed32(BigInteger value) {
        byte[] bytes = value.toByteArray();
        byte[] out = new byte[32];
        int length = Math.min(bytes.length, 32);
        System.arraycopy(bytes, bytes.length - length, out, 32 - length, length);
        return out;
    }
}
