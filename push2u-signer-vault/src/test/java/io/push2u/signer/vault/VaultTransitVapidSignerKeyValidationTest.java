package io.push2u.signer.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.push2u.PushCryptoException;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The fetched mode must establish that the Transit key really is P-256 <em>at construction</em>.
 * Before this, a misconfigured {@code ecdsa-p384} key sailed through: the P-384 coordinates were
 * silently cut to 32 bytes and published as a 65-byte "VAPID public key" that no push service could
 * ever verify, so the misconfiguration surfaced only at the first send, as an opaque rejection.
 *
 * <p>Both halves of the check are exercised independently: the advertised {@code data.type} (Vault's
 * claim about the key) and the domain parameters of the parsed key (the material itself). Neither
 * may be trusted to cover for the other.
 */
class VaultTransitVapidSignerKeyValidationTest {

    private static final String TOKEN = "s.push2u-test-vault-token";
    private static final URI VAULT = URI.create("http://vault.test:8200");

    /**
     * A real P-256 public key whose X coordinate is 248 bits and whose Y coordinate is 256 bits with
     * the top bit set — the two encoding corner cases in one key. {@code X.toByteArray()} is 31
     * bytes (must be right-aligned into the 32-byte field, leading zero), while
     * {@code Y.toByteArray()} is 33 bytes with a leading 0x00 two's-complement sign byte (padding
     * that must be dropped, not mistaken for an over-wide coordinate). Fixed, not generated, so the
     * case is covered on every run rather than once in a few hundred.
     */
    private static final String SHORT_COORDINATE_PEM = """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEALWvMDWfCNhXHATUR+THauwdKzK6
        OAhGj4Vz15/JYW/8F4W7av1mv3RKD4dNo4fV89Bzqm6CxpeOubkEBEzdIA==
        -----END PUBLIC KEY-----
        """;

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

        assertThatThrownBy(() -> new VaultTransitVapidSigner(VAULT, "transit", "vapid", TOKEN,
            new MetadataTransport(body)))
            .isInstanceOf(PushCryptoException.class)
            .hasMessageContaining("ecdsa-p384")
            .hasMessageContaining("ecdsa-p256");
    }

    @Test
    void rejectsAKeyOffP256EvenWhenTheAdvertisedTypeClaimsP256() throws Exception {
        // The type is only Vault's claim about the key; the curve check must stand on its own, so a
        // response whose metadata says ecdsa-p256 while the PEM carries a P-384 key still fails.
        String body = metadataBody(pem(generate("secp384r1")), "ecdsa-p256");

        assertThatThrownBy(() -> new VaultTransitVapidSigner(VAULT, "transit", "vapid", TOKEN,
            new MetadataTransport(body)))
            .isInstanceOf(PushCryptoException.class)
            .hasMessageContaining("not on NIST P-256")
            .hasMessageContaining("384-bit");
    }

    @Test
    void missingTypeFieldIsRejectedInsteadOfSilentlyAccepted() throws Exception {
        String body = "{\"data\":{\"keys\":{\"1\":{\"public_key\":\"" + escaped(pem(generate("secp256r1")))
            + "\"}},\"latest_version\":1}}";

        assertThatThrownBy(() -> new VaultTransitVapidSigner(VAULT, "transit", "vapid", TOKEN,
            new MetadataTransport(body)))
            .isInstanceOf(PushCryptoException.class)
            .hasMessageContaining("no 'type' field");
    }

    @Test
    void acceptsAP256KeyAndPublishesItsUncompressedPoint() throws Exception {
        ECPublicKey key = generate("secp256r1");

        VaultTransitVapidSigner signer = new VaultTransitVapidSigner(VAULT, "transit", "vapid", TOKEN,
            new MetadataTransport(metadataBody(pem(key), "ecdsa-p256")));

        assertThat(signer.publicKey()).isEqualTo(expectedUncompressed(key));
    }

    @Test
    void rightAlignsACoordinateNarrowerThanTheFieldWidth() throws Exception {
        ECPublicKey key = parse(SHORT_COORDINATE_PEM);
        assertThat(key.getW().getAffineX().bitLength())
            .as("fixture precondition: X is short enough to need left zero padding").isEqualTo(248);
        assertThat(key.getW().getAffineY().toByteArray())
            .as("fixture precondition: Y carries a two's-complement sign byte").hasSize(33);

        VaultTransitVapidSigner signer = new VaultTransitVapidSigner(VAULT, "transit", "vapid", TOKEN,
            new MetadataTransport(metadataBody(SHORT_COORDINATE_PEM, "ecdsa-p256")));

        byte[] point = signer.publicKey();
        assertThat(point).isEqualTo(expectedUncompressed(key));
        assertThat(point[1]).as("the short X is padded on the left, not shifted into the tag").isZero();
        assertThat(point[33]).as("Y's leading sign byte is dropped, not written into the field").isNotZero();
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

    private static String pem(PublicKey key) {
        return "-----BEGIN PUBLIC KEY-----\n"
            + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(key.getEncoded())
            + "\n-----END PUBLIC KEY-----\n";
    }

    private static ECPublicKey parse(String pem) throws Exception {
        byte[] der = Base64.getMimeDecoder().decode(pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", ""));
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
