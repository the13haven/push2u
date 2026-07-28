package io.push2u;

import static org.assertj.core.api.Assertions.assertThat;

import io.push2u.signer.vault.VaultTransitVapidSigner;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.vault.VaultContainer;

/**
 * {@link VaultTransitVapidSigner} satisfies the shared {@link VapidSignerContractTest} against a
 * real Vault (dev mode) with a Transit {@code ecdsa-p256} key — proving local and Vault signers
 * produce interchangeable, verifiable ES256 signatures.
 *
 * <p>The contract here runs against the <b>fetched</b> mode (no explicit public key — the signer
 * reads it from {@code transit/keys/<key>} itself). Since the contract verifies each signature
 * against {@code signer.publicKey()}, a green run proves the fetched public key actually matches the
 * private key Vault signs with — i.e. fetch resolved the right key. The explicit mode is covered by
 * its own test below.
 */
class VaultTransitVapidSignerContractTest extends VapidSignerContractTest {

    private static final String ROOT_TOKEN = "push2u-test-root";
    private static final String MOUNT = "transit";
    private static final String KEY_NAME = "vapid";

    private static VaultContainer<?> vault;
    private static byte[] vapidPublicKey;

    @BeforeAll
    @SuppressWarnings("resource") // the container lives across all test methods; it is closed in @AfterAll
    static void startVault() throws Exception {
        vault = new VaultContainer<>("hashicorp/vault:1.18")
            .withVaultToken(ROOT_TOKEN)
            .withInitCommand(
                "secrets enable " + MOUNT,
                "write " + MOUNT + "/keys/" + KEY_NAME + " type=ecdsa-p256");
        vault.start();
        vapidPublicKey = fetchTransitPublicKey(vault.getHttpHostAddress());
    }

    @AfterAll
    static void stopVault() {
        if (vault != null) {
            vault.stop();
        }
    }

    /** Fetched mode — the signer reads its own public key from Vault. */
    @Override
    protected VapidSigner signer() {
        return new VaultTransitVapidSigner(
            URI.create(vault.getHttpHostAddress()), MOUNT, KEY_NAME, ROOT_TOKEN);
    }

    @Test
    void fetchedMode_resolvesTheSamePublicKeyVaultHolds() {
        assertThat(signer().publicKey())
            .as("fetched public key equals the one transit/keys advertises")
            .isEqualTo(vapidPublicKey);
    }

    @Test
    void explicitMode_advertisesTheSuppliedKeyAndSigns() {
        VapidSigner explicit = new VaultTransitVapidSigner(
            URI.create(vault.getHttpHostAddress()), MOUNT, KEY_NAME, ROOT_TOKEN, vapidPublicKey);
        assertThat(explicit.publicKey()).isEqualTo(vapidPublicKey);
        // Same Vault sign path as the fetched mode the contract already verifies — assert it produces
        // a raw r||s ES256 signature without re-deriving the (identical) verification here.
        assertThat(explicit.sign("push2u explicit-mode probe".getBytes(StandardCharsets.UTF_8)))
            .as("raw r||s ES256 signature").hasSize(64);
    }

    private static byte[] fetchTransitPublicKey(String vaultAddress) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(vaultAddress + "/v1/" + MOUNT + "/keys/" + KEY_NAME))
            .header("X-Vault-Token", ROOT_TOKEN)
            .GET()
            .build();
        try (HttpClient client = HttpClient.newHttpClient()) {
            String body = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)).body();
            return uncompressedPoint(parsePublicKeyPem(extractPublicKeyPem(body)));
        }
    }

    /** Pull the {@code public_key} PEM out of {@code transit/keys/<name>} (its {@code \n} are escaped in JSON). */
    private static String extractPublicKeyPem(String json) {
        int key = json.indexOf("\"public_key\"");
        int open = json.indexOf('"', json.indexOf(':', key) + 1);
        int close = json.indexOf('"', open + 1);
        return json.substring(open + 1, close).replace("\\n", "\n");
    }

    private static ECPublicKey parsePublicKeyPem(String pem) throws Exception {
        String base64 = pem.replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(base64);
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
    }

    private static byte[] uncompressedPoint(ECPublicKey key) {
        byte[] out = new byte[65];
        out[0] = 0x04;
        System.arraycopy(toFixed32(key.getW().getAffineX()), 0, out, 1, 32);
        System.arraycopy(toFixed32(key.getW().getAffineY()), 0, out, 33, 32);
        return out;
    }

    private static byte[] toFixed32(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == 32) {
            return bytes;
        }
        byte[] out = new byte[32];
        if (bytes.length > 32) {
            System.arraycopy(bytes, bytes.length - 32, out, 0, 32);
        } else {
            System.arraycopy(bytes, 0, out, 32 - bytes.length, bytes.length);
        }
        return out;
    }
}
