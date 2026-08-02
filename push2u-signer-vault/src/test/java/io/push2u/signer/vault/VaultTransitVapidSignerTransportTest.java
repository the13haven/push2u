package io.push2u.signer.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * The signer routes <em>both</em> Vault calls through the supplied {@link VaultHttpTransport}: the fetched mode's
 * {@code transit/keys/<name>} metadata GET and the {@code transit/sign/<name>} POST. Routing both through one transport
 * is a guarantee this module adopted deliberately, not a bug fix: the earlier seam was push2u-core's POST-only
 * {@link io.push2u.PushHttpClient}, so the metadata GET necessarily used a private JDK client, and an application's
 * mTLS/proxy/observability configuration reached only the sign call. This test pins the guarantee — a future refactor
 * must not quietly reintroduce a second client.
 */
class VaultTransitVapidSignerTransportTest {

    private static final String TOKEN = "s.push2u-test-vault-token";

    /** One observed transport call: method, URI, and whether the token header was present. */
    private record Call(String method, URI uri, boolean tokenHeader) {}

    /** Answers GET with Transit key metadata and POST with a well-formed sign response. */
    private static final class RecordingVaultTransport implements VaultHttpTransport {

        final List<Call> calls = new ArrayList<>();
        private final String metadataBody;

        RecordingVaultTransport(String metadataBody) {
            this.metadataBody = metadataBody;
        }

        @Override
        public VaultHttpResponse get(URI uri, Map<String, String> headers) {
            calls.add(new Call("GET", uri, headers.containsKey("X-Vault-Token")));
            return new VaultHttpResponse(200, metadataBody);
        }

        @Override
        public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body) {
            calls.add(new Call("POST", uri, headers.containsKey("X-Vault-Token")));
            String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[64]);
            return new VaultHttpResponse(200, "{\"data\":{\"signature\":\"vault:v1:" + signature + "\"}}");
        }
    }

    @Test
    void fetchedModeUsesTheSuppliedTransportForBothTheMetadataReadAndSigning() throws Exception {
        KeyPair keyPair = generateP256KeyPair();
        RecordingVaultTransport transport = new RecordingVaultTransport(metadataBody(keyPair));

        VaultTransitVapidSigner signer =
                new VaultTransitVapidSigner(URI.create("http://vault.test:8200"), "transit", "vapid", TOKEN, transport);
        byte[] signature = signer.sign("transport probe".getBytes(StandardCharsets.UTF_8));

        assertThat(signature).hasSize(64);
        assertThat(signer.publicKey())
                .as("the fetched public key comes from the transport's metadata response")
                .isEqualTo(uncompressed((ECPublicKey) keyPair.getPublic()));
        assertThat(transport.calls)
                .extracting(Call::method, call -> call.uri().getPath())
                .containsExactly(tuple("GET", "/v1/transit/keys/vapid"), tuple("POST", "/v1/transit/sign/vapid"));
        assertThat(transport.calls)
                .allSatisfy(call -> assertThat(call.tokenHeader())
                        .as("every Vault call authenticates via X-Vault-Token")
                        .isTrue());
    }

    /**
     * A minimal {@code transit/keys/<name>} response advertising the pair's public key as v1. The {@code type} is part
     * of the minimum: the signer refuses any key not advertised as {@code ecdsa-p256} (see
     * {@link VaultTransitVapidSignerKeyValidationTest}).
     */
    private static String metadataBody(KeyPair keyPair) {
        String pem = "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'})
                        .encodeToString(keyPair.getPublic().getEncoded())
                + "\n-----END PUBLIC KEY-----\n";
        return "{\"data\":{\"keys\":{\"1\":{\"public_key\":\"" + pem.replace("\n", "\\n")
                + "\"}},\"latest_version\":1,\"type\":\"ecdsa-p256\"}}";
    }

    private static KeyPair generateP256KeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static byte[] uncompressed(ECPublicKey key) {
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
