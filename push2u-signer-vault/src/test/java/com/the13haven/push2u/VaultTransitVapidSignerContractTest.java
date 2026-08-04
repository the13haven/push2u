/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.vault.VaultContainer;

import com.the13haven.push2u.signer.vault.VaultTransitVapidSigner;

/**
 * {@link VaultTransitVapidSigner} satisfies the shared {@link VapidSignerContractTest} against a real Vault (dev mode)
 * with a Transit {@code ecdsa-p256} key — proving local and Vault signers produce interchangeable, verifiable ES256
 * signatures.
 *
 * <p>The contract here runs against the <b>fetched</b> mode (no explicit public key — the signer reads it from
 * {@code transit/keys/<key>} itself). Since the contract verifies each signature against {@code signer.publicKey()}, a
 * green run proves the fetched public key actually matches the private key Vault signs with — i.e. fetch resolved the
 * right key. The explicit mode is covered by its own test below.
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
                        "secrets enable " + MOUNT, "write " + MOUNT + "/keys/" + KEY_NAME + " type=ecdsa-p256");
        vault.start();
        vapidPublicKey = fetchTransitPublicKey(vault.getHttpHostAddress(), KEY_NAME);
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
        return new VaultTransitVapidSigner(URI.create(vault.getHttpHostAddress()), MOUNT, KEY_NAME, ROOT_TOKEN);
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
                .as("raw r||s ES256 signature")
                .hasSize(64);
    }

    /**
     * The regression the version pinning fixes: after the Transit key is rotated, a fetched-mode signer built before
     * the rotation must keep signing with the version whose public key it advertises — not with Vault's new latest.
     * Rotating twice (to v3) proves the pin holds across repeated rotations, not just past the first one. A dedicated
     * Transit key keeps the shared {@code vapid} key single-version for the other tests.
     */
    @Test
    void fetchedMode_keepsSigningWithItsPinnedVersionAfterKeyRotation() throws Exception {
        String keyName = "vapid-rotation";
        createTransitKey(keyName);
        VapidSigner pinned =
                new VaultTransitVapidSigner(URI.create(vault.getHttpHostAddress()), MOUNT, keyName, ROOT_TOKEN);
        byte[] advertised = pinned.publicKey();

        rotateTransitKey(keyName);
        assertThat(fetchTransitPublicKey(vault.getHttpHostAddress(), keyName))
                .as("rotation produced a new latest key different from the advertised one — otherwise "
                        + "this test would pass vacuously")
                .isNotEqualTo(advertised);
        assertPinnedSignatureVerifies(
                pinned, advertised, "push2u post-rotation probe", "signature after the first rotation (latest=v2)");

        rotateTransitKey(keyName);
        assertThat(fetchTransitPublicKey(vault.getHttpHostAddress(), keyName))
                .as("second rotation produced yet another latest key")
                .isNotEqualTo(advertised);
        assertPinnedSignatureVerifies(
                pinned,
                advertised,
                "push2u post-second-rotation probe",
                "signature after the second rotation (latest=v3)");
    }

    /** Sign {@code message} and verify against {@code advertised} — the key the signer pins. */
    private static void assertPinnedSignatureVerifies(
            VapidSigner pinned, byte[] advertised, String message, String description) throws Exception {
        byte[] signingInput = message.getBytes(StandardCharsets.UTF_8);
        byte[] signature = pinned.sign(signingInput);
        Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
        verifier.initVerify(decodeP256PublicKey(advertised));
        verifier.update(signingInput);
        assertThat(verifier.verify(signature))
                .as(description + " verifies against the public key the signer advertises")
                .isTrue();
    }

    /** Explicit mode with a pinned version: signing with v1 after a rotation to v2 stays on v1. */
    @Test
    void explicitMode_withKeyVersion_signsWithThatVersionAfterKeyRotation() throws Exception {
        String keyName = "vapid-explicit-pin";
        createTransitKey(keyName);
        byte[] v1PublicKey = fetchTransitPublicKey(vault.getHttpHostAddress(), keyName);
        rotateTransitKey(keyName);
        assertThat(fetchTransitPublicKey(vault.getHttpHostAddress(), keyName))
                .as("rotation produced a new latest key")
                .isNotEqualTo(v1PublicKey);

        VapidSigner pinned = new VaultTransitVapidSigner(
                URI.create(vault.getHttpHostAddress()), MOUNT, keyName, ROOT_TOKEN, v1PublicKey, 1);
        assertThat(pinned.publicKey()).isEqualTo(v1PublicKey);

        byte[] signingInput = "push2u explicit pinned-version probe".getBytes(StandardCharsets.UTF_8);
        byte[] signature = pinned.sign(signingInput);

        Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
        verifier.initVerify(decodeP256PublicKey(v1PublicKey));
        verifier.update(signingInput);
        assertThat(verifier.verify(signature))
                .as("signature pinned to key_version=1 verifies against the v1 public key")
                .isTrue();
    }

    private static void createTransitKey(String keyName) throws Exception {
        postToVault("/v1/" + MOUNT + "/keys/" + keyName, "{\"type\":\"ecdsa-p256\"}");
    }

    private static void rotateTransitKey(String keyName) throws Exception {
        postToVault("/v1/" + MOUNT + "/keys/" + keyName + "/rotate", "");
    }

    private static void postToVault(String path, String body) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(vault.getHttpHostAddress() + path))
                .header("X-Vault-Token", ROOT_TOKEN)
                .POST(
                        body.isEmpty()
                                ? HttpRequest.BodyPublishers.noBody()
                                : HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpResponse<String> response =
                    client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            assertThat(response.statusCode())
                    .as("Vault POST " + path + " responded: " + response.body())
                    .isIn(200, 204);
        }
    }

    /** The public key of the key's {@code latest_version}, as a 65-byte uncompressed point. */
    private static byte[] fetchTransitPublicKey(String vaultAddress, String keyName) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(vaultAddress + "/v1/" + MOUNT + "/keys/" + keyName))
                .header("X-Vault-Token", ROOT_TOKEN)
                .GET()
                .build();
        try (HttpClient client = HttpClient.newHttpClient()) {
            String body = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
                    .body();
            return uncompressedPoint(parsePublicKeyPem(latestVersionPublicKeyPem(body)));
        }
    }

    /**
     * Pull the {@code public_key} PEM of the {@code latest_version} entry out of {@code transit/keys/<name>} (its
     * {@code \n} are escaped in JSON). Deliberately written here rather than reusing the production extraction, so the
     * test stays an independent oracle — but version-aware all the same: it isolates the latest version's own entry
     * inside the {@code keys} object and takes {@code public_key} from that entry only. On a rotated key a
     * first-occurrence search can confirm another version's key and mask exactly the pinning bugs these tests exist to
     * catch.
     */
    private static String latestVersionPublicKeyPem(String json) {
        String data = directObjectMember(json, "data");
        int latest = directIntMember(data, "latest_version");
        String entry = directObjectMember(directObjectMember(data, "keys"), Integer.toString(latest));
        return directStringMember(entry, "public_key").replace("\\n", "\n");
    }

    /**
     * The value start of the direct member {@code name} of {@code object} (a string starting at an opening brace),
     * skipping members' nested values and string contents so a lookalike deeper down — or a string value equal to the
     * label — never matches. Fails the test if absent.
     */
    private static int directMemberValue(String object, String name) {
        String label = "\"" + name + "\"";
        boolean inString = false;
        int depth = 0;
        for (int i = 0; i < object.length(); i++) {
            char c = object.charAt(i);
            if (inString) {
                if (c == '\\') {
                    i++;
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            if (depth == 1 && object.startsWith(label, i)) {
                int cursor = skipWhitespace(object, i + label.length());
                if (cursor < object.length() && object.charAt(cursor) == ':') {
                    return skipWhitespace(object, cursor + 1);
                }
                i += label.length() - 1; // a string value equal to the label — skip it whole
                continue;
            }
            if (c == '"') {
                inString = true;
            } else if (c == '{' || c == '[') {
                depth++;
            } else if (c == '}' || c == ']') {
                depth--;
            }
        }
        throw new AssertionError("no direct member '" + name + "' in: " + object);
    }

    /** The direct member {@code name} of {@code object}, as its own {@code {...}} substring. */
    private static String directObjectMember(String object, String name) {
        int at = directMemberValue(object, name);
        if (object.charAt(at) != '{') {
            throw new AssertionError("direct member '" + name + "' is not an object in: " + object);
        }
        boolean inString = false;
        int depth = 0;
        for (int i = at; i < object.length(); i++) {
            char c = object.charAt(i);
            if (inString) {
                if (c == '\\') {
                    i++;
                } else if (c == '"') {
                    inString = false;
                }
            } else if (c == '"') {
                inString = true;
            } else if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return object.substring(at, i + 1);
                }
            }
        }
        throw new AssertionError("unterminated object member '" + name + "' in: " + object);
    }

    private static int directIntMember(String object, String name) {
        int at = directMemberValue(object, name);
        int end = at;
        while (end < object.length() && Character.isDigit(object.charAt(end))) {
            end++;
        }
        return Integer.parseInt(object.substring(at, end));
    }

    private static String directStringMember(String object, String name) {
        int at = directMemberValue(object, name);
        if (object.charAt(at) != '"') {
            throw new AssertionError("direct member '" + name + "' is not a string in: " + object);
        }
        int close = at + 1;
        while (close < object.length() && object.charAt(close) != '"') {
            close += object.charAt(close) == '\\' ? 2 : 1;
        }
        return object.substring(at + 1, close);
    }

    private static int skipWhitespace(String text, int from) {
        int i = from;
        while (i < text.length() && Character.isWhitespace(text.charAt(i))) {
            i++;
        }
        return i;
    }

    private static ECPublicKey decodeP256PublicKey(byte[] uncompressed) throws Exception {
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(uncompressed, 1, 33));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(uncompressed, 33, 65));
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec p256 = parameters.getParameterSpec(ECParameterSpec.class);
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), p256));
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
