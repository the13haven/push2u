package com.the13haven.push2u.signer.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.the13haven.push2u.PushCryptoException;

/**
 * What Vault answers when it is not answering the happy path: a sealed vault, a denied token, a proxy in front of it
 * returning HTML, a key that was deleted between startup and the first send. None of these produce the JSON the parser
 * is written for, and the diagnostic is the whole value of the failure — an operator reading it has to be able to tell
 * "your token lacks the sign capability" from "your key name is wrong" without turning on request logging in Vault.
 *
 * <p>The bodies are echoed back for exactly that reason, which is why they are also truncated: a 403 from a corporate
 * proxy can be an entire HTML page, and pasting it whole into an exception message moves it into every log line that
 * records the failure.
 */
class VaultTransitVapidSignerErrorResponseTest {

    private static final String TOKEN = "s.push2u-test-vault-token";
    private static final URI VAULT = URI.create("http://vault.test:8200");

    // ---- signing ---------------------------------------------------------------------------------

    @Test
    void aNonSuccessStatusFromTheSignEndpointReportsBothTheCodeAndTheBody() {
        for (int status : new int[] {400, 403, 404, 500, 503}) {
            assertThatThrownBy(
                            () -> explicitSigner(new VaultHttpResponse(status, "{\"errors\":[\"permission denied\"]}"))
                                    .sign("probe".getBytes(StandardCharsets.UTF_8)))
                    .as("HTTP %d", status)
                    .isInstanceOf(PushCryptoException.class)
                    .hasMessageContaining("Vault Transit sign failed: HTTP " + status)
                    .hasMessageContaining("permission denied");
        }
    }

    @Test
    void anOversizedErrorBodyIsTruncatedBeforeItReachesTheMessage() {
        String hugeBody = "<html><body>" + "A".repeat(64_000) + "</body></html>";

        assertThatThrownBy(() -> explicitSigner(new VaultHttpResponse(502, hugeBody))
                        .sign("probe".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(PushCryptoException.class)
                .satisfies(thrown -> assertThat(thrown.getMessage().length())
                        .as("an HTML error page must not be pasted whole into a log line")
                        .isLessThan(4096));
    }

    @Test
    void anEmptyBodyOnAFailedSignStillProducesAReadableMessage() {
        assertThatThrownBy(() ->
                        explicitSigner(new VaultHttpResponse(503, "")).sign("probe".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("HTTP 503");
    }

    // ---- key metadata ----------------------------------------------------------------------------

    @Test
    void aNonSuccessStatusFromTheKeyReadIsReportedAtConstruction() {
        assertThatThrownBy(() -> fetchedSigner(new VaultHttpResponse(403, "{\"errors\":[\"permission denied\"]}")))
                .as("the fetched mode reads the key while the application is still starting")
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("Vault Transit key read failed: HTTP 403")
                .hasMessageContaining("permission denied");
    }

    @Test
    void aBodyThatIsNotAJsonObjectIsRejected() {
        for (String body : new String[] {"", "   ", "[]", "\"a string\"", "null"}) {
            assertThatThrownBy(() -> fetchedSigner(new VaultHttpResponse(200, body)))
                    .as("body %s", body.isBlank() ? "(blank)" : body)
                    .isInstanceOf(PushCryptoException.class);
        }
    }

    @Test
    void aMissingDataObjectIsNamedInTheFailure() {
        assertThatThrownBy(() -> fetchedSigner(new VaultHttpResponse(200, "{\"warnings\":[]}")))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("data");
    }

    @Test
    void aDataFieldThatIsNotAnObjectIsRejected() {
        assertThatThrownBy(() -> fetchedSigner(new VaultHttpResponse(200, "{\"data\":\"nope\"}")))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("not an object");
    }

    // The key-type failure modes (missing type, wrong algorithm, managed_key) live in
    // VaultTransitVapidSignerKeyValidationTest, whose fixtures carry a real P-256 PEM so a failure
    // is attributable to the type check alone. This class once duplicated two of them with
    // PEM-less bodies — and asserted managed_key was "rejected" when production accepts it: the
    // hasMessageContaining("managed_key") check passed only because the failure ("no 'public_key'
    // for key version 1") echoes the response body, which contains the words being asserted.
    // Message-content checks against an exception that echoes the whole body prove nothing about
    // which check fired.

    @Test
    void aMissingOrMalformedLatestVersionIsRejected() {
        assertThatThrownBy(() -> fetchedSigner(
                        new VaultHttpResponse(200, "{\"data\":{\"keys\":{\"1\":{}},\"type\":\"ecdsa-p256\"}}")))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("latest_version");

        assertThatThrownBy(() -> fetchedSigner(new VaultHttpResponse(
                        200, "{\"data\":{\"keys\":{\"1\":{}},\"latest_version\":\"one\",\"type\":\"ecdsa-p256\"}}")))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("latest_version");
    }

    @Test
    void aKeysObjectWithoutTheLatestVersionIsRejected() {
        assertThatThrownBy(() -> fetchedSigner(new VaultHttpResponse(
                        200, "{\"data\":{\"keys\":{\"1\":{}},\"latest_version\":7,\"type\":\"ecdsa-p256\"}}")))
                .as("Vault says version 7 is current but only version 1 is present")
                .isInstanceOf(PushCryptoException.class);
    }

    // ---- constructor argument validation ----------------------------------------------------------

    @Test
    void anExplicitPublicKeyOfTheWrongShapeIsRejected() {
        byte[] wrongPrefix = new byte[65];
        wrongPrefix[0] = 0x03;

        assertThatThrownBy(
                        () -> new VaultTransitVapidSigner(VAULT, "transit", "vapid", TOKEN, wrongPrefix, alwaysFails()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("0x04");

        assertThatThrownBy(() ->
                        new VaultTransitVapidSigner(VAULT, "transit", "vapid", TOKEN, new byte[64], alwaysFails()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aKeyVersionBelowOneIsRejected() {
        byte[] publicKey = new byte[65];
        publicKey[0] = 0x04;

        for (int version : new int[] {0, -1}) {
            assertThatThrownBy(() -> new VaultTransitVapidSigner(
                            VAULT, "transit", "vapid", TOKEN, publicKey, version, alwaysFails()))
                    .as("key_version %d", version)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("keyVersion must be >= 1");
        }
    }

    // ---- fixtures ---------------------------------------------------------------------------------

    /** An explicit-mode signer whose Vault always answers {@code response} to a sign request. */
    private static VaultTransitVapidSigner explicitSigner(VaultHttpResponse response) {
        byte[] publicKey = new byte[65];
        publicKey[0] = 0x04;
        return new VaultTransitVapidSigner(VAULT, "transit", "vapid", TOKEN, publicKey, new VaultHttpTransport() {
            @Override
            public VaultHttpResponse get(URI uri, Map<String, String> headers) {
                throw new AssertionError("the explicit mode must never read key metadata");
            }

            @Override
            public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body) {
                return response;
            }
        });
    }

    /** A fetched-mode signer whose key read always answers {@code response}. */
    private static VaultTransitVapidSigner fetchedSigner(VaultHttpResponse response) {
        return new VaultTransitVapidSigner(VAULT, "transit", "vapid", TOKEN, new VaultHttpTransport() {
            @Override
            public VaultHttpResponse get(URI uri, Map<String, String> headers) {
                return response;
            }

            @Override
            public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body) {
                throw new AssertionError("construction must not sign anything");
            }
        });
    }

    private static VaultHttpTransport alwaysFails() {
        return new VaultHttpTransport() {
            @Override
            public VaultHttpResponse get(URI uri, Map<String, String> headers) {
                throw new AssertionError("argument validation must happen before any request");
            }

            @Override
            public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body) {
                throw new AssertionError("argument validation must happen before any request");
            }
        };
    }
}
