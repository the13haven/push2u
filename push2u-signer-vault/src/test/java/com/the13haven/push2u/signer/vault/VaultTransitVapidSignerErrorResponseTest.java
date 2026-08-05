/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
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

    // ---- factory argument validation --------------------------------------------------------------
    //
    // A missing required value no longer has a test because it no longer has a runtime failure:
    // the factory methods take the address, the key name and the token, so an incomplete builder
    // does not compile. A token or key name that is present but invalid is rejected by VaultToken /
    // TransitKeyName at construction — see VaultTokenTest and TransitKeyNameTest.

    /** The supplied public key is validated at the factory call that supplies it, before any Vault request. */
    @Test
    void anExplicitPublicKeyOfTheWrongShapeIsRejectedAtTheFactory() {
        byte[] wrongPrefix = new byte[65];
        wrongPrefix[0] = 0x03;

        assertThatThrownBy(() -> suppliedBuilder(wrongPrefix))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("0x04");

        assertThatThrownBy(() -> suppliedBuilder(new byte[64])).isInstanceOf(IllegalArgumentException.class);
    }

    /** {@code keyVersion} is validated where it is set, so the failure points at the offending call. */
    @Test
    void aKeyVersionBelowOneIsRejected() {
        byte[] publicKey = new byte[65];
        publicKey[0] = 0x04;

        for (int version : new int[] {0, -1}) {
            assertThatThrownBy(() -> suppliedBuilder(publicKey).keyVersion(version))
                    .as("key_version %d", version)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("keyVersion must be >= 1");
        }
    }

    /**
     * {@code mount(...)} is validated where it is set, in both builders — per segment, against the explicit allowed set
     * {@code [A-Za-z0-9_.-]}. The heaviest cases are the dot segments and their percent-encoded doubles:
     * {@link java.net.URI#resolve} does <em>not</em> normalize dot segments, so a {@code ..} — or a {@code %2e%2e} that
     * a literal check would miss — travels in the raw request path until a decoding or normalizing hop (Vault's own Go
     * router decodes the path before routing; a proxy in front of Vault may normalize it earlier) collapses it and
     * lands the request, {@code X-Vault-Token} header included, on a different Vault path. The allowed set also refuses
     * at this step ({@code alwaysFails()} proves no request is made) what would otherwise surface later in
     * {@code build()} as {@code URI.create}'s raw "Malformed escape pair" ({@code 50%off}) or as a query/fragment
     * diversion. Nested mounts stay legal: the accepted {@code secrets/transit} shape is asserted where it is
     * observable, in {@link VaultTransitVapidSignerTransportTest}.
     */
    @Test
    void aMountThatWouldAlterTheRequestUrlIsRejectedAtTheStep() {
        byte[] publicKey = new byte[65];
        publicKey[0] = 0x04;

        for (String mount : new String[] {
            "",
            "   ",
            "two words",
            "with\ttab",
            "q?uery",
            "f#ragment",
            "/transit",
            "transit/",
            "a//b",
            "..",
            "../sys",
            "transit/../sys",
            ".",
            "transit/./sys",
            "transit/%2e%2e/sys",
            "a%2Fb",
            "50%off",
            "a|b",
            "a\\b",
            "a[b"
        }) {
            assertThatThrownBy(() -> suppliedBuilder(publicKey).mount(mount))
                    .as("supplied builder, mount '%s'", mount)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("mount");
            assertThatThrownBy(() -> VaultTransitVapidSigner.builderWithFetchedPublicKey(
                                    VAULT, new TransitKeyName("vapid"), new VaultToken(TOKEN))
                            .transport(alwaysFails())
                            .mount(mount))
                    .as("fetched builder, mount '%s'", mount)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("mount");
        }
    }

    // ---- fixtures ---------------------------------------------------------------------------------

    /** A supplied-key builder for {@code publicKey}, wired to a transport that refuses every call. */
    private static VaultTransitVapidSigner.SuppliedPublicKeyBuilder suppliedBuilder(byte[] publicKey) {
        return VaultTransitVapidSigner.builderWithSuppliedPublicKey(
                        VAULT, new TransitKeyName("vapid"), new VaultToken(TOKEN), publicKey)
                .mount("transit")
                .transport(alwaysFails());
    }

    /** An explicit-mode signer whose Vault always answers {@code response} to a sign request. */
    private static VaultTransitVapidSigner explicitSigner(VaultHttpResponse response) {
        byte[] publicKey = new byte[65];
        publicKey[0] = 0x04;
        return VaultTransitVapidSigner.builderWithSuppliedPublicKey(
                        VAULT, new TransitKeyName("vapid"), new VaultToken(TOKEN), publicKey)
                .mount("transit")
                .transport(new VaultHttpTransport() {
                    @Override
                    public VaultHttpResponse get(URI uri, Map<String, String> headers) {
                        throw new AssertionError("the explicit mode must never read key metadata");
                    }

                    @Override
                    public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body) {
                        return response;
                    }
                })
                .build();
    }

    /** A fetched-mode signer whose key read always answers {@code response}. */
    private static VaultTransitVapidSigner fetchedSigner(VaultHttpResponse response) {
        return VaultTransitVapidSigner.builderWithFetchedPublicKey(
                        VAULT, new TransitKeyName("vapid"), new VaultToken(TOKEN))
                .mount("transit")
                .transport(new VaultHttpTransport() {
                    @Override
                    public VaultHttpResponse get(URI uri, Map<String, String> headers) {
                        return response;
                    }

                    @Override
                    public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body) {
                        throw new AssertionError("construction must not sign anything");
                    }
                })
                .build();
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
