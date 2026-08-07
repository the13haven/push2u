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
 * The {@code namespace(...)} step (Vault Enterprise/HCP): when set, the {@code X-Vault-Namespace} header rides on
 * <em>both</em> Vault calls — the fetched mode's {@code transit/keys/<name>} GET, which runs inside {@code build()}
 * before the signer exists and is the easy one to miss, and every {@code sign} POST. When unset, no such header is sent
 * at all — Vault OSS has no namespaces, and the pre-namespace request shape must stay byte-identical. Everything is
 * asserted on the headers the transport actually saw, never on a field read back.
 *
 * <p>The value is validated at the step, by the same per-segment rule as {@code mount(...)} — and validation matters
 * doubly here, because the namespace travels in an HTTP <em>header</em>: the allowed set {@code [A-Za-z0-9_.-]} plus
 * {@code /} is a strict subset of visible ASCII, so a value that passes it can never carry a header terminator. A
 * rejected value must never reach the transport ({@code alwaysFails()} proves no request is made).
 */
class VaultTransitVapidSignerNamespaceTest {

    private static final String TOKEN = "s.push2u-test-vault-token";
    private static final URI VAULT = URI.create("http://vault.test:8200");
    private static final String NAMESPACE_HEADER = "X-Vault-Namespace";

    /** One observed transport call: method plus the headers exactly as the transport received them. */
    private record Call(String method, Map<String, String> headers) {}

    /** Answers GET with Transit key metadata and POST with a well-formed sign response, recording all headers. */
    private static final class HeaderRecordingTransport implements VaultHttpTransport {

        final List<Call> calls = new ArrayList<>();
        private final String metadataBody;

        HeaderRecordingTransport(String metadataBody) {
            this.metadataBody = metadataBody;
        }

        @Override
        public VaultHttpResponse get(URI uri, Map<String, String> headers) {
            calls.add(new Call("GET", Map.copyOf(headers)));
            return new VaultHttpResponse(200, metadataBody);
        }

        @Override
        public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body) {
            calls.add(new Call("POST", Map.copyOf(headers)));
            String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[64]);
            return new VaultHttpResponse(200, "{\"data\":{\"signature\":\"vault:v1:" + signature + "\"}}");
        }
    }

    @Test
    void aConfiguredNamespaceRidesBothTheMetadataReadAndEverySignRequest() throws Exception {
        HeaderRecordingTransport transport = new HeaderRecordingTransport(metadataBody(generateP256KeyPair()));

        VaultTransitVapidSigner.builderWithFetchedPublicKey(VAULT, new TransitKeyName("vapid"), new VaultToken(TOKEN))
                .namespace("team-a")
                .transport(transport)
                .build()
                .sign("namespace probe".getBytes(StandardCharsets.UTF_8));

        assertThat(transport.calls).extracting(Call::method).containsExactly("GET", "POST");
        assertThat(transport.calls)
                .allSatisfy(call -> assertThat(call.headers())
                        .as("%s carries the exact namespace next to the token", call.method())
                        .containsEntry(NAMESPACE_HEADER, "team-a")
                        .containsKey("X-Vault-Token"));
    }

    @Test
    void theSuppliedKeyModeSendsTheNamespaceOnItsSignRequests() throws Exception {
        KeyPair keyPair = generateP256KeyPair();
        HeaderRecordingTransport transport = new HeaderRecordingTransport(metadataBody(keyPair));

        VaultTransitVapidSigner.builderWithSuppliedPublicKey(
                        VAULT, new TransitKeyName("vapid"), new VaultToken(TOKEN), uncompressed((ECPublicKey)
                                keyPair.getPublic()))
                .namespace("team-a")
                .transport(transport)
                .build()
                .sign("namespace probe".getBytes(StandardCharsets.UTF_8));

        assertThat(transport.calls).extracting(Call::method).containsExactly("POST");
        assertThat(transport.calls.get(0).headers()).containsEntry(NAMESPACE_HEADER, "team-a");
    }

    /**
     * The default: without the step, no {@code X-Vault-Namespace} header exists on any call, in either mode — not an
     * empty one, none. Vault OSS deployments must keep seeing exactly the pre-namespace request shape.
     */
    @Test
    void withoutTheStepNoCallCarriesANamespaceHeader() throws Exception {
        KeyPair keyPair = generateP256KeyPair();

        HeaderRecordingTransport fetched = new HeaderRecordingTransport(metadataBody(keyPair));
        VaultTransitVapidSigner.builderWithFetchedPublicKey(VAULT, new TransitKeyName("vapid"), new VaultToken(TOKEN))
                .transport(fetched)
                .build()
                .sign("no namespace probe".getBytes(StandardCharsets.UTF_8));

        HeaderRecordingTransport supplied = new HeaderRecordingTransport(metadataBody(keyPair));
        VaultTransitVapidSigner.builderWithSuppliedPublicKey(
                        VAULT, new TransitKeyName("vapid"), new VaultToken(TOKEN), uncompressed((ECPublicKey)
                                keyPair.getPublic()))
                .transport(supplied)
                .build()
                .sign("no namespace probe".getBytes(StandardCharsets.UTF_8));

        assertThat(fetched.calls).extracting(Call::method).containsExactly("GET", "POST");
        assertThat(supplied.calls).extracting(Call::method).containsExactly("POST");
        for (HeaderRecordingTransport transport : List.of(fetched, supplied)) {
            assertThat(transport.calls)
                    .allSatisfy(call -> assertThat(call.headers())
                            .as("%s must not carry any namespace header", call.method())
                            .doesNotContainKey(NAMESPACE_HEADER));
        }
    }

    /** Nested namespaces are legal ({@code team-a/sub} names a child namespace) and travel verbatim. */
    @Test
    void aNestedNamespaceIsAcceptedAndTravelsVerbatim() throws Exception {
        HeaderRecordingTransport transport = new HeaderRecordingTransport(metadataBody(generateP256KeyPair()));

        VaultTransitVapidSigner.builderWithFetchedPublicKey(VAULT, new TransitKeyName("vapid"), new VaultToken(TOKEN))
                .namespace("team-a/sub")
                .transport(transport)
                .build()
                .sign("nested namespace probe".getBytes(StandardCharsets.UTF_8));

        assertThat(transport.calls)
                .allSatisfy(call -> assertThat(call.headers()).containsEntry(NAMESPACE_HEADER, "team-a/sub"));
    }

    /**
     * {@code namespace(...)} is validated where it is set, in both builders, by the same per-segment rule as
     * {@code mount(...)} — and no rejected value ever reaches the transport ({@code alwaysFails()}). The reason is not
     * the mount's: a namespace rides in a header, where none of the path-collapsing hops act on it. It is that the
     * value lands in an HTTP header, where anything outside the allowed set is one hop away from splitting the header
     * itself, and that a {@code ..} cannot name a real namespace anyway — a configuration mistake worth refusing where
     * it is written.
     */
    @Test
    void aNamespaceThatWouldAlterTheRequestIsRejectedAtTheStep() {
        // A genuine P-256 point (the RFC 8291 §5 user-agent key): the supplied key is validated
        // against the curve, so a placeholder array would fail before the namespace step runs.
        byte[] publicKey = Base64.getUrlDecoder()
                .decode("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4");

        for (String namespace : new String[] {
            "",
            "   ",
            "..",
            "../root",
            "team-a/..",
            "%2e",
            "%2e%2e",
            "a|b",
            "/team-a",
            "team-a/",
            "a//b",
            "two words",
            "with\ttab",
            "with\nnewline"
        }) {
            assertThatThrownBy(() -> VaultTransitVapidSigner.builderWithSuppliedPublicKey(
                                    VAULT, new TransitKeyName("vapid"), new VaultToken(TOKEN), publicKey)
                            .transport(alwaysFails())
                            .namespace(namespace))
                    .as("supplied builder, namespace '%s'", namespace)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("namespace");
            assertThatThrownBy(() -> VaultTransitVapidSigner.builderWithFetchedPublicKey(
                                    VAULT, new TransitKeyName("vapid"), new VaultToken(TOKEN))
                            .transport(alwaysFails())
                            .namespace(namespace))
                    .as("fetched builder, namespace '%s'", namespace)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("namespace");
        }
    }

    // ---- fixtures ---------------------------------------------------------------------------------

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

    /**
     * A minimal {@code transit/keys/<name>} response advertising the pair's public key as v1. {@code type} is part of
     * the minimum: the signer refuses any key not advertised as {@code ecdsa-p256} (see
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
