/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.the13haven.push2u.PushCryptoException;

/**
 * The Vault base address: how it is validated at the factory methods and how the {@code /v1/…} API paths are joined
 * onto it. The join is the load-bearing part — {@code URI.resolve("/v1/…")} is an absolute-path reference that replaces
 * the base path <em>entirely</em> (RFC 3986 §5.3), so an address like {@code https://gw.example/vault} (Vault behind a
 * reverse proxy or ingress prefix, a legitimate topology) would silently lose its prefix and every call would land on
 * the proxy's {@code /v1/…} as an unexplained 404. The signer therefore preserves the path by explicit normalization,
 * and these tests pin both the joined URIs and the inputs the factories refuse.
 */
class VaultTransitVapidSignerAddressTest {

    private static final String TOKEN = "s.push2u-test-vault-token";

    /** A transport recording every request URI; GETs answer 404 (enough to observe the URI), POSTs sign. */
    private static final class UriRecordingTransport implements VaultHttpTransport {

        final List<URI> gets = new ArrayList<>();
        final List<URI> posts = new ArrayList<>();

        @Override
        public VaultHttpResponse get(URI uri, Map<String, String> headers) {
            gets.add(uri);
            return new VaultHttpResponse(404, "{\"errors\":[]}");
        }

        @Override
        public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body) {
            posts.add(uri);
            String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[64]);
            return new VaultHttpResponse(200, "{\"data\":{\"signature\":\"vault:v1:" + signature + "\"}}");
        }
    }

    /** A genuine P-256 point (the RFC 8291 §5 user-agent key): the supplied key is validated against the curve. */
    private static byte[] validPublicKey() {
        return Base64.getUrlDecoder()
                .decode("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4");
    }

    /** The sign URI the explicit-mode signer actually POSTs to for {@code address}. */
    private static URI signUriFor(String address) {
        UriRecordingTransport transport = new UriRecordingTransport();
        VaultTransitVapidSigner.builderWithSuppliedPublicKey(
                        URI.create(address), new TransitKeyName("vapid"), new VaultToken(TOKEN), validPublicKey())
                .transport(transport)
                .build()
                .sign("address probe".getBytes(StandardCharsets.UTF_8));
        return transport.posts.get(0);
    }

    // ---- the join ------------------------------------------------------------------------------

    @Test
    void aRootAddressYieldsTheDocumentedSignUri() {
        assertThat(signUriFor("https://vault.example:8200"))
                .isEqualTo(URI.create("https://vault.example:8200/v1/transit/sign/vapid"));
    }

    @Test
    void aPathPrefixedAddressKeepsItsPrefixInFrontOfTheApiPath() {
        assertThat(signUriFor("https://gw.example/vault"))
                .as("the reverse-proxy prefix must survive the join — resolve('/v1/…') would discard it")
                .isEqualTo(URI.create("https://gw.example/vault/v1/transit/sign/vapid"));
    }

    @Test
    void aTrailingSlashOnTheAddressChangesNothing() {
        assertThat(signUriFor("https://gw.example/vault/"))
                .as("with and without the trailing slash are the same base")
                .isEqualTo(URI.create("https://gw.example/vault/v1/transit/sign/vapid"));
        assertThat(signUriFor("https://vault.example:8200/"))
                .isEqualTo(URI.create("https://vault.example:8200/v1/transit/sign/vapid"));
    }

    @Test
    void aNestedPrefixSurvivesWhole() {
        // The relative-resolve trap: resolve("v1/…") against /infra/vault would drop "vault", the
        // last slashless segment. The explicit join must keep every segment.
        assertThat(signUriFor("https://gw.example/infra/vault"))
                .isEqualTo(URI.create("https://gw.example/infra/vault/v1/transit/sign/vapid"));
    }

    @Test
    void theFetchedModeKeysReadUsesTheSamePrefix() {
        UriRecordingTransport transport = new UriRecordingTransport();
        VaultTransitVapidSigner.FetchedPublicKeyBuilder builder = VaultTransitVapidSigner.builderWithFetchedPublicKey(
                        URI.create("https://gw.example/vault"), new TransitKeyName("vapid"), new VaultToken(TOKEN))
                .transport(transport);

        // The stub answers 404, so build() fails after the GET — the URI is what this test is for.
        assertThatThrownBy(builder::build).isInstanceOf(PushCryptoException.class);
        assertThat(transport.gets).containsExactly(URI.create("https://gw.example/vault/v1/transit/keys/vapid"));
    }

    // ---- what the factories refuse -------------------------------------------------------------

    @Test
    void anAddressWithAQueryIsRefusedAtTheFactory() {
        assertThatThrownBy(() -> VaultTransitVapidSigner.builderWithFetchedPublicKey(
                        URI.create("https://vault.example:8200?ns=team-a"),
                        new TransitKeyName("vapid"),
                        new VaultToken(TOKEN)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("query");
        // An empty query ("?") is as meaningless on a base address as a populated one.
        assertThatThrownBy(() -> VaultTransitVapidSigner.builderWithFetchedPublicKey(
                        URI.create("https://vault.example:8200/?"), new TransitKeyName("vapid"), new VaultToken(TOKEN)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("query");
    }

    @Test
    void anAddressWithAFragmentIsRefusedAtTheFactory() {
        assertThatThrownBy(() -> VaultTransitVapidSigner.builderWithFetchedPublicKey(
                        URI.create("https://vault.example:8200#prod"),
                        new TransitKeyName("vapid"),
                        new VaultToken(TOKEN)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("fragment");
    }

    @Test
    void aRelativeOrHostlessAddressIsRefusedAtTheFactory() {
        // No scheme: "//vault.example:8200" parses but names no protocol to speak.
        assertThatThrownBy(() -> VaultTransitVapidSigner.builderWithFetchedPublicKey(
                        URI.create("//vault.example:8200"), new TransitKeyName("vapid"), new VaultToken(TOKEN)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("absolute URI with a host");
        // Opaque: absolute by URI's definition, but there is no host to connect to.
        assertThatThrownBy(() -> VaultTransitVapidSigner.builderWithFetchedPublicKey(
                        URI.create("mailto:ops@example.com"), new TransitKeyName("vapid"), new VaultToken(TOKEN)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("absolute URI with a host");
    }

    @Test
    void aDotSegmentInTheAddressPathIsRefusedAtTheFactory() {
        assertThatThrownBy(() -> VaultTransitVapidSigner.builderWithFetchedPublicKey(
                        URI.create("https://gw.example/vault/../sys"),
                        new TransitKeyName("vapid"),
                        new VaultToken(TOKEN)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("'..' segment");
        assertThatThrownBy(() -> VaultTransitVapidSigner.builderWithFetchedPublicKey(
                        URI.create("https://gw.example/./vault"), new TransitKeyName("vapid"), new VaultToken(TOKEN)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("'.' segment");
    }

    @Test
    void aPercentEncodedDotSegmentCannotReopenWhatTheLiteralCheckCloses() {
        // %2e%2e decodes to ".." at whichever hop decodes first — the allowed set has no '%', so
        // the encoded probe dies at the factory exactly like the literal one.
        assertThatThrownBy(() -> VaultTransitVapidSigner.builderWithFetchedPublicKey(
                        URI.create("https://gw.example/%2e%2e/sys"),
                        new TransitKeyName("vapid"),
                        new VaultToken(TOKEN)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("allowed set");
    }

    @Test
    void anEmptyInteriorPathSegmentIsRefusedAtTheFactory() {
        assertThatThrownBy(() -> VaultTransitVapidSigner.builderWithFetchedPublicKey(
                        URI.create("https://gw.example//vault"), new TransitKeyName("vapid"), new VaultToken(TOKEN)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("'//'");
    }

    @Test
    void theSuppliedKeyFactoryAppliesTheSameAddressRule() {
        assertThatThrownBy(() -> VaultTransitVapidSigner.builderWithSuppliedPublicKey(
                        URI.create("https://gw.example/vault/../sys"),
                        new TransitKeyName("vapid"),
                        new VaultToken(TOKEN),
                        validPublicKey()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("'..' segment");
    }

    @Test
    void aPlainHttpAddressIsAcceptedForVaultDevMode() {
        // Deliberate: Vault's dev server listens on http, and the Vault CLI and Spring Vault accept
        // it the same way. The Javadoc, not the validator, says production must be https.
        assertThatCode(() -> VaultTransitVapidSigner.builderWithSuppliedPublicKey(
                        URI.create("http://127.0.0.1:8200"),
                        new TransitKeyName("vapid"),
                        new VaultToken(TOKEN),
                        validPublicKey()))
                .doesNotThrowAnyException();
    }
}
