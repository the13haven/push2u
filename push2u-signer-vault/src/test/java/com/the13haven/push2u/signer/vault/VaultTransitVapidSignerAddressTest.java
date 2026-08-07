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

    // ---- the scheme ----------------------------------------------------------------------------

    @Test
    void aNonHttpSchemeIsRefusedAtTheFactoryOnBothBuilders() {
        // The reported gap: ftp://vault.example used to pass both factories and build(), and failed
        // only on the first sign() inside the HTTP transport — far from the value that caused it.
        // The signer speaks Vault's HTTP API and nothing else, so the whitelist lives at the
        // factory, where every other invalid-but-present address is already rejected.
        for (String address : List.of("ftp://vault.example", "file://vault.example/etc")) {
            assertThatThrownBy(() -> VaultTransitVapidSigner.builderWithFetchedPublicKey(
                            URI.create(address), new TransitKeyName("vapid"), new VaultToken(TOKEN)))
                    .as("fetched factory refuses %s", address)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("scheme must be http or https");
            assertThatThrownBy(() -> VaultTransitVapidSigner.builderWithSuppliedPublicKey(
                            URI.create(address), new TransitKeyName("vapid"), new VaultToken(TOKEN), validPublicKey()))
                    .as("supplied factory refuses %s", address)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("scheme must be http or https");
        }
    }

    @Test
    void theSuppliedKeyFactoryRefusesSchemelessAndOpaqueAddressesToo() {
        // The fetched-builder shapes are pinned in aRelativeOrHostlessAddressIsRefusedAtTheFactory;
        // both factories share one validator, and this keeps the second entry point honest.
        assertThatThrownBy(() -> VaultTransitVapidSigner.builderWithSuppliedPublicKey(
                        URI.create("//vault.example:8200"),
                        new TransitKeyName("vapid"),
                        new VaultToken(TOKEN),
                        validPublicKey()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("absolute URI with a host");
        assertThatThrownBy(() -> VaultTransitVapidSigner.builderWithSuppliedPublicKey(
                        URI.create("mailto:ops@example.com"),
                        new TransitKeyName("vapid"),
                        new VaultToken(TOKEN),
                        validPublicKey()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("absolute URI with a host");
    }

    @Test
    void httpsIsAlwaysAcceptedWhateverItsCase() {
        // RFC 3986 §3.1: schemes are case-insensitive, and URI.getScheme() preserves the case the
        // caller typed — so HTTPS:// is the same valid https address.
        for (String address : List.of("https://vault.example:8200", "HTTPS://vault.example:8200")) {
            assertThatCode(() -> VaultTransitVapidSigner.builderWithSuppliedPublicKey(
                                    URI.create(address),
                                    new TransitKeyName("vapid"),
                                    new VaultToken(TOKEN),
                                    validPublicKey())
                            .build())
                    .as("%s builds without any opt-in", address)
                    .doesNotThrowAnyException();
        }
    }

    @Test
    void plainHttpToALiteralLoopbackHostNeedsNoOptIn() {
        // The Vault Agent / service-mesh sidecar pattern: the application talks plain http to an
        // agent on the same machine and the agent terminates TLS — a mainstream production
        // deployment that must work out of the box. The literal set is the browsers'
        // secure-context one; host names compare case-insensitively (RFC 3986 §3.2.2), and the
        // IPv6 loopback is recognised in any of its spellings, bracketed as URI.getHost() keeps it.
        for (String host : List.of(
                "localhost",
                "LocalHost",
                "vault.localhost",
                "127.0.0.1",
                "127.255.255.254",
                "[::1]",
                "[0:0:0:0:0:0:0:1]")) {
            assertThatCode(() -> VaultTransitVapidSigner.builderWithSuppliedPublicKey(
                                    URI.create("http://" + host + ":8200"),
                                    new TransitKeyName("vapid"),
                                    new VaultToken(TOKEN),
                                    validPublicKey())
                            .build())
                    .as("http to %s builds without any opt-in", host)
                    .doesNotThrowAnyException();
        }
    }

    @Test
    void plainHttpToANonLoopbackHostIsRefusedByBuildWithoutTheOptIn() {
        // The X-Vault-Token header would cross the network in clear text. The literal set decides,
        // never DNS — my-vault stands for a hosts-file alias of 127.0.0.1, which still needs the
        // opt-in; 127.0.0.1.evil.example wears a loopback prefix without being one; hTTp checks
        // the scheme comparison stays case-insensitive on the build() side too.
        for (String address : List.of(
                "http://vault.internal:8200",
                "http://my-vault:8200",
                "http://127.0.0.1.evil.example:8200",
                "hTTp://vault.internal:8200")) {
            assertThatThrownBy(() -> VaultTransitVapidSigner.builderWithSuppliedPublicKey(
                                    URI.create(address),
                                    new TransitKeyName("vapid"),
                                    new VaultToken(TOKEN),
                                    validPublicKey())
                            .build())
                    .as("build() refuses %s without allowInsecureHttp()", address)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("clear text")
                    .hasMessageContaining("https")
                    .hasMessageContaining("allowInsecureHttp()");
        }
    }

    @Test
    void allowInsecureHttpAcceptsARemoteHttpAddressOnBothBuilders() {
        // Supplied mode: build() contacts nothing, so a successful build is the whole proof.
        assertThatCode(() -> VaultTransitVapidSigner.builderWithSuppliedPublicKey(
                                URI.create("http://vault.internal:8200"),
                                new TransitKeyName("vapid"),
                                new VaultToken(TOKEN),
                                validPublicKey())
                        .allowInsecureHttp()
                        .build())
                .doesNotThrowAnyException();
        // Fetched mode: with the opt-in the address check passes and build() proceeds to the Vault
        // read — the stub answers 404, so reaching PushCryptoException with a recorded GET proves
        // the rejection is gone and the network call happened.
        UriRecordingTransport transport = new UriRecordingTransport();
        VaultTransitVapidSigner.FetchedPublicKeyBuilder optedIn = VaultTransitVapidSigner.builderWithFetchedPublicKey(
                        URI.create("http://vault.internal:8200"), new TransitKeyName("vapid"), new VaultToken(TOKEN))
                .allowInsecureHttp()
                .transport(transport);
        assertThatThrownBy(optedIn::build).isInstanceOf(PushCryptoException.class);
        assertThat(transport.gets).hasSize(1);
    }

    @Test
    void theFetchedBuilderRefusesARemoteHttpAddressBeforeAnyVaultCall() {
        // The check must run before the fetched mode's transit/keys read: a misconfigured address
        // fails without contacting anything, so nothing — token headers included — goes on the
        // wire towards a host the rule refuses.
        UriRecordingTransport transport = new UriRecordingTransport();
        VaultTransitVapidSigner.FetchedPublicKeyBuilder builder = VaultTransitVapidSigner.builderWithFetchedPublicKey(
                        URI.create("http://vault.internal:8200"), new TransitKeyName("vapid"), new VaultToken(TOKEN))
                .transport(transport);
        assertThatThrownBy(builder::build)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("allowInsecureHttp()");
        assertThat(transport.gets).as("no Vault call before the refusal").isEmpty();
        assertThat(transport.posts).isEmpty();
    }
}
