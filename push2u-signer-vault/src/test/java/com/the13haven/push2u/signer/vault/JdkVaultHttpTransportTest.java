/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.OutputStream;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import com.the13haven.push2u.PushCryptoException;

/**
 * {@link JdkVaultHttpTransport} against live sockets — the transport-level guarantees the Vault signer relies on: the
 * per-request timeout (a Vault that accepts the connection but never answers must not hang application startup
 * forever), the fail-closed response-size cap counted in raw bytes, interrupt handling, argument validation, and
 * exception hygiene (no token, no query).
 */
class JdkVaultHttpTransportTest {

    private static final String TOKEN = "s.push2u-test-vault-token";

    /** A transport over a fresh client with the given per-request timeout and size cap. */
    private static JdkVaultHttpTransport transport(Duration requestTimeout, int maxResponseBytes) {
        return new JdkVaultHttpTransport(HttpClient.newHttpClient(), requestTimeout, maxResponseBytes);
    }

    /** Serve {@code status} + {@code body} once on an ephemeral port and run {@code test} against it. */
    private static void withServer(int status, byte[] body, boolean declareLength, ServerTest test) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        try {
            server.createContext("/v1", exchange -> {
                exchange.getRequestBody().readAllBytes();
                // length 0 selects chunked transfer — no Content-Length header on the wire, so
                // only the streaming byte count can enforce the cap.
                exchange.sendResponseHeaders(status, declareLength ? body.length : 0);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
            });
            server.start();
            test.run(URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/v1/transit/keys/vapid"));
        } finally {
            server.stop(0);
        }
    }

    private interface ServerTest {
        void run(URI uri) throws Exception;
    }

    @Test
    void aServerThatAcceptsButNeverAnswersHitsTheRequestTimeoutInsteadOfHangingForever() throws Exception {
        // A bound socket with a backlog: the kernel completes the TCP handshake, so connectTimeout
        // is satisfied — exactly the hang the per-request timeout exists to break.
        try (ServerSocket silent = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            URI uri = URI.create("http://127.0.0.1:" + silent.getLocalPort() + "/v1/transit/keys/vapid");

            assertThatThrownBy(() -> transport(Duration.ofSeconds(1), 1024).get(uri, Map.of("X-Vault-Token", TOKEN)))
                    .isInstanceOf(PushCryptoException.class)
                    .hasMessageContaining("timed out")
                    .hasCauseInstanceOf(HttpTimeoutException.class)
                    .satisfies(e -> assertThat(e.getMessage()).doesNotContain(TOKEN));
        }
    }

    @Test
    void aResponseLargerThanTheCapFailsClosed() throws Exception {
        byte[] oversized = new byte[9];
        withServer(
                200,
                oversized,
                true,
                uri -> assertThatThrownBy(
                                () -> transport(Duration.ofSeconds(5), 8).get(uri, Map.of()))
                        .isInstanceOf(PushCryptoException.class)
                        .hasMessageStartingWith("Vault response exceeded the configured limit of 8 bytes")
                        .hasMessageContaining("GET")
                        .hasMessageContaining("/v1/transit/keys/vapid"));
    }

    @Test
    void aChunkedResponseWithoutContentLengthIsStillCappedByTheStreamingCount() throws Exception {
        // No Content-Length on the wire — the early header check cannot fire, proving the raw-byte
        // streaming count enforces the cap on its own.
        byte[] oversized = new byte[64];
        withServer(
                200,
                oversized,
                false,
                uri -> assertThatThrownBy(
                                () -> transport(Duration.ofSeconds(5), 8).get(uri, Map.of()))
                        .isInstanceOf(PushCryptoException.class)
                        .hasMessageStartingWith("Vault response exceeded the configured limit of 8 bytes")
                        .hasMessageContaining("GET")
                        .hasMessageContaining("/v1/transit/keys/vapid"));
    }

    @Test
    void aResponseExactlyAtTheCapSucceeds() throws Exception {
        byte[] exact = "12345678".getBytes(StandardCharsets.UTF_8);
        withServer(200, exact, true, uri -> {
            VaultHttpResponse response =
                    transport(Duration.ofSeconds(5), exact.length).get(uri, Map.of());
            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(response.body()).isEqualTo("12345678");
        });
    }

    @Test
    void interruptionRestoresTheInterruptFlagAndReportsAsThisModulesException() throws Exception {
        try (ServerSocket silent = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            URI uri = URI.create("http://127.0.0.1:" + silent.getLocalPort() + "/v1/transit/keys/vapid");
            AtomicReference<Throwable> thrown = new AtomicReference<>();
            AtomicReference<Boolean> flagRestored = new AtomicReference<>();
            Thread caller = new Thread(() -> {
                try {
                    transport(Duration.ofSeconds(30), 1024).get(uri, Map.of("X-Vault-Token", TOKEN));
                } catch (Throwable e) {
                    thrown.set(e);
                    flagRestored.set(Thread.currentThread().isInterrupted());
                }
            });
            caller.start();
            Thread.sleep(200); // let the request get in flight before interrupting
            caller.interrupt();
            caller.join(Duration.ofSeconds(5).toMillis());

            assertThat(caller.isAlive())
                    .as("the interrupted call returns promptly")
                    .isFalse();
            assertThat(thrown.get())
                    .isInstanceOf(PushCryptoException.class)
                    .hasMessageContaining("Interrupted")
                    .hasCauseInstanceOf(InterruptedException.class);
            assertThat(flagRestored.get())
                    .as("the interrupt flag is restored for the caller")
                    .isTrue();
        }
    }

    @Test
    void nonPositiveTimeoutsAndCapsAreRejectedAtConstruction() {
        HttpClient client = HttpClient.newHttpClient();

        assertThatThrownBy(() -> new JdkVaultHttpTransport(client, Duration.ZERO, 1024))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("requestTimeout must be positive");
        assertThatThrownBy(() -> new JdkVaultHttpTransport(client, Duration.ofSeconds(-1), 1024))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("requestTimeout must be positive");
        assertThatThrownBy(() -> new JdkVaultHttpTransport(client, Duration.ofSeconds(30), 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maxResponseBytes must be positive");
        assertThatThrownBy(() -> new JdkVaultHttpTransport(client, Duration.ofSeconds(30), -1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maxResponseBytes must be positive");
        assertThatThrownBy(() -> new JdkVaultHttpTransport(null, Duration.ofSeconds(30), 1024))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("httpClient");
    }

    @Test
    void aQueryCarryingUriIsReplacedByTheMarkerWholeNotTruncated() throws Exception {
        try (ServerSocket silent = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            // Vault APIs put sensitive detail in queries (e.g. list=true on secret paths). The old
            // rendering cut the query off and kept the rest; the cut is what once left a password
            // standing ("https://u:PASS?@vault" cut to "https://u:PASS"), so a query- or
            // fragment-carrying URI is now withheld whole. No URI the signer builds carries one —
            // it validates the base address up front — so nothing the signer can send loses its
            // path diagnostic (the clean-URI tests above pin that the path is named).
            URI uri = URI.create(
                    "http://127.0.0.1:" + silent.getLocalPort() + "/v1/transit/keys/vapid?secret-query=marker");

            assertThatThrownBy(() -> transport(Duration.ofMillis(500), 1024).get(uri, Map.of("X-Vault-Token", TOKEN)))
                    .isInstanceOf(PushCryptoException.class)
                    .hasMessageContaining("GET <unrenderable address>")
                    .satisfies(e -> assertThat(e.getMessage())
                            .doesNotContain(TOKEN)
                            .doesNotContain("secret-query")
                            .doesNotContain("marker")
                            .doesNotContain("/v1/transit/keys/vapid"));
        }
    }

    @Test
    void aTokenTheHttpClientWouldRejectNeverReachesTheExceptionOrItsCauses() {
        // The malformed-token path the timeout-based test above cannot reach: a token with a
        // trailing newline — exactly how it arrives from `kubectl create secret --from-file`, a
        // Vault Agent sidecar file, or a YAML block scalar — is illegal in an HTTP field value,
        // and HttpRequest.Builder.header() rejects it with THE WHOLE VALUE in the exception
        // message. That exception must neither escape the transport nor ride along as a cause:
        // in fetched mode it would surface in the constructor, putting the live token into the
        // application's startup stack trace. Port 9 (discard): header validation fires before
        // any connection is attempted.
        URI uri = URI.create("http://127.0.0.1:9/v1/transit/keys/vapid");

        assertThatThrownBy(() -> transport(Duration.ofSeconds(1), 1024).get(uri, Map.of("X-Vault-Token", TOKEN + "\n")))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("GET")
                .hasMessageContaining("/v1/transit/keys/vapid")
                .hasNoCause()
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain(TOKEN));
    }

    @Test
    void userinfoInTheVaultAddressNeverReachesTheExceptionMessage() {
        // Credentials in the URI authority (https://user:secret@vault:8200) are exactly as
        // secret as the token — an operator who smuggles basic-auth credentials for a fronting
        // proxy into the Vault address must not find them in every transport failure. The rest of
        // the URI stays: a failure message is most useful as a URI an operator can copy. Exercised
        // through the header-rejection path, which renders the URI without ever connecting.
        URI uri = URI.create("http://vault-user:secret-cred@127.0.0.1:9/v1/transit/keys/vapid");

        assertThatThrownBy(() -> transport(Duration.ofSeconds(1), 1024).get(uri, Map.of("X-Vault-Token", TOKEN + "\n")))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("http://127.0.0.1:9/v1/transit/keys/vapid")
                .satisfies(e ->
                        assertThat(e.getMessage()).doesNotContain("secret-cred").doesNotContain("vault-user"));
    }

    @Test
    void credentialsOutsideAnAuthorityAreWithheldWithTheWholeUri() {
        // A URI can carry credentials without an authority at all: "user:secret@vault:8200" — a
        // host:port typed with no scheme — parses as the scheme "user" with everything else as its
        // scheme-specific part, so no parsed component says which characters are credential. The
        // signer's own validation keeps such an address away from this transport; the rendering
        // must not depend on that, since it is what stands between a URI and a log — so a URI with
        // no parsed host is replaced by the marker whole, host included, rather than echoed on the
        // strength of a guess.
        URI uri = URI.create("vault-user:secret-cred@vault.test:8200/v1/transit/keys/vapid");

        assertThatThrownBy(() -> transport(Duration.ofSeconds(1), 1024).get(uri, Map.of("X-Vault-Token", TOKEN)))
                .isInstanceOf(PushCryptoException.class)
                .hasNoCause()
                .hasMessageContaining("<unrenderable address>")
                .satisfies(e -> assertThat(e.getMessage())
                        .doesNotContain("secret-cred")
                        .doesNotContain("vault-user")
                        .doesNotContain("vault.test"));
    }

    @Test
    void aRelativeReferenceIsReplacedByTheMarker() {
        // "/vault//a@b" has no scheme and no authority — nothing but path, whose "@" is an
        // ordinary character. It is still withheld: the rendering trusts only a parsed
        // scheme://host shape, and reasoning about which hostless strings are harmless is exactly
        // the guessing that used to leak a password carrying "/". Mirrors the starter's test of
        // the same shape: the two renderings are separate copies of one rule and can only stay in
        // step if both are pinned. Reached through the URI-rejection path, which renders without
        // ever connecting.
        URI uri = URI.create("/vault//a@b");

        assertThatThrownBy(() -> transport(Duration.ofSeconds(1), 1024).get(uri, Map.of("X-Vault-Token", TOKEN)))
                .isInstanceOf(PushCryptoException.class)
                .hasNoCause()
                .hasMessageContaining("<unrenderable address>")
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("/vault//a@b"));
    }

    @Test
    void anEmptyUserinfoLosesNothing() {
        // "https://@vault.test:8200" delimits a userinfo that is empty: there is no credential to
        // strip, and cutting at that "@" would drop the delimiter for nothing. The starter's mirror
        // of this test asserts it gains no "***@"; here the rendering must simply come through
        // whole. Reached through the header-rejection path, which renders without connecting.
        URI uri = URI.create("https://@vault.test:8200/v1/transit/keys/vapid");

        assertThatThrownBy(() -> transport(Duration.ofSeconds(1), 1024).get(uri, Map.of("X-Vault-Token", TOKEN + "\n")))
                .isInstanceOf(PushCryptoException.class)
                .hasNoCause()
                .hasMessageContaining("https://@vault.test:8200/v1/transit/keys/vapid");
    }

    @Test
    void anIllegalArgumentFromTheClientItselfKeepsItsOwnDiagnostic() {
        // The header-sanitising catch must wrap the header loop ALONE: an
        // IllegalArgumentException from inside the client's own send() has nothing to do with
        // header values, and relabelling it as one — with the original diagnostic deliberately
        // dropped, as the header path must — would destroy the only clue to an unrelated bug.
        JdkVaultHttpTransport transport =
                new JdkVaultHttpTransport(new IllegalArgumentThrowingClient(), Duration.ofSeconds(1), 1024);
        URI uri = URI.create("http://127.0.0.1:9/v1/transit/keys/vapid");

        assertThatThrownBy(() -> transport.get(uri, Map.of("X-Vault-Token", TOKEN)))
                .hasMessageContaining("client rejected the request for its own reasons")
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("illegal in an HTTP header value"));
    }

    @Test
    void aUriThatCannotBackAnHttpRequestIsReportedAsThisModulesException() {
        // HttpRequest.newBuilder rejects a URI without a usable scheme/host with a raw
        // IllegalArgumentException — escaping as such would contradict the transport's
        // PushCryptoException contract, and its message echoes the URI whole (userinfo
        // included), so the conversion must not attach it as a cause either.
        URI uri = URI.create("foo://vault-user:secret-cred@vault.test:8200/v1/transit/keys/vapid");

        assertThatThrownBy(() -> transport(Duration.ofSeconds(1), 1024).get(uri, Map.of("X-Vault-Token", TOKEN)))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("/v1/transit/keys/vapid")
                .hasNoCause()
                .satisfies(e ->
                        assertThat(e.getMessage()).doesNotContain("secret-cred").doesNotContain("vault-user"));
    }

    @Test
    void aRedirectFollowingClientIsRejectedAtConstruction() {
        // The JDK client does NOT strip custom headers such as X-Vault-Token across a
        // cross-origin redirect, so a Vault address resolving to an attacker (DNS hijack,
        // squatted typo host, compromised reverse proxy) could answer 307 and receive the
        // token. A client that follows redirects must be refused up front, not trusted.
        for (HttpClient.Redirect policy :
                new HttpClient.Redirect[] {HttpClient.Redirect.ALWAYS, HttpClient.Redirect.NORMAL}) {
            HttpClient following =
                    HttpClient.newBuilder().followRedirects(policy).build();

            assertThatThrownBy(() -> new JdkVaultHttpTransport(following, Duration.ofSeconds(5), 1024))
                    .as("followRedirects %s", policy)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("redirect")
                    .hasMessageContaining("X-Vault-Token");
        }
    }

    @Test
    void theDefaultTransportReturnsARedirectInsteadOfFollowingIt() throws Exception {
        // Pins the safe default: the transport must hand a 3xx back to the caller (where it
        // fails as an unexpected status) rather than chase the Location — following it would
        // replay X-Vault-Token against whatever host the redirect names.
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        try {
            server.createContext("/v1", exchange -> {
                exchange.getRequestBody().readAllBytes();
                exchange.getResponseHeaders().add("Location", "/stolen");
                exchange.sendResponseHeaders(307, -1);
                exchange.close();
            });
            server.createContext("/stolen", exchange -> {
                exchange.getRequestBody().readAllBytes();
                byte[] leaked = "leaked".getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, leaked.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(leaked);
                }
            });
            server.start();
            URI uri = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/v1/transit/keys/vapid");

            VaultHttpResponse response = new JdkVaultHttpTransport().get(uri, Map.of("X-Vault-Token", TOKEN));

            assertThat(response.statusCode()).isEqualTo(307);
            assertThat(response.body()).doesNotContain("leaked");
        } finally {
            server.stop(0);
        }
    }

    @Test
    void theSuppliedHttpClientCarriesTheRequests() throws Exception {
        RecordingHttpClient recording = new RecordingHttpClient(HttpClient.newHttpClient());
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        withServer(200, body, true, uri -> {
            JdkVaultHttpTransport transport = new JdkVaultHttpTransport(recording, Duration.ofSeconds(5), 1024);
            transport.get(uri, Map.of());
            transport.post(uri, Map.of(), body);
            assertThat(recording.sends())
                    .as("both calls went through the supplied client")
                    .isEqualTo(2);
        });
    }

    /**
     * A client whose {@code send} throws {@link IllegalArgumentException} — standing in for any client-internal IAE,
     * which the transport's header-sanitising catch must not relabel as a header problem. Everything else delegates to
     * a real (non-redirecting) client so the transport's constructor checks pass.
     */
    private static final class IllegalArgumentThrowingClient extends HttpClient {

        private final HttpClient delegate = HttpClient.newHttpClient();

        @Override
        public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler) {
            throw new IllegalArgumentException("client rejected the request for its own reasons");
        }

        @Override
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(
                HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler) {
            return delegate.sendAsync(request, responseBodyHandler);
        }

        @Override
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(
                HttpRequest request,
                HttpResponse.BodyHandler<T> responseBodyHandler,
                HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
            return delegate.sendAsync(request, responseBodyHandler, pushPromiseHandler);
        }

        @Override
        public Optional<CookieHandler> cookieHandler() {
            return delegate.cookieHandler();
        }

        @Override
        public Optional<Duration> connectTimeout() {
            return delegate.connectTimeout();
        }

        @Override
        public Redirect followRedirects() {
            return delegate.followRedirects();
        }

        @Override
        public Optional<ProxySelector> proxy() {
            return delegate.proxy();
        }

        @Override
        public SSLContext sslContext() {
            return delegate.sslContext();
        }

        @Override
        public SSLParameters sslParameters() {
            return delegate.sslParameters();
        }

        @Override
        public Optional<Authenticator> authenticator() {
            return delegate.authenticator();
        }

        @Override
        public Version version() {
            return delegate.version();
        }

        @Override
        public Optional<Executor> executor() {
            return delegate.executor();
        }
    }
}
