package io.push2u.signer.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import io.push2u.PushCryptoException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/**
 * {@link JdkVaultHttpTransport} against live sockets — the transport-level guarantees the Vault
 * signer relies on: the per-request timeout (a Vault that accepts the connection but never answers
 * must not hang application startup forever), the fail-closed response-size cap counted in raw
 * bytes, interrupt handling, argument validation, and exception hygiene (no token, no query).
 */
class JdkVaultHttpTransportTest {

    private static final String TOKEN = "s.push2u-test-vault-token";

    /** A transport over a fresh client with the given per-request timeout and size cap. */
    private static JdkVaultHttpTransport transport(Duration requestTimeout, int maxResponseBytes) {
        return new JdkVaultHttpTransport(HttpClient.newHttpClient(), requestTimeout, maxResponseBytes);
    }

    /** Serve {@code status} + {@code body} once on an ephemeral port and run {@code test} against it. */
    private static void withServer(int status, byte[] body, boolean declareLength, ServerTest test)
        throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
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

            assertThatThrownBy(() -> transport(Duration.ofSeconds(1), 1024)
                .get(uri, Map.of("X-Vault-Token", TOKEN)))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("timed out")
                .hasCauseInstanceOf(HttpTimeoutException.class)
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain(TOKEN));
        }
    }

    @Test
    void aResponseLargerThanTheCapFailsClosed() throws Exception {
        byte[] oversized = new byte[9];
        withServer(200, oversized, true, uri ->
            assertThatThrownBy(() -> transport(Duration.ofSeconds(5), 8).get(uri, Map.of()))
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
        withServer(200, oversized, false, uri ->
            assertThatThrownBy(() -> transport(Duration.ofSeconds(5), 8).get(uri, Map.of()))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageStartingWith("Vault response exceeded the configured limit of 8 bytes")
                .hasMessageContaining("GET")
                .hasMessageContaining("/v1/transit/keys/vapid"));
    }

    @Test
    void aResponseExactlyAtTheCapSucceeds() throws Exception {
        byte[] exact = "12345678".getBytes(StandardCharsets.UTF_8);
        withServer(200, exact, true, uri -> {
            VaultHttpResponse response = transport(Duration.ofSeconds(5), exact.length).get(uri, Map.of());
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

            assertThat(caller.isAlive()).as("the interrupted call returns promptly").isFalse();
            assertThat(thrown.get())
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("Interrupted")
                .hasCauseInstanceOf(InterruptedException.class);
            assertThat(flagRestored.get()).as("the interrupt flag is restored for the caller").isTrue();
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
    void exceptionMessagesCarryNeitherTheTokenNorTheQuery() throws Exception {
        try (ServerSocket silent = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            // Vault APIs put sensitive detail in queries (e.g. list=true on secret paths) — the
            // message may name the path, never the query.
            URI uri = URI.create("http://127.0.0.1:" + silent.getLocalPort()
                + "/v1/transit/keys/vapid?secret-query=marker");

            assertThatThrownBy(() -> transport(Duration.ofMillis(500), 1024)
                .get(uri, Map.of("X-Vault-Token", TOKEN)))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("/v1/transit/keys/vapid")
                .satisfies(e -> assertThat(e.getMessage())
                    .doesNotContain(TOKEN)
                    .doesNotContain("secret-query")
                    .doesNotContain("marker"));
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
            assertThat(recording.sends()).as("both calls went through the supplied client").isEqualTo(2);
        });
    }
}
