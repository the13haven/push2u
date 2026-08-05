/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Duration;
import java.util.Map;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.junit.jupiter.api.Test;

/**
 * {@link JdkPushHttpClient} against a live JDK {@link HttpsServer}. The scenario the discarding body handler exists
 * for: the endpoint is a capability URL from the (untrusted) subscription, so a hostile push service may answer with an
 * arbitrarily large body. The client must drain it without buffering and still hand the pipeline the status and headers
 * it needs.
 *
 * <p>The server is a bespoke streaming handler rather than the {@link MockPushReceiver} (which cannot stream a
 * 64&nbsp;MiB body), but it serves the same TLS identity ({@link LoopbackTls}) — the fixture models a real push
 * endpoint, so it speaks the protocol a real one does.
 */
class JdkPushHttpClientTest {

    /** Big enough that buffering it per send would be a real memory hit; streamed by the server. */
    private static final long HUGE_BODY_BYTES = 64L * 1024 * 1024;

    @Test
    void aHugeResponseBodyIsDiscardedAndTheStatusAndHeadersStillArrive() throws Exception {
        HttpsServer server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        try {
            server.setHttpsConfigurator(new HttpsConfigurator(LoopbackTls.serverContext()));
            byte[] chunk = new byte[64 * 1024];
            server.createContext("/push", exchange -> {
                exchange.getRequestBody().readAllBytes();
                exchange.getResponseHeaders().set("Retry-After", "17");
                exchange.sendResponseHeaders(429, HUGE_BODY_BYTES);
                try (OutputStream out = exchange.getResponseBody()) {
                    long remaining = HUGE_BODY_BYTES;
                    while (remaining > 0) {
                        int step = (int) Math.min(chunk.length, remaining);
                        out.write(chunk, 0, step);
                        remaining -= step;
                    }
                }
            });
            server.start();
            URI endpoint = URI.create("https://127.0.0.1:" + server.getAddress().getPort() + "/push");

            PushResponse response = new JdkPushHttpClient(
                            PushTestSupport.trustingJavaHttpClient(), Duration.ofSeconds(30))
                    .post(endpoint, Map.of("TTL", "60"), new byte[] {1, 2, 3});

            assertThat(response.statusCode()).isEqualTo(429);
            assertThat(response.header("Retry-After")).contains("17");
        } finally {
            server.stop(0);
        }
    }
}
