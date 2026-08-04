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
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Map;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

/**
 * {@link JdkPushHttpClient} against a live JDK {@link HttpServer}. The scenario the discarding body handler exists for:
 * the endpoint is a capability URL from the (untrusted) subscription, so a hostile push service may answer with an
 * arbitrarily large body. The client must drain it without buffering and still hand the pipeline the status and headers
 * it needs.
 */
class JdkPushHttpClientTest {

    /** Big enough that buffering it per send would be a real memory hit; streamed by the server. */
    private static final long HUGE_BODY_BYTES = 64L * 1024 * 1024;

    @Test
    void aHugeResponseBodyIsDiscardedAndTheStatusAndHeadersStillArrive() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        try {
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
            URI endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/push");

            PushResponse response = new JdkPushHttpClient(HttpClient.newHttpClient(), Duration.ofSeconds(30))
                    .post(endpoint, Map.of("TTL", "60"), new byte[] {1, 2, 3});

            assertThat(response.statusCode()).isEqualTo(429);
            assertThat(response.header("Retry-After")).contains("17");
        } finally {
            server.stop(0);
        }
    }
}
