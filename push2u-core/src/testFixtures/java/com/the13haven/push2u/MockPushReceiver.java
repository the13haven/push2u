/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.jspecify.annotations.Nullable;

/**
 * A minimal in-process push service for the send-pipeline tests: a JDK {@link HttpsServer} that answers every request
 * with one configured response — a status code, optionally with a {@code Retry-After} header; {@code 201 Created} until
 * a test says otherwise — and records every request it receives. One response, not a scripted sequence: a send makes at
 * most one POST, so a test that wants a different answer for its next send configures it between the sends. No
 * third-party HTTP mock — the test stack stays as dependency-free as the library.
 *
 * <p>It serves real TLS, presenting the per-JVM {@link LoopbackTls} certificate, so {@link #endpoint()} is an
 * {@code https://127.0.0.1:<port>/push} URI that passes {@link Endpoints#requireSecure} exactly as a production
 * endpoint does — the tests traverse the same protocol the production path does, with no plaintext escape hatch
 * anywhere. Clients trust the certificate via {@link LoopbackTls#clientContext()}; see
 * {@link PushTestSupport#trustingPushHttpClient()}.
 */
final class MockPushReceiver implements AutoCloseable {

    private final HttpsServer server;
    private final List<RecordedRequest> requests = new ArrayList<>();
    private Response response = new Response(201, null);

    MockPushReceiver() throws IOException {
        server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(LoopbackTls.serverContext()));
        server.createContext("/push", exchange -> {
            int bodyLength = exchange.getRequestBody().readAllBytes().length;
            Map<String, String> headers = new HashMap<>();
            exchange.getRequestHeaders().forEach((name, values) -> {
                if (!values.isEmpty()) {
                    headers.put(name.toLowerCase(Locale.ROOT), values.getFirst());
                }
            });
            Response configured;
            synchronized (this) {
                requests.add(new RecordedRequest(exchange.getRequestMethod(), headers, bodyLength));
                configured = response;
            }
            if (configured.retryAfter() != null) {
                exchange.getResponseHeaders().set("Retry-After", configured.retryAfter());
            }
            exchange.sendResponseHeaders(configured.status(), -1);
            exchange.close();
        });
        server.start();
    }

    /** Answer every request from now on with this status and no {@code Retry-After}. */
    void respondWith(int status) {
        respondWith(status, null);
    }

    /** Answer every request from now on with this status, carrying a {@code Retry-After} header unless {@code null}. */
    void respondWith(int status, @Nullable String retryAfter) {
        synchronized (this) {
            response = new Response(status, retryAfter);
        }
    }

    URI endpoint() {
        return URI.create("https://127.0.0.1:" + server.getAddress().getPort() + "/push");
    }

    synchronized List<RecordedRequest> requests() {
        return List.copyOf(requests);
    }

    @Override
    public void close() {
        server.stop(0);
    }

    /** The configured reply. {@code retryAfter} is nullable because most replies carry no such header. */
    record Response(int status, @Nullable String retryAfter) {}

    record RecordedRequest(String method, Map<String, String> headers, int bodyLength) {}
}
