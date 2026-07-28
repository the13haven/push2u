package io.push2u;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * A minimal in-process push service for the send-pipeline tests: a JDK {@link HttpServer} that
 * replies with a pre-queued sequence of status codes (defaulting to 201 once the queue drains)
 * and records every request it receives. No third-party HTTP mock — the test stack stays as
 * dependency-free as the library.
 */
final class MockPushReceiver implements AutoCloseable {

    private final HttpServer server;
    private final Deque<Response> responses = new ArrayDeque<>();
    private final List<RecordedRequest> requests = new ArrayList<>();

    MockPushReceiver() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/push", exchange -> {
            int bodyLength = exchange.getRequestBody().readAllBytes().length;
            Map<String, String> headers = new HashMap<>();
            exchange.getRequestHeaders().forEach((name, values) -> {
                if (!values.isEmpty()) {
                    headers.put(name.toLowerCase(Locale.ROOT), values.getFirst());
                }
            });
            Response response;
            synchronized (this) {
                requests.add(new RecordedRequest(exchange.getRequestMethod(), headers, bodyLength));
                response = responses.isEmpty() ? new Response(201, null) : responses.poll();
            }
            if (response.retryAfter() != null) {
                exchange.getResponseHeaders().set("Retry-After", response.retryAfter());
            }
            exchange.sendResponseHeaders(response.status(), -1);
            exchange.close();
        });
        server.start();
    }

    /** Queue one reply (FIFO). After the queue drains, further requests get 201. */
    void enqueue(int status) {
        enqueue(status, null);
    }

    void enqueue(int status, String retryAfter) {
        synchronized (this) {
            responses.add(new Response(status, retryAfter));
        }
    }

    URI endpoint() {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/push");
    }

    synchronized List<RecordedRequest> requests() {
        return List.copyOf(requests);
    }

    @Override
    public void close() {
        server.stop(0);
    }

    record Response(int status, String retryAfter) {
    }

    record RecordedRequest(String method, Map<String, String> headers, int bodyLength) {
    }
}
