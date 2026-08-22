/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLServerSocket;

/**
 * One loopback HTTPS listener of the transport contract's harness: a raw {@link SSLServerSocket} whose exchanges are
 * read and answered through the minimal HTTP/1.1 in {@link TransportContractHttp} — including, for the
 * unanswered-request check, answering with no status line at all. Package-private machinery of
 * {@link PushHttpClientContractTest} and nothing else: no consumer may depend on its shape, its behaviour or its
 * continued existence.
 *
 * <p>A raw socket rather than an HTTP server library, because the wire is what the contract is about: a server that
 * parses the request into an object, decides the framing and manages the connection on the harness's behalf is a layer
 * whose behaviour would become part of what every check asserts. It also keeps the artifact's dependency surface where
 * it is — nothing here reaches outside {@code java.base}. The listener advertises nothing in ALPN, so a client that
 * prefers HTTP/2 over TLS falls back to HTTP/1.1 by itself. Every listener binds to the loopback address only, and
 * headers the transport adds of its own pass through untouched — the checks assert presence of what they gave, never
 * the exact set.
 */
final class TransportContractServer implements AutoCloseable {

    /**
     * How long one exchange may sit idle before the harness gives up on it. Generous on purpose: the contract's own
     * budget aborts a check long before this, and the read timeout exists only so a handler thread does not hold a
     * socket forever after the check has moved on.
     */
    private static final int READ_TIMEOUT_MILLIS = 60_000;

    private final SSLServerSocket listener;
    private final Responder responder;
    private final List<ReceivedRequest> received = new CopyOnWriteArrayList<>();
    private final AtomicInteger acceptedConnections = new AtomicInteger();
    private volatile boolean closed;

    private TransportContractServer(SSLServerSocket listener, Responder responder) {
        this.listener = listener;
        this.responder = responder;
    }

    /** What a listener does with one fully read request: answer with these bytes, or close without writing any. */
    @FunctionalInterface
    interface Responder {

        /**
         * The raw response bytes for one request, or {@link Optional#empty()} to close the connection without writing a
         * status line — the unanswered-request case.
         */
        Optional<byte[]> respond(ReceivedRequest request);
    }

    /**
     * Opens a listener on an ephemeral loopback port, presenting the harness's per-JVM certificate and answering every
     * request through {@code responder}. The accept loop runs on a daemon thread until {@link #close()}.
     */
    // CloseResource: the listener is owned by the server instance under construction — close()
    // closes it, and the contract's checks hold every server in a try-with-resources.
    @SuppressWarnings("PMD.CloseResource")
    static TransportContractServer answeringWith(Responder responder) throws IOException {
        SSLServerSocket listener = (SSLServerSocket) TransportContractTls.serverContext()
                .getServerSocketFactory()
                .createServerSocket(0, 16, InetAddress.getLoopbackAddress());
        TransportContractServer server = new TransportContractServer(listener, responder);
        Thread acceptor = new Thread(server::acceptLoop, "push2u-transport-contract-server");
        acceptor.setDaemon(true);
        acceptor.start();
        return server;
    }

    /** The endpoint a transport under test is pointed at: {@code https} on this listener, at the given target. */
    URI endpoint(String pathAndQuery) {
        return URI.create("https://" + InetAddress.getLoopbackAddress().getHostAddress() + ":" + listener.getLocalPort()
                + pathAndQuery);
    }

    /** A point-in-time snapshot of every request read in full so far, in the order they completed. */
    List<ReceivedRequest> received() {
        return List.copyOf(received);
    }

    /**
     * How many connections this listener has accepted, whether or not a request ever arrived on them. The redirect
     * check asserts zero of these on the redirect target, which is a stronger claim than "no request arrived": a
     * transport that so much as connects to an origin nobody vetted has already failed.
     */
    int acceptedConnections() {
        return acceptedConnections.get();
    }

    @Override
    public void close() {
        closed = true;
        try {
            listener.close();
        } catch (IOException alreadyClosing) {
            // Nothing to do: the listener is being discarded, and the accept loop ends on either outcome.
        }
    }

    // CloseResource: each accepted socket is owned and closed by the handler thread it is handed
    // to, in its try-with-resources — closing it here would race the handler mid-exchange.
    @SuppressWarnings("PMD.CloseResource")
    private void acceptLoop() {
        while (!closed) {
            Socket connection;
            try {
                connection = listener.accept();
            } catch (IOException endOfService) {
                return;
            }
            acceptedConnections.incrementAndGet();
            Thread handler = new Thread(() -> handle(connection), "push2u-transport-contract-exchange");
            handler.setDaemon(true);
            handler.start();
        }
    }

    /** One connection: complete the handshake by reading, record the request, answer it (or not), close. */
    private void handle(Socket connection) {
        try (Socket exchange = connection) {
            exchange.setSoTimeout(READ_TIMEOUT_MILLIS);
            ReceivedRequest request = TransportContractHttp.parse(exchange.getInputStream());
            received.add(request);
            Optional<byte[]> response = responder.respond(request);
            if (response.isPresent()) {
                exchange.getOutputStream().write(response.get());
                exchange.getOutputStream().flush();
            }
        } catch (IOException halfExchange) {
            // A connection that never carried a full request — a handshake probe, a peer that gave
            // up, a client refusing the certificate — records nothing; the checks assert over what
            // was received and over connection counts, and both are already accounted for.
        }
    }

    /**
     * One request as the wire carried it: the method, the request target as it was sent, the header fields with their
     * names lower-cased, and the body bytes exactly as they arrived.
     */
    static final class ReceivedRequest {

        private final String method;
        private final String target;
        private final Map<String, String> headers;
        private final byte[] body;

        ReceivedRequest(String method, String target, Map<String, String> headers, byte[] body) {
            this.method = method;
            this.target = target;
            this.headers = Map.copyOf(headers);
            this.body = body.clone();
        }

        String method() {
            return method;
        }

        String target() {
            return target;
        }

        /** Case-insensitive header lookup, over whatever spelling the transport sent. */
        Optional<String> header(String name) {
            return Optional.ofNullable(headers.get(name.toLowerCase(Locale.ROOT)));
        }

        byte[] body() {
            return body.clone();
        }

        /**
         * Written by hand, because the values this type holds must not reach a build log through an accidental
         * rendering: a transport under test may add headers of its own out of the environment it runs in — a proxy
         * credential is the canonical example — and on a real send the given headers carry a VAPID token. Names, counts
         * and the harness-made target say everything a diagnostic needs.
         */
        @Override
        public String toString() {
            return "ReceivedRequest[method=" + method + ", target=" + target + ", headerNames=" + headers.keySet()
                    + ", bodyBytes=" + body.length + "]";
        }
    }
}
