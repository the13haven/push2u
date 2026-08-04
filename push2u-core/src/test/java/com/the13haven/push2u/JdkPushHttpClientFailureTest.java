/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Transport failures, which are the cases a caller cannot read as a push-service verdict. The distinction this library
 * draws is that an HTTP status — even 410 Gone — is a {@link PushResult}, while a connection that never produced one is
 * a {@link PushDeliveryException}. These tests cover the second half.
 *
 * <p>The endpoint is redacted in the message on both paths: a push endpoint carries the subscription identifier, which
 * is a bearer credential for that subscription, and exception messages reach logs.
 */
class JdkPushHttpClientFailureTest {

    private static final byte[] BODY = new byte[] {1, 2, 3};

    @Test
    @Timeout(60)
    void aRefusedConnectionBecomesADeliveryFailureWithTheEndpointRedacted() throws IOException {
        URI unreachable = URI.create("https://127.0.0.1:" + closedPort() + "/wpush/v1/AAAA-secret-token");

        assertThatThrownBy(() -> new JdkPushHttpClient(HttpClient.newHttpClient(), Duration.ofSeconds(2))
                        .post(unreachable, Map.of(), BODY))
                .isInstanceOf(PushDeliveryException.class)
                .hasMessageContaining("POST to push endpoint failed")
                .hasCauseInstanceOf(IOException.class)
                .satisfies(thrown -> assertThat(thrown.getMessage())
                        .as("the subscription token must not reach the logs")
                        .doesNotContain("AAAA-secret-token"));
    }

    @Test
    @Timeout(60)
    void interruptionDuringASendBecomesADeliveryFailureWithTheFlagRestored() throws Exception {
        CountDownLatch requestArrived = new CountDownLatch(1);
        CountDownLatch releaseServer = new CountDownLatch(1);
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/push", exchange -> {
            requestArrived.countDown();
            try {
                releaseServer.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            exchange.sendResponseHeaders(201, -1);
            exchange.close();
        });
        server.start();

        AtomicReference<Throwable> thrown = new AtomicReference<>();
        AtomicBoolean flagStillSet = new AtomicBoolean();
        URI endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/push");

        try {
            Thread sender = new Thread(() -> {
                try {
                    new JdkPushHttpClient(HttpClient.newHttpClient(), Duration.ofSeconds(30))
                            .post(endpoint, Map.of(), BODY);
                } catch (RuntimeException e) {
                    thrown.set(e);
                    flagStillSet.set(Thread.currentThread().isInterrupted());
                }
            });
            sender.start();

            assertThat(requestArrived.await(30, TimeUnit.SECONDS)).isTrue();
            sender.interrupt();
            sender.join(TimeUnit.SECONDS.toMillis(30));

            assertThat(thrown.get())
                    .isInstanceOf(PushDeliveryException.class)
                    .hasMessageContaining("Interrupted while POSTing")
                    .hasCauseInstanceOf(InterruptedException.class);
            assertThat(flagStillSet)
                    .as("the send cleared the flag; the client has to put it back")
                    .isTrue();
        } finally {
            releaseServer.countDown();
            server.stop(0);
        }
    }

    /** A port nothing is listening on: bound to get a free one from the OS, then released. */
    private static int closedPort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
