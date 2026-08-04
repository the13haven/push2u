/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

/**
 * The transport's redirect invariant. The push endpoint is a capability URL taken from an untrusted subscription, and
 * {@link EndpointPolicy} vetted exactly the URI the pipeline hands to {@link JdkPushHttpClient#post} — a followed
 * {@code 3xx} would POST the encrypted body and its headers to a host the policy never saw (the JDK strips
 * {@code Authorization} across origins but not custom headers or the body), and would report the redirect target's
 * answer as the delivery result.
 */
class JdkPushHttpClientRedirectTest {

    private static final byte[] BODY = new byte[] {1, 2, 3};

    @Test
    void aRedirectFollowingClientIsRejectedAtConstruction() {
        for (HttpClient.Redirect policy :
                new HttpClient.Redirect[] {HttpClient.Redirect.ALWAYS, HttpClient.Redirect.NORMAL}) {
            HttpClient following =
                    HttpClient.newBuilder().followRedirects(policy).build();

            assertThatThrownBy(() -> new JdkPushHttpClient(following, Duration.ofSeconds(5)))
                    .as("followRedirects %s", policy)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("must not follow redirects")
                    .hasMessageContaining("EndpointPolicy")
                    .hasMessageContaining("followRedirects(HttpClient.Redirect.NEVER)");
        }
    }

    @Test
    void aNonRedirectingClientIsAccepted() {
        HttpClient never = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        assertThatCode(() -> new JdkPushHttpClient(never, Duration.ofSeconds(5)))
                .doesNotThrowAnyException();
    }

    @Test
    void theDefaultClientReturnsARedirectInsteadOfFollowingIt() throws Exception {
        // Pins the safe default: the 3xx comes back as an ordinary status (PushSender classifies
        // it as a failure) instead of the redirect target's 200, and the target is never contacted.
        AtomicInteger targetHits = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        try {
            server.createContext("/push", exchange -> {
                exchange.getRequestBody().readAllBytes();
                exchange.getResponseHeaders().add("Location", "/stolen");
                exchange.sendResponseHeaders(307, -1);
                exchange.close();
            });
            server.createContext("/stolen", exchange -> {
                exchange.getRequestBody().readAllBytes();
                targetHits.incrementAndGet();
                byte[] leaked = "leaked".getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("X-Redirect-Target", "reached");
                exchange.sendResponseHeaders(201, leaked.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(leaked);
                }
            });
            server.start();
            URI endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/push");

            PushResponse response = new JdkPushHttpClient().post(endpoint, Map.of("TTL", "60"), BODY);

            assertThat(response.statusCode())
                    .as("the redirect itself is the result, not the redirect target's 201")
                    .isEqualTo(307);
            assertThat(response.header("X-Redirect-Target")).isEmpty();
            assertThat(targetHits)
                    .as("the body and headers must never reach the Location host")
                    .hasValue(0);
        } finally {
            server.stop(0);
        }
    }
}
