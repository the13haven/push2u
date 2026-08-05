/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The default {@link PushHttpClient}, over the JDK's {@code java.net.http.HttpClient} — no third party HTTP stack,
 * keeping {@code core} free of runtime implementation dependencies. The response body is discarded without buffering:
 * push delivery (RFC 8030 §5) only needs the status and headers, and the endpoint is a capability URL taken from the
 * subscription — a hostile server answering with a huge body must cost the sender nothing. Discarding still drains the
 * stream, so connections stay reusable.
 *
 * <p>A second guarantee holds at construction: <b>the client must not follow redirects.</b> The endpoint is an
 * attacker-supplied capability URL and the {@link EndpointPolicy} validated exactly the URI handed to {@link #post} — a
 * {@code 3xx} chased by the client would re-send the encrypted body and the request headers to whatever host
 * {@code Location} names, an address the policy never saw, and the redirect target's answer would be reported as the
 * delivery result. A supplied client whose {@link HttpClient#followRedirects()} is not
 * {@link HttpClient.Redirect#NEVER} is rejected; the default client is built that way. A {@code 3xx} therefore reaches
 * the caller as an ordinary status, which {@link PushSender} classifies as a failed {@link PushResult}.
 */
public final class JdkPushHttpClient implements PushHttpClient {

    private static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(30);

    private final HttpClient httpClient;
    private final Duration requestTimeout;

    /**
     * Uses a fresh {@link HttpClient} that never follows redirects, and a 30-second per-request timeout. The redirect
     * policy is set explicitly rather than inherited: it is this class's own invariant, not a JDK default to rely on.
     */
    // The delegation to the validating constructor is load-bearing, not a convenience: it is what
    // makes "no instance of this class can follow redirects" true of every instance rather than
    // only of the ones a caller configured. `httpClient` is assigned there and nowhere else, so a
    // future constructor that sets the field directly would silently drop the guarantee — no test
    // can catch that, because the wrapped client is not observable from outside.
    public JdkPushHttpClient() {
        this(HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build(), DEFAULT_REQUEST_TIMEOUT);
    }

    /**
     * Uses the given {@link HttpClient} (bring your own proxy, executor, or TLS configuration) and per-request timeout.
     *
     * @param httpClient the HTTP client to send requests with; must be built with {@link HttpClient.Redirect#NEVER}
     * @param requestTimeout the per-request timeout, applied to every request
     * @throws IllegalArgumentException if the client follows redirects
     */
    public JdkPushHttpClient(HttpClient httpClient, Duration requestTimeout) {
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
        if (httpClient.followRedirects() != HttpClient.Redirect.NEVER) {
            // The endpoint is attacker-supplied and EndpointPolicy vetted that exact URI. A
            // followed 3xx carries the encrypted body and the request headers to a host the
            // policy never saw (the JDK strips Authorization cross-origin, but not TTL, Topic,
            // Urgency or the body), reports the redirect target's answer as the delivery result,
            // and under Redirect.ALWAYS will downgrade https to http on the way. No push service
            // answers a delivery POST with a redirect, so there is nothing legitimate to lose.
            throw new IllegalArgumentException("httpClient must not follow redirects (followRedirects() is "
                    + httpClient.followRedirects() + "): the push endpoint is an attacker-supplied capability URL"
                    + " and the EndpointPolicy vetted exactly that URI, so following a 3xx would POST the encrypted"
                    + " body and its headers to a host no policy ever saw, and would report that host's answer as"
                    + " the delivery result. Build the client with followRedirects(HttpClient.Redirect.NEVER)");
        }
        this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout");
    }

    @Override
    public PushResponse post(URI endpoint, Map<String, String> headers, byte[] body) {
        HttpRequest.Builder request = HttpRequest.newBuilder(endpoint)
                .timeout(requestTimeout)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        headers.forEach(request::header);

        try {
            HttpResponse<Void> response = httpClient.send(request.build(), HttpResponse.BodyHandlers.discarding());
            return new PushResponse(
                    response.statusCode(), firstValues(response.headers().map()));
        } catch (IOException e) {
            throw new PushDeliveryException(
                    "POST to push endpoint failed: " + Endpoints.redact(endpoint.toString()), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new PushDeliveryException(
                    "Interrupted while POSTing to push endpoint: " + Endpoints.redact(endpoint.toString()), e);
        }
    }

    private static Map<String, String> firstValues(Map<String, List<String>> headers) {
        Map<String, String> flattened = new HashMap<>();
        headers.forEach((name, values) -> {
            if (!values.isEmpty()) {
                flattened.put(name, values.getFirst());
            }
        });
        return flattened;
    }
}
