/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.net.URI;
import java.util.Map;

/**
 * The HTTP transport seam: POST the encrypted body to a push endpoint and report the status.
 *
 * <p>An extension point because users standardize on a specific HTTP stack for connection pooling, proxies, and
 * observability. The default is {@link JdkPushHttpClient} over {@code java.net.http}; applications can supply another
 * implementation (OkHttp, Apache HttpClient 5, ...) by implementing this interface.
 *
 * <p>Implementations report a push service <em>rejecting</em> the request as a {@link PushResponse} with the status
 * code — only genuine I/O failures (no connection, timeout) throw {@link PushDeliveryException}. The {@link PushSender}
 * owns the status interpretation; a transport neither classifies nor repeats a request, and the sender makes one POST
 * per send, so however a repeat is scheduled, each attempt arrives here as its own {@link #post} call.
 *
 * <p>The response body is never consumed by the pipeline — {@link PushResponse} does not carry one. Because the
 * endpoint is a capability URL supplied by the (untrusted) subscription, implementations should discard the body
 * without buffering it, as {@link JdkPushHttpClient} does, rather than materialize a response of attacker-chosen size.
 *
 * <p><b>Implementations must not follow redirects.</b> A {@code 3xx} is returned to the caller like any other status,
 * and {@link PushSender} classifies it — as a non-retryable failure, since RFC 8030 §5 delivery has no redirect step.
 * The endpoint is untrusted and the {@link EndpointPolicy} ran against exactly the URI passed to {@link #post}: chasing
 * a {@code Location} would re-send the encrypted body and the request headers to a host the policy never saw, would let
 * the redirect target's answer stand in for the push service's verdict, and — under a permissive redirect policy —
 * would follow an {@code https} endpoint down to {@code http}. This is a property of the implementation, not of the
 * stack it wraps, and nothing at run time can check it: {@link JdkPushHttpClient} rejects a redirect-following
 * {@code java.net.http.HttpClient} at construction, but a client built on another stack must set it deliberately —
 * OkHttp's {@code followRedirects} defaults to {@code true}, so the straightforward implementation there is unsafe
 * until it is turned off (its {@code followSslRedirects} too).
 *
 * <p><b>Implementations must be thread-safe.</b> One {@link PushSender} is shared across threads and
 * {@link PushSender#sendAsync} makes concurrent {@link #post} calls the normal case, so per-request state belongs in
 * the call rather than in a field — which is also what makes a pooled client the natural implementation.
 *
 * <p><b>Most of these obligations are executable.</b> The {@code push2u-testkit} artifact publishes
 * {@code PushHttpClientContractTest}, a contract an implementation extends in its own test suite. It stands up a
 * loopback TLS server of its own, hands the implementation the {@code SSLContext} and {@code X509TrustManager} that
 * trust the server's throwaway certificate, and checks over that wire: an HTTP error status comes back as a
 * {@link PushResponse} rather than an exception; the response headers reach the caller; exactly one request arrives per
 * {@link #post} call and it is the request that was handed over, the body compared byte for byte; a redirect is
 * returned rather than followed; a refused connection and a request read but never answered each surface as
 * {@link PushDeliveryException}; and concurrent calls each receive the response to their own request. Two things it
 * deliberately does not check, so their sentences above bind on their own: that the response body goes unmaterialised,
 * because {@link PushResponse} has no slot a buffered body could reach the caller through and no observation from
 * outside tells draining a stream apart from holding it in memory; and any timeout or retry schedule, which this seam
 * does not promise — though how many HTTP requests one {@code post} call produces is this seam's own promise, not a
 * retry policy, and it is checked.
 */
@FunctionalInterface
public interface PushHttpClient {

    /**
     * POST {@code body} to {@code endpoint} with the given request headers.
     *
     * @param endpoint the push service endpoint to POST to
     * @param headers the request headers (Authorization, Content-Encoding, TTL, ...)
     * @param body the encrypted {@code aes128gcm} message body
     * @return the push service's response (status code + headers)
     * @throws PushDeliveryException on a transport failure (not on an HTTP error status)
     */
    PushResponse post(URI endpoint, Map<String, String> headers, byte[] body);
}
