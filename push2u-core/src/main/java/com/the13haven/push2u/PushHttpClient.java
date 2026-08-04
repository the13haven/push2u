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
 * owns retry and status interpretation.
 *
 * <p>The response body is never consumed by the pipeline — {@link PushResponse} does not carry one. Because the
 * endpoint is a capability URL supplied by the (untrusted) subscription, implementations should discard the body
 * without buffering it, as {@link JdkPushHttpClient} does, rather than materialize a response of attacker-chosen size.
 *
 * <p><b>Implementations must not follow redirects.</b> A {@code 3xx} is returned to the caller like any other status,
 * and {@link PushSender} classifies it — as a failure, since RFC 8030 §5 delivery has no redirect step. The endpoint is
 * untrusted and the {@link EndpointPolicy} ran against exactly the URI passed to {@link #post}: chasing a
 * {@code Location} would re-send the encrypted body and the request headers to a host the policy never saw, would let
 * the redirect target's answer stand in for the push service's verdict, and — under a permissive redirect policy —
 * would follow an {@code https} endpoint down to {@code http}. This is a property of the implementation, not of the
 * stack it wraps, and it is not checked here: {@link JdkPushHttpClient} rejects a redirect-following
 * {@code java.net.http.HttpClient} at construction, but a client built on another stack must set it deliberately —
 * OkHttp's {@code followRedirects} defaults to {@code true}, so the straightforward implementation there is unsafe
 * until it is turned off (its {@code followSslRedirects} too).
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
