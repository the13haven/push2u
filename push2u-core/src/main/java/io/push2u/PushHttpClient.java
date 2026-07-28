package io.push2u;

import java.net.URI;
import java.util.Map;

/**
 * The HTTP transport seam: POST the encrypted body to a push endpoint and report the status.
 *
 * <p>An extension point (DESIGN.md §5.1) because users standardize on a specific HTTP stack for
 * connection pooling, proxies, and observability. The default is {@link JdkHttpPushClient} over
 * {@code java.net.http}; OkHttp / Apache HttpClient 5 implementations are opt-in modules
 * (ROADMAP phase 4).
 *
 * <p>Implementations report a push service <em>rejecting</em> the request as a {@link PushResponse}
 * with the status code — only genuine I/O failures (no connection, timeout) throw
 * {@link PushDeliveryException}. The {@link PushSender} owns retry and status interpretation.
 */
@FunctionalInterface
public interface PushHttpClient {

    /**
     * POST {@code body} to {@code endpoint} with the given request headers.
     *
     * @param endpoint the push service endpoint to POST to
     * @param headers  the request headers (Authorization, Content-Encoding, TTL, ...)
     * @param body     the encrypted {@code aes128gcm} message body
     * @return the push service's response (status code + headers)
     * @throws PushDeliveryException on a transport failure (not on an HTTP error status)
     */
    PushResponse post(URI endpoint, Map<String, String> headers, byte[] body);
}
