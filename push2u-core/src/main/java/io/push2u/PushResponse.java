package io.push2u;

import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * The push service's answer to a POST: the status code and the response headers. Header names are
 * stored and looked up case-insensitively, as HTTP requires.
 *
 * <p>A {@link PushHttpClient} returns this; the {@link PushSender} reads the status and
 * {@code Retry-After}. There is deliberately no body: RFC 8030 push delivery never consumes one,
 * and materializing it would let a hostile endpoint (the URL comes from the subscription) feed the
 * sender an arbitrarily large response.
 *
 * @param statusCode the HTTP status code
 * @param headers    the response headers (keys lower-cased); the pipeline reads {@code Retry-After}
 */
public record PushResponse(int statusCode, Map<String, String> headers) {

    /** Lower-cases the header keys (for case-insensitive lookup) and makes the map immutable. */
    public PushResponse {
        Objects.requireNonNull(headers, "headers");
        headers = headers.entrySet().stream()
            .collect(Collectors.toUnmodifiableMap(
                entry -> entry.getKey().toLowerCase(Locale.ROOT),
                Map.Entry::getValue,
                (existing, replacement) -> replacement));
    }

    /**
     * A response with the given status code and no headers.
     *
     * @param statusCode the HTTP status code
     * @return the response
     */
    public static PushResponse of(int statusCode) {
        return new PushResponse(statusCode, Map.of());
    }

    /**
     * Case-insensitive header lookup.
     *
     * @param name the header name (any case)
     * @return the header value, if present
     */
    public Optional<String> header(String name) {
        return Optional.ofNullable(headers.get(name.toLowerCase(Locale.ROOT)));
    }
}
