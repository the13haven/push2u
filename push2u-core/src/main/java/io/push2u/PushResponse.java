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
 * @param statusCode the HTTP status code; never negative
 * @param headers    the response headers (keys lower-cased); the pipeline reads {@code Retry-After}
 * @throws IllegalArgumentException if {@code statusCode} is negative
 */
public record PushResponse(int statusCode, Map<String, String> headers) {

    /**
     * Rejects a negative status code, then lower-cases the header keys (for case-insensitive
     * lookup) and makes the map immutable.
     *
     * <p>{@link PushHttpClient} is a public seam, so a custom transport could hand back a sentinel
     * such as {@code -1} for "no response". It is refused here, at the boundary that produced it,
     * rather than allowed to travel into the {@link PushResult} the sender returns — where the same
     * invariant holds and the offending transport would no longer be identifiable.
     */
    public PushResponse {
        Objects.requireNonNull(headers, "headers");
        if (statusCode < 0) {
            throw new IllegalArgumentException("statusCode must not be negative, was " + statusCode);
        }
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
