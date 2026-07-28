package io.push2u;

import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * The raw HTTP response from a POST: the status code, the response headers, and the body. Header
 * names are stored and looked up case-insensitively, as HTTP requires.
 *
 * <p>A {@link PushHttpClient} returns this; the {@link PushSender} reads the status and
 * {@code Retry-After} (it ignores the body), while a remote signer reads the body.
 *
 * @param statusCode the HTTP status code
 * @param headers    the response headers (keys lower-cased); the pipeline reads {@code Retry-After}
 * @param body       the response body decoded as UTF-8 (empty for a push send; JSON for a signer call)
 */
public record PushResponse(int statusCode, Map<String, String> headers, String body) {

    /** Lower-cases the header keys (for case-insensitive lookup) and makes the map immutable. */
    public PushResponse {
        Objects.requireNonNull(headers, "headers");
        Objects.requireNonNull(body, "body");
        headers = headers.entrySet().stream()
            .collect(Collectors.toUnmodifiableMap(
                entry -> entry.getKey().toLowerCase(Locale.ROOT),
                Map.Entry::getValue,
                (existing, replacement) -> replacement));
    }

    /**
     * A response with the given status code, no headers, and an empty body.
     *
     * @param statusCode the HTTP status code
     * @return the response
     */
    public static PushResponse of(int statusCode) {
        return new PushResponse(statusCode, Map.of(), "");
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
