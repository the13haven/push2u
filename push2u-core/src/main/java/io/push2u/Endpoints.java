package io.push2u;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Push-endpoint hygiene: validation of the RFC 8030 endpoint contract and a log-safe rendering.
 *
 * <p>A push endpoint is a capability URL — its path/query is the bearer credential that lets
 * anyone holding it send messages to the subscriber (RFC 8030 §8.3, §8.5 "Logging Risk"). It must
 * therefore never appear verbatim in logs or exception messages; {@link #redact} renders the
 * origin plus a short fingerprint instead, which is enough to correlate log lines without
 * disclosing the credential.
 */
public final class Endpoints {

    private static final String NULL_ENDPOINT = "<null endpoint>";
    private static final String OPAQUE_ENDPOINT = "<opaque endpoint>";
    private static final int FINGERPRINT_HEX_LENGTH = 16;

    /**
     * When set to {@code TRUE}, {@link #requireSecure} accepts {@code http} endpoints on
     * the current thread. Test-only; see {@link #allowPlaintextEndpointsForTests()}.
     */
    private static final ThreadLocal<Boolean> PLAINTEXT_ALLOWED = ThreadLocal.withInitial(() -> Boolean.FALSE);

    private Endpoints() {
    }

    /**
     * Renders an endpoint safely for logs and exception messages: the origin (scheme, host,
     * explicit port if any) plus a 16-hex-character SHA-256 fingerprint of the full original URI
     * string — e.g. {@code https://fcm.googleapis.com/…#a1b2c3d4e5f60718}. The path, query and
     * fragment (the capability part of the URL) are never included; the fingerprint lets log lines
     * about the same subscription be correlated without disclosing it.
     *
     * <p>Never throws: it runs on error-handling and logging paths. A {@code null} endpoint
     * renders as {@code <null endpoint>}; an unparseable string or a URI without scheme/host
     * renders as {@code <opaque endpoint>#} plus the fingerprint of the raw string.
     *
     * @param endpoint the endpoint URL to redact, possibly {@code null}
     * @return a representation containing only the origin and a fingerprint, never the full URL
     */
    public static String redact(String endpoint) {
        if (endpoint == null) {
            return NULL_ENDPOINT;
        }
        String fingerprint = fingerprint(endpoint);
        URI uri;
        try {
            uri = new URI(endpoint);
        } catch (URISyntaxException e) {
            return OPAQUE_ENDPOINT + "#" + fingerprint;
        }
        String scheme = uri.getScheme();
        String host = uri.getHost();
        if (scheme == null || host == null || host.isEmpty()) {
            return OPAQUE_ENDPOINT + "#" + fingerprint;
        }
        int port = uri.getPort();
        String origin = port == -1 ? scheme + "://" + host : scheme + "://" + host + ":" + port;
        return origin + "/…#" + fingerprint;
    }

    /**
     * Validates the {@link Subscription} endpoint contract: an absolute {@code https} URL with a
     * host (RFC 8030 requires TLS between the application server and the push service; there is no
     * loopback exception). Public so consumers can enforce the same contract at their own API
     * boundary — e.g. reject a subscription registration before persisting it — instead of storing
     * data every later send will refuse.
     *
     * <p>Violations throw {@link IllegalArgumentException} whose message never contains the raw
     * URL — only the {@link #redact}ed form (origin + fingerprint, never the capability
     * path/query), if the URI parsed at all.
     *
     * @param endpoint the endpoint URL to validate
     * @throws IllegalArgumentException if the endpoint is not an absolute https URL with a host
     */
    public static void requireSecure(String endpoint) {
        URI uri;
        try {
            uri = new URI(endpoint);
        } catch (URISyntaxException e) {
            // No cause: URISyntaxException's message carries the raw input, which must not leak.
            throw new IllegalArgumentException("subscription endpoint is not a valid URI");
        }
        String scheme = uri.getScheme();
        // java.net.URI returns getHost() == null for authorities that are not valid RFC 2396
        // server-based hostnames — e.g. an underscore in a label ("https://exa_mple.com/x").
        // Rejecting those here is intentional: underscores are invalid in hostnames (RFC 1123)
        // and no real push service uses them, so the null-host check doubles as syntax hygiene.
        String host = uri.getHost();
        boolean secureScheme = "https".equalsIgnoreCase(scheme)
            || (PLAINTEXT_ALLOWED.get() && "http".equalsIgnoreCase(scheme));
        if (!uri.isAbsolute() || host == null || host.isEmpty() || !secureScheme) {
            throw new IllegalArgumentException(
                "subscription endpoint must be an absolute https URL (RFC 8030): " + redact(endpoint));
        }
    }

    /**
     * Lets {@link #requireSecure} accept {@code http} endpoints on the current thread
     * until the returned handle is closed (try-with-resources; the previous state is restored on
     * {@code close()}, so nested use is safe).
     *
     * <p>Package-private on purpose: it exists solely for this library's own tests, which run an
     * in-process HTTP receiver on {@code http://127.0.0.1}. The public {@link Subscription}
     * contract stays strictly https — there is no plaintext dev mode for consumers.
     *
     * @return a handle whose {@code close()} restores the previous per-thread setting
     */
    static AutoCloseable allowPlaintextEndpointsForTests() {
        Boolean previous = PLAINTEXT_ALLOWED.get();
        PLAINTEXT_ALLOWED.set(Boolean.TRUE);
        return () -> PLAINTEXT_ALLOWED.set(previous);
    }

    /** First 16 lowercase hex characters of SHA-256 over the raw endpoint string. */
    private static String fingerprint(String endpoint) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // Every JVM ships SHA-256; if it is missing the runtime is broken beyond this library.
            throw new IllegalStateException("SHA-256 MessageDigest is unavailable", e);
        }
        byte[] hash = digest.digest(endpoint.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(hash).substring(0, FINGERPRINT_HEX_LENGTH);
    }
}
