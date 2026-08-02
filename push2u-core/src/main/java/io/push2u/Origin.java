package io.push2u;

import java.net.IDN;
import java.net.URI;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Serializes the origin of a push endpoint for the VAPID {@code aud} claim. RFC 8292 §2 requires {@code aud} to be the
 * origin of the push resource. RFC 6454 §4 computes that origin with the scheme and host lowercased, and §6.1 pins down
 * its Unicode serialization: the scheme, {@code "://"}, the host with each label converted to Unicode (IDNA A-label →
 * U-label), and the port only when it differs from the scheme's default. {@link java.net.URI} performs none of that
 * normalization — it preserves the scheme/host case and an explicit default port verbatim — so a push service comparing
 * {@code aud} against its canonical origin would reject an otherwise valid JWT.
 */
final class Origin {

    /**
     * An IPv4 dotted-quad, which must bypass IDNA: RFC 6454 §6.1 applies the ToUnicode conversion only to registered
     * names, and RFC 5890 excludes address literals from IDNA entirely. The pattern is deliberately loose about octet
     * ranges — anything {@link java.net.URI} accepted as a host and that matches this shape is an address literal for
     * our purposes, not a registered name.
     */
    private static final Pattern IPV4_LITERAL = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");

    private Origin() {}

    /**
     * The Unicode serialization (RFC 6454 §6.1) of the endpoint's origin, for use as the VAPID {@code aud} claim (RFC
     * 8292 §2).
     *
     * @param endpoint the push endpoint URI
     * @return the serialized origin, e.g. {@code https://push.example} or {@code https://push.example:8443}
     * @throws IllegalArgumentException if the URI has no scheme or host; the message contains only the
     *     {@link Endpoints#redact}ed endpoint, never the raw capability URL
     */
    static String serialize(URI endpoint) {
        String scheme = endpoint.getScheme();
        String host = endpoint.getHost();
        // Only structure is checked here — an origin needs a scheme and a host. Enforcing https
        // is Endpoints.requireSecure's job at the Subscription boundary, not this serializer's.
        if (scheme == null || host == null || host.isEmpty()) {
            throw new IllegalArgumentException(
                    "subscription endpoint URI has no scheme or host: " + Endpoints.redact(endpoint.toString()));
        }
        scheme = scheme.toLowerCase(Locale.ROOT);
        host = unicodeHost(host);
        int port = endpoint.getPort();
        boolean defaultPort =
                port == -1 || (port == 443 && "https".equals(scheme)) || (port == 80 && "http".equals(scheme));
        return defaultPort ? scheme + "://" + host : scheme + "://" + host + ":" + port;
    }

    /** The host with A-labels converted to U-labels (RFC 6454 §6.1 step 4), lowercased per §4. */
    private static String unicodeHost(String host) {
        // IDN.toUnicode does not lowercase: it returns non-A-label hosts verbatim ("PUSH.EXAMPLE"
        // stays "PUSH.EXAMPLE") and preserves the case of the ASCII part of a decoded label
        // ("XN--BCHER-KVA" becomes "BüCHER"), so the RFC 6454 §4 lowercase step is ours to do.
        String lowered = host.toLowerCase(Locale.ROOT);
        if (lowered.startsWith("[") || IPV4_LITERAL.matcher(lowered).matches()) {
            // Address literals are not registered names, so IDNA does not apply (RFC 5890 §2.3.2.1).
            // The current java.net.IDN happens to pass them through unchanged, but that is an
            // implementation detail, not a contract — bypass it explicitly rather than rely on it.
            return lowered;
        }
        try {
            return IDN.toUnicode(lowered);
        } catch (RuntimeException e) {
            // IDN.toUnicode is documented to return its input unmodified on error, but historically
            // threw unchecked exceptions on malformed A-labels (JDK-8023881). The aud claim must
            // not be the reason a send fails, so fall back to the plain lowercase host — for the
            // all-ASCII hosts real push services use, that is already the correct serialization.
            return lowered;
        }
    }
}
