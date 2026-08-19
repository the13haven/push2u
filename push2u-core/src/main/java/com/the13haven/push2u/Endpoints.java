/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import org.jspecify.annotations.Nullable;

/**
 * Push-endpoint hygiene: validation of the RFC 8030 endpoint contract and a log-safe rendering.
 *
 * <p>A push endpoint is a capability URL — its path/query is the bearer credential that lets anyone holding it send
 * messages to the subscriber (RFC 8030 §8.3, §8.5 "Logging Risk"). It must therefore never appear verbatim in logs or
 * exception messages; {@link #redact} renders the origin plus a short fingerprint instead, which is enough to correlate
 * log lines without disclosing the credential.
 */
public final class Endpoints {

    private static final String NULL_ENDPOINT = "<null endpoint>";
    private static final String OPAQUE_ENDPOINT = "<opaque endpoint>";
    private static final int FINGERPRINT_HEX_LENGTH = 16;

    private Endpoints() {}

    /**
     * Renders an endpoint safely for logs and exception messages: the origin (scheme, host, explicit port if any) plus
     * a 16-hex-character SHA-256 fingerprint of the full original URI string — e.g.
     * {@code https://fcm.googleapis.com/…#a1b2c3d4e5f60718}. The path, query and fragment (the capability part of the
     * URL) are never included; the fingerprint lets log lines about the same subscription be correlated without
     * disclosing it.
     *
     * <p><b>Nothing about the endpoint makes it throw</b>, which is what lets it run on error-handling and logging
     * paths: a {@code null} endpoint renders as {@code <null endpoint>}, and an unparseable string or a URI without
     * scheme/host renders as {@code <opaque endpoint>#} plus the fingerprint of the raw string.
     *
     * <p>One thing can still leave here, and it is about the platform rather than the argument: a runtime with no
     * {@code SHA-256} raises {@link PushCryptoException}. It is allowed to escape rather than degraded into a
     * fingerprint-less rendering, because the condition it reports is a runtime that is not a Java SE implementation —
     * on which every other cryptographic step of a send has already failed for the same reason — and swallowing it here
     * would buy a promise that holds only where nothing else in this library does.
     *
     * @param endpoint the endpoint URL to redact, possibly {@code null}
     * @return a representation containing only the origin and a fingerprint, never the full URL
     * @throws PushCryptoException if the platform has no {@code SHA-256}, which no conforming Java runtime can be
     */
    public static String redact(@Nullable String endpoint) {
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
     * Validates the protocol half of the {@link Subscription} endpoint contract: an absolute {@code https} URL with a
     * host (RFC 8030 requires TLS between the application server and the push service; there is no loopback exception).
     * Public so consumers can enforce the same contract at their own API boundary — e.g. reject a subscription
     * registration before persisting it — instead of storing data every later send will refuse. Deliberately not
     * checked here: the 2048-character length bound {@link Subscription}'s constructor applies, which is a resource
     * control rather than a protocol rule and needs no helper — it is a plain length comparison.
     *
     * <p>Violations throw {@link IllegalArgumentException} whose message never contains the raw URL — only the
     * {@link #redact}ed form (origin + fingerprint, never the capability path/query), if the URI parsed at all.
     *
     * @param endpoint the endpoint URL to validate
     * @throws IllegalArgumentException if the endpoint is not an absolute https URL with a host
     * @throws PushCryptoException if the platform has no {@code SHA-256}, which no conforming Java runtime can be — the
     *     refusal above renders the endpoint with {@link #redact} to say which one it refused, so it inherits that
     *     method's one platform condition
     */
    // PreserveStackTrace: the cause is dropped on purpose — URISyntaxException's message embeds the
    // raw endpoint, which is a capability URL and must not travel in an exception the caller logs.
    @SuppressWarnings("PMD.PreserveStackTrace")
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
        if (!uri.isAbsolute() || host == null || host.isEmpty() || !"https".equalsIgnoreCase(scheme)) {
            throw new IllegalArgumentException(
                    "subscription endpoint must be an absolute https URL (RFC 8030): " + redact(endpoint));
        }
    }

    /** First 16 lowercase hex characters of SHA-256 over the raw endpoint string. */
    private static String fingerprint(String endpoint) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // The fingerprint hashes with the platform's own SHA-256 whatever provider this library
            // is configured with, deliberately: it is diagnostics rather than protocol. So a failure
            // here does not mean a misconfigured provider — it means a runtime that is not a Java SE
            // implementation, since every one of those ships SHA-256. That is an unusable
            // cryptographic substrate, and an unusable substrate is worth one channel and not two,
            // which is why it leaves as the same type a missing AES/GCM or HmacSHA256 does.
            throw new PushCryptoException("SHA-256 MessageDigest is unavailable", e);
        }
        byte[] hash = digest.digest(endpoint.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(hash).substring(0, FINGERPRINT_HEX_LENGTH);
    }
}
