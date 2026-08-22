/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

import com.the13haven.push2u.Endpoints;

/**
 * One POST as {@link ScriptedPushHttpClient} recorded it: the endpoint, an immutable copy of the request headers, and
 * the encrypted body's length in bytes.
 *
 * <p><b>The body itself is deliberately not kept.</b> A test holding the ciphertext will eventually decrypt it, and
 * asserting on a record this library produced means either re-implementing the encryption or comparing against whatever
 * the code currently emits — a tautology either way, and neither is the consumer's test to write. The length is kept
 * because it is what a consumer's own contract can reach ({@code PushOutcome.PayloadRejected} speaks the same
 * {@code payloadBytes} vocabulary), and it is why the component is {@code bodyBytes} rather than a spelling of its own.
 *
 * <p>{@link #toString()} is written by hand because a recorded push carries two values that must not reach a CI log
 * through a failed assertion's message: the endpoint is a capability URL — whoever holds it can message the subscriber
 * — and the {@code Authorization} header carries a VAPID token. The rendering therefore passes the endpoint through the
 * same redaction the library itself logs with, which keeps the origin (so a failure still says which service was
 * called) and replaces the capability part, and prints header <em>names</em> without their values. The accessors are
 * unredacted — an assertion may inspect everything; only the printed form is constrained.
 *
 * @param endpoint the endpoint the body was POSTed to
 * @param headers an immutable copy of the request headers, exactly as the sender passed them
 * @param bodyBytes the encrypted body's length in bytes
 */
public record SentPush(URI endpoint, Map<String, String> headers, int bodyBytes) {

    /**
     * Copies the headers into an immutable map, so a recorded call cannot change under an assertion that reads it while
     * other sends are still running.
     *
     * @throws IllegalArgumentException if {@code bodyBytes} is negative
     * @throws NullPointerException if {@code endpoint} or {@code headers} is {@code null}
     */
    public SentPush {
        Objects.requireNonNull(endpoint, "endpoint");
        Objects.requireNonNull(headers, "headers");
        if (bodyBytes < 0) {
            throw new IllegalArgumentException("bodyBytes must not be negative, was " + bodyBytes);
        }
        headers = Map.copyOf(headers);
    }

    /**
     * A rendering safe for a test failure message: the endpoint redacted to origin plus fingerprint, header names
     * without their values, and the body length.
     *
     * @return a representation carrying neither the capability URL nor any header value
     */
    @Override
    public String toString() {
        return "SentPush[endpoint=" + Endpoints.redact(endpoint.toString())
                + ", headers=" + new TreeMap<>(headers).keySet()
                + ", bodyBytes=" + bodyBytes + "]";
    }
}
