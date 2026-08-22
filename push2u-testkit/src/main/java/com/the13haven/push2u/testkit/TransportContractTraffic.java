/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The traffic the transport contract hands its subject — synthetic headers and bodies in the shape of a real send — and
 * the verification of what the harness then recorded against it. Package-private machinery of
 * {@link PushHttpClientContractTest}: one class knows both what was given and how to recognise it on the wire, so the
 * two cannot drift apart.
 *
 * <p>Every value here is synthetic on purpose — nothing in the contract holds or publishes a credential, and the wire
 * observation ends inside the harness. The failure messages hold the same line the contract holds a transport to: they
 * name headers, counts, positions and statuses, and never render an endpoint, a header value or body bytes, because on
 * a real send those carry the capability URL and the VAPID token, and a contract's failure output goes to a consumer's
 * build log.
 */
final class TransportContractTraffic {

    /**
     * The per-call request header of the concurrency check. The harness echoes its value back in the response it
     * writes, which is what lets the check tie every response a caller received to the request that caller made.
     */
    static final String CORRELATION_HEADER = "X-Push2u-Contract-Call";

    /** A deliberately synthetic {@code Authorization} value, in the shape a send would carry. */
    static final String GIVEN_AUTHORIZATION =
            "vapid t=synthetic-contract-token.no-credential, k=synthetic-contract-key";

    /** The content coding a real send declares; given so the request carries the headers a push service sees. */
    static final String GIVEN_CONTENT_ENCODING = "aes128gcm";

    /** A TTL value like the one a send carries. */
    static final String GIVEN_TTL = "60";

    /** An urgency value like the one a send carries. */
    static final String GIVEN_URGENCY = "high";

    /** How many callers the concurrency check puts inside {@code post} at the same moment. */
    static final int CONCURRENT_CALLS = 6;

    /** The length of the synthetic body the single-request check compares byte for byte. */
    private static final int SYNTHETIC_BODY_BYTES = 512;

    private TransportContractTraffic() {}

    /** The headers every check hands over: the shape of a real send, every value synthetic. */
    static Map<String, String> givenHeaders() {
        return Map.of(
                "Authorization", GIVEN_AUTHORIZATION,
                "Content-Encoding", GIVEN_CONTENT_ENCODING,
                "TTL", GIVEN_TTL,
                "Urgency", GIVEN_URGENCY);
    }

    /**
     * The synthetic body of the single-request check: a fixed patterned sequence, nothing encrypted and nothing real.
     */
    static byte[] syntheticBody() {
        byte[] body = new byte[SYNTHETIC_BODY_BYTES];
        for (int index = 0; index < body.length; index++) {
            body[index] = (byte) (index * 31 + 7);
        }
        return body;
    }

    /** The correlation value one concurrent caller sends and must get back. */
    static String correlationValue(int call) {
        return "call-" + call;
    }

    /** The body one concurrent caller sends: unique bytes and a unique length per caller. */
    static byte[] concurrentBody(int call) {
        byte[] body = new byte[SYNTHETIC_BODY_BYTES + call];
        for (int index = 0; index < body.length; index++) {
            body[index] = (byte) (call * 131 + index * 31 + 7);
        }
        return body;
    }

    /** One caller's request headers: the shared given set plus its own correlation value. */
    static Map<String, String> concurrentHeaders(int call) {
        Map<String, String> headers = new LinkedHashMap<>(givenHeaders());
        headers.put(CORRELATION_HEADER, correlationValue(call));
        return headers;
    }

    /** A request header the caller gave must arrive, with the value the caller gave. Extra headers are permitted. */
    static void requireGivenHeader(TransportContractServer.ReceivedRequest request, String name, String value) {
        Optional<String> observed = request.header(name);
        if (observed.isEmpty()) {
            throw new AssertionError("the request that arrived is missing the " + name + " header the caller gave. "
                    + "Every header handed to post must reach the push service — the signed authorization and the "
                    + "content coding among them — while headers the transport adds of its own are permitted.");
        }
        if (!observed.get().equals(value)) {
            throw new AssertionError("the " + name + " header arrived with a value different from the one the caller "
                    + "gave. Headers must reach the push service unchanged; the values are deliberately not printed "
                    + "here — on a real send this one may carry the VAPID token.");
        }
    }

    /** Every given header must arrive with the value it was given. */
    static void requireGivenHeaders(TransportContractServer.ReceivedRequest request) {
        for (Map.Entry<String, String> given : givenHeaders().entrySet()) {
            requireGivenHeader(request, given.getKey(), given.getValue());
        }
    }

    /** The body must arrive byte for byte; the failure names lengths and the first differing position, never bytes. */
    static void requireGivenBody(byte[] given, byte[] arrived) {
        if (Arrays.equals(given, arrived)) {
            return;
        }
        String difference = given.length == arrived.length
                ? "the lengths agree at " + given.length + " bytes and the first difference is at index "
                        + Arrays.mismatch(given, arrived)
                : arrived.length + " bytes arrived where " + given.length + " were handed over";
        throw new AssertionError("the body must arrive byte for byte as it was handed to post — " + difference
                + ". A transport may frame the body either way, but must deliver exactly these bytes: an encrypted "
                + "push body altered anywhere reaches the subscriber as a message the browser cannot decrypt, with "
                + "no symptom before that.");
    }

    /** The concurrency check's server-side half: every caller's request arrived, once, intact. */
    static void requireOneRequestPerCaller(List<TransportContractServer.ReceivedRequest> received) {
        if (received.size() != CONCURRENT_CALLS) {
            throw new AssertionError("the server must see exactly one request per caller — " + CONCURRENT_CALLS
                    + " here — and it saw " + received.size() + ".");
        }
        Set<String> seen = new HashSet<>();
        for (TransportContractServer.ReceivedRequest request : received) {
            int call = callOf(request.header(CORRELATION_HEADER).orElse(""));
            if (call < 0 || !seen.add(correlationValue(call))) {
                throw new AssertionError("every request must carry exactly one caller's correlation header, each "
                        + "arriving exactly once; one request arrived without one, or with one that had already "
                        + "arrived. A transport reusing a header map between calls sends one caller's headers on "
                        + "another's request.");
            }
            requireGivenBody(concurrentBody(call), request.body());
            requireGivenHeaders(request);
        }
    }

    /** The caller index a correlation value names, or {@code -1} for a value no caller sent. */
    private static int callOf(String correlation) {
        for (int call = 0; call < CONCURRENT_CALLS; call++) {
            if (correlationValue(call).equals(correlation)) {
                return call;
            }
        }
        return -1;
    }
}
