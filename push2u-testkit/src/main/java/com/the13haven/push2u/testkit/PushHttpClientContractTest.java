/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;

import org.junit.jupiter.api.Test;

import com.the13haven.push2u.PushDeliveryException;
import com.the13haven.push2u.PushHttpClient;
import com.the13haven.push2u.PushResponse;

/**
 * The conformance contract every {@link PushHttpClient} must satisfy, checked over a real TLS exchange: an HTTP error
 * status is an answer and never an exception, the response headers reach the caller, exactly one request arrives per
 * {@link PushHttpClient#post} call and it is byte for byte the request that was handed over, a redirect is returned
 * rather than followed, a refused connection and a request read but never answered each surface as
 * {@link PushDeliveryException}, and concurrent calls each receive the response to their own request. These are the
 * obligations that pass every unit test and fail in production — a transport that quietly starts following redirects on
 * a dependency bump has no other test anywhere that notices.
 *
 * <p>An implementation extends this class and supplies its subject through the one abstract method, which receives the
 * {@link SSLContext} and {@link X509TrustManager} that trust the contract's own throwaway server certificate —
 * generated once per test JVM, never committed anywhere and never shipped. Both halves are handed over because the
 * common HTTP stacks want different ones: the JDK's {@code HttpClient} and Apache HttpClient 5 take the context, while
 * OkHttp's supported configuration call takes the socket factory <em>and</em> the trust manager beside it. Use
 * whichever half your stack needs and ignore the other.
 *
 * <pre>{@code
 * class MyPushHttpClientContractTest extends PushHttpClientContractTest {
 *     @Override
 *     protected PushHttpClient transport(SSLContext sslContext, X509TrustManager trustManager) {
 *         return new MyTransport(HttpClient.newBuilder()
 *                 .sslContext(sslContext)
 *                 .followRedirects(HttpClient.Redirect.NEVER)
 *                 .build());
 *     }
 * }
 * }</pre>
 *
 * <p><b>The contract invents no lifecycle for the transport.</b> {@link #transport} is called once per test method and
 * nothing here ever closes what it returns, because the seam itself has none: a sender takes a transport when it is
 * built, holds it for as long as it exists, and closes it never. A subject built over a stack that does hold resources
 * — an OkHttp client, a pooled connection manager — keeps the reference in its own factory method and closes it in its
 * own {@code @AfterEach}; that is ordinary JUnit and needs nothing from this kit.
 *
 * <p><b>What is deliberately not checked.</b> That the response body goes unmaterialised: {@link PushResponse} has no
 * slot a buffered body could reach the caller through, so structurally the obligation is already kept as far as the
 * seam can tell, and no observation from outside distinguishes draining a stream from holding it in memory — that
 * obligation stays a written one on the seam. Timeouts, retry policies and schedules, connection pooling and
 * persistent-connection behaviour: the seam promises none of them. How many HTTP requests one {@code post} call
 * produces is not on that list — the seam promises exactly one, and it is checked. And every check that reaches the
 * network carries a budget whose expiry <em>aborts</em> the check rather than failing it: the seam sets no latency
 * requirement, so a subject still silent when the budget runs out may be hung or merely slow on a loaded machine, and
 * nothing outside can tell those apart — the budget exists so that a hung subject ends the check instead of hanging the
 * build it was added to.
 *
 * <p><b>A contract test protects against error, not against deliberate circumvention.</b> A transport built to detect a
 * loopback harness and behave differently is bound by the sentences in {@link PushHttpClient}'s own contract, not by
 * this class.
 */
public abstract class PushHttpClientContractTest {

    /** For subclasses: the kit is extended, never instantiated on its own. */
    protected PushHttpClientContractTest() {}

    /**
     * The transport under test, configured to trust the contract's server certificate. Called once per test method; the
     * contract never closes what it returns, since the seam carries no lifecycle for it to exercise — a subject whose
     * stack holds resources keeps the reference in this method and releases it in its own {@code @AfterEach}.
     *
     * @param sslContext trusts exactly the contract's per-JVM server certificate — what the JDK's client and Apache
     *     HttpClient 5 take
     * @param trustManager the same trust, as the manager OkHttp's configuration call wants beside the socket factory
     * @return a fully configured {@link PushHttpClient} speaking to whatever endpoint it is handed
     */
    protected abstract PushHttpClient transport(SSLContext sslContext, X509TrustManager trustManager);

    /**
     * An HTTP error status is an answer, not an exception. The harness answers {@code 410 Gone} and the caller must
     * receive a {@link PushResponse} carrying {@code 410}: a transport that throws on an error status turns a
     * subscription the sender classifies as expired into an unanswered exchange the caller will keep repeating for the
     * life of the stored row.
     */
    // UnitTestShouldIncludeAssert: checked by hand and thrown, rather than through an assertion
    // library, because an assertion prints its actual value — here a response or an exception a
    // defective transport may have built out of anything at all — and this contract's failures go
    // to a consumer's build log. The messages below name what did not match and no values.
    @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
    @Test
    void anErrorStatusIsAnAnswerNotATransportFailure() throws Exception {
        try (TransportContractServer server = TransportContractServer.answeringWith(
                request -> Optional.of(TransportContractHttp.response(410, Map.of())))) {
            PushHttpClient subject = subject();

            PushResponse response = PostAttempt.one(
                            subject,
                            server.endpoint("/wpush/contract/status"),
                            TransportContractTraffic.givenHeaders(),
                            TransportContractTraffic.syntheticBody())
                    .response("the 410 the push service answered");

            if (response.statusCode() != 410) {
                throw new AssertionError("post must hand back the status the push service answered — a 410 here — "
                        + "unchanged, for the sender to classify. The response carried " + response.statusCode()
                        + " instead.");
            }
        }
    }

    /**
     * The response headers reach the caller, {@code Retry-After} in particular. The library performs exactly one POST
     * and hands the repeat decision to the caller together with the hint the push service sent; a transport that
     * returns the status and drops the headers empties that hint silently, for every {@code 429} a deployment ever
     * receives. A second, unhinted header is checked beside it so that passing takes forwarding the headers rather than
     * special-casing one name.
     */
    // UnitTestShouldIncludeAssert: see the first check — checked by hand so that no
    // transport-supplied value is ever rendered into a consumer's build log.
    @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
    @Test
    void theResponseHeadersReachTheCaller() throws Exception {
        try (TransportContractServer server =
                TransportContractServer.answeringWith(request -> Optional.of(TransportContractHttp.response(
                        429, Map.of("Retry-After", "30", "X-Push2u-Contract-Probe", "reached-the-caller"))))) {
            PushHttpClient subject = subject();

            PushResponse response = PostAttempt.one(
                            subject,
                            server.endpoint("/wpush/contract/headers"),
                            TransportContractTraffic.givenHeaders(),
                            TransportContractTraffic.syntheticBody())
                    .response("the 429 with its headers");

            requireEchoedHeader(response, "Retry-After", "30");
            requireEchoedHeader(response, "X-Push2u-Contract-Probe", "reached-the-caller");
        }
    }

    /**
     * Exactly one request arrives, and it is the one that was handed over. Two obligations, one observation of the
     * wire. <em>One request</em>: a transport neither classifies nor repeats — a transport retrying inside {@code post}
     * delivers the notification twice, and the sender it reports one outcome to never learns of the second. <em>That
     * request</em>: a POST, at the URI it was given — observed through the request target and the {@code Host} header,
     * which is what a server can see of it — carrying the headers it was given and the body it was given, the body
     * compared byte for byte rather than by length: a transport that replaced every byte with a zero of the same length
     * passes a length check and hands every subscriber a message their browser cannot decrypt. The bytes are synthetic,
     * made by this contract, and the comparison happens inside the harness and ends there. Headers the transport adds
     * of its own are permitted; the exact set is never asserted.
     */
    // UnitTestShouldIncludeAssert: see the first check. Here in particular, the values compared
    // include the request headers — which on a real send carry the VAPID token — so the failures
    // name the header or the byte position that did not match and never the value.
    @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
    @Test
    void exactlyOneRequestArrivesAndItIsTheRequestThatWasHandedOver() throws Exception {
        try (TransportContractServer server = TransportContractServer.answeringWith(
                request -> Optional.of(TransportContractHttp.response(201, Map.of())))) {
            PushHttpClient subject = subject();
            URI endpoint = server.endpoint("/wpush/contract/one-request?probe=echo");
            byte[] body = TransportContractTraffic.syntheticBody();

            PostAttempt.one(subject, endpoint, TransportContractTraffic.givenHeaders(), body)
                    .response("the 201 the push service answered");

            List<TransportContractServer.ReceivedRequest> received = server.received();
            if (received.size() != 1) {
                throw new AssertionError("exactly one request must arrive per post call — the seam says a transport "
                        + "neither classifies nor repeats, and a repeat delivers the notification twice while the "
                        + "sender learns of one outcome. The server saw " + received.size() + " requests.");
            }
            TransportContractServer.ReceivedRequest request = received.get(0);
            if (!"POST".equals(request.method())) {
                throw new AssertionError("the request must be a POST, and it arrived as " + request.method() + ".");
            }
            requireGivenTarget(request, endpoint);
            TransportContractTraffic.requireGivenHeaders(request);
            // Compared against a fresh generation, never against the array handed to post: the
            // expected bytes and the sent bytes must have separate lives, or a transport that
            // rewrites the caller's array in place and sends the rewrite is compared with itself
            // and passes while delivering the right number of wrong bytes.
            TransportContractTraffic.requireGivenBody(TransportContractTraffic.syntheticBody(), request.body());
        }
    }

    /**
     * A redirect is not followed. The harness answers a {@code 307} whose {@code Location} names a second listener on
     * another loopback port — a different port is a different origin, and the claim is about an origin the endpoint
     * policy never assessed, not about a path — and both halves are asserted: the caller was handed the {@code 3xx}
     * itself, and the second listener accepted no connection at all. The certificate covers both listeners, so a
     * transport that does follow arrives at the second one with no trust error to stop it, and its silence means what
     * this check needs it to mean. A followed redirect re-sends the encrypted body and the request headers to a host
     * nobody vetted and reports that host's answer as the delivery result, which is the one gap a URI-level endpoint
     * policy cannot close itself.
     */
    // UnitTestShouldIncludeAssert: see the first check — checked by hand, and the messages name
    // statuses and connection counts, never the endpoint or a header value.
    @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
    @Test
    void aRedirectIsNotFollowed() throws Exception {
        try (TransportContractServer redirectTarget = TransportContractServer.answeringWith(
                request -> Optional.of(TransportContractHttp.response(201, Map.of())))) {
            URI stolen = redirectTarget.endpoint("/wpush/contract/stolen");
            try (TransportContractServer server = TransportContractServer.answeringWith(request ->
                    Optional.of(TransportContractHttp.response(307, Map.of("Location", stolen.toString()))))) {
                PushHttpClient subject = subject();

                PushResponse response = PostAttempt.one(
                                subject,
                                server.endpoint("/wpush/contract/redirect"),
                                TransportContractTraffic.givenHeaders(),
                                TransportContractTraffic.syntheticBody())
                        .response("the 307 itself");

                if (response.statusCode() != 307) {
                    throw new AssertionError("post must hand back the redirect status itself — the 307 the push "
                            + "service answered — for the sender to classify; it answered " + response.statusCode()
                            + " instead, which means the transport followed the redirect and reported another "
                            + "origin's answer as the delivery result. A followed redirect re-sends the encrypted "
                            + "body and the request headers to a host the endpoint policy never assessed. Turn "
                            + "redirect following off in the stack this transport wraps.");
                }
                int connections = redirectTarget.acceptedConnections();
                if (connections != 0) {
                    throw new AssertionError("nothing may be sent to the origin a redirect names — the endpoint "
                            + "policy assessed the URI post was handed and no other — yet the redirect target "
                            + "accepted " + connections + " connection(s). Turn redirect following off in the stack "
                            + "this transport wraps.");
                }
            }
        }
    }

    /**
     * A refused connection is a {@link PushDeliveryException}: a port nothing is listening on. This is the transport
     * failure that happens before a byte of the request is written, kept separate from the unanswered request below — a
     * caller's exposure differs between them, and a transport can honestly report this one while swallowing the other.
     */
    // UnitTestShouldIncludeAssert: see the first check.
    @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
    @Test
    void aRefusedConnectionIsADeliveryFailure() throws Exception {
        URI unreachable = URI.create("https://"
                + TransportContractServer.loopback().getHostAddress() + ":" + closedPort()
                + "/wpush/contract/refused");
        PushHttpClient subject = subject();

        PostAttempt.one(
                        subject,
                        unreachable,
                        TransportContractTraffic.givenHeaders(),
                        TransportContractTraffic.syntheticBody())
                .deliveryFailure("a connection nothing accepted");
    }

    /**
     * A request sent with nothing answering it is a {@link PushDeliveryException}. The harness completes the TLS
     * handshake, reads the whole request, and closes the connection without writing a status line — the case the
     * sender's indeterminate outcome exists for: the POST went out and no answer came, so whether the push service
     * received the message is unknown and only the transport's exception can say so. A transport that swallows this and
     * fabricates a response makes an unanswered send indistinguishable from an answered one.
     */
    // UnitTestShouldIncludeAssert: see the first check.
    @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
    @Test
    void anUnansweredRequestIsADeliveryFailure() throws Exception {
        try (TransportContractServer server = TransportContractServer.answeringWith(request -> Optional.empty())) {
            PushHttpClient subject = subject();

            PostAttempt.one(
                            subject,
                            server.endpoint("/wpush/contract/unanswered"),
                            TransportContractTraffic.givenHeaders(),
                            TransportContractTraffic.syntheticBody())
                    .deliveryFailure("a request that was read in full and never answered");
        }
    }

    /**
     * A concurrency smoke check with teeth. Every caller sends a unique correlation header; the harness echoes it back
     * in its response and records what it received; and the check asserts that every caller got the response to its own
     * request, that the server saw exactly as many requests as there were callers, and that no request arrived carrying
     * another caller's body or missing the headers its caller gave. A transport keeping per-request state in a field —
     * a builder, a buffer, a header map reused between calls — hands one caller another's response here, and in
     * production that is an accepted status credited to a send that was refused.
     *
     * <p>It is still a smoke check: no schedule is forced, so a passing run proves nothing. What earns it its place is
     * having no false positives — a thread-safe transport cannot fail it however the calls interleave.
     */
    // UnitTestShouldIncludeAssert: see the first check — counted, matched and thrown by hand; the
    // failures report caller indices and counts, never a header value or an endpoint.
    @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
    @Test
    void concurrentPostsEachReceiveTheirOwnResponse() throws Exception {
        try (TransportContractServer server =
                TransportContractServer.answeringWith(request -> Optional.of(TransportContractHttp.response(
                        201,
                        Map.of(
                                TransportContractTraffic.CORRELATION_HEADER,
                                request.header(TransportContractTraffic.CORRELATION_HEADER)
                                        .orElse("")))))) {
            PushHttpClient subject = subject();
            URI endpoint = server.endpoint("/wpush/contract/concurrent");
            int calls = TransportContractTraffic.CONCURRENT_CALLS;
            List<Map<String, String>> headers = new ArrayList<>(calls);
            List<byte[]> bodies = new ArrayList<>(calls);
            for (int call = 0; call < calls; call++) {
                headers.add(TransportContractTraffic.concurrentHeaders(call));
                bodies.add(TransportContractTraffic.concurrentBody(call));
            }

            List<PostAttempt> attempts = PostAttempt.concurrently(subject, endpoint, headers, bodies);

            for (int call = 0; call < calls; call++) {
                PushResponse answer = attempts.get(call).response("the response to its own request, under concurrency");
                Optional<String> echoed = answer.header(TransportContractTraffic.CORRELATION_HEADER);
                if (echoed.isEmpty() || !echoed.get().equals(TransportContractTraffic.correlationValue(call))) {
                    throw new AssertionError("every caller must receive the response to its own request, and caller "
                            + call + " did not: the correlation header echoed back to it "
                            + (echoed.isEmpty() ? "is missing" : "belongs to another call")
                            + ". A transport keeping per-request state in a field hands one caller another's "
                            + "response under concurrency, and in production that is an accepted status credited to "
                            + "a send that was refused.");
                }
            }
            TransportContractTraffic.requireOneRequestPerCaller(server.received());
        }
    }

    /** The subject, built exactly once per test method with the harness's trust material. */
    private PushHttpClient subject() {
        return transport(TransportContractTls.clientContext(), TransportContractTls.clientTrustManager());
    }

    /** A port nothing is listening on: bound to get a free one from the OS, then released. */
    private static int closedPort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0, 1, TransportContractServer.loopback())) {
            return socket.getLocalPort();
        }
    }

    /** A response header the harness set must reach the caller with the value the harness set. */
    private static void requireEchoedHeader(PushResponse response, String name, String value) {
        Optional<String> observed = response.header(name);
        if (observed.isEmpty()) {
            throw new AssertionError("the response headers must reach the caller, and the " + name + " header the "
                    + "push service sent did not. The sender reads the repeat hint out of exactly this map, so a "
                    + "transport that returns the status and drops the headers empties that hint silently.");
        }
        if (!observed.get().equals(value)) {
            throw new AssertionError("the " + name + " header reached the caller with a value different from the one "
                    + "the push service sent. Headers must be forwarded unchanged; the values are deliberately not "
                    + "printed here.");
        }
    }

    /**
     * The request target and {@code Host} header must name the URI the call was handed — what a server can see of it.
     */
    private static void requireGivenTarget(TransportContractServer.ReceivedRequest request, URI endpoint) {
        String path = endpoint.getRawPath();
        String query = endpoint.getRawQuery();
        String expectedTarget = query == null ? path : path + "?" + query;
        if (!expectedTarget.equals(request.target())) {
            throw new AssertionError("the request must go to the URI post was handed: the request target that "
                    + "arrived differs from the path and query of that URI. The endpoint policy assessed exactly "
                    + "that URI, so a request target of the transport's own invention was never vetted. The values "
                    + "are deliberately not printed here: on a real send the target is the capability part of the "
                    + "endpoint.");
        }
        Optional<String> host = request.header("Host");
        if (host.isEmpty() || !host.get().equals(endpoint.getRawAuthority())) {
            throw new AssertionError("the request must go to the URI post was handed: the Host header that arrived "
                    + (host.isEmpty() ? "is missing" : "differs from that URI's authority") + ".");
        }
    }
}
