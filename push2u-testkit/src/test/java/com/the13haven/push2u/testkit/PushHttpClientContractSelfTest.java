/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.function.BiFunction;
import java.util.function.Function;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.opentest4j.TestAbortedException;

import com.the13haven.push2u.JdkPushHttpClient;
import com.the13haven.push2u.PushDeliveryException;
import com.the13haven.push2u.PushHttpClient;
import com.the13haven.push2u.PushResponse;

/**
 * The kit checking itself. {@link PushHttpClientContractTest} is published so that a transport implementation finds out
 * it follows redirects, swallows failures or crosses responses under concurrency before production does — which is
 * worth exactly as much as the contract's ability to fail. So beside one conforming subject that passes everything,
 * every check is run against a transport that breaks precisely what that check is about.
 *
 * <p>The redirect subject carries the most weight: it is the stated precondition for deleting this library's own
 * redirect test in the core. Without a redirect-following transport seen failing here, the only evidence that the
 * harness can detect a followed redirect would be that the one transport it is pointed at does not follow them — which
 * is evidence of nothing, since a harness whose redirect never reaches the client passes every subject including the
 * unsafe ones it exists to fail.
 *
 * <p>The failure messages are asserted on by shape, which is itself part of the contract: they name headers, counts and
 * statuses and never render an endpoint, a header value or a body — the contract's own output goes to the same build
 * log a leaked credential would have gone to, and on a real send the given headers carry the VAPID token.
 */
final class PushHttpClientContractSelfTest {

    /** A distinctive piece of the synthetic Authorization value: asserted absent from every failure message. */
    private static final String AUTHORIZATION_MARKER = "synthetic-contract-token";

    /** Drives one contract instance over a supplied transport factory. */
    private static final class Contract extends PushHttpClientContractTest {

        private final BiFunction<SSLContext, X509TrustManager, PushHttpClient> factory;

        Contract(BiFunction<SSLContext, X509TrustManager, PushHttpClient> factory) {
            this.factory = factory;
        }

        static Contract over(BiFunction<SSLContext, X509TrustManager, PushHttpClient> factory) {
            return new Contract(factory);
        }

        @Override
        protected PushHttpClient transport(SSLContext sslContext, X509TrustManager trustManager) {
            return factory.apply(sslContext, trustManager);
        }
    }

    /**
     * The library's own transport is the first subject: a contract nothing extends drifts from what the library
     * actually requires, and the drift is discovered by the first outside author who trusted it.
     */
    @Test
    void theLibrarysOwnTransportSatisfiesEveryCheck() {
        Contract contract = Contract.over((ssl, trust) -> new JdkPushHttpClient(
                HttpClient.newBuilder()
                        .sslContext(ssl)
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .build(),
                Duration.ofSeconds(20)));

        assertThatCode(contract::anErrorStatusIsAnAnswerNotATransportFailure).doesNotThrowAnyException();
        assertThatCode(contract::theResponseHeadersReachTheCaller).doesNotThrowAnyException();
        assertThatCode(contract::exactlyOneRequestArrivesAndItIsTheRequestThatWasHandedOver)
                .doesNotThrowAnyException();
        assertThatCode(contract::aRedirectIsNotFollowed).doesNotThrowAnyException();
        assertThatCode(contract::aRefusedConnectionIsADeliveryFailure).doesNotThrowAnyException();
        assertThatCode(contract::anUnansweredRequestIsADeliveryFailure).doesNotThrowAnyException();
        assertThatCode(contract::concurrentPostsEachReceiveTheirOwnResponse).doesNotThrowAnyException();
    }

    /**
     * The precondition for deleting the core's own redirect test: a redirect-following transport must fail the fourth
     * check. This subject wraps the JDK client built the unsafe way — {@code Redirect.ALWAYS} — which is exactly the
     * transport the production class refuses to be, and the failure must say the redirect was followed without naming
     * the endpoint or any header value.
     */
    @Test
    void aRedirectFollowingTransportFailsTheRedirectCheck() {
        Contract contract = Contract.over((ssl, trust) -> exchanging(clientOver(ssl, HttpClient.Redirect.ALWAYS)));

        assertThatThrownBy(contract::aRedirectIsNotFollowed)
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("followed the redirect")
                .hasMessageNotContaining("127.0.0.1")
                .hasMessageNotContaining(AUTHORIZATION_MARKER);
    }

    /**
     * The redirect check's second half, which the redirect-following subject above never reaches — it already fails on
     * the status. This subject answers the caller truthfully with the 307 and still opens a connection to the host the
     * {@code Location} names, which is the half whose failure means "something was sent towards an origin nobody vetted
     * while the caller was told the truth". The harness counts the connection at accept time, before any TLS handshake,
     * so a bare TCP probe is enough to be caught.
     */
    @Test
    void aTransportConnectingToTheRedirectTargetFailsTheRedirectCheckOnTheConnectionCount() {
        Contract contract = Contract.over((ssl, trust) -> {
            PushHttpClient conforming = exchanging(neverFollowing(ssl));
            return (endpoint, headers, body) -> {
                PushResponse response = conforming.post(endpoint, headers, body);
                response.header("Location").ifPresent(PushHttpClientContractSelfTest::openConnectionTowards);
                return response;
            };
        });

        assertThatThrownBy(contract::aRedirectIsNotFollowed)
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("accepted 1 connection")
                .hasMessageNotContaining("127.0.0.1");
    }

    /**
     * The classic mistake the first check exists for: a transport that reads an HTTP error status as a transport
     * failure. Every {@code 410} — a subscription this library classifies as expired — then reaches the caller as an
     * unanswered exchange it will keep repeating for the life of the stored row.
     */
    @Test
    void aTransportThrowingOnAnErrorStatusFailsTheStatusCheck() {
        Contract contract = Contract.over((ssl, trust) -> {
            PushHttpClient conforming = exchanging(neverFollowing(ssl));
            return (endpoint, headers, body) -> {
                PushResponse response = conforming.post(endpoint, headers, body);
                if (response.statusCode() >= 400) {
                    throw new PushDeliveryException("status " + response.statusCode());
                }
                return response;
            };
        });

        assertThatThrownBy(contract::anErrorStatusIsAnAnswerNotATransportFailure)
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("PushResponse")
                .hasMessageContaining("PushDeliveryException")
                .hasCauseInstanceOf(PushDeliveryException.class);
    }

    /** A transport that returns the status and drops the headers empties every repeat hint silently. */
    @Test
    void aTransportDroppingResponseHeadersFailsTheHeaderCheck() {
        Contract contract = Contract.over((ssl, trust) -> {
            PushHttpClient conforming = exchanging(neverFollowing(ssl));
            return (endpoint, headers, body) ->
                    new PushResponse(conforming.post(endpoint, headers, body).statusCode(), Map.of());
        });

        assertThatThrownBy(contract::theResponseHeadersReachTheCaller)
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("Retry-After")
                .hasMessageNotContaining(AUTHORIZATION_MARKER);
    }

    /**
     * A transport retrying inside {@code post} delivers the notification twice while the sender learns of one outcome.
     * The failure reports the count the server saw and nothing else.
     */
    @Test
    void aTransportRepeatingTheRequestInsidePostFailsTheSingleRequestCheck() {
        Contract contract = Contract.over((ssl, trust) -> {
            PushHttpClient conforming = exchanging(neverFollowing(ssl));
            return (endpoint, headers, body) -> {
                conforming.post(endpoint, headers, body);
                return conforming.post(endpoint, headers, body);
            };
        });

        assertThatThrownBy(contract::exactlyOneRequestArrivesAndItIsTheRequestThatWasHandedOver)
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("exactly one request")
                .hasMessageContaining("2 requests")
                .hasMessageNotContaining("127.0.0.1");
    }

    /**
     * A repeat conditioned on the answer, which is what a real one looks like. A transport retrying only when the push
     * service asks to be retried passes every scenario that answers success, and delivers the notification twice for
     * every {@code 429} a deployment receives — so the one-request obligation is asserted where such a transport
     * actually repeats.
     */
    @Test
    void aTransportRepeatingAfterARetryableStatusFailsTheHeaderCheck() {
        Contract contract = Contract.over((ssl, trust) -> {
            PushHttpClient conforming = exchanging(neverFollowing(ssl));
            return (endpoint, headers, body) -> {
                PushResponse first = conforming.post(endpoint, headers, body);
                return first.statusCode() == 429 || first.statusCode() >= 500
                        ? conforming.post(endpoint, headers, body)
                        : first;
            };
        });

        assertThatThrownBy(contract::theResponseHeadersReachTheCaller)
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("exactly one request")
                .hasMessageContaining("2 requests")
                .hasMessageNotContaining("127.0.0.1");
    }

    /**
     * The other conditional repeat, and the more dangerous one: after an exchange nothing answered, the message may
     * already have been delivered, so a repeat can deliver it twice and then report — truthfully, from where it stands
     * — that nothing was delivered at all. The transport here even ends with the exception the check requires, so only
     * the count catches it.
     */
    @Test
    void aTransportRepeatingAfterAnUnansweredRequestFailsTheUnansweredRequestCheck() {
        Contract contract = Contract.over((ssl, trust) -> {
            PushHttpClient conforming = exchanging(neverFollowing(ssl));
            return (endpoint, headers, body) -> {
                try {
                    return conforming.post(endpoint, headers, body);
                } catch (PushDeliveryException nothingAnswered) {
                    return conforming.post(endpoint, headers, body);
                }
            };
        });

        assertThatThrownBy(contract::anUnansweredRequestIsADeliveryFailure)
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("exactly one request")
                .hasMessageContaining("2 requests")
                .hasMessageNotContaining("127.0.0.1");
    }

    /**
     * The harness's chunked branch, pinned by a subject that uses it. Both framings are correct HTTP and the harness's
     * own documentation promises to read either, so a transport choosing the one nothing exercises would meet a parser
     * no test had ever run — and the failure would land on the implementor as a body mismatch in a contract they had
     * every reason to trust. A publisher of unknown length is what makes the JDK client frame the request chunked;
     * passing the third check then means the harness dechunked the body back to exactly the bytes that were handed
     * over.
     */
    @Test
    void aTransportFramingTheBodyChunkedSatisfiesTheSingleRequestCheck() {
        Contract contract = Contract.over((ssl, trust) -> exchanging(
                neverFollowing(ssl),
                body -> HttpRequest.BodyPublishers.ofInputStream(() -> new ByteArrayInputStream(body))));

        assertThatCode(contract::exactlyOneRequestArrivesAndItIsTheRequestThatWasHandedOver)
                .doesNotThrowAnyException();
    }

    /**
     * The line this contract draws around its own output, pinned on the rendering a runner actually prints rather than
     * on the top message alone — a cause's text reaches a build log through the stack trace, so a check that read only
     * {@code getMessage()} would pin half the claim and miss the half that matters.
     *
     * <p>Both halves are asserted, including the uncomfortable one. What the kit renders carries no value it was given
     * or observed. What the subject put in its own exception is printed, whatever that is: it is the frame an
     * implementor has to look at, it is their exception in their own build, and a transport can hold values from its
     * environment that this kit never saw. Asserting that it <em>is</em> printed keeps the next reader from removing
     * the cause on the strength of the first half.
     */
    @Test
    void aFailureRendersNoValueOfTheKitsOwnAndStillCarriesTheSubjectsException() {
        Contract contract = Contract.over((ssl, trust) -> (endpoint, headers, body) -> {
            throw new IllegalStateException("thrown by the subject, quoting " + endpoint);
        });

        AssertionError failure =
                catchThrowableOfType(AssertionError.class, contract::anErrorStatusIsAnAnswerNotATransportFailure);

        assertThat(failure.getMessage())
                .as("what the kit itself writes names no value it was given or observed")
                .doesNotContain("127.0.0.1")
                .doesNotContain(AUTHORIZATION_MARKER);
        assertThat(failure).hasCauseInstanceOf(IllegalStateException.class);
        assertThat(rendered(failure))
                .as("and the subject's own exception is printed as the cause, text and all — deliberately, since it "
                        + "is the frame the implementor has to look at")
                .contains("thrown by the subject, quoting");
    }

    /** The failure exactly as a test runner would print it: message, then the cause chain. */
    private static String rendered(Throwable failure) {
        StringWriter rendering = new StringWriter();
        try (PrintWriter out = new PrintWriter(rendering)) {
            failure.printStackTrace(out);
        }
        return rendering.toString();
    }

    /**
     * The byte-for-byte half of the third check: a transport delivering the right number of wrong bytes passes a length
     * check and hands every subscriber a message their browser cannot decrypt. The failure names positions and lengths,
     * never bytes.
     */
    @Test
    void aTransportCorruptingTheBodyFailsTheSingleRequestCheck() {
        Contract contract = Contract.over((ssl, trust) -> {
            PushHttpClient conforming = exchanging(neverFollowing(ssl));
            return (endpoint, headers, body) -> conforming.post(endpoint, headers, new byte[body.length]);
        });

        assertThatThrownBy(contract::exactlyOneRequestArrivesAndItIsTheRequestThatWasHandedOver)
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("byte for byte")
                .hasMessageContaining("first difference");
    }

    /**
     * The regression for a comparison made against the caller's own array. A transport that rewrites the array it was
     * handed <em>in place</em> and sends the rewrite delivers the right number of wrong bytes — and a check whose
     * expected value is the same reference would be comparing the rewrite with itself and passing. The contract
     * compares against a fresh generation of the deterministic body instead, so this subject must fail.
     */
    @Test
    void aTransportRewritingTheCallersArrayInPlaceFailsTheSingleRequestCheck() {
        Contract contract = Contract.over((ssl, trust) -> {
            PushHttpClient conforming = exchanging(neverFollowing(ssl));
            return (endpoint, headers, body) -> {
                Arrays.fill(body, (byte) 0);
                return conforming.post(endpoint, headers, body);
            };
        });

        assertThatThrownBy(contract::exactlyOneRequestArrivesAndItIsTheRequestThatWasHandedOver)
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("byte for byte");
    }

    /**
     * The URI half of the same check: a transport that rewrites the URI it was handed — a normalising wrapper stack is
     * the realistic shape — sends the request to a target the endpoint policy never assessed, and the request-target
     * comparison must catch it. Here the query is stripped; the failure names the mismatch without printing either URI.
     */
    @Test
    void aTransportRewritingTheUriFailsTheSingleRequestCheck() {
        Contract contract = Contract.over((ssl, trust) -> {
            PushHttpClient conforming = exchanging(neverFollowing(ssl));
            return (endpoint, headers, body) -> conforming.post(withoutQuery(endpoint), headers, body);
        });

        assertThatThrownBy(contract::exactlyOneRequestArrivesAndItIsTheRequestThatWasHandedOver)
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("request target")
                .hasMessageNotContaining("127.0.0.1");
    }

    /**
     * The header half of the same check, and the message discipline where it matters most: the failure names the
     * missing header and must not carry its value, which on a real send is the VAPID token.
     */
    @Test
    void aTransportStrippingARequestHeaderFailsTheSingleRequestCheck() {
        Contract contract = Contract.over((ssl, trust) -> {
            PushHttpClient conforming = exchanging(neverFollowing(ssl));
            return (endpoint, headers, body) -> {
                Map<String, String> stripped = new HashMap<>(headers);
                stripped.remove("Authorization");
                return conforming.post(endpoint, stripped, body);
            };
        });

        assertThatThrownBy(contract::exactlyOneRequestArrivesAndItIsTheRequestThatWasHandedOver)
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("missing the Authorization header")
                .hasMessageNotContaining(AUTHORIZATION_MARKER);
    }

    /**
     * A transport that swallows a failed exchange and fabricates a response makes an unanswered send indistinguishable
     * from an answered one — the sender would classify an invented status as the push service's verdict. Both
     * delivery-failure checks must catch it: the refused connection and the request read but never answered are
     * separate obligations, failing before any byte is written and after all of them are.
     */
    @Test
    void aTransportFabricatingAResponseFailsBothDeliveryFailureChecks() {
        Contract contract = Contract.over((ssl, trust) -> {
            PushHttpClient conforming = exchanging(neverFollowing(ssl));
            return (endpoint, headers, body) -> {
                try {
                    return conforming.post(endpoint, headers, body);
                } catch (PushDeliveryException swallowed) {
                    return PushResponse.of(503);
                }
            };
        });

        assertThatThrownBy(contract::aRefusedConnectionIsADeliveryFailure)
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("PushDeliveryException")
                .hasMessageContaining("503");
        assertThatThrownBy(contract::anUnansweredRequestIsADeliveryFailure)
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("PushDeliveryException")
                .hasMessageContaining("503");
    }

    /**
     * The wrong exception type is a different defect from the wrong answer: the sender converts exactly
     * {@code PushDeliveryException} into an outcome and treats every other runtime exception from the seam as a defect
     * that propagates. A transport reporting an unanswered exchange as anything else fails the check, and the failure
     * names the type it threw.
     */
    @Test
    void aTransportThrowingTheWrongTypeFailsTheUnansweredRequestCheck() {
        Contract contract = Contract.over((ssl, trust) -> {
            PushHttpClient conforming = exchanging(neverFollowing(ssl));
            return (endpoint, headers, body) -> {
                try {
                    return conforming.post(endpoint, headers, body);
                } catch (PushDeliveryException relabelled) {
                    throw new IllegalStateException("exchange failed");
                }
            };
        });

        assertThatThrownBy(contract::anUnansweredRequestIsADeliveryFailure)
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("IllegalStateException")
                .hasCauseInstanceOf(IllegalStateException.class);
    }

    /**
     * The concurrency check's teeth: a transport keeping per-request state in a field hands one caller another's
     * response. This subject serialises its calls and returns each caller the previous caller's response — the
     * deterministic form of the stale-buffer defect — and the check must report the crossing by caller index, without
     * rendering a header value or an endpoint.
     */
    @Test
    void aTransportHandingBackAnotherCallersResponseFailsTheConcurrencyCheck() {
        Contract contract = Contract.over((ssl, trust) -> new StaleResponseTransport(exchanging(neverFollowing(ssl))));

        assertThatThrownBy(contract::concurrentPostsEachReceiveTheirOwnResponse)
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("its own request")
                .hasMessageNotContaining("127.0.0.1")
                .hasMessageNotContaining(AUTHORIZATION_MARKER);
    }

    /**
     * The budget's semantics, pinned because the record deciding this contract was corrected on exactly this point: a
     * subject that never answers ends the check as an <em>abort</em>, never as a failure — the seam sets no latency
     * requirement, so an expired budget is not a verdict — and never as a hang, which is how a contract gets deleted
     * from the build it was added to. The budget is shortened through the package-private hook for this test alone and
     * restored in the {@code finally}: what is being proved is the abort semantics, not the length of the published
     * budget, and waiting out the real thirty seconds would tax every build of this repository forever.
     */
    @Test
    @Timeout(30)
    void aTransportThatNeverAnswersAbortsTheCheckInsteadOfFailingOrHangingIt() {
        Contract contract = Contract.over((ssl, trust) -> (endpoint, headers, body) -> {
            try {
                new CountDownLatch(1).await();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new PushDeliveryException("interrupted", interrupted);
            }
            throw new AssertionError("unreachable");
        });

        PostAttempt.shortenAnswerBudgetForSelfTest(1);
        try {
            assertThatThrownBy(contract::anErrorStatusIsAnAnswerNotATransportFailure)
                    .isInstanceOf(TestAbortedException.class)
                    .hasMessageContaining("without reaching a verdict");
        } finally {
            PostAttempt.restorePublishedAnswerBudget();
        }
    }

    /** The URI with its query stripped: the rewriting subject's one alteration. */
    private static URI withoutQuery(URI endpoint) {
        String flat = endpoint.toString();
        int query = flat.indexOf('?');
        return query < 0 ? endpoint : URI.create(flat.substring(0, query));
    }

    /**
     * One bare TCP connection towards the host and port a {@code Location} header names, then gone: the modelled defect
     * is a transport leaking a connection to the redirect target, and the harness must count it at accept time. The
     * short read gives the listener's accept loop a moment to run before the check reads the counter, so the count is
     * there deterministically rather than by winning a race.
     */
    private static void openConnectionTowards(String location) {
        URI target = URI.create(location);
        try (Socket connection = new Socket()) {
            connection.connect(new InetSocketAddress(target.getHost(), target.getPort()), 5_000);
            connection.setSoTimeout(100);
            connection.getInputStream().read();
        } catch (IOException expected) {
            // The server sends nothing on a plain TCP connection, so the read times out or the
            // close races it; the connection itself — already counted — is all this probe is for.
        }
    }

    /** A JDK client over the harness's trust material that never follows redirects — the conforming base. */
    private static HttpClient neverFollowing(SSLContext sslContext) {
        return clientOver(sslContext, HttpClient.Redirect.NEVER);
    }

    private static HttpClient clientOver(SSLContext sslContext, HttpClient.Redirect redirects) {
        return HttpClient.newBuilder()
                .sslContext(sslContext)
                .followRedirects(redirects)
                .build();
    }

    /**
     * One plain exchange over the given client, converting exceptions the way the seam requires. The defective subjects
     * above are built by wrapping this — each one breaks exactly the obligation its test is about and nothing else.
     */
    private static PushHttpClient exchanging(HttpClient client) {
        return exchanging(client, HttpRequest.BodyPublishers::ofByteArray);
    }

    /**
     * The same conforming transport over a chosen framing. A transport is free to frame the body either way, and the
     * harness reads both; which one the JDK picks follows from the publisher — a known length declares
     * {@code Content-Length}, an unknown one goes chunked.
     */
    private static PushHttpClient exchanging(HttpClient client, Function<byte[], HttpRequest.BodyPublisher> framing) {
        return (endpoint, headers, body) -> {
            HttpRequest.Builder request = HttpRequest.newBuilder(endpoint)
                    .timeout(Duration.ofSeconds(20))
                    .POST(framing.apply(body));
            headers.forEach(request::header);
            try {
                HttpResponse<Void> response = client.send(request.build(), HttpResponse.BodyHandlers.discarding());
                return new PushResponse(
                        response.statusCode(), firstValues(response.headers().map()));
            } catch (IOException noAnswer) {
                throw new PushDeliveryException("no answer", noAnswer);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new PushDeliveryException("interrupted", interrupted);
            }
        };
    }

    private static Map<String, String> firstValues(Map<String, List<String>> headers) {
        Map<String, String> flattened = new HashMap<>();
        headers.forEach((name, values) -> {
            if (!values.isEmpty()) {
                flattened.put(name, values.getFirst());
            }
        });
        return flattened;
    }

    /**
     * The stale-buffer defect in its deterministic form: calls serialise on the transport's own lock and every caller
     * after the first receives the response to the <em>previous</em> caller's request — which is what a field-kept
     * builder, buffer or response slot does under concurrency, minus the luck.
     */
    private static final class StaleResponseTransport implements PushHttpClient {

        private final PushHttpClient delegate;
        private PushResponse previous;

        StaleResponseTransport(PushHttpClient delegate) {
            this.delegate = delegate;
        }

        @Override
        public synchronized PushResponse post(URI endpoint, Map<String, String> headers, byte[] body) {
            PushResponse current = delegate.post(endpoint, headers, body);
            PushResponse answer = previous == null ? current : previous;
            previous = current;
            return answer;
        }
    }
}
