/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.function.BiFunction;
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
     * from the build it was added to. This is the one deliberately slow test in the kit: it waits out the full budget.
     */
    @Test
    @Timeout(90)
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

        assertThatThrownBy(contract::anErrorStatusIsAnAnswerNotATransportFailure)
                .isInstanceOf(TestAbortedException.class)
                .hasMessageContaining("without reaching a verdict");
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
        return (endpoint, headers, body) -> {
            HttpRequest.Builder request = HttpRequest.newBuilder(endpoint)
                    .timeout(Duration.ofSeconds(20))
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body));
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
