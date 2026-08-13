/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import com.the13haven.push2u.PushCryptoException;
import com.the13haven.push2u.VapidSignerUnavailableException;

/**
 * The custodian's status matrix (ADR-021): which Vault answer means "cannot serve now" — worth waiting out, leaving as
 * {@link VapidSignerUnavailableException} with the status and any retry hint carried — and which means a failure that
 * recurs until the deployment changes what it supplied, staying {@link PushCryptoException}. The worked rows come from
 * Vault's own published status table; a status neither list names falls to RFC 9110's classes, a 5xx being a statement
 * about the server and a 4xx one about the request. This is deliberately not the push service's matrix: 501 is carved
 * out as permanent there and published as "not initialized" — a cluster state — here.
 */
class VaultTransitVapidSignerCustodianStatusTest {

    private static final String TOKEN = "s.push2u-test-vault-token";
    private static final URI VAULT = URI.create("https://vault.test:8200");

    // ---- the unavailable side: a state of the cluster, or of a service it called -----------------

    @Test
    void everyStatusVaultPublishesAsAClusterStateLeavesAsTheUnavailableTypeCarryingTheStatus() {
        // Vault's own table: 500 "try again later", 501 not initialized, 502 a third party Vault
        // called, 503 sealed/maintenance/overloaded, 412 eventual consistency not caught up,
        // 429 a standby's health answer, 472 a DR replication secondary, 473 a performance
        // standby. 412/429/472/473 are the rows only the vendor's table can classify — as bare
        // numbers the 4xx rule would call them recurring.
        for (int status : new int[] {500, 501, 502, 503, 412, 429, 472, 473}) {
            assertThatThrownBy(() -> explicitSigner(new VaultHttpResponse(status, "{\"errors\":[\"try later\"]}"))
                            .sign("probe".getBytes(StandardCharsets.UTF_8)))
                    .as("HTTP %d", status)
                    .isInstanceOf(VapidSignerUnavailableException.class)
                    .hasMessageContaining("HTTP " + status)
                    .hasMessageContaining("try later")
                    .satisfies(e -> {
                        VapidSignerUnavailableException unavailable = (VapidSignerUnavailableException) e;
                        assertThat(unavailable.status()).hasValue(status);
                        assertThat(unavailable.retryAfter())
                                .as("no hint arrived, so none is invented")
                                .isEmpty();
                    });
        }
    }

    @Test
    void anUnrecognisedServerErrorStatusFallsToTheUnavailableSide() {
        // RFC 9110 §15.6: a 5xx says the server is aware it has erred — a statement about the
        // custodian, so a 5xx from a Vault newer than this code (or a proxy in front of it) is
        // still a custodian that cannot serve now.
        assertThatThrownBy(() ->
                        explicitSigner(new VaultHttpResponse(599, "{}")).sign("probe".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(VapidSignerUnavailableException.class)
                .satisfies(e -> assertThat(((VapidSignerUnavailableException) e).status())
                        .hasValue(599));
    }

    @Test
    void theRetryHintCrossesFromTheResponseIntoTheException() {
        // The whole reason VaultHttpResponse carries the hint: the caller's scheduler is the only
        // component able to honour it, and this is the only route by which it gets there.
        VaultHttpResponse rateLimited = new VaultHttpResponse(
                429, "{\"errors\":[\"rate limit quota exceeded\"]}", Optional.of(Duration.ofSeconds(17)));

        assertThatThrownBy(() -> explicitSigner(rateLimited).sign("probe".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(VapidSignerUnavailableException.class)
                .satisfies(e -> {
                    VapidSignerUnavailableException unavailable = (VapidSignerUnavailableException) e;
                    assertThat(unavailable.status()).hasValue(429);
                    assertThat(unavailable.retryAfter()).contains(Duration.ofSeconds(17));
                });
    }

    @Test
    void theKeyReadClassifiesByTheSameMatrixAtConstruction() {
        // The fetched mode reads the key while the application is still starting, so this is the
        // startup supervisor's case: a sealed Vault at boot is a boot worth retrying with backoff,
        // not a deployment to fail.
        assertThatThrownBy(() -> fetchedSigner(new VaultHttpResponse(
                        503, "{\"errors\":[\"Vault is sealed\"]}", Optional.of(Duration.ofSeconds(30)))))
                .isInstanceOf(VapidSignerUnavailableException.class)
                .hasMessageContaining("Vault Transit key read")
                .hasMessageContaining("HTTP 503")
                .satisfies(e -> {
                    VapidSignerUnavailableException unavailable = (VapidSignerUnavailableException) e;
                    assertThat(unavailable.status()).hasValue(503);
                    assertThat(unavailable.retryAfter()).contains(Duration.ofSeconds(30));
                });
    }

    @Test
    void anOversizedBodyOnTheUnavailableSideIsTruncatedBeforeItReachesTheMessage() {
        String hugeBody = "<html><body>" + "A".repeat(64_000) + "</body></html>";

        assertThatThrownBy(() -> explicitSigner(new VaultHttpResponse(503, hugeBody))
                        .sign("probe".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(VapidSignerUnavailableException.class)
                .satisfies(thrown -> assertThat(thrown.getMessage().length())
                        .as("a proxy's HTML error page must not be pasted whole into a log line")
                        .isLessThan(4096));
    }

    // ---- the recurring side: an answer about the request -----------------------------------------

    @Test
    void anUnrecognisedClientErrorStatusStaysARecurringDefect() {
        // RFC 9110 §15.5: a 4xx says the client seems to have erred — a statement about the
        // request, answered identically until the deployment changes what it supplied.
        assertThatThrownBy(() ->
                        explicitSigner(new VaultHttpResponse(418, "{}")).sign("probe".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("HTTP 418");
    }

    @Test
    void aRedirectStatusStaysARecurringDefect() {
        // A 3xx is neither class, and what it reports here is an address misconfiguration (a
        // redirecting standby or proxy the transport rightly refused to follow) — the same answer
        // arrives on every attempt until the address changes.
        assertThatThrownBy(() ->
                        explicitSigner(new VaultHttpResponse(307, "")).sign("probe".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("HTTP 307");
    }

    @Test
    void aHintOnARecurringAnswerDoesNotChangeItsClass() {
        // The hint never classifies: a 403 stays an answer about the request however the response
        // is decorated, because waiting does not put a capability on a token.
        VaultHttpResponse denied =
                new VaultHttpResponse(403, "{\"errors\":[\"permission denied\"]}", Optional.of(Duration.ofSeconds(9)));

        assertThatThrownBy(() -> explicitSigner(denied).sign("probe".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("HTTP 403");
    }

    // ---- the interruption, tested in the order a supervisor must read it -------------------------

    @Test
    void aBootInterruptedDuringTheFetchedKeyReadIsRecognisableAsACancellationBeforeItsType() throws Exception {
        // The supervisor's contract on builderWithFetchedPublicKey(...).build(): a boot
        // interrupted while the key is read raises the unavailable type too, so the supervisor
        // tests the interruption first — the flag, or an InterruptedException in the chain — and
        // only then reads the type. This test asserts in that order on purpose. A real transport
        // against a socket that accepts and never answers, so the interrupt lands mid-exchange.
        try (ServerSocket silent = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            URI address = URI.create("http://127.0.0.1:" + silent.getLocalPort());
            AtomicReference<Throwable> thrown = new AtomicReference<>();
            AtomicReference<Boolean> flagSet = new AtomicReference<>();
            Thread boot = new Thread(() -> {
                try {
                    VaultTransitVapidSigner.builderWithFetchedPublicKey(
                                    address, new TransitKeyName("vapid"), new VaultToken(TOKEN))
                            .transport(new JdkVaultHttpTransport(
                                    HttpClient.newHttpClient(), Duration.ofSeconds(30), 1024 * 1024))
                            .build();
                } catch (Throwable e) {
                    thrown.set(e);
                    flagSet.set(Thread.currentThread().isInterrupted());
                }
            });
            boot.start();
            Thread.sleep(200); // let the key read get in flight before interrupting
            boot.interrupt();
            boot.join(Duration.ofSeconds(5).toMillis());

            assertThat(boot.isAlive())
                    .as("the interrupted boot returns promptly")
                    .isFalse();
            // The interruption first — the supervisor's first test, and the one that must win.
            assertThat(flagSet.get())
                    .as("the interrupt status is re-set for the building thread")
                    .isTrue();
            assertThat(hasInterruptedExceptionInChain(thrown.get()))
                    .as("the InterruptedException stays in the cause chain")
                    .isTrue();
            // Only then the type.
            assertThat(thrown.get()).isInstanceOf(VapidSignerUnavailableException.class);
        }
    }

    private static boolean hasInterruptedExceptionInChain(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof InterruptedException) {
                return true;
            }
        }
        return false;
    }

    // ---- fixtures ---------------------------------------------------------------------------------

    /** A genuine P-256 point (the RFC 8291 §5 user-agent key): the supplied key is validated against the curve. */
    private static byte[] validPublicKey() {
        return Base64.getUrlDecoder()
                .decode("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4");
    }

    /** An explicit-mode signer whose Vault always answers {@code response} to a sign request. */
    private static VaultTransitVapidSigner explicitSigner(VaultHttpResponse response) {
        return VaultTransitVapidSigner.builderWithSuppliedPublicKey(
                        VAULT, new TransitKeyName("vapid"), new VaultToken(TOKEN), validPublicKey())
                .transport(new VaultHttpTransport() {
                    @Override
                    public VaultHttpResponse get(URI uri, Map<String, String> headers) {
                        throw new AssertionError("the explicit mode must never read key metadata");
                    }

                    @Override
                    public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body) {
                        return response;
                    }
                })
                .build();
    }

    /** A fetched-mode signer whose key read always answers {@code response}. */
    private static VaultTransitVapidSigner fetchedSigner(VaultHttpResponse response) {
        return VaultTransitVapidSigner.builderWithFetchedPublicKey(
                        VAULT, new TransitKeyName("vapid"), new VaultToken(TOKEN))
                .transport(new VaultHttpTransport() {
                    @Override
                    public VaultHttpResponse get(URI uri, Map<String, String> headers) {
                        return response;
                    }

                    @Override
                    public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body) {
                        throw new AssertionError("construction must not sign anything");
                    }
                })
                .build();
    }
}
