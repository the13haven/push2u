/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import org.junit.jupiter.api.Test;

import com.the13haven.push2u.PushCryptoException;
import com.the13haven.push2u.VapidSigner;
import com.the13haven.push2u.VapidSignerUnavailableException;

/**
 * The deferred-fetch mode's initialization contract (ADR-026): {@code build()} performs no I/O, the first use performs
 * exactly one {@code transit/keys} read, a successful pair is retained for the signer's lifetime, and the four ways a
 * flight can end — success, shared failure, cancelled fetching caller, foreign failure — stay distinct.
 *
 * <p>Every concurrent case is gated deterministically inside the scripted transport: the fetching caller blocks on a
 * latch the test releases, and a waiter is released only after it is provably parked on the flight
 * ({@link #awaitParkedOnFlight}), so no assertion here depends on two threads merely racing the same window. That
 * discipline exists because a wave that is only probably concurrent passes for the wrong reason on a busy CI runner.
 */
class VaultTransitVapidSignerDeferredFetchTest {

    private static final URI ADDRESS = URI.create("https://vault.example:8200");
    private static final TransitKeyName KEY_NAME = new TransitKeyName("vapid");
    private static final VaultToken TOKEN = new VaultToken("push2u-test-token");
    private static final byte[] SIGNING_INPUT = "deferred-fetch probe".getBytes(StandardCharsets.US_ASCII);

    /** A healthy Transit key at version 3 — a version above 1, so a lazily pinned v3 cannot pass by accident. */
    private static final FakeTransitVault HEALTHY_VAULT = new FakeTransitVault(3);

    // ---------------------------------------------------------------------------------------------------------------
    // build() — no I/O, every local check intact
    // ---------------------------------------------------------------------------------------------------------------

    @Test
    void deferredBuildTouchesTheTransportNotAtAll() {
        ScriptedVaultTransport transport = new ScriptedVaultTransport(); // no steps: any call fails the test
        VaultTransitVapidSigner.builderWithDeferredPublicKeyFetch(ADDRESS, KEY_NAME, TOKEN)
                .mount("transit")
                .namespace("team-a")
                .transport(transport)
                .build();
        assertThat(transport.calls).isEmpty();
    }

    @Test
    void deferredBuildStillRefusesPlainHttpToARemoteHost_withoutContactingAnything() {
        ScriptedVaultTransport transport = new ScriptedVaultTransport();
        VaultTransitVapidSigner.DeferredPublicKeyFetchBuilder builder =
                VaultTransitVapidSigner.builderWithDeferredPublicKeyFetch(
                                URI.create("http://vault.internal:8200"), KEY_NAME, TOKEN)
                        .transport(transport);
        assertThatThrownBy(builder::build)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("allowInsecureHttp()");
        assertThat(transport.calls).isEmpty();
    }

    @Test
    void deferredBuildAcceptsPlainHttpToALoopbackLiteral_andWithTheOptInToAnyHost() {
        VaultTransitVapidSigner.builderWithDeferredPublicKeyFetch(URI.create("http://127.0.0.1:8200"), KEY_NAME, TOKEN)
                .transport(new ScriptedVaultTransport())
                .build();
        VaultTransitVapidSigner.builderWithDeferredPublicKeyFetch(
                        URI.create("http://vault.internal:8200"), KEY_NAME, TOKEN)
                .allowInsecureHttp()
                .transport(new ScriptedVaultTransport())
                .build();
    }

    @Test
    void deferredFactoryAppliesTheSameAddressRulesAsTheOthers() {
        assertThatThrownBy(() -> VaultTransitVapidSigner.builderWithDeferredPublicKeyFetch(
                        URI.create("ftp://vault.example"), KEY_NAME, TOKEN))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("scheme must be http or https");
        assertThatThrownBy(() -> VaultTransitVapidSigner.builderWithDeferredPublicKeyFetch(
                        URI.create("https://vault.example:8200?query=1"), KEY_NAME, TOKEN))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not carry a query");
        assertThatThrownBy(() -> VaultTransitVapidSigner.builderWithDeferredPublicKeyFetch(
                        URI.create("https://gw.example/vault/../other"), KEY_NAME, TOKEN))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("'..' segment");
    }

    @Test
    void deferredBuilderValidatesMountAndNamespaceAtTheStepThatSetsThem() {
        VaultTransitVapidSigner.DeferredPublicKeyFetchBuilder builder =
                VaultTransitVapidSigner.builderWithDeferredPublicKeyFetch(ADDRESS, KEY_NAME, TOKEN);
        assertThatThrownBy(() -> builder.mount("secrets//transit")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> builder.namespace("team-a/..")).isInstanceOf(IllegalArgumentException.class);
    }

    // ---------------------------------------------------------------------------------------------------------------
    // First use — one read, pinned version, retained pair
    // ---------------------------------------------------------------------------------------------------------------

    @Test
    void coldPublicKeyPerformsExactlyOneMetadataRead_andTheSubsequentSignPinsThatVersion() {
        ScriptedVaultTransport transport = new ScriptedVaultTransport()
                .onGet(VaultTransitVapidSignerDeferredFetchTest::healthyKeys)
                .onPost(VaultTransitVapidSignerDeferredFetchTest::healthySignature);
        VapidSigner signer = deferredSigner(transport);

        byte[] advertised = signer.publicKey();

        assertThat(advertised).isEqualTo(HEALTHY_VAULT.publicKeyUncompressed());
        assertThat(transport.calls).containsExactly("GET " + keysUri());

        byte[] signature = signer.sign(SIGNING_INPUT);

        assertThat(signature).hasSize(64);
        assertThat(transport.calls).containsExactly("GET " + keysUri(), "POST " + signUri());
        assertThat(transport.postBodies.get(0))
                .as("the version the read reported is pinned in the sign request")
                .contains("\"key_version\":3");
    }

    @Test
    void coldSignPerformsExactlyOneMetadataRead_beforeItsOwnPost() {
        ScriptedVaultTransport transport = new ScriptedVaultTransport()
                .onGet(VaultTransitVapidSignerDeferredFetchTest::healthyKeys)
                .onPost(VaultTransitVapidSignerDeferredFetchTest::healthySignature);
        VapidSigner signer = deferredSigner(transport);

        byte[] signature = signer.sign(SIGNING_INPUT);

        assertThat(signature).hasSize(64);
        assertThat(transport.calls).containsExactly("GET " + keysUri(), "POST " + signUri());
        assertThat(transport.postBodies.get(0)).contains("\"key_version\":3");
    }

    @Test
    void coldPublicKeyBase64UrlInitializesLikeTheOtherTwo() {
        ScriptedVaultTransport transport =
                new ScriptedVaultTransport().onGet(VaultTransitVapidSignerDeferredFetchTest::healthyKeys);
        VapidSigner signer = deferredSigner(transport);

        String published = signer.publicKeyBase64Url();

        assertThat(published).isNotEmpty();
        assertThat(transport.calls).containsExactly("GET " + keysUri());
    }

    @Test
    void aSuccessfulPairIsRetained_noSecondReadEver() {
        ScriptedVaultTransport transport = new ScriptedVaultTransport()
                .onGet(VaultTransitVapidSignerDeferredFetchTest::healthyKeys)
                .onPost(VaultTransitVapidSignerDeferredFetchTest::healthySignature)
                .onPost(VaultTransitVapidSignerDeferredFetchTest::healthySignature);
        VapidSigner signer = deferredSigner(transport);

        byte[] first = signer.publicKey();
        byte[] second = signer.publicKey();
        signer.sign(SIGNING_INPUT);
        signer.sign(SIGNING_INPUT);

        assertThat(second).isEqualTo(first).isNotSameAs(first);
        assertThat(transport.keyReads())
                .as("one metadata read for the signer's lifetime")
                .isEqualTo(1);
    }

    @Test
    void theFetchedKeyIsValidatedExactlyAsTheEagerModeValidatesIt() {
        // The three checks that read the response move to first use with their types intact: a key
        // of the wrong Transit type is the recurring failure, raised by the first use instead of by
        // build().
        ScriptedVaultTransport transport = new ScriptedVaultTransport()
                .onGet(() -> new VaultHttpResponse(
                        200,
                        "{\"data\":{\"type\":\"ecdsa-p384\",\"latest_version\":1,\"keys\":{\"1\":{\"public_key\":"
                                + "\"irrelevant\"}}}}"));
        VapidSigner signer = deferredSigner(transport);

        assertThatThrownBy(signer::publicKey)
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("ecdsa-p256");
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Failures are forgotten — no negative cache
    // ---------------------------------------------------------------------------------------------------------------

    @Test
    void aLaterCallerAfterAFailedReadStartsANewOne() {
        VapidSignerUnavailableException outage =
                new VapidSignerUnavailableException("Vault Transit key read must wait", 503, null, null);
        ScriptedVaultTransport transport = new ScriptedVaultTransport()
                .onGet(() -> {
                    throw outage;
                })
                .onGet(VaultTransitVapidSignerDeferredFetchTest::healthyKeys);
        VapidSigner signer = deferredSigner(transport);

        assertThatThrownBy(signer::publicKey).isSameAs(outage);
        assertThat(signer.publicKey()).isEqualTo(HEALTHY_VAULT.publicKeyUncompressed());
        assertThat(transport.keyReads()).isEqualTo(2);
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Concurrent waves — gated inside the transport
    // ---------------------------------------------------------------------------------------------------------------

    @Test
    void aConcurrentColdWavePerformsOneRead_andEveryCallerGetsTheSamePair() throws Exception {
        CountDownLatch fetchArrived = new CountDownLatch(1);
        CountDownLatch releaseFetch = new CountDownLatch(1);
        ScriptedVaultTransport transport = new ScriptedVaultTransport()
                .onGetGated(fetchArrived, releaseFetch, VaultTransitVapidSignerDeferredFetchTest::healthyKeys);
        VapidSigner signer = deferredSigner(transport);

        Caller fetcher = Caller.start("fetcher", signer::publicKey);
        awaitGate(fetchArrived);
        Caller waiterOne = Caller.start("waiter-1", signer::publicKey);
        Caller waiterTwo = Caller.start("waiter-2", signer::publicKey);
        awaitParkedOnFlight(waiterOne);
        awaitParkedOnFlight(waiterTwo);
        releaseFetch.countDown();

        byte[] expected = HEALTHY_VAULT.publicKeyUncompressed();
        assertThat(fetcher.awaitValue()).isEqualTo(expected);
        assertThat(waiterOne.awaitValue()).isEqualTo(expected);
        assertThat(waiterTwo.awaitValue()).isEqualTo(expected);
        assertThat(transport.keyReads()).isEqualTo(1);
    }

    @Test
    void aConcurrentFailingWavePerformsOneRead_eachCallerGetsItsOwnExceptionOfTheContractType() throws Exception {
        // Vault answering 503 with a declared delay and no cause of its own: the sharpest shape,
        // because a waiter rebuilt from the failure's cause alone would have been rebuilt from
        // nothing.
        VapidSignerUnavailableException outage = new VapidSignerUnavailableException(
                "Vault Transit key read must wait — Vault cannot serve it now: HTTP 503",
                503,
                Duration.ofSeconds(7),
                null);
        CountDownLatch fetchArrived = new CountDownLatch(1);
        CountDownLatch releaseFetch = new CountDownLatch(1);
        ScriptedVaultTransport transport = new ScriptedVaultTransport().onGetGated(fetchArrived, releaseFetch, () -> {
            throw outage;
        });
        VapidSigner signer = deferredSigner(transport);

        Caller fetcher = Caller.start("fetcher", signer::publicKey);
        awaitGate(fetchArrived);
        Caller waiterOne = Caller.start("waiter-1", signer::publicKey);
        Caller waiterTwo = Caller.start("waiter-2", signer::publicKey);
        awaitParkedOnFlight(waiterOne);
        awaitParkedOnFlight(waiterTwo);
        releaseFetch.countDown();

        Throwable fetcherFailure = fetcher.awaitFailure();
        Throwable waiterOneFailure = waiterOne.awaitFailure();
        Throwable waiterTwoFailure = waiterTwo.awaitFailure();

        assertThat(fetcherFailure)
                .as("the fetching caller keeps the exception it was given")
                .isSameAs(outage);
        for (Throwable waiterFailure : List.of(waiterOneFailure, waiterTwoFailure)) {
            assertThat(waiterFailure)
                    .as("a waiter throws its own instance, never the fetching caller's")
                    .isNotSameAs(outage)
                    .isInstanceOf(VapidSignerUnavailableException.class)
                    .hasMessage(outage.getMessage());
            assertThat(waiterFailure.getCause())
                    .as("carrying the fetch's own failure whole as its cause — the failure, not its cause")
                    .isSameAs(outage);
            VapidSignerUnavailableException reconstructed = (VapidSignerUnavailableException) waiterFailure;
            assertThat(reconstructed.status()).hasValue(503);
            assertThat(reconstructed.retryAfter()).contains(Duration.ofSeconds(7));
        }
        assertThat(waiterOneFailure).isNotSameAs(waiterTwoFailure);
        assertThat(outage.getCause())
                .as("the shared failure itself had no cause of its own")
                .isNull();
        assertThat(transport.keyReads()).isEqualTo(1);
    }

    @Test
    void aSharedRecurringFailureIsAlsoReconstructedPerWaiter() throws Exception {
        PushCryptoException wrongKey = new PushCryptoException("Vault Transit key type is 'ed25519'");
        CountDownLatch fetchArrived = new CountDownLatch(1);
        CountDownLatch releaseFetch = new CountDownLatch(1);
        ScriptedVaultTransport transport = new ScriptedVaultTransport().onGetGated(fetchArrived, releaseFetch, () -> {
            throw wrongKey;
        });
        VapidSigner signer = deferredSigner(transport);

        Caller fetcher = Caller.start("fetcher", signer::publicKey);
        awaitGate(fetchArrived);
        Caller waiter = Caller.start("waiter", signer::publicKey);
        awaitParkedOnFlight(waiter);
        releaseFetch.countDown();

        assertThat(fetcher.awaitFailure()).isSameAs(wrongKey);
        Throwable waiterFailure = waiter.awaitFailure();
        assertThat(waiterFailure)
                .isNotSameAs(wrongKey)
                .isInstanceOf(PushCryptoException.class)
                .hasMessage(wrongKey.getMessage());
        assertThat(waiterFailure.getCause()).isSameAs(wrongKey);
        assertThat(transport.keyReads()).isEqualTo(1);
    }

    @Test
    void theReconstructionPromisesTheContractType_andReadsTheDeclaredValuesExactlyOnce() throws Exception {
        // A transport may raise its own subclass; the waiters' promise is the contract type, so a
        // reconstruction is exactly VapidSignerUnavailableException — and the two declared values
        // are read once, when the description is taken, not once per waiter.
        CountingUnavailable subclassed = new CountingUnavailable("custodian busy", 429, Duration.ofSeconds(30));
        CountDownLatch fetchArrived = new CountDownLatch(1);
        CountDownLatch releaseFetch = new CountDownLatch(1);
        ScriptedVaultTransport transport = new ScriptedVaultTransport().onGetGated(fetchArrived, releaseFetch, () -> {
            throw subclassed;
        });
        VapidSigner signer = deferredSigner(transport);

        Caller fetcher = Caller.start("fetcher", signer::publicKey);
        awaitGate(fetchArrived);
        Caller waiterOne = Caller.start("waiter-1", signer::publicKey);
        Caller waiterTwo = Caller.start("waiter-2", signer::publicKey);
        awaitParkedOnFlight(waiterOne);
        awaitParkedOnFlight(waiterTwo);
        releaseFetch.countDown();

        assertThat(fetcher.awaitFailure())
                .as("its own caller still receives the subclass it was given")
                .isSameAs(subclassed);
        for (Caller waiter : List.of(waiterOne, waiterTwo)) {
            Throwable waiterFailure = waiter.awaitFailure();
            assertThat(waiterFailure.getClass())
                    .as("the promise is the contract type, never the runtime class")
                    .isEqualTo(VapidSignerUnavailableException.class);
            assertThat(((VapidSignerUnavailableException) waiterFailure).status())
                    .hasValue(429);
        }
        assertThat(subclassed.statusReads)
                .as("status() read exactly once, when the description was taken")
                .hasValue(1);
        assertThat(subclassed.retryAfterReads)
                .as("retryAfter() read exactly once, when the description was taken")
                .hasValue(1);
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Cancellation — caller-local in both directions
    // ---------------------------------------------------------------------------------------------------------------

    @Test
    void anInterruptedFetchingCallerKeepsItsOwnException_flagHalfOfTheDisjunction() throws Exception {
        // The transport re-set the flag but attached no InterruptedException — the flag half alone
        // must keep the failure from being shared.
        VapidSignerUnavailableException interruptedExchange =
                new VapidSignerUnavailableException("Vault Transit key read produced no response", null);
        fetchingCallerCancellationIsCallerLocal(
                () -> {
                    Thread.currentThread().interrupt();
                    throw interruptedExchange;
                },
                interruptedExchange);
    }

    @Test
    void anInterruptedFetchingCallerKeepsItsOwnException_causeChainHalfOfTheDisjunction() throws Exception {
        // The transport kept the InterruptedException in the chain but failed to re-set the flag —
        // the chain half alone must keep the failure from being shared.
        VapidSignerUnavailableException interruptedExchange = new VapidSignerUnavailableException(
                "Vault Transit key read produced no response", new InterruptedException("exchange interrupted"));
        fetchingCallerCancellationIsCallerLocal(
                () -> {
                    throw interruptedExchange;
                },
                interruptedExchange);
    }

    @Test
    void anInterruptionMislabelledAsARecurringFailureIsStillNotShared() throws Exception {
        // A defective transport wrapped an interruption in the recurring type. The flight applies
        // the disjunction before classifying by type, so the waiters are not handed a recurring
        // failure that was really a cancellation — while the fetching caller still receives it
        // exactly as labelled.
        PushCryptoException mislabelled =
                new PushCryptoException("read failed", new InterruptedException("exchange interrupted"));
        fetchingCallerCancellationIsCallerLocal(
                () -> {
                    throw mislabelled;
                },
                mislabelled);
    }

    private void fetchingCallerCancellationIsCallerLocal(
            Supplier<VaultHttpResponse> firstReadOutcome, RuntimeException expectedFetcherFailure) throws Exception {
        CountDownLatch fetchArrived = new CountDownLatch(1);
        CountDownLatch releaseFetch = new CountDownLatch(1);
        ScriptedVaultTransport transport = new ScriptedVaultTransport()
                .onGetGated(fetchArrived, releaseFetch, firstReadOutcome)
                .onGet(VaultTransitVapidSignerDeferredFetchTest::healthyKeys);
        VapidSigner signer = deferredSigner(transport);

        Caller fetcher = Caller.start("fetcher", signer::publicKey);
        awaitGate(fetchArrived);
        Caller waiterOne = Caller.start("waiter-1", signer::publicKey);
        Caller waiterTwo = Caller.start("waiter-2", signer::publicKey);
        awaitParkedOnFlight(waiterOne);
        awaitParkedOnFlight(waiterTwo);
        releaseFetch.countDown();

        assertThat(fetcher.awaitFailure())
                .as("the fetching caller keeps its own exception, as labelled")
                .isSameAs(expectedFetcherFailure);
        byte[] expected = HEALTHY_VAULT.publicKeyUncompressed();
        assertThat(waiterOne.awaitValue())
                .as("no waiter is handed a cancellation: they retry, one takes over")
                .isEqualTo(expected);
        assertThat(waiterTwo.awaitValue()).isEqualTo(expected);
        assertThat(transport.keyReads())
                .as("the abandoned flight is followed by exactly one takeover read")
                .isEqualTo(2);
    }

    @Test
    void anInterruptedWaiterTakesItsOwnCancellation_whileTheFlightContinuesForEveryoneElse() throws Exception {
        CountDownLatch fetchArrived = new CountDownLatch(1);
        CountDownLatch releaseFetch = new CountDownLatch(1);
        ScriptedVaultTransport transport = new ScriptedVaultTransport()
                .onGetGated(fetchArrived, releaseFetch, VaultTransitVapidSignerDeferredFetchTest::healthyKeys);
        VapidSigner signer = deferredSigner(transport);

        Caller fetcher = Caller.start("fetcher", signer::publicKey);
        awaitGate(fetchArrived);
        Caller interruptedWaiter = Caller.start("interrupted-waiter", signer::publicKey);
        Caller patientWaiter = Caller.start("patient-waiter", signer::publicKey);
        awaitParkedOnFlight(interruptedWaiter);
        awaitParkedOnFlight(patientWaiter);

        interruptedWaiter.thread.interrupt();
        Throwable cancellation = interruptedWaiter.awaitFailure();

        // Its cancellation takes the shape the transport would have produced: the unavailability
        // type, the InterruptedException beneath it, the flag re-set — a waiter has no transport
        // failure of its own to keep.
        assertThat(cancellation).isInstanceOf(VapidSignerUnavailableException.class);
        assertThat(cancellation.getCause()).isInstanceOf(InterruptedException.class);
        assertThat(interruptedWaiter.interruptFlagAfterFailure)
                .as("the interrupt flag is re-set for whoever supervises the call")
                .isTrue();

        releaseFetch.countDown();
        byte[] expected = HEALTHY_VAULT.publicKeyUncompressed();
        assertThat(fetcher.awaitValue()).isEqualTo(expected);
        assertThat(patientWaiter.awaitValue()).isEqualTo(expected);
        assertThat(transport.keyReads())
                .as("the flight the waiter left kept running — no second read")
                .isEqualTo(1);
    }

    // ---------------------------------------------------------------------------------------------------------------
    // A failure of neither contract type
    // ---------------------------------------------------------------------------------------------------------------

    @Test
    void aFailureOfNeitherContractTypeReachesItsOwnCallerUnchanged_andTheWaitersRetry() throws Exception {
        IllegalStateException defect = new IllegalStateException("a consumer transport's own defect");
        CountDownLatch fetchArrived = new CountDownLatch(1);
        CountDownLatch releaseFetch = new CountDownLatch(1);
        ScriptedVaultTransport transport = new ScriptedVaultTransport()
                .onGetGated(fetchArrived, releaseFetch, () -> {
                    throw defect;
                })
                .onGet(VaultTransitVapidSignerDeferredFetchTest::healthyKeys);
        VapidSigner signer = deferredSigner(transport);

        Caller fetcher = Caller.start("fetcher", signer::publicKey);
        awaitGate(fetchArrived);
        Caller waiter = Caller.start("waiter", signer::publicKey);
        awaitParkedOnFlight(waiter);
        releaseFetch.countDown();

        assertThat(fetcher.awaitFailure())
                .as("a defect is never laundered into a contract type")
                .isSameAs(defect);
        assertThat(waiter.awaitValue()).isEqualTo(HEALTHY_VAULT.publicKeyUncompressed());
        assertThat(transport.keyReads()).isEqualTo(2);
    }

    // ---------------------------------------------------------------------------------------------------------------
    // The initialization guard never serializes signing
    // ---------------------------------------------------------------------------------------------------------------

    @Test
    void afterInitialization_aSecondSignCompletesWhileAFirstIsBlockedInsideTheTransport() throws Exception {
        CountDownLatch firstSignArrived = new CountDownLatch(1);
        CountDownLatch releaseFirstSign = new CountDownLatch(1);
        ScriptedVaultTransport transport = new ScriptedVaultTransport()
                .onGet(VaultTransitVapidSignerDeferredFetchTest::healthyKeys)
                .onPostGated(
                        firstSignArrived, releaseFirstSign, VaultTransitVapidSignerDeferredFetchTest::healthySignature)
                .onPost(VaultTransitVapidSignerDeferredFetchTest::healthySignature);
        VapidSigner signer = deferredSigner(transport);
        signer.publicKey(); // initialize

        Caller blockedSigner = Caller.start("blocked-sign", () -> signer.sign(SIGNING_INPUT));
        awaitGate(firstSignArrived);
        Caller concurrentSigner = Caller.start("concurrent-sign", () -> signer.sign(SIGNING_INPUT));

        assertThat(concurrentSigner.awaitValue())
                .as("a second sign completes while the first is still blocked inside the transport")
                .isNotNull();
        assertThat(blockedSigner.thread.isAlive())
                .as("the first sign is still inside the transport")
                .isTrue();

        releaseFirstSign.countDown();
        assertThat(blockedSigner.awaitValue()).isNotNull();
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Plumbing
    // ---------------------------------------------------------------------------------------------------------------

    private static VapidSigner deferredSigner(VaultHttpTransport transport) {
        return VaultTransitVapidSigner.builderWithDeferredPublicKeyFetch(ADDRESS, KEY_NAME, TOKEN)
                .transport(transport)
                .build();
    }

    private static String keysUri() {
        return ADDRESS + "/v1/transit/keys/" + KEY_NAME.value();
    }

    private static String signUri() {
        return ADDRESS + "/v1/transit/sign/" + KEY_NAME.value();
    }

    private static VaultHttpResponse healthyKeys() {
        return HEALTHY_VAULT.get(URI.create(keysUri()), Map.of());
    }

    private static VaultHttpResponse healthySignature() {
        // A canned envelope carrying the version the healthy vault advertises; the content need not
        // verify — nothing on this path verifies it — but the length and the envelope must hold.
        return new VaultHttpResponse(
                200,
                "{\"data\":{\"signature\":\"vault:v3:"
                        + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[64]) + "\"}}");
    }

    private static void awaitGate(CountDownLatch gate) throws InterruptedException {
        assertThat(gate.await(10, java.util.concurrent.TimeUnit.SECONDS))
                .as("the gated transport call arrived")
                .isTrue();
    }

    /**
     * Waits until {@code caller}'s thread is provably parked on the flight's latch — its only untimed wait point on
     * this path — so releasing the transport gate afterwards proves the caller was attached to the flight rather than
     * merely racing it. State-based, not sleep-based: it converges on any runner, however loaded.
     */
    private static void awaitParkedOnFlight(Caller caller) {
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(10);
        while (caller.thread.getState() != Thread.State.WAITING) {
            if (caller.thread.getState() == Thread.State.TERMINATED) {
                throw new AssertionError("caller finished instead of waiting on the flight: " + caller.outcome.get());
            }
            if (System.nanoTime() > deadline) {
                throw new AssertionError("caller never parked on the flight: " + caller.thread.getState());
            }
            Thread.onSpinWait();
        }
    }

    /** A signer call on a dedicated platform thread, its value or failure captured for the test to read. */
    private static final class Caller {

        private final Thread thread;
        private final AtomicReference<Object> outcome = new AtomicReference<>();
        private volatile boolean interruptFlagAfterFailure;

        private Caller(String name, Supplier<Object> body) {
            this.thread = new Thread(
                    () -> {
                        try {
                            outcome.set(body.get());
                        } catch (Throwable failure) {
                            interruptFlagAfterFailure = Thread.currentThread().isInterrupted();
                            outcome.set(failure);
                        }
                    },
                    name);
        }

        static Caller start(String name, Supplier<Object> body) {
            Caller caller = new Caller(name, body);
            caller.thread.start();
            return caller;
        }

        private Object await() throws InterruptedException {
            thread.join(10_000);
            assertThat(thread.isAlive())
                    .as("caller '%s' finished", thread.getName())
                    .isFalse();
            return outcome.get();
        }

        Object awaitValue() throws InterruptedException {
            Object result = await();
            if (result instanceof Throwable failure) {
                throw new AssertionError("caller '" + thread.getName() + "' failed instead of answering", failure);
            }
            return result;
        }

        Throwable awaitFailure() throws InterruptedException {
            Object result = await();
            assertThat(result)
                    .as("caller '%s' should have failed", thread.getName())
                    .isInstanceOf(Throwable.class);
            return (Throwable) result;
        }
    }

    /** A subclass whose declared-value accessors count their reads — the reconstruction must read each once. */
    private static final class CountingUnavailable extends VapidSignerUnavailableException {

        private final AtomicInteger statusReads = new AtomicInteger();
        private final AtomicInteger retryAfterReads = new AtomicInteger();

        private CountingUnavailable(String message, int status, Duration retryAfter) {
            super(message, status, retryAfter, null);
        }

        @Override
        public java.util.OptionalInt status() {
            statusReads.incrementAndGet();
            return super.status();
        }

        @Override
        public java.util.Optional<Duration> retryAfter() {
            retryAfterReads.incrementAndGet();
            return super.retryAfter();
        }
    }

    /**
     * A transport whose every answer is scripted in advance, step by step: an unscripted call fails the test — which is
     * what pins "no second read" as a hard assertion — and a gated step signals its arrival and then holds the calling
     * thread until the test releases it, which is what makes the concurrent waves deterministic rather than probable.
     */
    private static final class ScriptedVaultTransport implements VaultHttpTransport {

        private record Step(CountDownLatch arrived, CountDownLatch release, Supplier<VaultHttpResponse> action) {}

        private static final CountDownLatch OPEN = new CountDownLatch(0);

        private final List<Step> gets = new CopyOnWriteArrayList<>();
        private final List<Step> posts = new CopyOnWriteArrayList<>();
        private final AtomicInteger nextGet = new AtomicInteger();
        private final AtomicInteger nextPost = new AtomicInteger();
        private final List<String> calls = new CopyOnWriteArrayList<>();
        private final List<String> postBodies = new CopyOnWriteArrayList<>();

        ScriptedVaultTransport onGet(Supplier<VaultHttpResponse> action) {
            gets.add(new Step(OPEN, OPEN, action));
            return this;
        }

        ScriptedVaultTransport onGetGated(
                CountDownLatch arrived, CountDownLatch release, Supplier<VaultHttpResponse> action) {
            gets.add(new Step(arrived, release, action));
            return this;
        }

        ScriptedVaultTransport onPost(Supplier<VaultHttpResponse> action) {
            posts.add(new Step(OPEN, OPEN, action));
            return this;
        }

        ScriptedVaultTransport onPostGated(
                CountDownLatch arrived, CountDownLatch release, Supplier<VaultHttpResponse> action) {
            posts.add(new Step(arrived, release, action));
            return this;
        }

        long keyReads() {
            return calls.stream().filter(call -> call.startsWith("GET ")).count();
        }

        @Override
        public VaultHttpResponse get(URI uri, Map<String, String> headers) {
            calls.add("GET " + uri);
            return run(gets, nextGet, "GET");
        }

        @Override
        public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body) {
            calls.add("POST " + uri);
            postBodies.add(new String(body, StandardCharsets.UTF_8));
            return run(posts, nextPost, "POST");
        }

        private VaultHttpResponse run(List<Step> steps, AtomicInteger next, String method) {
            int index = next.getAndIncrement();
            if (index >= steps.size()) {
                throw new AssertionError("unscripted " + method + " call #" + (index + 1)
                        + " — the code under test performed a Vault call the contract forbids");
            }
            Step step = steps.get(index);
            step.arrived().countDown();
            try {
                step.release().await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AssertionError("a test gate was interrupted — no test interrupts a thread at a gate", e);
            }
            return step.action().get();
        }
    }
}
