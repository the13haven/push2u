/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import com.the13haven.push2u.PushCryptoException;
import com.the13haven.push2u.VapidSigner;
import com.the13haven.push2u.VapidSignerUnavailableException;

/**
 * The deferred-fetch mode's initialization contract (ADR-026): {@code build()} performs no I/O, the first use performs
 * exactly one {@code transit/keys} read, a successful pair is retained for the signer's lifetime, and the ways a flight
 * can end stay distinct — success, shared failure, cancelled fetching caller, foreign failure, plus the two the
 * transport's own contract does not admit (a throwable that is not a {@code RuntimeException}, and a failure whose
 * description cannot be taken because its own accessors throw), which end a flight as a foreign failure does.
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

    @Test
    void aFailureWhoseDescriptionCannotBeTakenStillEndsTheFlight_andItsCallerKeepsIt() throws Exception {
        // Describing a failure calls getCause(), getMessage(), status() and retryAfter() on an
        // exception a replaceable transport produced — all overridable, which is why the declared
        // values are snapshotted at all. One of them throwing must not leave the flight recorded as
        // active (the waiters would park forever), and must not reach the fetching caller in place
        // of the failure it was given: that failure is the classified thing, and the accessor's
        // complaint is diagnostics about the exception object, which is where it is filed.
        IllegalStateException accessorDefect = new IllegalStateException("status() is broken in this subclass");
        UndescribableUnavailable outage =
                new UndescribableUnavailable("Vault Transit key read must wait", accessorDefect);
        CountDownLatch fetchArrived = new CountDownLatch(1);
        CountDownLatch releaseFetch = new CountDownLatch(1);
        ScriptedVaultTransport transport = new ScriptedVaultTransport()
                .onGetGated(fetchArrived, releaseFetch, () -> {
                    throw outage;
                })
                .onGet(VaultTransitVapidSignerDeferredFetchTest::healthyKeys);
        VapidSigner signer = deferredSigner(transport);

        Caller fetcher = Caller.start("fetcher", signer::publicKey);
        awaitGate(fetchArrived);
        Caller waiter = Caller.start("waiter", signer::publicKey);
        awaitParkedOnFlight(waiter);
        releaseFetch.countDown();

        Throwable fetcherFailure = fetcher.awaitFailure();
        assertThat(fetcherFailure)
                .as("the caller that performed the fetch keeps the exception it was given")
                .isSameAs(outage);
        assertThat(fetcherFailure.getSuppressed())
                .as("the accessor's own failure is filed on it rather than thrown in its place")
                .contains(accessorDefect);
        assertThat(waiter.awaitValue())
                .as("nothing was shared, so the waiter retried instead of parking on a latch nobody opens")
                .isEqualTo(HEALTHY_VAULT.publicKeyUncompressed());
        assertThat(transport.keyReads())
                .as("the flight was released, so a later caller could still start a read")
                .isEqualTo(2);
    }

    @Test
    void anAccessorThrowingTheFailureItselfIsNotDisplacedByTheRefusalThatCauses() throws Exception {
        // The one refusal recording a secondary can raise: an exception offered as its own
        // suppressor. It arrives whenever the accessor threw the failure itself, and it must not
        // reach the caller in place of that failure — the caller keeps it, with nothing recorded
        // on it, because nothing can be — nor leave the flight recorded as active.
        SelfThrowingUnavailable outage = new SelfThrowingUnavailable("Vault Transit key read must wait");
        CountDownLatch fetchArrived = new CountDownLatch(1);
        CountDownLatch releaseFetch = new CountDownLatch(1);
        ScriptedVaultTransport transport = new ScriptedVaultTransport()
                .onGetGated(fetchArrived, releaseFetch, () -> {
                    throw outage;
                })
                .onGet(VaultTransitVapidSignerDeferredFetchTest::healthyKeys);
        VapidSigner signer = deferredSigner(transport);

        Caller fetcher = Caller.start("fetcher", signer::publicKey);
        awaitGate(fetchArrived);
        Caller waiter = Caller.start("waiter", signer::publicKey);
        awaitParkedOnFlight(waiter);
        releaseFetch.countDown();

        Throwable fetcherFailure = fetcher.awaitFailure();
        assertThat(fetcherFailure)
                .as("the refusal is swallowed; the caller keeps the failure it was given")
                .isSameAs(outage);
        assertThat(fetcherFailure.getSuppressed())
                .as("and nothing is recorded on it, an exception being unable to suppress itself")
                .isEmpty();
        assertThat(waiter.awaitValue()).isEqualTo(HEALTHY_VAULT.publicKeyUncompressed());
        assertThat(transport.keyReads()).isEqualTo(2);
    }

    @Test
    @Timeout(value = 30, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    void anEndlesslyFabricatedCauseChainIsCutAtTheCeiling_andTheFlightStillEnds() throws Exception {
        // A getCause() manufacturing a fresh wrapper on every read is an acyclic infinite chain:
        // every element is new, so the identity set that ends a cycle never fires on it and the
        // depth ceiling is the only thing that ends the walk. Without it the interruption test
        // never returns, and here that is worse than a spinning send — the walk runs inside the
        // flight, so its release is never reached, every waiter parks on a latch nobody counts
        // down, and every later caller attaches to that same dead flight. The separate-thread mode
        // is what makes the timeout the assertion's teeth: the default mode only interrupts the
        // test thread, while the walk is a CPU-bound loop on another one that never reads the
        // flag. The cost of a regression is a spinning zombie thread until this forked JVM exits,
        // accepted for a failure that fails in seconds and names this test.
        EndlesslyCausedFailure endless = new EndlesslyCausedFailure("Vault Transit key metadata read failed");
        CountDownLatch fetchArrived = new CountDownLatch(1);
        CountDownLatch releaseFetch = new CountDownLatch(1);
        ScriptedVaultTransport transport = new ScriptedVaultTransport()
                .onGetGated(fetchArrived, releaseFetch, () -> {
                    throw endless;
                })
                .onGet(VaultTransitVapidSignerDeferredFetchTest::healthyKeys);
        VapidSigner signer = deferredSigner(transport);

        Caller fetcher = Caller.start("fetcher", signer::publicKey);
        awaitGate(fetchArrived);
        Caller waiter = Caller.start("waiter", signer::publicKey);
        awaitParkedOnFlight(waiter);
        releaseFetch.countDown();

        Throwable fetcherFailure = fetcher.awaitFailure();
        assertThat(fetcherFailure)
                .as("the caller that performed the fetch keeps the exception it was given")
                .isSameAs(endless);
        assertThat(fetcherFailure.getSuppressed())
                .as("with the cut filed on it as a diagnostic rather than thrown in its place")
                .hasSize(1);
        assertThat(fetcherFailure.getSuppressed()[0])
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("cause chain");
        assertThat(waiter.awaitValue())
                .as("nothing was shared, though the failure was of a contract type: an interruption beyond"
                        + " the cut is exactly what could not be ruled out, so the waiter retried")
                .isEqualTo(HEALTHY_VAULT.publicKeyUncompressed());
        assertThat(transport.keyReads())
                .as("the flight was released, so a later caller could still start a read")
                .isEqualTo(2);
    }

    @Test
    @Timeout(value = 30, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    void aCyclicCauseChainIsWalkedToItsEnd_andTheFailureIsStillShared() throws Exception {
        // The other way a chain fails to end, and the one where the answer stays sound: two
        // exceptions closed onto each other are walked to the identity set's stop having shown
        // every element they hold, so nothing is unknown and the failure is shared as the
        // recurring one it is. Nothing recorded on it is what tells this apart from the same loop
        // cut by the depth ceiling a thousand elements later.
        IllegalStateException other = new IllegalStateException("the other half of the cycle");
        CyclicallyCausedFailure cyclic = new CyclicallyCausedFailure("Vault Transit key type is 'ed25519'", other);
        other.initCause(cyclic);
        CountDownLatch fetchArrived = new CountDownLatch(1);
        CountDownLatch releaseFetch = new CountDownLatch(1);
        ScriptedVaultTransport transport = new ScriptedVaultTransport().onGetGated(fetchArrived, releaseFetch, () -> {
            throw cyclic;
        });
        VapidSigner signer = deferredSigner(transport);

        Caller fetcher = Caller.start("fetcher", signer::publicKey);
        awaitGate(fetchArrived);
        Caller waiter = Caller.start("waiter", signer::publicKey);
        awaitParkedOnFlight(waiter);
        releaseFetch.countDown();

        Throwable fetcherFailure = fetcher.awaitFailure();
        assertThat(fetcherFailure).isSameAs(cyclic);
        assertThat(fetcherFailure.getSuppressed())
                .as("the cycle was recognised as a cycle: nothing was filed on the failure")
                .isEmpty();
        Throwable waiterFailure = waiter.awaitFailure();
        assertThat(waiterFailure)
                .as("and the failure was shared, the walk having answered rather than refused")
                .isNotSameAs(cyclic)
                .isInstanceOf(PushCryptoException.class)
                .hasMessage(cyclic.getMessage());
        assertThat(transport.keyReads()).as("a shared failure is not retried").isEqualTo(1);
    }

    // ---------------------------------------------------------------------------------------------------------------
    // The recording of an accessor's complaint is bounded per exception instance
    // ---------------------------------------------------------------------------------------------------------------

    @Test
    void oneReusedUndescribableFailureDoesNotGrowItsSuppressedListWithEveryFlight() {
        // A transport preallocating one exception and throwing it for every failed read is
        // ordinary — a custodian refusing everything while a breaker is open builds nothing per
        // call — and a failed flight is forgotten rather than cached, so every later caller starts
        // a fresh flight that fails the same way. With a broken accessor on that one instance, an
        // unbounded recording would grow its suppressed list by one entry per read for as long as
        // the custodian stays down.
        IllegalStateException accessorDefect = new IllegalStateException("status() is broken in this subclass");
        UndescribableUnavailable reused =
                new UndescribableUnavailable("Vault Transit key read must wait", accessorDefect);
        VapidSigner signer = deferredSigner(new AlwaysFailingTransport(reused));

        for (int i = 0; i < 1000; i++) {
            assertThatThrownBy(signer::publicKey)
                    .as("every flight still ends with its caller keeping the failure it was given")
                    .isSameAs(reused);
        }

        assertThat(reused.getSuppressed())
                .as("the recording is bounded rather than one entry per read")
                .hasSizeLessThanOrEqualTo(8);
        assertThat(reused.getSuppressed()[0])
                .as("what was recorded is still the diagnostic, not something the ceiling substituted")
                .isSameAs(accessorDefect);
    }

    @Test
    @Timeout(value = 60, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    void severalSignersDescribingOneSharedFailureAtOnceStayWithinTheBound() throws Exception {
        // Single-flight serialises the description within one signer and not across several, so
        // several deferred signers over one transport are where the recording is genuinely
        // concurrent. Be honest about what a green run proves: a probe on the core's copy of this
        // recording found the ungated form exceeding its limit only about one run in fifteen, even
        // at 2000 concurrent describers, because the window is the gap between two acquisitions of
        // one monitor and nothing a test can write goes in between — both members are final on
        // Throwable. So this is a regression net rather than a proof that the critical section is
        // there; the sequential test above is what pins the ceiling. The timeout covers the start
        // gate: a rendezvous that never completes must fail the test rather than hang the run.
        for (int round = 0; round < 4; round++) {
            IllegalStateException accessorDefect = new IllegalStateException("status() is broken in this subclass");
            UndescribableUnavailable shared =
                    new UndescribableUnavailable("Vault Transit key read must wait", accessorDefect);
            AlwaysFailingTransport transport = new AlwaysFailingTransport(shared);
            int signers = 512;
            CountDownLatch ready = new CountDownLatch(signers);
            CountDownLatch start = new CountDownLatch(1);

            try (ExecutorService threads = Executors.newVirtualThreadPerTaskExecutor()) {
                List<Future<?>> flights = new ArrayList<>();
                for (int i = 0; i < signers; i++) {
                    VapidSigner signer = deferredSigner(transport);
                    flights.add(threads.submit(() -> {
                        ready.countDown();
                        start.await();
                        assertThatThrownBy(signer::publicKey).isSameAs(shared);
                        return null;
                    }));
                }
                ready.await();
                start.countDown();
                for (Future<?> flight : flights) {
                    flight.get();
                }
            }

            assertThat(shared.getSuppressed())
                    .as(
                            "round %d: many flights describing one instance leave exactly the bound, not one entry more",
                            round)
                    .hasSize(8);
        }
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

    @Test
    void anInterruptArrivingDuringTheCauseWalkIsStillNotShared() throws Exception {
        // The disjunction's flag half is asked before the walk and again after it, and this is the
        // window between the two: consumer code inside getCause() is where a cancellation can land
        // while the chain is being read. Asking only before it would share a failure the fetching
        // caller had already taken as its own cancellation with waiters nobody interrupted.
        InterruptingCausedFailure interruptedMidWalk =
                new InterruptingCausedFailure("Vault Transit key metadata read failed");
        // Nothing to clear afterwards: the flag is set on the fetching caller's own thread, inside
        // the read it performs there, and that thread ends with the failure.
        fetchingCallerCancellationIsCallerLocal(
                () -> {
                    throw interruptedMidWalk;
                },
                interruptedMidWalk);
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

    @Test
    void aCheckedThrowableOutOfTheTransportEndsTheFlightToo_andTheWaitersRetry() throws Exception {
        // VaultHttpTransport declares no checked exceptions, but it is a seam an application
        // implements: Kotlin has none to declare, and a signature-erasing helper throws an
        // IOException straight through a Java method that declares none. It must end the flight
        // exactly as a failure of neither contract type does — before this was so, the waiters
        // parked forever and every later caller attached to the same dead flight, which turned one
        // consumer's transport bug into a signer that never answers again.
        IOException undeclared = new IOException("a consumer transport's undeclared I/O failure");
        CountDownLatch fetchArrived = new CountDownLatch(1);
        CountDownLatch releaseFetch = new CountDownLatch(1);
        ScriptedVaultTransport transport = new ScriptedVaultTransport()
                .onGetGated(fetchArrived, releaseFetch, () -> {
                    throw sneakyThrow(undeclared);
                })
                .onGet(VaultTransitVapidSignerDeferredFetchTest::healthyKeys);
        VapidSigner signer = deferredSigner(transport);

        Caller fetcher = Caller.start("fetcher", signer::publicKey);
        awaitGate(fetchArrived);
        Caller waiter = Caller.start("waiter", signer::publicKey);
        awaitParkedOnFlight(waiter);
        releaseFetch.countDown();

        assertThat(fetcher.awaitFailure())
                .as("it reaches its own caller exactly as thrown, laundered into nothing")
                .isSameAs(undeclared);
        assertThat(waiter.awaitValue())
                .as("the flight was released, so the waiter retried and one caller took the read over")
                .isEqualTo(HEALTHY_VAULT.publicKeyUncompressed());
        assertThat(transport.keyReads())
                .as("the abandoned flight is followed by exactly one takeover read")
                .isEqualTo(2);
        assertThat(signer.publicKey())
                .as("and the read that took over published the pair every later caller answers from")
                .isEqualTo(HEALTHY_VAULT.publicKeyUncompressed());
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
     * merely racing it. The convergence criterion is the observed state, never elapsed time; the millisecond between
     * looks only keeps three waiting observers off the cores the threads they are waiting for need, which on a
     * four-vCPU runner is the difference between waiting for convergence and competing with it.
     */
    private static void awaitParkedOnFlight(Caller caller) throws InterruptedException {
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(10);
        while (caller.thread.getState() != Thread.State.WAITING) {
            if (caller.thread.getState() == Thread.State.TERMINATED) {
                throw new AssertionError("caller finished instead of waiting on the flight: " + caller.outcome.get());
            }
            if (System.nanoTime() > deadline) {
                throw new AssertionError("caller never parked on the flight: " + caller.thread.getState());
            }
            Thread.sleep(1);
        }
    }

    /**
     * Throws {@code failure} through a signature that declares nothing — what {@link VaultHttpTransport#get}, which
     * declares no checked exception, still receives from an implementation written in a language that has none.
     */
    @SuppressWarnings("unchecked")
    private static <T extends Throwable> RuntimeException sneakyThrow(Throwable failure) throws T {
        throw (T) failure;
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

    /**
     * A subclass whose declared-value accessor throws instead of answering — a defective transport's exception, and the
     * reason the description-taking cannot be assumed to return at all.
     */
    private static final class UndescribableUnavailable extends VapidSignerUnavailableException {

        private final RuntimeException accessorFailure;

        private UndescribableUnavailable(String message, RuntimeException accessorFailure) {
            super(message);
            this.accessorFailure = accessorFailure;
        }

        @Override
        public java.util.OptionalInt status() {
            throw accessorFailure;
        }
    }

    /**
     * A recurring failure whose cause chain never ends: every read builds a fresh link, and every link does the same,
     * so the chain is acyclic and infinite and no identity test can recognise it for what it is.
     */
    private static final class EndlesslyCausedFailure extends PushCryptoException {

        private EndlesslyCausedFailure(String message) {
            super(message);
        }

        @Override
        public synchronized Throwable getCause() {
            return new FabricatedLink();
        }
    }

    /**
     * A recurring failure whose cause chain sets the reading thread's interrupt flag while it is being walked — the
     * cancellation that arrives after the walk's first look at the flag, and is missed by a walk that never looks
     * again.
     */
    private static final class InterruptingCausedFailure extends PushCryptoException {

        private InterruptingCausedFailure(String message) {
            super(message);
        }

        @Override
        public synchronized Throwable getCause() {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    /** One link of the chain above, fabricating its own successor exactly as the failure that starts it does. */
    private static final class FabricatedLink extends RuntimeException {

        private FabricatedLink() {
            super("a freshly fabricated link");
        }

        @Override
        public synchronized Throwable getCause() {
            return new FabricatedLink();
        }
    }

    /** A recurring failure whose cause chain closes onto itself — the finite way a chain fails to end. */
    private static final class CyclicallyCausedFailure extends PushCryptoException {

        private final Throwable half;

        private CyclicallyCausedFailure(String message, Throwable half) {
            super(message);
            this.half = half;
        }

        @Override
        public synchronized Throwable getCause() {
            return half;
        }
    }

    /**
     * A subclass whose declared-value accessor throws the failure itself — the shape that makes recording the secondary
     * refuse, since nothing can be its own suppressor.
     */
    private static final class SelfThrowingUnavailable extends VapidSignerUnavailableException {

        private SelfThrowingUnavailable(String message) {
            super(message);
        }

        @Override
        public java.util.OptionalInt status() {
            throw this;
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
     * A transport whose every read fails with the one exception it was handed — the preallocated-instance shape a
     * consumer's transport takes while a breaker is open, and the one this signer must not accumulate diagnostics on.
     */
    private static final class AlwaysFailingTransport implements VaultHttpTransport {

        private final RuntimeException failure;

        private AlwaysFailingTransport(RuntimeException failure) {
            this.failure = failure;
        }

        @Override
        public VaultHttpResponse get(URI uri, Map<String, String> headers) {
            throw failure;
        }

        @Override
        public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body) {
            throw new AssertionError("no signing call is reachable: the metadata read never succeeds");
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
