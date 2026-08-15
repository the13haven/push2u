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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.the13haven.push2u.EndpointPolicies;
import com.the13haven.push2u.PushCryptoException;
import com.the13haven.push2u.PushHttpClient;
import com.the13haven.push2u.PushInterruptedException;
import com.the13haven.push2u.PushMessage;
import com.the13haven.push2u.PushOutcome;
import com.the13haven.push2u.PushResponse;
import com.the13haven.push2u.PushSender;
import com.the13haven.push2u.Subscription;
import com.the13haven.push2u.VapidSignerUnavailableException;

/**
 * The deferred-fetch signer under a real {@code PushSender}: the first {@code publicKey()} happens at the token-cache
 * key step rather than where the VAPID header is built, and a first read that fails there is still sorted by the
 * taxonomy — an unavailability is the {@code SignerUnavailable} outcome, a {@code PushCryptoException} leaves
 * {@code send} as itself. After initialization a token-cache hit performs no Vault call at all, and a cancellation
 * stays with the thread that was interrupted, on the send path exactly as at the signer.
 */
class VaultTransitVapidSignerDeferredSendPathTest {

    private static final URI ADDRESS = URI.create("https://vault.example:8200");
    private static final TransitKeyName KEY_NAME = new TransitKeyName("vapid");
    private static final VaultToken TOKEN = new VaultToken("push2u-test-token");
    private static final String ENDPOINT = "https://push.example/subscription/1";

    private static final FakeTransitVault HEALTHY_VAULT = new FakeTransitVault(2);

    private static Subscription subscription;

    @BeforeAll
    static void createSubscription() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair browserKeys = generator.generateKeyPair();
        subscription = new Subscription(ENDPOINT, uncompressed((ECPublicKey) browserKeys.getPublic()), new byte[16]);
    }

    @Test
    void aFirstReadUnavailabilityInsideASendArrivesAsTheSignerUnavailableOutcome() {
        VapidSignerUnavailableException outage = new VapidSignerUnavailableException(
                "Vault Transit key read must wait — Vault cannot serve it now: HTTP 503",
                503,
                Duration.ofSeconds(9),
                null);
        RecordingPushClient pushClient = new RecordingPushClient();
        PushSender sender = sender(new SequencedVaultTransport(List.of(() -> {
            throw outage;
        })), pushClient);

        PushOutcome outcome = sender.send(subscription, PushMessage.of("hello".getBytes(StandardCharsets.UTF_8)));

        assertThat(outcome).isInstanceOf(PushOutcome.SignerUnavailable.class);
        PushOutcome.SignerUnavailable unavailable = (PushOutcome.SignerUnavailable) outcome;
        assertThat(unavailable.status()).hasValue(503);
        assertThat(unavailable.retryAfter()).contains(Duration.ofSeconds(9));
        assertThat(pushClient.posts.get()).as("no POST was made").isZero();
    }

    @Test
    void aFirstReadRecurringFailureLeavesSendAsItself() {
        PushCryptoException wrongKey = new PushCryptoException("Vault Transit key type is 'ed25519'");
        RecordingPushClient pushClient = new RecordingPushClient();
        PushSender sender = sender(new SequencedVaultTransport(List.of(() -> {
            throw wrongKey;
        })), pushClient);

        assertThatThrownBy(() -> sender.send(subscription, PushMessage.of("hello".getBytes(StandardCharsets.UTF_8))))
                .isSameAs(wrongKey);
        assertThat(pushClient.posts.get()).isZero();
    }

    @Test
    void afterInitializationATokenCacheHitPerformsNoVaultCallAtAll() {
        SequencedVaultTransport transport = new SequencedVaultTransport(List.of(
                VaultTransitVapidSignerDeferredSendPathTest::healthyKeys,
                VaultTransitVapidSignerDeferredSendPathTest::cannedSignature));
        RecordingPushClient pushClient = new RecordingPushClient();
        PushSender sender = sender(transport, pushClient);
        byte[] payload = "hello".getBytes(StandardCharsets.UTF_8);

        assertThat(sender.send(subscription, PushMessage.of(payload))).isInstanceOf(PushOutcome.Accepted.class);
        assertThat(sender.send(subscription, PushMessage.of(payload))).isInstanceOf(PushOutcome.Accepted.class);

        assertThat(transport.calls)
                .as("one metadata read and one signature; the second send is a token-cache hit with no Vault call")
                .hasSize(2);
        assertThat(pushClient.posts.get()).isEqualTo(2);
    }

    @Test
    void anInterruptedWaitingSendReportsTheCancellation_whileTheFlightServesTheRest() throws Exception {
        CountDownLatch fetchArrived = new CountDownLatch(1);
        CountDownLatch releaseFetch = new CountDownLatch(1);
        SequencedVaultTransport transport = new SequencedVaultTransport(List.of(
                () -> {
                    fetchArrived.countDown();
                    awaitGate(releaseFetch);
                    return healthyKeys();
                },
                VaultTransitVapidSignerDeferredSendPathTest::cannedSignature));
        RecordingPushClient pushClient = new RecordingPushClient();
        PushSender sender = sender(transport, pushClient);
        byte[] payload = "hello".getBytes(StandardCharsets.UTF_8);

        AtomicReference<Object> fetcherOutcome = new AtomicReference<>();
        Thread fetchingSend = new Thread(
                () -> {
                    try {
                        fetcherOutcome.set(sender.send(subscription, PushMessage.of(payload)));
                    } catch (Throwable failure) {
                        fetcherOutcome.set(failure);
                    }
                },
                "fetching-send");
        fetchingSend.start();
        assertThat(fetchArrived.await(10, TimeUnit.SECONDS)).isTrue();

        AtomicReference<Object> waiterOutcome = new AtomicReference<>();
        Thread waitingSend = new Thread(
                () -> {
                    try {
                        waiterOutcome.set(sender.send(subscription, PushMessage.of(payload)));
                    } catch (Throwable failure) {
                        waiterOutcome.set(failure);
                    }
                },
                "waiting-send");
        waitingSend.start();
        awaitParked(waitingSend, waiterOutcome);

        waitingSend.interrupt();
        waitingSend.join(10_000);
        assertThat(waitingSend.isAlive()).isFalse();
        assertThat(waiterOutcome.get())
                .as("the interrupted waiting send reports the cancellation, not an outage and not an outcome")
                .isInstanceOf(PushInterruptedException.class);

        releaseFetch.countDown();
        fetchingSend.join(10_000);
        assertThat(fetchingSend.isAlive()).isFalse();
        assertThat(fetcherOutcome.get())
                .as("the flight the waiter left kept serving its own caller")
                .isInstanceOf(PushOutcome.Accepted.class);
        assertThat(transport.calls).as("no second metadata read").hasSize(2);
    }

    @Test
    void anInterruptedFetchingSendKeepsItsCancellation_andNoWaitersSendReportsOne() throws Exception {
        CountDownLatch fetchArrived = new CountDownLatch(1);
        CountDownLatch releaseFetch = new CountDownLatch(1);
        VapidSignerUnavailableException interruptedExchange = new VapidSignerUnavailableException(
                "Vault Transit key read produced no response", new InterruptedException("exchange interrupted"));
        SequencedVaultTransport transport = new SequencedVaultTransport(List.of(
                () -> {
                    fetchArrived.countDown();
                    awaitGate(releaseFetch);
                    // What a real transport does after an interrupted exchange: the flag re-set,
                    // the InterruptedException kept in the chain, the unavailable type raised.
                    Thread.currentThread().interrupt();
                    throw interruptedExchange;
                },
                VaultTransitVapidSignerDeferredSendPathTest::healthyKeys,
                VaultTransitVapidSignerDeferredSendPathTest::cannedSignature));
        RecordingPushClient pushClient = new RecordingPushClient();
        PushSender sender = sender(transport, pushClient);
        byte[] payload = "hello".getBytes(StandardCharsets.UTF_8);

        AtomicReference<Object> fetcherOutcome = new AtomicReference<>();
        Thread fetchingSend = new Thread(
                () -> {
                    try {
                        fetcherOutcome.set(sender.send(subscription, PushMessage.of(payload)));
                    } catch (Throwable failure) {
                        fetcherOutcome.set(failure);
                    }
                },
                "fetching-send");
        fetchingSend.start();
        assertThat(fetchArrived.await(10, TimeUnit.SECONDS)).isTrue();

        AtomicReference<Object> waiterOutcome = new AtomicReference<>();
        Thread waitingSend = new Thread(
                () -> {
                    try {
                        waiterOutcome.set(sender.send(subscription, PushMessage.of(payload)));
                    } catch (Throwable failure) {
                        waiterOutcome.set(failure);
                    }
                },
                "waiting-send");
        waitingSend.start();
        awaitParked(waitingSend, waiterOutcome);
        releaseFetch.countDown();

        fetchingSend.join(10_000);
        waitingSend.join(10_000);
        assertThat(fetchingSend.isAlive()).isFalse();
        assertThat(waitingSend.isAlive()).isFalse();

        assertThat(fetcherOutcome.get())
                .as("the interrupted fetching send reports its own cancellation")
                .isInstanceOf(PushInterruptedException.class);
        assertThat(waiterOutcome.get())
                .as("the waiter's send was not handed the cancellation: it retried, took over, and delivered")
                .isInstanceOf(PushOutcome.Accepted.class);
        assertThat(transport.calls).as("the abandoned flight was followed by one takeover read").hasSize(3);
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Plumbing
    // ---------------------------------------------------------------------------------------------------------------

    private static PushSender sender(VaultHttpTransport transport, PushHttpClient pushClient) {
        return PushSender.builder(
                        VaultTransitVapidSigner.builderWithDeferredPublicKeyFetch(ADDRESS, KEY_NAME, TOKEN)
                                .transport(transport)
                                .build(),
                        "mailto:ops@example.com",
                        EndpointPolicies.allowedOrigins("https://push.example"))
                .httpClient(pushClient)
                .build();
    }

    private static void awaitGate(CountDownLatch gate) {
        try {
            if (!gate.await(10, TimeUnit.SECONDS)) {
                throw new AssertionError("gate never released");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError("no test interrupts a thread at this gate", e);
        }
    }

    private static VaultHttpResponse healthyKeys() {
        return HEALTHY_VAULT.get(URI.create(ADDRESS + "/v1/transit/keys/vapid"), Map.of());
    }

    private static VaultHttpResponse cannedSignature() {
        // The envelope version matches the healthy vault's latest, which the deferred signer pins;
        // the payload's content is irrelevant here — nothing on the send path verifies it.
        return new VaultHttpResponse(
                200,
                "{\"data\":{\"signature\":\"vault:v2:"
                        + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[64]) + "\"}}");
    }

    /** Waits until {@code thread} is parked on the flight — its only untimed wait on this path — or has finished. */
    private static void awaitParked(Thread thread, AtomicReference<Object> outcome) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (thread.getState() != Thread.State.WAITING) {
            if (thread.getState() == Thread.State.TERMINATED) {
                throw new AssertionError("send finished instead of waiting on the flight: " + outcome.get());
            }
            if (System.nanoTime() > deadline) {
                throw new AssertionError("send never parked on the flight: " + thread.getState());
            }
            Thread.onSpinWait();
        }
    }

    private static byte[] uncompressed(ECPublicKey key) {
        byte[] out = new byte[65];
        out[0] = 0x04;
        byte[] x = key.getW().getAffineX().toByteArray();
        byte[] y = key.getW().getAffineY().toByteArray();
        copyFixed32(x, out, 1);
        copyFixed32(y, out, 33);
        return out;
    }

    private static void copyFixed32(byte[] value, byte[] out, int offset) {
        int start = value.length > 32 ? value.length - 32 : 0;
        int length = value.length - start;
        System.arraycopy(value, start, out, offset + 32 - length, length);
    }

    /** A push transport that accepts everything and counts its POSTs. */
    private static final class RecordingPushClient implements PushHttpClient {

        private final AtomicInteger posts = new AtomicInteger();

        @Override
        public PushResponse post(URI endpoint, Map<String, String> headers, byte[] body) {
            posts.incrementAndGet();
            return PushResponse.of(201);
        }
    }

    /**
     * A transport answering one scripted step per Vault call, in order, whatever the method — an extra call fails the
     * test, which is what turns "no second read" and "no Vault call on a cache hit" into hard assertions.
     */
    private static final class SequencedVaultTransport implements VaultHttpTransport {

        private final List<java.util.function.Supplier<VaultHttpResponse>> steps;
        private final AtomicInteger next = new AtomicInteger();
        private final List<String> calls = new CopyOnWriteArrayList<>();

        private SequencedVaultTransport(List<java.util.function.Supplier<VaultHttpResponse>> steps) {
            this.steps = steps;
        }

        @Override
        public VaultHttpResponse get(URI uri, Map<String, String> headers) {
            calls.add("GET " + uri);
            return run();
        }

        @Override
        public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body) {
            calls.add("POST " + uri);
            return run();
        }

        private VaultHttpResponse run() {
            int index = next.getAndIncrement();
            if (index >= steps.size()) {
                throw new AssertionError("unscripted Vault call #" + (index + 1) + ": " + calls);
            }
            return steps.get(index).get();
        }
    }
}
