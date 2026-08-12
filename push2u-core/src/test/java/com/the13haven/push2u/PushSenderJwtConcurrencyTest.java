/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static com.the13haven.push2u.PushTestSupport.generateVapidKeys;
import static com.the13haven.push2u.TestVectors.b64;
import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

/**
 * The token cache's locking discipline: look up, release, sign, publish. The signature may be a remote key-service
 * round trip, so it must never run while whatever guards the cache is held — otherwise every send to every audience
 * queues behind one signature, which is the very stall the cache exists to remove, rebuilt in a narrower place. And
 * because {@link PushSender#sendAsync} makes concurrent sends the normal case, two threads missing on one audience at
 * once is expected rather than exceptional: each signs its own valid token, one is published, the other discarded.
 */
class PushSenderJwtConcurrencyTest {

    private static final String AUDIENCE_A_ENDPOINT = "https://push-a.example/sub/1";
    private static final String AUDIENCE_B_ENDPOINT = "https://push-b.example/sub/2";

    /**
     * A signer is held mid-{@code sign} on one audience while another thread completes a cache hit on a second
     * audience. The hit needs the cache's monitor (an access-ordered LRU mutates on a read), so if the blocked
     * signature held that monitor, the hit could not complete until the signature did — and this test would time out
     * instead of passing.
     */
    @Test
    void aCacheHitCompletesWhileASignatureIsInFlight() throws Exception {
        BlockableSigner signer = new BlockableSigner(new LocalEcVapidSigner(generateVapidKeys()));
        PushSender sender = PushSender.builder(signer, "mailto:ops@example.com", EndpointPolicies.unrestricted())
                .httpClient((endpoint, headers, body) -> PushResponse.of(201))
                .build();
        sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message()); // audience A is now cached

        // An explicit pool, never the common pool: these tasks rendezvous (one blocks until the other has
        // finished), so they need one worker each, and the common pool's parallelism — availableProcessors() - 1 —
        // can be smaller than that on a small machine, deadlocking the rendezvous until its bounded waits time out.
        try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
            signer.blockNextSign();
            CompletableFuture<PushResult> blockedMint = CompletableFuture.supplyAsync(
                    () -> sender.send(subscriptionAt(AUDIENCE_B_ENDPOINT), message()), executor);
            assertThat(signer.awaitSignEntered(5, TimeUnit.SECONDS))
                    .as("the miss on audience B reached the signer")
                    .isTrue();

            try {
                PushResult hit = CompletableFuture.supplyAsync(
                                () -> sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message()), executor)
                        .get(5, TimeUnit.SECONDS);
                assertThat(hit.isDelivered())
                        .as("the hit on audience A completed while B's signature was still in flight")
                        .isTrue();
                assertThat(blockedMint.isDone())
                        .as("B's mint really was still in flight when A's hit completed")
                        .isFalse();
            } finally {
                signer.releaseSign();
            }
            assertThat(blockedMint.get(5, TimeUnit.SECONDS).isDelivered()).isTrue();
        }
    }

    /**
     * All threads miss on one audience before any of them publishes — forced by a barrier inside {@code sign}, which no
     * thread passes until every thread has entered it, so every thread has already looked up and found nothing. The
     * race is benign: each send carries its own independently signed token, every one of them verifies against the
     * advertised key, and afterwards exactly one entry serves the audience.
     */
    @Test
    void concurrentMissesOnOneAudienceProduceValidTokens() throws Exception {
        int threads = 4;
        CyclicBarrier allMissed = new CyclicBarrier(threads);
        RecordingClient client = new RecordingClient();
        VapidSigner delegate = new LocalEcVapidSigner(generateVapidKeys());
        AtomicInteger signCalls = new AtomicInteger();
        VapidSigner rendezvousSigner = new VapidSigner() {
            @Override
            public byte[] sign(byte[] signingInput) {
                signCalls.incrementAndGet();
                try {
                    allMissed.await(5, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new PushCryptoException("interrupted at the test barrier", e);
                } catch (BrokenBarrierException | java.util.concurrent.TimeoutException e) {
                    throw new PushCryptoException("the test barrier broke", e);
                }
                return delegate.sign(signingInput);
            }

            @Override
            public byte[] publicKey() {
                return delegate.publicKey();
            }
        };
        PushSender sender = PushSender.builder(
                        rendezvousSigner, "mailto:ops@example.com", EndpointPolicies.unrestricted())
                .httpClient(client)
                .build();

        // An explicit pool with one worker per barrier party, never the common pool: its parallelism is
        // availableProcessors() - 1, so on a 4-vCPU CI runner only three of the four tasks start and a barrier
        // that needs all four can never trip — the waiters deadlock until the await times out.
        List<CompletableFuture<PushResult>> sends = new ArrayList<>();
        try (ExecutorService executor = Executors.newFixedThreadPool(threads)) {
            for (int i = 0; i < threads; i++) {
                sends.add(CompletableFuture.supplyAsync(
                        () -> sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message()), executor));
            }
            for (CompletableFuture<PushResult> send : sends) {
                assertThat(send.get(10, TimeUnit.SECONDS).isDelivered()).isTrue();
            }
        }

        assertThat(signCalls.get())
                .as("every concurrent miss signed its own token")
                .isEqualTo(threads);
        assertThat(client.authorizations()).hasSize(threads);
        for (String authorization : client.authorizations()) {
            assertThat(isValidVapidHeader(authorization))
                    .as("every concurrently minted token verifies against the key its own header advertises")
                    .isTrue();
        }

        assertThat(sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message()).isDelivered())
                .isTrue();
        assertThat(signCalls.get())
                .as("one of the racing tokens was published and now serves the audience")
                .isEqualTo(threads);
    }

    /** Splits a {@code vapid t=<jwt>, k=<key>} header and verifies the JWT's ES256 signature against its own k. */
    private static boolean isValidVapidHeader(String authorization) {
        String jwt = authorization.substring("vapid t=".length(), authorization.indexOf(", k="));
        String key = authorization.substring(authorization.indexOf(", k=") + ", k=".length());
        int lastDot = jwt.lastIndexOf('.');
        byte[] signingInput = jwt.substring(0, lastDot).getBytes(StandardCharsets.US_ASCII);
        byte[] signature = Base64Url.decode(jwt.substring(lastDot + 1));
        return Es256Verifier.verify(Base64Url.decode(key), signingInput, signature);
    }

    private static Subscription subscriptionAt(String endpoint) {
        return new Subscription(endpoint, b64(TestVectors.UA_PUBLIC), b64(TestVectors.AUTH_SECRET));
    }

    private static PushMessage message() {
        return PushMessage.of("x".getBytes(StandardCharsets.UTF_8));
    }

    /** Thread-safe recording client answering 201. */
    private static final class RecordingClient implements PushHttpClient {
        private final List<String> authorizations = Collections.synchronizedList(new ArrayList<>());

        @Override
        public PushResponse post(URI endpoint, Map<String, String> headers, byte[] body) {
            authorizations.add(headers.get("Authorization"));
            return PushResponse.of(201);
        }

        List<String> authorizations() {
            synchronized (authorizations) {
                return new ArrayList<>(authorizations);
            }
        }
    }

    /** Delegates signing, but can hold the next {@code sign} call open until released. */
    private static final class BlockableSigner implements VapidSigner {
        private final VapidSigner delegate;
        private final AtomicBoolean blockNext = new AtomicBoolean();
        private final CountDownLatch entered = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);

        BlockableSigner(VapidSigner delegate) {
            this.delegate = delegate;
        }

        void blockNextSign() {
            blockNext.set(true);
        }

        boolean awaitSignEntered(long timeout, TimeUnit unit) throws InterruptedException {
            return entered.await(timeout, unit);
        }

        void releaseSign() {
            release.countDown();
        }

        @Override
        public byte[] sign(byte[] signingInput) {
            if (blockNext.compareAndSet(true, false)) {
                entered.countDown();
                try {
                    if (!release.await(10, TimeUnit.SECONDS)) {
                        throw new PushCryptoException("the test never released the blocked signature");
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new PushCryptoException("interrupted while blocked in the test signer", e);
                }
            }
            return delegate.sign(signingInput);
        }

        @Override
        public byte[] publicKey() {
            return delegate.publicKey();
        }
    }
}
