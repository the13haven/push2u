/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

import com.the13haven.push2u.PushDeliveryException;
import com.the13haven.push2u.PushResponse;

/**
 * The transport fake's honesty checks: the script plays in order and exhausts loudly, the failing mode records before
 * it throws, and the atomic take-and-record step holds under genuinely concurrent posts.
 */
final class ScriptedPushHttpClientTest {

    private static final URI ENDPOINT = URI.create("https://push.example.net/wp/token");
    private static final byte[] BODY = "ciphertext".getBytes(StandardCharsets.US_ASCII);

    @Test
    void answersTheScriptedStatusesInOrder() {
        ScriptedPushHttpClient client = ScriptedPushHttpClient.respondingWith(429, 429, 201);

        assertThat(client.post(ENDPOINT, Map.of(), BODY).statusCode()).isEqualTo(429);
        assertThat(client.post(ENDPOINT, Map.of(), BODY).statusCode()).isEqualTo(429);
        assertThat(client.post(ENDPOINT, Map.of(), BODY).statusCode()).isEqualTo(201);
    }

    @Test
    void eachScriptedResponseKeepsItsOwnHeaders() {
        ScriptedPushHttpClient client = ScriptedPushHttpClient.respondingWith(
                new PushResponse(429, Map.of("Retry-After", "120")), new PushResponse(429, Map.of("Retry-After", "1")));

        assertThat(client.post(ENDPOINT, Map.of(), BODY).header("Retry-After")).isEqualTo(Optional.of("120"));
        assertThat(client.post(ENDPOINT, Map.of(), BODY).header("Retry-After")).isEqualTo(Optional.of("1"));
    }

    @Test
    void anExhaustedScriptRaisesIllegalStateExceptionAndStillRecordsTheCall() {
        ScriptedPushHttpClient client = ScriptedPushHttpClient.respondingWith(201);
        client.post(ENDPOINT, Map.of(), BODY);

        assertThatThrownBy(() -> client.post(ENDPOINT, Map.of(), BODY))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("exhausted");
        assertThat(client.sent())
                .as("the one POST too many was still attempted, so it is recorded")
                .hasSize(2);
    }

    @Test
    void recordsTheEndpointTheHeadersAndTheBodyLength() {
        ScriptedPushHttpClient client = ScriptedPushHttpClient.respondingWith(201);
        Map<String, String> headers = Map.of("TTL", "60", "Content-Encoding", "aes128gcm");

        client.post(ENDPOINT, headers, BODY);

        SentPush recorded = client.sent().get(0);
        assertThat(recorded.endpoint()).isEqualTo(ENDPOINT);
        assertThat(recorded.headers()).isEqualTo(headers);
        assertThat(recorded.bodyBytes()).isEqualTo(BODY.length);
    }

    @Test
    void failingWithRecordsTheCallBeforeThrowingTheGivenFailure() {
        PushDeliveryException failure = new PushDeliveryException("connection refused");
        ScriptedPushHttpClient client = ScriptedPushHttpClient.failingWith(failure);

        assertThatThrownBy(() -> client.post(ENDPOINT, Map.of(), BODY)).isSameAs(failure);
        assertThat(client.sent())
                .as("the POST was attempted, so the failing call is recorded")
                .hasSize(1);

        assertThatThrownBy(() -> client.post(ENDPOINT, Map.of(), BODY))
                .as("the mode covers every call, not only the first")
                .isSameAs(failure);
        assertThat(client.sent()).hasSize(2);
    }

    @Test
    void sentAnswersAnImmutablePointInTimeSnapshot() {
        ScriptedPushHttpClient client = ScriptedPushHttpClient.respondingWith(201, 201);
        client.post(ENDPOINT, Map.of(), BODY);

        List<SentPush> snapshot = client.sent();
        client.post(ENDPOINT, Map.of(), BODY);

        assertThat(snapshot)
                .as("a snapshot does not grow when later calls arrive")
                .hasSize(1);
        assertThatThrownBy(() -> snapshot.add(snapshot.get(0))).isInstanceOf(UnsupportedOperationException.class);
    }

    /**
     * The atomicity claim under real contention: every concurrent post draws exactly one scripted answer and is
     * recorded, so the answers handed out and the calls recorded both come to exactly the script's size — no answer
     * skipped, none handed out twice, no call lost. A dedicated pool rather than the common one, so the rendezvous
     * cannot starve on a small shared pool.
     */
    @Test
    void concurrentPostsEachDrawOneAnswerAndAllAreRecorded() throws Exception {
        int threads = 8;
        int postsPerThread = 25;
        int totalPosts = threads * postsPerThread;
        int[] followingStatuses = new int[totalPosts - 1];
        Arrays.fill(followingStatuses, 201);
        ScriptedPushHttpClient client = ScriptedPushHttpClient.respondingWith(201, followingStatuses);

        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Future<Integer>> answered = new ArrayList<>();
            for (int thread = 0; thread < threads; thread++) {
                answered.add(pool.submit(() -> {
                    start.await();
                    int count = 0;
                    for (int post = 0; post < postsPerThread; post++) {
                        client.post(ENDPOINT, Map.of(), BODY);
                        count++;
                    }
                    return count;
                }));
            }
            start.countDown();

            int totalAnswered = 0;
            for (Future<Integer> perThread : answered) {
                totalAnswered += perThread.get(30, TimeUnit.SECONDS);
            }
            assertThat(totalAnswered)
                    .as("every post drew an answer — the script never over- or under-ran")
                    .isEqualTo(totalPosts);
        } finally {
            pool.shutdownNow();
        }

        assertThat(client.sent())
                .as("every answered call was recorded, exactly once")
                .hasSize(totalPosts);
    }

    @Test
    void aNegativeStatusIsRefusedAtDeclarationNotAtPostTime() {
        assertThatThrownBy(() -> ScriptedPushHttpClient.respondingWith(201, -1))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
