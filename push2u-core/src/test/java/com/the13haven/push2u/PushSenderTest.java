/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static com.the13haven.push2u.PushTestSupport.generateVapidKeys;
import static com.the13haven.push2u.PushTestSupport.subscription;
import static com.the13haven.push2u.PushTestSupport.trustingPushHttpClient;
import static com.the13haven.push2u.TestVectors.b64;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ForkJoinWorkerThread;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

/**
 * End-to-end send-pipeline tests: a real {@link PushSender} (real RFC 8291 encryption + RFC 8292 VAPID + the JDK HTTP
 * client) against an in-process {@link MockPushReceiver}, asserting the request shape, the VAPID claims of a real
 * request, the {@code Retry-After} reporting and the async execution contract. The full status-code →
 * {@link PushOutcome} classification table (the per-status matrix and its edges) lives in
 * {@link PushSenderStatusClassificationTest}; the seam-signal conversions and the interruption discipline in
 * {@link PushSenderSeamConversionTest}.
 */
class PushSenderTest {

    @Test
    void acceptsOn201AndSendsAWellFormedRequest() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushOutcome outcome = pusher().send(
                            subscription(receiver),
                            PushMessage.builder(bytes("hello"))
                                    .ttl(Duration.ofHours(1))
                                    .build());

            assertThat(outcome).isEqualTo(new PushOutcome.Accepted(201));

            assertThat(receiver.requests()).hasSize(1);
            MockPushReceiver.RecordedRequest request = receiver.requests().getFirst();
            assertThat(request.method()).isEqualTo("POST");
            assertThat(request.headers())
                    .containsEntry("content-encoding", "aes128gcm")
                    .containsEntry("ttl", "3600");
            assertThat(request.headers().get("authorization")).startsWith("vapid t=");
            // aes128gcm body = 86-byte header + plaintext(5) + delimiter(1) + GCM tag(16)
            assertThat(request.bodyLength()).isEqualTo(86 + 5 + 1 + 16);
        }
    }

    @Test
    void audClaimCarriesTheNormalizedRfc6454Origin() {
        // A capturing transport instead of the receiver: the endpoint's uppercase scheme/host and
        // explicit :443 exist purely to exercise the origin serialization, not real delivery.
        AtomicReference<Map<String, String>> captured = new AtomicReference<>();
        PushHttpClient capturingClient = (endpoint, headers, body) -> {
            captured.set(headers);
            return PushResponse.of(201);
        };
        Subscription subscription = new Subscription(
                "HTTPS://PUSH.Example:443/subscriber-token", b64(TestVectors.UA_PUBLIC), b64(TestVectors.AUTH_SECRET));

        PushOutcome outcome = PushSender.builder(
                        generateVapidKeys(), "mailto:ops@example.com", EndpointPolicies.unrestricted())
                .httpClient(capturingClient)
                .build()
                .send(subscription, PushMessage.of(bytes("x")));

        assertThat(outcome).isInstanceOf(PushOutcome.Accepted.class);
        String claims = claimsOf(captured.get().get("Authorization"));
        assertThat(claims)
                .as("aud is the RFC 6454 §6.1 origin: lowercase scheme+host, default port dropped (RFC 8292 §2)")
                .contains("\"aud\":\"https://push.example\"")
                .doesNotContain("PUSH.Example")
                .doesNotContain(":443");
    }

    @Test
    void expClaimOfASentRequestIsThePinnedClockPlusTheConfiguredExpiry() throws IOException {
        // RFC 8292 §2 caps exp at 24 hours after the request; the builder already rejects a larger
        // configuration (PushSenderOptionsTest), so what is left unproven is the request itself:
        // exp must be exactly clock-now plus the configured expiry. Configuring the 24h ceiling
        // makes the equality double as the RFC bound — an arithmetic slip that lands exp even one
        // second later produces a JWT every push service is entitled to answer with 401.
        Instant now = Instant.parse("2030-01-01T00:00:00Z");
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushSender pusher = PushSender.builder(
                            generateVapidKeys(), "mailto:ops@example.com", EndpointPolicies.unrestricted())
                    .httpClient(trustingPushHttpClient())
                    .clock(Clock.fixed(now, ZoneOffset.UTC))
                    .jwtExpiry(Duration.ofHours(24))
                    .build();

            PushOutcome outcome = pusher.send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(outcome).isInstanceOf(PushOutcome.Accepted.class);
            String claims = claimsOf(receiver.requests().getFirst().headers().get("authorization"));
            assertThat(claims)
                    .as("exp is exactly now + 24h, the RFC 8292 §2 maximum (the trailing comma pins"
                            + " the whole number, not a prefix of a larger one)")
                    .contains("\"exp\":" + now.plus(Duration.ofHours(24)).getEpochSecond() + ",");
        }
    }

    @Test
    void expClaimDefaultsToTwelveHoursAfterTheClock() throws IOException {
        // Pins the documented builder default: a sender that never calls jwtExpiry() must sign
        // 12h ahead, not silently drift to some other offset the Javadoc no longer matches.
        Instant now = Instant.parse("2030-01-01T00:00:00Z");
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushSender pusher = PushSender.builder(
                            generateVapidKeys(), "mailto:ops@example.com", EndpointPolicies.unrestricted())
                    .httpClient(trustingPushHttpClient())
                    .clock(Clock.fixed(now, ZoneOffset.UTC))
                    .build();

            PushOutcome outcome = pusher.send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(outcome).isInstanceOf(PushOutcome.Accepted.class);
            String claims = claimsOf(receiver.requests().getFirst().headers().get("authorization"));
            assertThat(claims)
                    .contains("\"exp\":" + now.plus(Duration.ofHours(12)).getEpochSecond() + ",");
        }
    }

    // ---- what the outcome reports of Retry-After -----------------------------------------------
    //
    // The value is parsed by the sender and published on the retryable variant for the caller's
    // scheduler; the send itself makes exactly one POST whatever the header says. The parser's own
    // conformance vectors live in RetryAfterTest — these tests pin that its output reaches the
    // outcome, unclamped.

    @Test
    void reportsDeltaSecondsRetryAfterOnThe429Outcome() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.respondWith(429, "2");

            PushOutcome outcome = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(outcome).isEqualTo(new PushOutcome.RetryableFailure(429, Optional.of(Duration.ofSeconds(2))));
            assertThat(receiver.requests())
                    .as("the hint is reported, never acted on: one POST only")
                    .hasSize(1);
        }
    }

    @Test
    void reportsHttpDateRetryAfterAgainstThePinnedClock() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.respondWith(503, "Tue, 01 Jan 2030 00:00:30 GMT");
            PushSender pusher = PushSender.builder(
                            generateVapidKeys(), "mailto:ops@example.com", EndpointPolicies.unrestricted())
                    .httpClient(trustingPushHttpClient())
                    .clock(Clock.fixed(Instant.parse("2030-01-01T00:00:00Z"), ZoneOffset.UTC))
                    .build();

            PushOutcome outcome = pusher.send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(outcome).isEqualTo(new PushOutcome.RetryableFailure(503, Optional.of(Duration.ofSeconds(30))));
        }
    }

    @Test
    void anUnparseableRetryAfterIsReportedAsNoHintAtAll() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.respondWith(429, "soon");

            PushOutcome outcome = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(outcome)
                    .as("a header the grammar rejects degrades to an empty hint, never to a failed send")
                    .isEqualTo(new PushOutcome.RetryableFailure(429, Optional.empty()));
        }
    }

    @Test
    void anOverflowingRetryAfterIsReportedAsNoHintAtAll() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.respondWith(429, "99999999999999999999");

            PushOutcome outcome = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(outcome)
                    .as("delta-seconds beyond a long are treated as unparseable, not propagated")
                    .isEqualTo(new PushOutcome.RetryableFailure(429, Optional.empty()));
        }
    }

    @Test
    void aLargeRetryAfterIsReportedWithNoCeilingApplied() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            receiver.respondWith(429, "3600");

            PushOutcome outcome = pusher().send(subscription(receiver), PushMessage.of(bytes("x")));

            assertThat(outcome)
                    .as("the value that arrived is the value reported — the caller's ceiling is the only one")
                    .isEqualTo(new PushOutcome.RetryableFailure(429, Optional.of(Duration.ofSeconds(3600))));
        }
    }

    // ---- the async execution contract ----------------------------------------------------------

    @Test
    void sendAsyncCompletesWithTheOutcome() throws Exception {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushOutcome outcome = pusher().sendAsync(subscription(receiver), PushMessage.of(bytes("x")))
                    .get(5, TimeUnit.SECONDS);
            assertThat(outcome).isInstanceOf(PushOutcome.Accepted.class);
        }
    }

    @Test
    void sendAsyncDefaultRunsOnAVirtualThreadNotTheCommonPool() throws Exception {
        AtomicReference<Thread> sendThread = new AtomicReference<>();
        PushHttpClient capturingClient = (endpoint, headers, body) -> {
            sendThread.set(Thread.currentThread());
            return PushResponse.of(201);
        };
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushOutcome outcome = PushSender.builder(
                            generateVapidKeys(), "mailto:ops@example.com", EndpointPolicies.unrestricted())
                    .httpClient(capturingClient)
                    .build()
                    .sendAsync(subscription(receiver), PushMessage.of(bytes("x")))
                    .get(5, TimeUnit.SECONDS);

            assertThat(outcome).isInstanceOf(PushOutcome.Accepted.class);
            Thread thread = sendThread.get();
            assertThat(thread.isVirtual())
                    .as("the default async executor runs each send on a virtual thread")
                    .isTrue();
            assertThat(thread)
                    .as("a blocking send must never occupy a common-ForkJoinPool worker")
                    .isNotInstanceOf(ForkJoinWorkerThread.class);
        }
    }

    @Test
    void sendAsyncRunsOnTheConfiguredExecutor() throws Exception {
        AtomicReference<Thread> executorThread = new AtomicReference<>();
        ExecutorService executor = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "push2u-configured-executor");
            executorThread.set(thread);
            return thread;
        });
        AtomicReference<Thread> sendThread = new AtomicReference<>();
        PushHttpClient capturingClient = (endpoint, headers, body) -> {
            sendThread.set(Thread.currentThread());
            return PushResponse.of(201);
        };
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushOutcome outcome = PushSender.builder(
                            generateVapidKeys(), "mailto:ops@example.com", EndpointPolicies.unrestricted())
                    .httpClient(capturingClient)
                    .executor(executor)
                    .build()
                    .sendAsync(subscription(receiver), PushMessage.of(bytes("x")))
                    .get(5, TimeUnit.SECONDS);

            assertThat(outcome).isInstanceOf(PushOutcome.Accepted.class);
            assertThat(sendThread.get())
                    .as("the send runs on the single thread of the executor passed to .executor(...)")
                    .isSameAs(executorThread.get());
        } finally {
            executor.shutdown();
        }
    }

    @Test
    void sendAsyncPropagatesAnExecutorRejectionSynchronously() throws IOException {
        // CompletableFuture.supplyAsync calls execute() inline, so a rejecting executor throws
        // out of sendAsync rather than completing the returned future exceptionally — callers
        // that only attach an exception handler to the future would otherwise miss it.
        Executor rejecting = runnable -> {
            throw new RejectedExecutionException("saturated");
        };
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            PushSender pusher = PushSender.builder(
                            generateVapidKeys(), "mailto:ops@example.com", EndpointPolicies.unrestricted())
                    .executor(rejecting)
                    .build();
            Subscription subscription = subscription(receiver);
            PushMessage message = PushMessage.of(bytes("x"));

            assertThatThrownBy(() -> pusher.sendAsync(subscription, message))
                    .isInstanceOf(RejectedExecutionException.class)
                    .hasMessage("saturated");
        }
    }

    @Test
    void externalSignerPathDelivers() throws IOException {
        try (MockPushReceiver receiver = new MockPushReceiver()) {
            VapidSigner externalSigner = new LocalEcVapidSigner(generateVapidKeys());
            PushSender pusher = PushSender.builder(
                            externalSigner, "mailto:ops@example.com", EndpointPolicies.unrestricted())
                    .httpClient(trustingPushHttpClient())
                    .build();

            assertThat(pusher.send(subscription(receiver), PushMessage.of(bytes("x"))))
                    .isInstanceOf(PushOutcome.Accepted.class);
        }
    }

    // The same full pipeline with BC-FIPS as the crypto provider (the ES256 DER fallback) lives
    // in BcFipsPushSenderTest in the fipsTest source set — bc-fips cannot share a classpath with
    // the stock bcprov this source set carries.

    // A sender without a key source, with two key sources, or without a contact no longer has a
    // test because it no longer has a runtime failure: the factory overloads each take exactly one
    // key source plus the contact, so none of those states compile.

    @Test
    void theFactoryRejectsABlankContact() {
        // A blank contact would still build a JWT carrying an empty/whitespace 'sub' claim, which
        // satisfies push2u's contact contract no better than the omission RFC 8292 §2.1 permits —
        // reject it at the factory rather than ship a claim a push service may or may not refuse.
        // The value is present but invalid, so this is IllegalArgumentException — a *missing*
        // required value is inexpressible.
        VapidKeys keys = generateVapidKeys();

        assertThatThrownBy(() -> PushSender.builder(keys, "   ", EndpointPolicies.unrestricted()))
                .as("keys overload")
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("contact is required");
        assertThatThrownBy(() -> PushSender.builder(new LocalEcVapidSigner(keys), "", EndpointPolicies.unrestricted()))
                .as("signer overload")
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("contact is required");
    }

    @Test
    void theFactoryRejectsANullEndpointPolicy() {
        // The policy is a required argument, so omitting it does not compile; null is the one way
        // to express "no policy" that still typechecks, and it is refused at the factory like every
        // other present-but-invalid value. A deployment wanting no restriction says
        // EndpointPolicies.unrestricted(), which is a token in its own source.
        VapidKeys keys = generateVapidKeys();

        assertThatThrownBy(() -> PushSender.builder(keys, "mailto:ops@example.com", null))
                .as("keys overload")
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("endpointPolicy");
        assertThatThrownBy(() -> PushSender.builder(new LocalEcVapidSigner(keys), "mailto:ops@example.com", null))
                .as("signer overload")
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("endpointPolicy");
    }

    @Test
    void bothFactoryOverloadsRunThePolicyTheyWereGiven() {
        // The two entry points differ only in the key source; neither may lose the policy on the
        // way to the sender. Proven by refusal, not by a getter: a policy that refuses everything
        // must stop a send through either overload — as the EndpointRejected outcome, since a
        // policy refusal is a value the fan-out records rather than an exception that aborts it.
        VapidKeys keys = generateVapidKeys();
        EndpointPolicy refuseEverything = endpoint -> {
            throw new EndpointRejectedException("refused by test policy");
        };
        Subscription subscription = new Subscription(
                "https://push.example.com/never-contacted",
                TestVectors.b64(TestVectors.UA_PUBLIC),
                TestVectors.b64(TestVectors.AUTH_SECRET));
        PushMessage message = PushMessage.of(bytes("x"));

        PushSender fromKeys = PushSender.builder(keys, "mailto:ops@example.com", refuseEverything)
                .httpClient((endpoint, headers, body) -> PushResponse.of(201))
                .build();
        PushSender fromSigner = PushSender.builder(
                        new LocalEcVapidSigner(keys), "mailto:ops@example.com", refuseEverything)
                .httpClient((endpoint, headers, body) -> PushResponse.of(201))
                .build();

        assertThat(fromKeys.send(subscription, message))
                .as("keys overload")
                .isInstanceOf(PushOutcome.EndpointRejected.class);
        assertThat(fromSigner.send(subscription, message))
                .as("signer overload")
                .isInstanceOf(PushOutcome.EndpointRejected.class);
    }

    private PushSender pusher() {
        return PushSender.builder(generateVapidKeys(), "mailto:ops@example.com", EndpointPolicies.unrestricted())
                // The real JdkPushHttpClient, trusting the receiver's per-JVM TLS certificate —
                // the sends here traverse an actual https handshake, same as production.
                .httpClient(trustingPushHttpClient())
                .build();
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    /** The decoded claims JSON of the JWT inside a {@code vapid t=<jwt>, k=<key>} Authorization header. */
    private static String claimsOf(String authorization) {
        String jwt = authorization.substring("vapid t=".length(), authorization.indexOf(", k="));
        return new String(Base64Url.decode(jwt.split("\\.", -1)[1]), StandardCharsets.UTF_8);
    }
}
