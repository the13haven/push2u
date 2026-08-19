/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.testcontainers.vault.VaultContainer;

import com.the13haven.push2u.EndpointPolicies;
import com.the13haven.push2u.EndpointPolicy;
import com.the13haven.push2u.EndpointRule;
import com.the13haven.push2u.PushMessage;
import com.the13haven.push2u.PushOutcome;
import com.the13haven.push2u.PushResponse;
import com.the13haven.push2u.PushSender;
import com.the13haven.push2u.Subscription;
import com.the13haven.push2u.VapidSigner;

/**
 * The other half of the hot-path measurement: what a Transit signature costs per message. The Vault here runs in a
 * container on the same machine, so every number below is a <b>lower bound</b> — a real deployment adds the network
 * between the sender and Vault, plus TLS, which this dev-mode container does not speak.
 *
 * <p>Sequential on purpose: the question is what one message pays on the critical path, not what throughput a pool of
 * threads can reach.
 */
@EnabledIfSystemProperty(
        named = "push2u.measure",
        matches = "true",
        disabledReason = "measurement suite, not a test — run with -Dpush2u.measure=true")
class VaultHotPathMeasurement {

    private static final String ROOT_TOKEN = "push2u-test-root";
    private static final String MOUNT = "transit";
    private static final String KEY_NAME = "vapid";

    private static final Duration WARMUP = Duration.ofMillis(300);
    private static final Duration MEASURE = Duration.ofMillis(400);
    private static final int REPEATS = 5;

    private static VaultContainer<?> vault;

    private long sink;

    @BeforeAll
    @SuppressWarnings("resource") // the container lives across the measurement; it is closed in @AfterAll
    static void startVault() {
        vault = new VaultContainer<>("hashicorp/vault:1.18")
                .withVaultToken(ROOT_TOKEN)
                .withInitCommand(
                        "secrets enable " + MOUNT, "write " + MOUNT + "/keys/" + KEY_NAME + " type=ecdsa-p256");
        vault.start();
    }

    @AfterAll
    static void stopVault() {
        if (vault != null) {
            vault.stop();
        }
    }

    @Test
    void measureTheVaultHotPath() {
        VapidSigner signer = VaultTransitVapidSigner.builderWithFetchedPublicKey(
                        URI.create(vault.getHttpHostAddress()),
                        new TransitKeyName(KEY_NAME),
                        new VaultToken(ROOT_TOKEN))
                .allowInsecureHttp()
                .build();
        // The deferred mode reads Vault on first use rather than at construction. Both modes end
        // up serving the same retained pair through one volatile read, and the row below is here
        // to say so rather than to leave it assumed. publicKey() is itself a first use, so the
        // single fetch is paid by the first call of that step's warm-up and falls outside every
        // measured repetition — which is what the row is meant to report, the retained read and
        // not the fetch.
        VapidSigner deferredSigner = VaultTransitVapidSigner.builderWithDeferredPublicKeyFetch(
                        URI.create(vault.getHttpHostAddress()),
                        new TransitKeyName(KEY_NAME),
                        new VaultToken(ROOT_TOKEN))
                .allowInsecureHttp()
                .build();

        byte[] signingInput = "push2u hot path measurement".getBytes(StandardCharsets.US_ASCII);

        URI endpoint = URI.create("https://fcm.googleapis.com/fcm/send/f1LsxkKpMr4:APA91bG7-opaque-capability-token");
        EndpointPolicy policy = EndpointPolicies.allowedEndpoints(EndpointRule.origin("https://fcm.googleapis.com"));
        Subscription subscription =
                Subscription.fromBase64(endpoint.toString(), generateUaPublicKey(), "BTBZMqHH6r4Tts7J_aSIgg");
        PushMessage message =
                PushMessage.builder("hot path".getBytes(StandardCharsets.UTF_8)).build();
        // The default sender signs once per push-service origin and reuses the token; the second
        // signs on every send, which is what every send did before the cache existed. Against a
        // remote custodian that is the difference between a Transit round trip on the message's
        // critical path and none at all, so the two are measured rather than reasoned about.
        PushSender reusingSender = PushSender.builder(signer, "mailto:push@example.com", policy)
                .httpClient((uri, headers, body) -> new PushResponse(201, Map.of()))
                .build();
        PushSender signingSender = PushSender.builder(signer, "mailto:push@example.com", policy)
                .httpClient((uri, headers, body) -> new PushResponse(201, Map.of()))
                .jwtReuse(false)
                .build();

        List<Result> results = new ArrayList<>();
        results.add(measure("VaultTransitVapidSigner.publicKey() — eager mode", () -> sink(signer.publicKey().length)));
        results.add(measure(
                "VaultTransitVapidSigner.sign() — Transit round trip", () -> sink(signer.sign(signingInput).length)));
        results.add(measure(
                "VaultTransitVapidSigner.publicKey() — deferred mode", () -> sink(deferredSigner.publicKey().length)));
        results.add(measure(
                "PushSender.send with Vault, cached token", () -> accepted(reusingSender.send(subscription, message))));
        results.add(measure(
                "PushSender.send with Vault, signing every time",
                () -> accepted(signingSender.send(subscription, message))));

        report(results);
    }

    private long sink(long value) {
        return value;
    }

    /**
     * The status of an accepted outcome, refusing anything else: a send that never reached the transport is a different
     * and much cheaper path, and measuring it under the send's name is the one failure worth stopping for.
     */
    private static long accepted(PushOutcome outcome) {
        if (outcome instanceof PushOutcome.Accepted acceptedOutcome) {
            return acceptedOutcome.statusCode();
        }
        throw new IllegalStateException("the measured send did not reach the transport: " + outcome);
    }

    /** A real on-curve P-256 point in the X9.62 uncompressed form the subscription constructor requires. */
    private static String generateUaPublicKey() {
        try {
            java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("EC");
            generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
            java.security.spec.ECPoint point = ((java.security.interfaces.ECPublicKey)
                            generator.generateKeyPair().getPublic())
                    .getW();
            byte[] uncompressed = new byte[65];
            uncompressed[0] = 0x04;
            writeCoordinate(point.getAffineX(), uncompressed, 1);
            writeCoordinate(point.getAffineY(), uncompressed, 33);
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(uncompressed);
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void writeCoordinate(java.math.BigInteger value, byte[] out, int offset) {
        byte[] raw = value.toByteArray();
        int length = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - length, out, offset + 32 - length, length);
    }

    private Result measure(String name, LongSupplier step) {
        driveCounted(step, WARMUP.toNanos());
        List<Double> nanosPerOp = new ArrayList<>();
        for (int repeat = 0; repeat < REPEATS; repeat++) {
            long[] driven = driveCounted(step, MEASURE.toNanos());
            nanosPerOp.add((double) driven[1] / driven[0]);
        }
        nanosPerOp.sort(Double::compareTo);
        return new Result(name, nanosPerOp.get(REPEATS / 2), nanosPerOp.get(0));
    }

    private long[] driveCounted(LongSupplier step, long budgetNanos) {
        long operations = 0;
        long start = System.nanoTime();
        long elapsed;
        do {
            // Batched for the same reason the core suite batches: one System.nanoTime() per
            // iteration is ~12 ns on this platform, which is most of what a field clone costs and
            // would be reported as if it were the step.
            for (int i = 0; i < 16; i++) {
                sink += step.getAsLong();
            }
            operations += 16;
            elapsed = System.nanoTime() - start;
        } while (elapsed < budgetNanos);
        return new long[] {operations, elapsed};
    }

    private void report(List<Result> results) {
        StringBuilder out = new StringBuilder(512);
        out.append(System.lineSeparator())
                .append("=== push2u: Vault Transit hot path (container on this machine) ===")
                .append(System.lineSeparator())
                .append(String.format("%-58s %14s %14s%n", "step", "median", "best"));
        for (Result result : results) {
            out.append(
                    String.format("%-58s %14s %14s%n", result.name(), format(result.median()), format(result.best())));
        }
        out.append(System.lineSeparator())
                .append("JVM: ")
                .append(System.getProperty("java.vm.name"))
                .append(' ')
                .append(System.getProperty("java.version"))
                .append(" · ")
                .append(System.getProperty("os.name"))
                .append(' ')
                .append(System.getProperty("os.arch"))
                .append(" · ")
                .append(Runtime.getRuntime().availableProcessors())
                .append(" CPU")
                .append(System.lineSeparator())
                .append("sink=")
                .append(sink)
                .append(System.lineSeparator());
        System.out.println(out);
    }

    private static String format(double nanos) {
        if (nanos < 1_000) {
            return String.format("%.0f ns", nanos);
        }
        if (nanos < 1_000_000) {
            return String.format("%.1f us", nanos / 1_000);
        }
        return String.format("%.2f ms", nanos / 1_000_000);
    }

    private record Result(String name, double median, double best) {}
}
