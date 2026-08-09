/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

/**
 * Measures the per-message path step by step, for every JCE provider the library can be configured with, so that a
 * performance claim in {@code docs/PERFORMANCE.md} rests on numbers that can be reproduced rather than on intuition
 * about which step is expensive.
 *
 * <p><b>Opt-in.</b> It spends wall clock on purpose and asserts nothing, so it never runs in CI:
 *
 * <pre>{@code
 * ./gradlew :push2u-core:test --tests "*HotPathMeasurement" -Dpush2u.measure=true
 * }</pre>
 *
 * <p>Not a JMH benchmark: no forks, no dead-code elimination analysis beyond the sink below, no statistics past a
 * median. The resolution it claims is an order of magnitude, which is the resolution the questions it answers need —
 * whether a step is worth optimising at all, and whether one provider is in a different class from another. Every step
 * is driven for a fixed wall-clock budget after a warm-up of the same shape, repeated, and reported as the median and
 * the best of those repetitions; results are summed into a sink that is printed, so no step can be optimised away as
 * dead code.
 */
@EnabledIfSystemProperty(
        named = "push2u.measure",
        matches = "true",
        disabledReason = "measurement suite, not a test — run with -Dpush2u.measure=true")
class HotPathMeasurement {

    private static final Duration WARMUP = Duration.ofMillis(400);
    private static final Duration MEASURE = Duration.ofMillis(500);
    private static final int REPEATS = 5;

    /** The endpoint shape the policy and the origin serialization actually work on. */
    private static final URI ENDPOINT =
            URI.create("https://fcm.googleapis.com/fcm/send/f1LsxkKpMr4:APA91bG7-opaque-capability-token");

    private long sink;

    @Test
    void measureTheSendHotPath() {
        List<Named> providers =
                List.of(new Named("JDK (SunEC/SunJCE)", null), new Named("BouncyCastle", bouncyCastle()));

        Map<String, Map<String, Double>> table = new LinkedHashMap<>();
        measureProviderIndependent(table);
        for (Named provider : providers) {
            measureProvider(provider, table);
        }

        report(providers, table);
    }

    /** Steps that touch no JCE provider at all: they are measured once and shared by every column. */
    private void measureProviderIndependent(Map<String, Map<String, Double>> table) {
        EndpointPolicy policy = standardPolicy();
        String audience = Origin.serialize(ENDPOINT);
        Instant expiry = Instant.now().plus(Duration.ofHours(12));

        record(
                table,
                "Origin.serialize",
                null,
                measure(() -> sink(Origin.serialize(ENDPOINT).length())));
        record(table, "EndpointPolicy.validate", null, measure(() -> {
            policy.validate(ENDPOINT);
            return 1;
        }));
        record(
                table,
                "Vapid.signingInput (JSON + base64url)",
                null,
                measure(() -> sink(Vapid.signingInput(audience, TestVectors.VAPID_SUBJECT, expiry)
                        .length())));
    }

    private void measureProvider(Named named, Map<String, Map<String, Double>> table) {
        Provider provider = named.provider();
        Jca jca = provider == null ? Jca.platform() : Jca.using(provider);
        Base64.Decoder b64 = Base64.getUrlDecoder();

        byte[] uaPublic = b64.decode(TestVectors.UA_PUBLIC);
        byte[] authSecret = b64.decode(TestVectors.AUTH_SECRET);
        byte[] salt = b64.decode(TestVectors.SALT);
        byte[] plaintext = TestVectors.PLAINTEXT.getBytes(StandardCharsets.UTF_8);

        VapidKeys vapidKeys = VapidKeys.fromBase64(TestVectors.AS_PUBLIC, TestVectors.AS_PRIVATE);
        LocalEcVapidSigner signer = new LocalEcVapidSigner(vapidKeys, jca);

        WebPushEncryptor encryptor = new WebPushEncryptor(jca);
        Hkdf hkdf = new Hkdf(jca);

        // Fixed halves for the deterministic encrypt overload — the shape the RFC 8291 vector test uses.
        ECPublicKey uaKey = EcKeys.decodeP256PublicKey(uaPublic, jca);
        KeyPair fixedEphemeral = EcKeys.generateP256(jca);
        ECPrivateKey ephemeralPrivate = (ECPrivateKey) fixedEphemeral.getPrivate();
        ECPublicKey ephemeralPublic = (ECPublicKey) fixedEphemeral.getPublic();
        byte[] ecdhSecret = EcKeys.ecdh(ephemeralPrivate, uaKey, jca);

        Subscription subscription =
                Subscription.fromBase64(ENDPOINT.toString(), TestVectors.UA_PUBLIC, TestVectors.AUTH_SECRET);
        PushMessage message = PushMessage.builder(plaintext).build();
        PushSender.Builder builder = PushSender.builder(vapidKeys, TestVectors.VAPID_SUBJECT, standardPolicy())
                .httpClient((uri, headers, body) -> new PushResponse(201, Map.of()));
        PushSender sender = (provider == null ? builder : builder.cryptoProvider(provider)).build();

        String audience = Origin.serialize(ENDPOINT);
        Instant expiry = Instant.now().plus(Duration.ofHours(12));
        String label = named.label();

        record(
                table,
                "getInstance: ECDH",
                label,
                measure(() -> sink(jca.ecdh().getAlgorithm().length())));
        record(
                table,
                "getInstance: EC KeyFactory",
                label,
                measure(() -> sink(jca.ecKeyFactory().getAlgorithm().length())));
        record(
                table,
                "Decode p256dh (on-curve check included)",
                label,
                measure(() -> sink(EcKeys.decodeP256PublicKey(uaPublic, jca)
                        .getW()
                        .getAffineX()
                        .bitLength())));
        record(
                table,
                "Ephemeral P-256 key pair",
                label,
                measure(() -> sink(EcKeys.generateP256(jca).getPublic().getEncoded().length)));
        record(table, "ECDH", label, measure(() -> sink(EcKeys.ecdh(ephemeralPrivate, uaKey, jca).length)));
        record(table, "HKDF: 2 extract + 3 expand", label, measure(() -> {
            byte[] prkKey = hkdf.extract(authSecret, ecdhSecret);
            byte[] ikm = hkdf.expand(prkKey, authSecret, 32);
            byte[] prk = hkdf.extract(salt, ikm);
            byte[] cek = hkdf.expand(prk, authSecret, 16);
            byte[] nonce = hkdf.expand(prk, authSecret, 12);
            return sink(cek.length + nonce.length);
        }));
        record(
                table,
                "encrypt without keygen (decode + ECDH + HKDF + GCM)",
                label,
                measure(() -> sink(encryptor.encrypt(
                                uaPublic, authSecret, plaintext, 4096, ephemeralPrivate, ephemeralPublic, salt)
                        .length)));
        record(
                table,
                "encrypt whole (+ ephemeral pair and salt)",
                label,
                measure(() -> sink(encryptor.encrypt(uaPublic, authSecret, plaintext, 4096).length)));
        record(
                table,
                "VAPID signature (ES256, local)",
                label,
                measure(() -> sink(signer.sign(Vapid.signingInput(audience, TestVectors.VAPID_SUBJECT, expiry)
                                .getBytes(StandardCharsets.US_ASCII))
                        .length)));
        record(
                table,
                "Authorization whole (JWT + signature + k)",
                label,
                measure(() -> sink(Vapid.authorizationHeader(signer, audience, TestVectors.VAPID_SUBJECT, expiry)
                        .length())));
        record(
                table,
                "PushSender.send without the network",
                label,
                measure(() -> sink(sender.send(subscription, message).statusCode())));
    }

    private static EndpointPolicy standardPolicy() {
        return EndpointPolicies.allowedEndpoints(
                EndpointRule.origin("https://fcm.googleapis.com"),
                EndpointRule.domain("push.apple.com"),
                EndpointRule.domain("notify.windows.com"),
                EndpointRule.origin("https://updates.push.services.mozilla.com"));
    }

    private static Provider bouncyCastle() {
        // Passed to the library as an object rather than registered in Security: registering it
        // would change the provider order for every other test in this JVM.
        return new BouncyCastleProvider();
    }

    /** Which ES256 name a provider registers decides whether the library signs directly or re-encodes DER. */
    private static String es256Resolution(@Nullable Provider provider) {
        try {
            if (provider == null) {
                Signature.getInstance("SHA256withECDSAinP1363Format");
            } else {
                Signature.getInstance("SHA256withECDSAinP1363Format", provider);
            }
            return "native r||s (SHA256withECDSAinP1363Format)";
        } catch (NoSuchAlgorithmException noP1363) {
            return "DER + re-encoding (SHA256withECDSA)";
        }
    }

    private long sink(long value) {
        return value;
    }

    private void record(
            Map<String, Map<String, Double>> table, String step, @Nullable String providerLabel, Result result) {
        table.computeIfAbsent(step, key -> new LinkedHashMap<>())
                .put(providerLabel == null ? "*" : providerLabel, result.median());
    }

    private Result measure(LongSupplier step) {
        driveCounted(step, WARMUP.toNanos());
        List<Double> nanosPerOp = new ArrayList<>();
        for (int repeat = 0; repeat < REPEATS; repeat++) {
            long[] driven = driveCounted(step, MEASURE.toNanos());
            nanosPerOp.add((double) driven[1] / driven[0]);
        }
        nanosPerOp.sort(Double::compareTo);
        return new Result(nanosPerOp.get(REPEATS / 2), nanosPerOp.get(0));
    }

    /** Runs {@code step} until the budget is spent; returns {@code [operations, elapsedNanos]}. */
    private long[] driveCounted(LongSupplier step, long budgetNanos) {
        long operations = 0;
        long start = System.nanoTime();
        long elapsed;
        do {
            // A batch keeps System.nanoTime() out of the measured cost for the cheapest steps
            // without letting an expensive one overshoot the budget by much.
            for (int i = 0; i < 16; i++) {
                sink += step.getAsLong();
            }
            operations += 16;
            elapsed = System.nanoTime() - start;
        } while (elapsed < budgetNanos);
        return new long[] {operations, elapsed};
    }

    private void report(List<Named> providers, Map<String, Map<String, Double>> table) {
        StringBuilder out = new StringBuilder(2048);
        out.append(System.lineSeparator())
                .append("=== push2u: per-message hot path, medians ===")
                .append(System.lineSeparator());
        out.append(String.format("%-46s", "step"));
        for (Named provider : providers) {
            out.append(String.format("%22s", provider.label()));
        }
        out.append(System.lineSeparator());

        for (Map.Entry<String, Map<String, Double>> row : table.entrySet()) {
            out.append(String.format("%-46s", row.getKey()));
            Map<String, Double> byProvider = row.getValue();
            for (Named provider : providers) {
                Double value = byProvider.containsKey("*") ? byProvider.get("*") : byProvider.get(provider.label());
                out.append(String.format("%22s", value == null ? "—" : format(value)));
            }
            out.append(System.lineSeparator());
        }

        out.append(System.lineSeparator());
        for (Named provider : providers) {
            out.append(provider.label())
                    .append(": ES256 — ")
                    .append(es256Resolution(provider.provider()))
                    .append(System.lineSeparator());
        }
        out.append("JVM: ")
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

    private record Named(String label, @Nullable Provider provider) {}

    private record Result(double median, double best) {}
}
