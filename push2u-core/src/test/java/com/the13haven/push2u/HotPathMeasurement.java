/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.net.URI;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;

import org.junit.jupiter.api.Test;

/**
 * Measures the per-message hot path step by step, so that an optimisation decision rests on numbers rather than on
 * intuition about which step is expensive. Not a JMH benchmark and not a regression gate: it establishes orders of
 * magnitude, which is the resolution the question needs (is the local cryptography within one decade of the network
 * calls, or three?). Every step is driven for a fixed wall-clock budget after a warm-up of the same shape, repeated,
 * and reported as the median and the best of those repetitions — the best being the one least contaminated by GC and
 * by whatever else the machine was doing.
 *
 * <p>Results are consumed into a sink that is printed at the end, so a step cannot be optimised away as dead code.
 */
class HotPathMeasurement {

    private static final Duration WARMUP = Duration.ofMillis(400);
    private static final Duration MEASURE = Duration.ofMillis(500);
    private static final int REPEATS = 5;

    private long sink;

    @Test
    void measureTheSendHotPath() {
        Jca jca = Jca.platform();
        Base64.Decoder b64 = Base64.getUrlDecoder();

        byte[] uaPublic = b64.decode(TestVectors.UA_PUBLIC);
        byte[] authSecret = b64.decode(TestVectors.AUTH_SECRET);
        byte[] salt = b64.decode(TestVectors.SALT);
        byte[] plaintext = TestVectors.PLAINTEXT.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        VapidKeys vapidKeys = VapidKeys.fromBase64(TestVectors.AS_PUBLIC, TestVectors.AS_PRIVATE);
        LocalEcVapidSigner signer = new LocalEcVapidSigner(vapidKeys);

        // A real capability URL shape: the host is what the policy and the origin serialization work on.
        URI endpoint = URI.create("https://fcm.googleapis.com/fcm/send/f1LsxkKpMr4:APA91bG7-verylongopaquecapabilitytoken");
        EndpointPolicy policy = EndpointPolicies.allowedEndpoints(
                EndpointRule.origin("https://fcm.googleapis.com"),
                EndpointRule.domain("push.apple.com"),
                EndpointRule.domain("notify.windows.com"),
                EndpointRule.origin("https://updates.push.services.mozilla.com"));

        WebPushEncryptor encryptor = new WebPushEncryptor(jca);
        Hkdf hkdf = new Hkdf(jca);

        // Fixed halves for the deterministic encrypt overload — the same shape the RFC 8291 vector test uses.
        ECPublicKey uaKey = EcKeys.decodeP256PublicKey(uaPublic, jca);
        KeyPair fixedEphemeral = EcKeys.generateP256(jca);
        ECPrivateKey ephemeralPrivate = (ECPrivateKey) fixedEphemeral.getPrivate();
        ECPublicKey ephemeralPublic = (ECPublicKey) fixedEphemeral.getPublic();
        byte[] ecdhSecret = EcKeys.ecdh(ephemeralPrivate, uaKey, jca);

        Subscription subscription = Subscription.fromBase64(endpoint.toString(), TestVectors.UA_PUBLIC, TestVectors.AUTH_SECRET);
        PushMessage message = PushMessage.builder(plaintext).build();
        PushSender sender = PushSender.builder(vapidKeys, TestVectors.VAPID_SUBJECT, policy)
                .httpClient((uri, headers, body) -> new PushResponse(201, Map.of()))
                .build();

        String audience = Origin.serialize(endpoint);
        Instant expiry = Instant.now().plus(Duration.ofHours(12));

        List<Result> results = new ArrayList<>();
        results.add(measure("Origin.serialize(endpoint)", () -> sink(Origin.serialize(endpoint).length())));
        results.add(measure("EndpointPolicy.validate(endpoint)", () -> {
            policy.validate(endpoint);
            return 1;
        }));
        results.add(measure("EcKeys.decodeP256PublicKey (p256dh)", () -> sink(
                EcKeys.decodeP256PublicKey(uaPublic, jca).getW().getAffineX().bitLength())));
        results.add(measure("EcKeys.generateP256 (эфемерная пара)", () -> sink(
                EcKeys.generateP256(jca).getPublic().getEncoded().length)));
        results.add(measure("EcKeys.ecdh", () -> sink(EcKeys.ecdh(ephemeralPrivate, uaKey, jca).length)));
        // ECDH came out several times more expensive than the key generation it is supposed to
        // cost the same as, so the step is split into the JCA lookup and the arithmetic.
        results.add(measure("  ↳ jca.ecdh() — только getInstance", () -> sink(
                jca.ecdh().getAlgorithm().length())));
        javax.crypto.KeyAgreement reused = jca.ecdh();
        results.add(measure("  ↳ ECDH без getInstance", () -> {
            try {
                reused.init(ephemeralPrivate);
                reused.doPhase(uaKey, true);
                return sink(reused.generateSecret().length);
            } catch (java.security.GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
        }));
        results.add(measure("  ↳ jca.ecKeyFactory() — только getInstance", () -> sink(
                jca.ecKeyFactory().getAlgorithm().length())));
        // Both sides straight from the generator: no imported point, no imported parameters.
        KeyPair nativePair = EcKeys.generateP256(jca);
        ECPublicKey nativePublic = (ECPublicKey) nativePair.getPublic();
        results.add(measure("  ↳ ECDH: обе стороны от KeyPairGenerator", () -> sink(
                EcKeys.ecdh(ephemeralPrivate, nativePublic, jca).length)));
        // The same point as the library imports, but re-imported carrying the generator's own
        // parameter object rather than the one AlgorithmParameters produced.
        ECPublicKey reimported;
        try {
            reimported = (ECPublicKey) jca.ecKeyFactory()
                    .generatePublic(new java.security.spec.ECPublicKeySpec(uaKey.getW(), nativePublic.getParams()));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
        results.add(measure("  ↳ ECDH: тот же ключ, params от генератора", () -> sink(
                EcKeys.ecdh(ephemeralPrivate, reimported, jca).length)));
        results.add(measure("  ↳ jca.ecKeyPairGenerator() — только getInstance", () -> sink(
                jca.ecKeyPairGenerator().getAlgorithm().length())));
        results.add(measure("HKDF: 2 extract + 3 expand", () -> {
            byte[] prkKey = hkdf.extract(authSecret, ecdhSecret);
            byte[] ikm = hkdf.expand(prkKey, authSecret, 32);
            byte[] prk = hkdf.extract(salt, ikm);
            byte[] cek = hkdf.expand(prk, authSecret, 16);
            byte[] nonce = hkdf.expand(prk, authSecret, 12);
            return sink(cek.length + nonce.length);
        }));
        results.add(measure("encrypt без keygen (декод+ECDH+HKDF+GCM)", () -> sink(encryptor.encrypt(
                        uaPublic, authSecret, plaintext, 4096, ephemeralPrivate, ephemeralPublic, salt)
                .length)));
        results.add(measure("encrypt полностью (+ keygen + соль)", () -> sink(
                encryptor.encrypt(uaPublic, authSecret, plaintext, 4096).length)));
        results.add(measure("Vapid.signingInput (JSON + base64url)", () -> sink(
                Vapid.signingInput(audience, TestVectors.VAPID_SUBJECT, expiry).length())));
        results.add(measure("LocalEcVapidSigner.sign (ECDSA)", () -> sink(
                signer.sign(Vapid.signingInput(audience, TestVectors.VAPID_SUBJECT, expiry)
                                .getBytes(java.nio.charset.StandardCharsets.US_ASCII))
                        .length)));
        results.add(measure("Vapid.authorizationHeader (JWT целиком)", () -> sink(
                Vapid.authorizationHeader(signer, audience, TestVectors.VAPID_SUBJECT, expiry).length())));
        results.add(measure("PushSender.send без сети (весь путь)", () -> sink(
                sender.send(subscription, message).statusCode())));

        report(results);
    }

    private long sink(long value) {
        return value;
    }

    private Result measure(String name, LongSupplier step) {
        drive(step, WARMUP.toNanos());
        List<Double> nanosPerOp = new ArrayList<>();
        for (int repeat = 0; repeat < REPEATS; repeat++) {
            long[] driven = driveCounted(step, MEASURE.toNanos());
            nanosPerOp.add((double) driven[1] / driven[0]);
        }
        nanosPerOp.sort(Double::compareTo);
        return new Result(name, nanosPerOp.get(REPEATS / 2), nanosPerOp.get(0));
    }

    private void drive(LongSupplier step, long budgetNanos) {
        driveCounted(step, budgetNanos);
    }

    /** Runs {@code step} until the budget is spent; returns {@code [operations, elapsedNanos]}. */
    private long[] driveCounted(LongSupplier step, long budgetNanos) {
        long operations = 0;
        long start = System.nanoTime();
        long elapsed;
        do {
            // A batch of 16 keeps System.nanoTime() out of the measured cost for the cheapest steps
            // without letting an expensive one overshoot the budget by much.
            for (int i = 0; i < 16; i++) {
                sink += step.getAsLong();
            }
            operations += 16;
            elapsed = System.nanoTime() - start;
        } while (elapsed < budgetNanos);
        return new long[] {operations, elapsed};
    }

    private void report(List<Result> results) {
        StringBuilder out = new StringBuilder(1024);
        out.append(System.lineSeparator())
                .append("=== push2u: горячий путь, локальная стоимость одной отправки ===")
                .append(System.lineSeparator())
                .append(String.format("%-44s %14s %14s%n", "шаг", "медиана", "лучшее"));
        for (Result result : results) {
            out.append(String.format("%-44s %14s %14s%n", result.name(), format(result.median()), format(result.best())));
        }
        out.append(System.lineSeparator())
                .append("JVM: ")
                .append(System.getProperty("java.vm.name"))
                .append(' ')
                .append(System.getProperty("java.version"))
                .append(" · ")
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
            return String.format("%.1f мкс", nanos / 1_000);
        }
        return String.format("%.2f мс", nanos / 1_000_000);
    }

    private record Result(String name, double median, double best) {}

    /** Unused, but keeps the SecureRandom import honest if the encryptor overload is switched to a seeded one. */
    @SuppressWarnings("unused")
    private static SecureRandom fixedRandom() {
        return new SecureRandom();
    }
}
