/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;

import com.the13haven.push2u.LocalEcVapidSigner;
import com.the13haven.push2u.VapidKeys;
import com.the13haven.push2u.VapidSigner;

/**
 * {@link Push2uHealthIndicator} caches the probe result (health endpoints are polled, and with a remote signer every
 * probe is a backend round-trip — a Vault Transit sign operation that is audited, quota-counted and possibly
 * HSM-billed), collapses concurrent evaluations into a single signing operation, and finishes the probe with a local
 * ES256 verification against the signer's advertised public key. Time is injected through a mutable {@link Clock} so
 * TTL expiry is proved by advancing time, not by sleeping through real TTLs.
 */
class Push2uHealthIndicatorTest {

    private static VapidSigner realSigner;
    /** The public half of an unrelated pair, for the advertised-key-mismatch case. */
    private static byte[] foreignPublicKey;

    private final MutableClock clock = new MutableClock();

    @BeforeAll
    static void generateVapidKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = generator.generateKeyPair();
        Base64.Encoder base64Url = Base64.getUrlEncoder().withoutPadding();
        realSigner = new LocalEcVapidSigner(VapidKeys.fromBase64(
                base64Url.encodeToString(uncompressed((ECPublicKey) keyPair.getPublic())),
                base64Url.encodeToString(toFixed32(((ECPrivateKey) keyPair.getPrivate()).getS()))));
        foreignPublicKey =
                uncompressed((ECPublicKey) generator.generateKeyPair().getPublic());
    }

    @Test
    void severalCallsWithinTheTtlCostExactlyOneSigningOperation() {
        CountingSigner signer = new CountingSigner(realSigner);
        Push2uHealthIndicator indicator =
                new Push2uHealthIndicator(signer, Push2uHealthIndicator.DEFAULT_CACHE_TTL, clock);

        // Five evaluations spread across 20s of (virtual) time — all inside the 30s TTL, so the
        // signer must be exercised exactly once and every caller served the cached UP.
        for (int i = 0; i < 5; i++) {
            Health health = indicator.health();
            assertThat(health.getStatus()).isEqualTo(Status.UP);
            // The `verification` detail marks the degraded (length-check-only) mode; its ABSENCE
            // is the signal that this UP went through the full cryptographic verification.
            assertThat(health.getDetails()).doesNotContainKey("verification");
            clock.advance(Duration.ofSeconds(5));
        }
        assertThat(signer.signOperations()).isEqualTo(1);
    }

    @Test
    void aCallAfterTheTtlExpiresSignsAgain() {
        CountingSigner signer = new CountingSigner(realSigner);
        Push2uHealthIndicator indicator =
                new Push2uHealthIndicator(signer, Push2uHealthIndicator.DEFAULT_CACHE_TTL, clock);

        assertThat(indicator.health().getStatus()).isEqualTo(Status.UP);
        clock.advance(Push2uHealthIndicator.DEFAULT_CACHE_TTL);

        assertThat(indicator.health().getStatus()).isEqualTo(Status.UP);
        assertThat(signer.signOperations())
                .as("once the TTL has fully elapsed the next evaluation probes the signer again")
                .isEqualTo(2);
    }

    @Test
    void thePublishedSingleArgumentConstructorCachesOnTheDefaultTtl() {
        // The constructor a consumer holding the artifact writes — `new Push2uHealthIndicator(
        // signer)` — has to arrive at the shipped default rather than at no caching at all: a
        // health endpoint is polled, and with a remote signer an uncached probe is one audited
        // backend signing operation per poll per pod. The TTL itself is not observable, so what is
        // asserted is what a second poll costs. This one runs on the system clock, which the 30s
        // default leaves ample room for.
        CountingSigner signer = new CountingSigner(realSigner);
        Push2uHealthIndicator indicator = new Push2uHealthIndicator(signer);

        assertThat(indicator.health().getStatus()).isEqualTo(Status.UP);
        assertThat(indicator.health().getStatus()).isEqualTo(Status.UP);

        assertThat(signer.signOperations())
                .as("the second poll is served from the cache the default TTL established")
                .isEqualTo(1);
    }

    @Test
    void aTtlTooLargeForMillisMeansForeverRatherThanFailingOrExpiringAtOnce() {
        // Two quiet defects hide behind an absurd cache-ttl, and they fail in opposite directions.
        // Duration.toMillis() throws above ~292 million years, which would refuse to build an
        // indicator over a value saying nothing worse than "cache it"; and an unsaturated now + ttl
        // wraps negative, putting the expiry in the past so that every poll re-probes the backend —
        // the exact load the cache exists to prevent, produced by the setting that asked for the
        // most caching. The clock starts at a real epoch millis so the sum can overflow at all, and
        // the second poll is a century later so a cache hit cannot be an ordinary one.
        clock.advance(Duration.ofMillis(System.currentTimeMillis()));
        CountingSigner signer = new CountingSigner(realSigner);
        Push2uHealthIndicator indicator = new Push2uHealthIndicator(signer, ChronoUnit.FOREVER.getDuration(), clock);

        assertThat(indicator.health().getStatus()).isEqualTo(Status.UP);
        clock.advance(Duration.ofDays(36_500));
        assertThat(indicator.health().getStatus()).isEqualTo(Status.UP);

        assertThat(signer.signOperations())
                .as("the clamped TTL means forever, and the saturated expiry keeps it in the future")
                .isEqualTo(1);
    }

    @Test
    void concurrentCallsCollapseIntoASingleSigningOperation() throws Exception {
        // Real threads, really concurrent: the first thread to probe is held INSIDE sign() until
        // the test has proven that all the others are running, so the burst cannot degenerate into
        // sequential cache hits by scheduling luck. Exactly one signing operation may result.
        int threads = 8;
        CountDownLatch signEntered = new CountDownLatch(1);
        CountDownLatch releaseSign = new CountDownLatch(1);
        CountingSigner signer = new CountingSigner(new VapidSigner() {
            @Override
            public byte[] sign(byte[] signingInput) {
                signEntered.countDown();
                await(releaseSign);
                return realSigner.sign(signingInput);
            }

            @Override
            public byte[] publicKey() {
                return realSigner.publicKey();
            }
        });
        Push2uHealthIndicator indicator =
                new Push2uHealthIndicator(signer, Push2uHealthIndicator.DEFAULT_CACHE_TTL, clock);

        ExecutorService executor = Executors.newFixedThreadPool(threads);
        try {
            CountDownLatch ready = new CountDownLatch(threads);
            CountDownLatch go = new CountDownLatch(1);
            List<Future<Health>> results = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                results.add(executor.submit((Callable<Health>) () -> {
                    ready.countDown();
                    await(go);
                    return indicator.health();
                }));
            }
            assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
            go.countDown();
            // One thread is now blocked inside sign(); the rest are queued on the probe lock (or
            // about to be). Only then is the probe allowed to complete.
            assertThat(signEntered.await(10, TimeUnit.SECONDS)).isTrue();
            releaseSign.countDown();
            for (Future<Health> result : results) {
                assertThat(result.get(10, TimeUnit.SECONDS).getStatus()).isEqualTo(Status.UP);
            }
        } finally {
            executor.shutdownNow();
        }
        assertThat(signer.signOperations())
                .as("a burst of concurrent health calls must cost exactly one signing operation")
                .isEqualTo(1);
    }

    @Test
    void aFailureIsCachedForTheFailureTtlNotTheSuccessTtl() {
        SwitchableSigner signer = new SwitchableSigner(realSigner);
        signer.failing.set(true);
        Push2uHealthIndicator indicator =
                new Push2uHealthIndicator(signer, Push2uHealthIndicator.DEFAULT_CACHE_TTL, clock);

        assertThat(indicator.health().getStatus()).isEqualTo(Status.DOWN);
        assertThat(signer.signAttempts()).isEqualTo(1);

        // Inside the 5s failure TTL: the DOWN is served from cache, no new backend attempt.
        clock.advance(Duration.ofSeconds(4));
        assertThat(indicator.health().getStatus()).isEqualTo(Status.DOWN);
        assertThat(signer.signAttempts()).isEqualTo(1);

        // 6s in: past the failure TTL but far inside the 30s success TTL. Were the failure cached
        // under the success TTL, this would still be a cache hit — it must be a fresh probe.
        clock.advance(Duration.ofSeconds(2));
        assertThat(indicator.health().getStatus()).isEqualTo(Status.DOWN);
        assertThat(signer.signAttempts())
                .as("a failed result expires on the short failure TTL, not the long success TTL")
                .isEqualTo(2);
    }

    @Test
    void recoveryFlipsBackToUpOnceTheFailureTtlLapses() {
        SwitchableSigner signer = new SwitchableSigner(realSigner);
        signer.failing.set(true);
        Push2uHealthIndicator indicator =
                new Push2uHealthIndicator(signer, Push2uHealthIndicator.DEFAULT_CACHE_TTL, clock);

        assertThat(indicator.health().getStatus()).isEqualTo(Status.DOWN);

        // Vault comes back. Within the failure TTL the cached DOWN is still served — that bounded
        // staleness is the deal — but the first evaluation after the TTL lapses must report UP.
        signer.failing.set(false);
        clock.advance(Duration.ofSeconds(4));
        assertThat(indicator.health().getStatus()).isEqualTo(Status.DOWN);
        clock.advance(Duration.ofSeconds(2));
        assertThat(indicator.health().getStatus()).isEqualTo(Status.UP);
        assertThat(signer.signAttempts()).isEqualTo(2);
    }

    @Test
    void sixtyFourArbitraryBytesDoNotPassTheProbe() {
        // The maintainer's bar for the probe: a signer returning 64 bytes of garbage — right
        // length, cryptographically meaningless — must be DOWN, which only local verification
        // against the advertised public key can establish.
        VapidSigner garbageSigner = new VapidSigner() {
            @Override
            public byte[] sign(byte[] signingInput) {
                byte[] signature = new byte[64];
                Arrays.fill(signature, (byte) 0x42);
                return signature;
            }

            @Override
            public byte[] publicKey() {
                return realSigner.publicKey();
            }
        };
        Health health = new Push2uHealthIndicator(garbageSigner, Duration.ZERO, clock).health();
        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(String.valueOf(health.getDetails().get("reason"))).contains("verif");
    }

    @Test
    void aSignatureThatDoesNotMatchTheAdvertisedPublicKeyIsDown() {
        // A real, well-formed ES256 signature — but the signer advertises a key that is not the
        // signing key's public half. This is the mispinned Vault public-key/key-version case,
        // which without verification would probe UP and then fail every actual send with 401/403.
        VapidSigner mismatchedSigner = new VapidSigner() {
            @Override
            public byte[] sign(byte[] signingInput) {
                return realSigner.sign(signingInput);
            }

            @Override
            public byte[] publicKey() {
                return foreignPublicKey.clone();
            }
        };
        Health health = new Push2uHealthIndicator(mismatchedSigner, Duration.ZERO, clock).health();
        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(String.valueOf(health.getDetails().get("reason")))
                .contains("does not verify against the advertised public key");
    }

    @Test
    void aSignatureOfTheWrongLengthIsDownNamingWhatArrivedAndWhatWasExpected() {
        // The commonest way an implementation gets the signer contract wrong: it returns the
        // provider's DER-encoded ECDSA signature instead of the raw r||s pair a VAPID JWT carries.
        // Nothing throws and nothing is malformed — every push service simply answers 401 with no
        // diagnostic — so this is the shape the probe has to catch by measuring. Both lengths go
        // into the reason on purpose: "produced 72, expected 64" tells the implementer they are one
        // conversion away from correct, where "the signer probe failed" would not.
        Health health = new Push2uHealthIndicator(new DerSigner(), Duration.ZERO, clock).health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(String.valueOf(health.getDetails().get("reason")))
                .contains("72 bytes")
                .contains("expected 64");
        assertThat(health.getDetails())
                .as("the signer type, so the payload says which implementation answered")
                .containsEntry("signer", "DerSigner");
        assertThat(health.getDetails())
                .as("nothing was thrown, so there is no exception type to report")
                .doesNotContainKey("error");
    }

    @Test
    void aMalformedAdvertisedPublicKeyIsDownWithTheErrorTypeOnly() {
        VapidSigner malformedKeySigner = new VapidSigner() {
            @Override
            public byte[] sign(byte[] signingInput) {
                return realSigner.sign(signingInput);
            }

            @Override
            public byte[] publicKey() {
                return new byte[10];
            }
        };
        Health health = new Push2uHealthIndicator(malformedKeySigner, Duration.ZERO, clock).health();
        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(String.valueOf(health.getDetails().get("reason"))).contains("could not be verified");
        // Same payload discipline as signing failures: the exception TYPE, never its message.
        assertThat(String.valueOf(health.getDetails().get("error"))).contains("IllegalArgumentException");
    }

    @Test
    void anUnsupportedPlatformDegradesToTheLengthCheckAndSaysSoInThePayload() {
        // On a JVM whose providers offer no ES256 verify primitive, the same garbage that must be
        // DOWN elsewhere is accepted by the degraded length-only check — the signer might be fine,
        // and a permanent DOWN for a platform property would be worse than the old length probe.
        // The degraded mode must be durably visible though: the WARN fires once and scrolls away,
        // so every payload carries the fixed `verification: unavailable` detail. Capability is
        // injected (like the clock) because it cannot be varied on the stock JDK the tests run on.
        try (CapturedLogs logs = new CapturedLogs()) {
            VapidSigner garbageSigner = new VapidSigner() {
                @Override
                public byte[] sign(byte[] signingInput) {
                    byte[] signature = new byte[64];
                    Arrays.fill(signature, (byte) 0x42);
                    return signature;
                }

                @Override
                public byte[] publicKey() {
                    return realSigner.publicKey();
                }
            };
            Push2uHealthIndicator indicator =
                    new Push2uHealthIndicator(garbageSigner, Duration.ZERO, clock, () -> false);

            for (int i = 0; i < 2; i++) {
                Health health = indicator.health();
                assertThat(health.getStatus()).isEqualTo(Status.UP);
                assertThat(health.getDetails()).containsEntry("verification", "unavailable");
            }

            assertThat(logs.count(Level.WARNING))
                    .as("the platform-capability WARN fires once per process, not per probe")
                    .isEqualTo(1);
        }
    }

    @Test
    void defaultTtlKeepsTheTransitionLoggingSemantics() {
        // The cache-ttl=0s variant of this pin lives in Push2uAutoConfigurationTest; this one runs
        // at the DEFAULT 30s TTL — the deployment shape that actually ships — where the sequence
        // is: WARN on the transition into failure, cached DOWNs log nothing at all, the re-probe
        // after the 5s failure TTL logs at DEBUG, and a recovery re-arms the WARN for the next
        // outage. Driven by the injected clock, not by sleeping.
        try (CapturedLogs logs = new CapturedLogs()) {
            SwitchableSigner signer = new SwitchableSigner(realSigner);
            signer.failing.set(true);
            Push2uHealthIndicator indicator =
                    new Push2uHealthIndicator(signer, Push2uHealthIndicator.DEFAULT_CACHE_TTL, clock);

            indicator.health(); // t=0s: probe -> DOWN, WARN (transition)
            clock.advance(Duration.ofSeconds(2));
            indicator.health(); // t=2s: inside the failure TTL -> cached, no probe, no log
            clock.advance(Duration.ofSeconds(4));
            indicator.health(); // t=6s: failure TTL lapsed -> re-probe -> still DOWN, DEBUG
            signer.failing.set(false);
            clock.advance(Duration.ofSeconds(6));
            assertThat(indicator.health().getStatus()).isEqualTo(Status.UP); // t=12s: recovery re-arms
            signer.failing.set(true);
            clock.advance(Duration.ofSeconds(31));
            indicator.health(); // t=43s: success TTL lapsed -> new outage -> WARN again

            assertThat(signer.signAttempts())
                    .as("the t=2s call was served from cache")
                    .isEqualTo(4);
            assertThat(logs.count(Level.WARNING))
                    .as("one WARN per outage, on each transition")
                    .isEqualTo(2);
            assertThat(logs.count(Level.FINE))
                    .as("the persisting failure's re-probe degrades to DEBUG")
                    .isEqualTo(1);
        }
    }

    @Test
    void aThrowingPublicKeyWarnsOnceNotOnEveryProbe() {
        // sign() succeeds, publicKey() throws — a legal SPI implementation (a remote signer may
        // fetch its key). The failing-state flag must be derived from the probe's FINAL outcome:
        // were it cleared mid-probe after sign() returned, every evaluation would read as a fresh
        // transition and WARN-stack-trace — at the failure-TTL cadence, a WARN every 5 seconds
        // for the whole outage.
        try (CapturedLogs logs = new CapturedLogs()) {
            VapidSigner keylessSigner = new VapidSigner() {
                @Override
                public byte[] sign(byte[] signingInput) {
                    return realSigner.sign(signingInput);
                }

                @Override
                public byte[] publicKey() {
                    throw new IllegalStateException("vault key metadata fetch failed");
                }
            };
            Push2uHealthIndicator indicator = new Push2uHealthIndicator(keylessSigner, Duration.ZERO, clock);

            for (int i = 0; i < 3; i++) {
                Health health = indicator.health();
                assertThat(health.getStatus()).isEqualTo(Status.DOWN);
                assertThat(health.getDetails()).containsEntry("reason", "signer probe failed");
            }

            assertThat(logs.count(Level.WARNING))
                    .as("one WARN for the whole outage")
                    .isEqualTo(1);
            assertThat(logs.count(Level.FINE))
                    .as("subsequent probes degrade to DEBUG")
                    .isEqualTo(2);
        }
    }

    @Test
    void aVerificationFailureLogsOnTransitionLikeAnyOtherFailure() {
        // A verification-failure DOWN without any log line would leave an operator running the
        // default show-details (never) with nothing to go on. The reason string is fixed and
        // carries no signer internals, so it follows the same WARN-on-transition cadence.
        try (CapturedLogs logs = new CapturedLogs()) {
            VapidSigner garbageSigner = new VapidSigner() {
                @Override
                public byte[] sign(byte[] signingInput) {
                    byte[] signature = new byte[64];
                    Arrays.fill(signature, (byte) 0x42);
                    return signature;
                }

                @Override
                public byte[] publicKey() {
                    return realSigner.publicKey();
                }
            };
            Push2uHealthIndicator indicator = new Push2uHealthIndicator(garbageSigner, Duration.ZERO, clock);

            indicator.health();
            indicator.health();

            assertThat(logs.count(Level.WARNING)).isEqualTo(1);
            assertThat(logs.warnMessages())
                    .allSatisfy(message -> assertThat(message).contains("push2u health check failed"));
            assertThat(logs.count(Level.FINE)).isEqualTo(1);
        }
    }

    @Test
    void aNullSignerIsRefusedWhereItIsHandedOver() {
        // Spring cannot deliver null here: the bean method takes the signer as a required
        // parameter, so a context without one fails to start rather than building an indicator
        // over nothing. The constructors are public, though, and documented as the way to build
        // this by hand — and without the check the NPE arrives on the first health() call, at
        // signer.getClass() outside the try that turns a failing probe into DOWN. An endpoint
        // whose whole job is to report trouble would throw instead of reporting it.
        assertThatThrownBy(() -> new Push2uHealthIndicator(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("signer");
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(10, TimeUnit.SECONDS)) {
                throw new AssertionError("latch not released within 10s");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError("interrupted while waiting", e);
        }
    }

    /**
     * A signer that hands back an ASN.1-encoded ECDSA signature instead of the raw {@code r||s} pair the contract
     * requires: a well-formed answer of the wrong shape, and never 64 bytes. Each half is written as a 33-byte INTEGER
     * with an unconditional leading zero, which a real provider would emit only for a value whose high bit is set — so
     * this blob is BER rather than strict DER about half the time, and a provider's would be 70 to 72 bytes. The point
     * of writing it this way is the fixed 72: the length the probe reports is then the same on every run, whatever
     * signature the freshly generated key produced. Named rather than anonymous because the probe reports the signer's
     * simple name, and an anonymous class has none.
     */
    private static final class DerSigner implements VapidSigner {

        @Override
        public byte[] sign(byte[] signingInput) {
            byte[] raw = realSigner.sign(signingInput);
            byte[] der = new byte[72];
            der[0] = 0x30; // SEQUENCE
            der[1] = 70; // of everything that follows
            der[2] = 0x02; // INTEGER r: 33 bytes, the zero at index 4 written whether or not it is needed
            der[3] = 33;
            System.arraycopy(raw, 0, der, 5, 32);
            der[37] = 0x02; // INTEGER s, the same shape
            der[38] = 33;
            System.arraycopy(raw, 32, der, 40, 32);
            return der;
        }

        @Override
        public byte[] publicKey() {
            return realSigner.publicKey();
        }
    }

    /** Counts delegated {@code sign} calls — the unit the whole fix is about limiting. */
    private static final class CountingSigner implements VapidSigner {

        private final VapidSigner delegate;
        private final AtomicInteger signOperations = new AtomicInteger();

        CountingSigner(VapidSigner delegate) {
            this.delegate = delegate;
        }

        @Override
        public byte[] sign(byte[] signingInput) {
            signOperations.incrementAndGet();
            return delegate.sign(signingInput);
        }

        @Override
        public byte[] publicKey() {
            return delegate.publicKey();
        }

        int signOperations() {
            return signOperations.get();
        }
    }

    /** A signer whose backend can be failed and recovered mid-test, counting every sign attempt. */
    private static final class SwitchableSigner implements VapidSigner {

        private final VapidSigner delegate;
        private final AtomicInteger signAttempts = new AtomicInteger();
        final AtomicBoolean failing = new AtomicBoolean();

        SwitchableSigner(VapidSigner delegate) {
            this.delegate = delegate;
        }

        @Override
        public byte[] sign(byte[] signingInput) {
            signAttempts.incrementAndGet();
            if (failing.get()) {
                throw new IllegalStateException("signer backend unavailable");
            }
            return delegate.sign(signingInput);
        }

        @Override
        public byte[] publicKey() {
            return delegate.publicKey();
        }

        int signAttempts() {
            return signAttempts.get();
        }
    }

    /**
     * Captures the indicator's JUL records (the commons-logging backend on this test classpath — no SLF4J binding is
     * present) so the WARN/DEBUG cadence can be asserted; restores the logger on close.
     */
    private static final class CapturedLogs implements AutoCloseable {

        private final Logger julLogger = Logger.getLogger(Push2uHealthIndicator.class.getName());
        private final List<LogRecord> records = new CopyOnWriteArrayList<>();
        private final Level originalLevel;
        private final Handler handler = new Handler() {
            @Override
            public void publish(LogRecord logRecord) {
                records.add(logRecord);
            }

            @Override
            public void flush() {}

            @Override
            public void close() {}
        };

        CapturedLogs() {
            originalLevel = julLogger.getLevel();
            julLogger.addHandler(handler);
            julLogger.setLevel(Level.ALL);
        }

        long count(Level level) {
            return records.stream()
                    .filter(logRecord -> logRecord.getLevel().equals(level))
                    .count();
        }

        List<String> warnMessages() {
            return records.stream()
                    .filter(logRecord -> logRecord.getLevel().equals(Level.WARNING))
                    .map(LogRecord::getMessage)
                    .toList();
        }

        @Override
        public void close() {
            julLogger.removeHandler(handler);
            julLogger.setLevel(originalLevel);
        }
    }

    /** A clock the test advances by hand — TTL expiry is proved without sleeping through real TTLs. */
    private static final class MutableClock extends Clock {

        private final AtomicLong nowMillis = new AtomicLong();

        void advance(Duration amount) {
            nowMillis.addAndGet(amount.toMillis());
        }

        @Override
        public long millis() {
            return nowMillis.get();
        }

        @Override
        public Instant instant() {
            return Instant.ofEpochMilli(nowMillis.get());
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }
    }

    private static byte[] uncompressed(ECPublicKey key) {
        byte[] out = new byte[65];
        out[0] = 0x04;
        System.arraycopy(toFixed32(key.getW().getAffineX()), 0, out, 1, 32);
        System.arraycopy(toFixed32(key.getW().getAffineY()), 0, out, 33, 32);
        return out;
    }

    private static byte[] toFixed32(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == 32) {
            return bytes;
        }
        byte[] out = new byte[32];
        if (bytes.length > 32) {
            System.arraycopy(bytes, bytes.length - 32, out, 0, 32);
        } else {
            System.arraycopy(bytes, 0, out, 32 - bytes.length, bytes.length);
        }
        return out;
    }
}
