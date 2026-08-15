/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.spring;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BooleanSupplier;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.boot.health.contributor.Status;

import com.the13haven.push2u.Es256Verifier;
import com.the13haven.push2u.VapidSigner;

/**
 * Reports push2u readiness by exercising the configured {@link VapidSigner} end to end: it signs a small probe and
 * reports {@code UP} only if the signer returns a 64-byte raw {@code r||s} ES256 signature that <em>verifies</em>
 * against the signer's own advertised public key ({@link VapidSigner#publicKey()}, checked locally through
 * {@link Es256Verifier}). Verifying is what makes this a probe rather than a length check — a signer returning 64
 * arbitrary bytes must be {@code DOWN}, and a signer whose advertised public key does not belong to its signing key (a
 * mispinned Vault {@code public-key} / {@code key-version}, say) is exactly the misconfiguration that otherwise
 * surfaces as a push service rejecting every send with 401/403. The verification is pure local computation over the
 * public key: no network, no key material. On the rare JVM whose providers offer no ES256 verification primitive at all
 * ({@link Es256Verifier#isSupported()}), the probe degrades to the length-only check with a one-time WARN and a fixed
 * {@code verification: unavailable} payload detail — that is a platform capability statement, not a signer failure, and
 * a signer that signs correctly there must not be reported {@code DOWN} forever.
 *
 * <p>The probe result is cached per indicator instance, because the health endpoint is polled: Kubernetes probes
 * commonly evaluate it every ~10 seconds per pod, Spring's own endpoint caching is off unless
 * {@code management.endpoint.health.cache.time-to-live} is set, and with a remote signer every evaluation is a full
 * backend round-trip. Against Vault Transit that means one audited sign operation per probe — Vault writes every
 * request and response to each audit device and refuses ALL requests when an audit device cannot be written, so an
 * uncached probe is an amplification path into shared Vault infrastructure (plus rate-limit quota burn, plus billable
 * HSM operations for {@code managed_key}-backed keys). A success is served from cache for {@code cacheTtl} (default
 * {@link #DEFAULT_CACHE_TTL}); a failure for at most {@link #MAX_FAILURE_CACHE_TTL}, shorter so recovery is noticed
 * quickly — see the constants for why those values. Concurrent evaluations are collapsed into a single signing
 * operation (see {@link #health()}); the cache is deliberately per-process — probes are per-pod questions, and a
 * distributed cache would be a new failure mode, not a feature.
 *
 * <p>Reports the signer type; never private key material, and never the failure's exception message — signer messages
 * embed internal detail (the Vault address, mount and key name, response body excerpts), which {@code show-details:
 * always} would republish to anyone who can reach the health endpoint. The full failure goes to the log instead, where
 * the operator diagnosing the DOWN already looks — at WARN once per outage (on the transition into failure) and at
 * DEBUG while it persists, because health is polled and re-tracing an unchanged failure every few seconds helps nobody.
 *
 * <p>Registered, unless a deployment switches it off, wherever the {@link VapidSigner} it probes with is a bean (see
 * {@link Push2uHealthAutoConfiguration}, which also carries the switch), because the signer is the only part of a send
 * that can stop working while the application runs — the rest of a {@link com.the13haven.push2u.PushSender} is
 * immutable configuration validated at build time, and an incomplete configuration fails startup rather than surfacing
 * here. Left alone it stays a readiness-style check: Spring Boot builds its {@code liveness} group from the
 * application's own {@code LivenessState} alone, so a signer outage does not restart pods — an unreachable Vault is not
 * something a container restart fixes. An operator who declares a group of that name including this contributor gets
 * what they declared, so the property that keeps the two apart is the deployment's rather than this class's.
 *
 * <p>What this asserts that a probe of the signer's backend cannot: it signs, so it fails on a credential that no
 * longer authorises signing — an expired or revoked token, a key renamed or deleted, a permission withdrawn — where a
 * probe asking the backend whether it is up and unsealed answers yes to all of them. It then verifies what came back
 * against the signer's own advertised public key, which reaches the case no credential check does either: bytes
 * returned successfully that do not verify. A deployment carrying such a backend probe beside this one is not carrying
 * the same question twice.
 */
public final class Push2uHealthIndicator implements HealthIndicator {

    private static final Log LOG = LogFactory.getLog(Push2uHealthIndicator.class);

    private static final String NAME = "signer";
    private static final byte[] PROBE_SIGNING_INPUT = "push2u signer probe".getBytes(StandardCharsets.UTF_8);
    private static final int ES256_SIGNATURE_LENGTH = 64;
    /** The longest TTL representable in millis; anything above is clamped rather than overflowed. */
    private static final Duration MAX_MILLIS_DURATION = Duration.ofMillis(Long.MAX_VALUE);

    /**
     * How long a successful probe result is reused before the signer is exercised again. 30 seconds sits at the
     * conservative end of the sensible 30–60 s range: Kubernetes' default probe cadence is one evaluation every 10
     * seconds with a failure threshold of 3, so a pod whose signer just died takes ~30 s of failing probes to leave the
     * endpoints anyway — a stale UP of at most 30 s adds no meaningful detection latency, while cutting the per-pod
     * Vault signing load from one operation per probe to at most two per minute.
     */
    static final Duration DEFAULT_CACHE_TTL = Duration.ofSeconds(30);

    /**
     * The ceiling on how long a FAILED probe result is reused — the effective failure TTL is {@code min(cacheTtl, 5s)},
     * so a long success TTL never delays recovery detection. 5 seconds is the aggressive end of the sensible 5–10 s
     * range on purpose: while DOWN the pod is already out of rotation and the operator is watching for the flip back to
     * UP, so re-probing five times a minute is cheap for the backend and keeps time-to-recover within one probe period
     * of the uncached behaviour. Taking the {@code min} (rather than the constant alone) keeps {@code cache-ttl: 0s}
     * meaning "no caching at all", failures included.
     */
    static final Duration MAX_FAILURE_CACHE_TTL = Duration.ofSeconds(5);

    private final VapidSigner signer;
    private final long successTtlMillis;
    private final long failureTtlMillis;
    private final Clock clock;
    /** {@link Es256Verifier#isSupported()} in production; injectable so tests can pin the degraded mode. */
    private final BooleanSupplier verificationSupported;

    /**
     * Serializes probe execution — the single-flight mechanism. A plain mutual-exclusion lock (rather than a
     * future-based coalescer) is enough here because every caller wants exactly what a coalescer would give it: the one
     * in-flight probe's result. Waiters that queued behind the winning thread re-check the cache under the lock and
     * leave with the value the winner just stored, so a burst of N concurrent health calls costs exactly one signing
     * operation, never N.
     */
    private final ReentrantLock probeLock = new ReentrantLock();

    /**
     * Whether the previous probe concluded DOWN — the state whose transitions gate the loud logging below. Health
     * endpoints are polled (Kubernetes probes commonly every few seconds), so this is the only thing standing between
     * one Vault outage and an unbounded stream of identical stack traces. The result cache above already suppresses
     * most re-probing; this keeps the guarantee even at {@code cache-ttl: 0s}. Cleared only from a probe's FINAL
     * outcome (see {@link #probe()}), never mid-probe: a signer whose {@code sign()} succeeds but whose
     * {@code publicKey()} then throws is one persistent failure, not a fresh transition on every evaluation.
     */
    private final AtomicBoolean probeFailing = new AtomicBoolean();

    /**
     * Whether the one-time "this JVM cannot verify ES256" WARN has been emitted. A platform property never changes at
     * runtime, so one line per process is exactly the right amount of noise.
     */
    private final AtomicBoolean verificationUnsupportedWarned = new AtomicBoolean();

    /**
     * The last probe result with its expiry instant; volatile so the fast path can read it without taking
     * {@link #probeLock}. Written only under the lock.
     */
    @Nullable
    private volatile CachedProbe cache;

    private record CachedProbe(Health health, long expiresAtMillis) {}

    /**
     * Creates the indicator over the configured signer with the default cache TTL ({@link #DEFAULT_CACHE_TTL}).
     *
     * @param signer the configured VAPID signer
     */
    public Push2uHealthIndicator(VapidSigner signer) {
        this(signer, DEFAULT_CACHE_TTL);
    }

    /**
     * Creates the indicator over the configured signer with an explicit cache TTL.
     *
     * @param signer the configured VAPID signer
     * @param cacheTtl how long a successful probe result is served from cache; a failed result is cached for at most
     *     {@link #MAX_FAILURE_CACHE_TTL} regardless. {@link Duration#ZERO} disables caching entirely
     * @throws IllegalArgumentException if {@code cacheTtl} is negative
     */
    public Push2uHealthIndicator(VapidSigner signer, Duration cacheTtl) {
        this(signer, cacheTtl, Clock.systemUTC());
    }

    /**
     * Visible for tests: TTL expiry must be provable without a test suite that sleeps through real TTLs, so time is
     * injected rather than read from the system.
     */
    Push2uHealthIndicator(VapidSigner signer, Duration cacheTtl, Clock clock) {
        this(signer, cacheTtl, clock, Es256Verifier::isSupported);
    }

    /**
     * Visible for tests, like the clock: whether the platform can verify ES256 is a JVM property that cannot be varied
     * inside a test running on a stock JDK, so the degraded mode's contract (UP on the length check alone, one WARN,
     * the {@code verification: unavailable} detail) is pinned by injecting the capability answer.
     */
    Push2uHealthIndicator(VapidSigner signer, Duration cacheTtl, Clock clock, BooleanSupplier verificationSupported) {
        if (cacheTtl.isNegative()) {
            throw new IllegalArgumentException("the cache TTL must not be negative: " + cacheTtl);
        }
        this.signer = signer;
        this.successTtlMillis = toMillisClamped(cacheTtl);
        this.failureTtlMillis = Math.min(this.successTtlMillis, MAX_FAILURE_CACHE_TTL.toMillis());
        this.clock = clock;
        this.verificationSupported = verificationSupported;
    }

    @Override
    public Health health() {
        // Fast path: an unexpired cached result answers with one volatile read and one clock read,
        // never touching the lock — the steady state for the overwhelming majority of evaluations.
        // Callers that find the cache expired queue on the lock below. There is deliberately no
        // probe timeout: a signer hanging on its backend holds those callers until the backend
        // call itself gives up — bounding that wait belongs to the signer's transport (the Vault
        // transport carries connect/read timeouts), and a second timeout here would only race it.
        CachedProbe cachedProbe = cache;
        if (cachedProbe != null && clock.millis() < cachedProbe.expiresAtMillis()) {
            return cachedProbe.health();
        }
        probeLock.lock();
        try {
            // Re-check under the lock: every thread that queued behind the winning prober lands
            // here after the winner stored its fresh result, and must reuse it instead of firing
            // another backend round-trip — this re-check is what turns the lock into single-flight.
            cachedProbe = cache;
            if (cachedProbe != null && clock.millis() < cachedProbe.expiresAtMillis()) {
                return cachedProbe.health();
            }
            Health health = probe();
            long ttlMillis = Status.UP.equals(health.getStatus()) ? successTtlMillis : failureTtlMillis;
            cache = new CachedProbe(health, saturatedAdd(clock.millis(), ttlMillis));
            return health;
        } finally {
            probeLock.unlock();
        }
    }

    private Health probe() {
        Health health = evaluateSigner();
        if (Status.UP.equals(health.getStatus())) {
            // Recovery re-arms the WARN — and only a probe that concluded UP as a WHOLE does so.
            // Clearing the flag mid-probe (say, right after sign() returned) would turn a signer
            // whose publicKey() throws on every probe into a WARN stack trace on every probe:
            // precisely the log storm the transition gating exists to prevent.
            probeFailing.set(false);
        }
        return health;
    }

    private Health evaluateSigner() {
        String signerType = signer.getClass().getSimpleName();
        try {
            byte[] signature = signer.sign(PROBE_SIGNING_INPUT);
            if (signature.length != ES256_SIGNATURE_LENGTH) {
                String reason = "signer produced " + signature.length + " bytes, expected " + ES256_SIGNATURE_LENGTH;
                logFailure("the " + reason, null);
                return Health.down()
                        .withDetail(NAME, signerType)
                        .withDetail("reason", reason)
                        .build();
            }
            // publicKey() is read inside this try on purpose: it is a signer call like sign(), and
            // an implementation that fetches the key remotely can fail the same way — such a
            // failure is classified (and transition-logged) as "signer probe failed", not as a
            // verification problem.
            byte[] advertisedKey = signer.publicKey();
            return verifyAgainstAdvertisedKey(signerType, advertisedKey, signature);
        } catch (RuntimeException e) {
            // The exception message is deliberately kept OUT of the health payload: signer
            // failure messages embed internal detail by design (a Vault signer's names the Vault
            // address, mount and key name, and echoes up to 2 KiB of response body), and health
            // details are served to whoever can reach the endpoint once show-details is opened
            // up — `always` is a very common setting. The payload carries a fixed reason plus
            // the exception type (getName(), never null unlike getMessage() and never empty
            // unlike an anonymous class's getSimpleName()); the full exception goes to the log,
            // which is where the operator diagnosing the DOWN already looks.
            logFailure("the signer probe threw", e);
            return Health.down()
                    .withDetail(NAME, signerType)
                    .withDetail("reason", "signer probe failed")
                    .withDetail("error", e.getClass().getName())
                    .build();
        }
    }

    /**
     * Finishes the probe with a local ES256 verification of the signature over the probe input, against the public key
     * the signer itself advertises. Without this, any signer returning 64 arbitrary bytes would probe as UP. The key is
     * re-read on every probe rather than cached: probes run at most every few seconds, the verification is microseconds
     * of local work, and a custom signer whose advertised key changes (rotation) must be verified against its current
     * key, not the one it advertised at startup.
     */
    private Health verifyAgainstAdvertisedKey(String signerType, byte[] advertisedKey, byte[] signature) {
        if (!verificationSupported.getAsBoolean()) {
            // A platform-capability statement, not a signer failure: this JVM's providers register
            // neither the raw-format nor the DER-form ECDSA name (push2u-core's own resolution —
            // a stock JDK always has at least one). A remote signer on such a platform still signs
            // perfectly well, so condemning it to a permanent DOWN would be strictly worse than
            // the length-only probe this verification replaced. Degrade to that check, saying so
            // once in the log — a platform property cannot change mid-process — and on EVERY
            // payload: the startup WARN has scrolled away by the time an operator looks at
            // /actuator/health, so the degraded mode must be visible where they are looking. The
            // detail appears only in this mode — its presence IS the signal; the fully verified UP
            // stays as lean as before. A fixed string, per the payload discipline above.
            if (verificationUnsupportedWarned.compareAndSet(false, true)) {
                LOG.warn("push2u health probe cannot verify ES256 signatures with this JVM's providers;"
                        + " the probe degrades to checking the signature length only");
            }
            return Health.up()
                    .withDetail(NAME, signerType)
                    .withDetail("verification", "unavailable")
                    .build();
        }
        boolean valid;
        try {
            valid = Es256Verifier.verify(advertisedKey, PROBE_SIGNING_INPUT, signature);
        } catch (RuntimeException e) {
            // The advertised key is malformed or cannot be imported as a P-256 point. Same payload
            // discipline as the signing failure above — a fixed reason and the exception type,
            // never the message.
            logFailure("the signer probe signature could not be verified", e);
            return Health.down()
                    .withDetail(NAME, signerType)
                    .withDetail("reason", "signer probe signature could not be verified")
                    .withDetail("error", e.getClass().getName())
                    .build();
        }
        if (!valid) {
            logFailure("the signer probe signature does not verify against the advertised public key", null);
            return Health.down()
                    .withDetail(NAME, signerType)
                    .withDetail("reason", "signer probe signature does not verify against the advertised public key")
                    .build();
        }
        return Health.up().withDetail(NAME, signerType).build();
    }

    /**
     * Logs a probe failure loudly only on the TRANSITION into failure: health is polled, so a Vault outage would
     * otherwise stack-trace on every probe (every ~10s under Kubernetes, every ~5s once the failure TTL drives the
     * cadence) for its whole duration — from a library that otherwise never logs. While the failure persists the detail
     * goes to DEBUG (opt-in); recovery re-arms the WARN (see {@link #probe()}), so each new outage announces itself
     * once. All failure modes share the one flag: what the operator needs announced is "the probe started failing",
     * with the current mode carried in the message.
     */
    private void logFailure(String what, @Nullable Throwable cause) {
        // The level guards exist for PMD's GuardLogStatement, and they are honest: the message is
        // concatenated eagerly, so skip building it when the level is off. The state transition
        // (compareAndSet) must happen regardless — it tracks the outage, not the logging.
        if (probeFailing.compareAndSet(false, true)) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("push2u health check failed: " + what, cause);
            }
        } else if (LOG.isDebugEnabled()) {
            LOG.debug("push2u health check still failing: " + what, cause);
        }
    }

    /** Millis conversion that clamps instead of overflowing, so an absurdly large TTL means "forever", not "never". */
    private static long toMillisClamped(Duration duration) {
        return duration.compareTo(MAX_MILLIS_DURATION) > 0 ? Long.MAX_VALUE : duration.toMillis();
    }

    /** Overflow-safe {@code now + ttl}: a clamped TTL near {@code Long.MAX_VALUE} must not wrap negative. */
    private static long saturatedAdd(long nowMillis, long ttlMillis) {
        long sum = nowMillis + ttlMillis;
        return sum < nowMillis ? Long.MAX_VALUE : sum;
    }
}
