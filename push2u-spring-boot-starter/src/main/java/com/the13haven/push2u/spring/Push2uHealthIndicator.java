package com.the13haven.push2u.spring;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.boot.health.contributor.Status;

import com.the13haven.push2u.VapidSigner;

/**
 * Reports push2u readiness by exercising the configured {@link VapidSigner} end to end: it signs a small probe and
 * reports {@code UP} only if the signer returns a 64-byte raw {@code r||s} ES256 signature that <em>verifies</em>
 * against the signer's own advertised public key ({@link VapidSigner#publicKey()}). Verifying locally is what makes
 * this a probe rather than a length check — a signer returning 64 arbitrary bytes must be {@code DOWN}, and a signer
 * whose advertised public key does not belong to its signing key (a mispinned Vault {@code public-key} /
 * {@code key-version}, say) is exactly the misconfiguration that otherwise surfaces as a push service rejecting every
 * send with 401/403. The verification is pure local computation over the public key: no network, no key material.
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
 * always} would republish to anyone who can reach the health endpoint. The full exception goes to the log instead,
 * where the operator diagnosing the DOWN already looks — at WARN once per outage (on the transition into failure) and
 * at DEBUG while it persists, because health is polled and re-tracing an unchanged failure every few seconds helps
 * nobody.
 *
 * <p>Registered only when a {@link com.the13haven.push2u.PushSender} is configured (see
 * {@link Push2uHealthAutoConfiguration}), so "the sender is wired" is the precondition and "the signer can sign" is the
 * live check. It participates in readiness-style checks only: Spring Boot's {@code liveness} group contains just the
 * application's own {@code LivenessState}, so a signer outage can never restart pods — an unreachable Vault is not
 * something a container restart fixes.
 */
public final class Push2uHealthIndicator implements HealthIndicator {

    private static final Log LOG = LogFactory.getLog(Push2uHealthIndicator.class);

    private static final String NAME = "signer";
    private static final byte[] PROBE_SIGNING_INPUT = "push2u signer probe".getBytes(StandardCharsets.UTF_8);
    private static final int ES256_SIGNATURE_LENGTH = 64;
    /** The JCA name for ES256 with JOSE's raw {@code r||s} output — registered by SunEC on every stock JDK. */
    private static final String ES256_P1363 = "SHA256withECDSAinP1363Format";

    private static final int UNCOMPRESSED_POINT_LENGTH = 65;
    private static final byte UNCOMPRESSED_POINT_TAG = 0x04;
    private static final int COORDINATE_LENGTH = 32;
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

    /**
     * Serializes probe execution — the single-flight mechanism. A plain mutual-exclusion lock (rather than a
     * future-based coalescer) is enough here because every caller wants exactly what a coalescer would give it: the one
     * in-flight probe's result. Waiters that queued behind the winning thread re-check the cache under the lock and
     * leave with the value the winner just stored, so a burst of N concurrent health calls costs exactly one signing
     * operation, never N.
     */
    private final ReentrantLock probeLock = new ReentrantLock();

    /**
     * Whether the previous probe threw — the state whose transitions gate the loud logging below. Health endpoints are
     * polled (Kubernetes probes commonly every few seconds), so this is the only thing standing between one Vault
     * outage and an unbounded stream of identical stack traces. The result cache above already suppresses most
     * re-probing; this keeps the guarantee even at {@code cache-ttl: 0s}.
     */
    private final AtomicBoolean probeFailing = new AtomicBoolean();

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
        if (cacheTtl.isNegative()) {
            throw new IllegalArgumentException("the cache TTL must not be negative: " + cacheTtl);
        }
        this.signer = signer;
        this.successTtlMillis = toMillisClamped(cacheTtl);
        this.failureTtlMillis = Math.min(this.successTtlMillis, MAX_FAILURE_CACHE_TTL.toMillis());
        this.clock = clock;
    }

    @Override
    public Health health() {
        // Fast path: an unexpired cached result answers without contending on the lock — during
        // steady state (the overwhelming majority of probe evaluations) this is one volatile read
        // and one clock read, and a probe hanging on its backend never blocks callers that arrive
        // while a valid result is still cached.
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
        String signerType = signer.getClass().getSimpleName();
        try {
            byte[] signature = signer.sign(PROBE_SIGNING_INPUT);
            // The probe no longer throws — arm the transition logging for the next outage.
            probeFailing.set(false);
            if (signature.length != ES256_SIGNATURE_LENGTH) {
                return Health.down()
                        .withDetail(NAME, signerType)
                        .withDetail(
                                "reason",
                                "signer produced " + signature.length + " bytes, expected " + ES256_SIGNATURE_LENGTH)
                        .build();
            }
            return verifyAgainstAdvertisedKey(signerType, signature);
        } catch (RuntimeException e) {
            // The exception message is deliberately kept OUT of the health payload: signer
            // failure messages embed internal detail by design (a Vault signer's names the Vault
            // address, mount and key name, and echoes up to 2 KiB of response body), and health
            // details are served to whoever can reach the endpoint once show-details is opened
            // up — `always` is a very common setting. The payload carries a fixed reason plus
            // the exception type (getName(), never null unlike getMessage() and never empty
            // unlike an anonymous class's getSimpleName()); the full exception goes to the log,
            // which is where the operator diagnosing the DOWN already looks.
            //
            // Logged loudly only on the TRANSITION into failure: health is polled, so a Vault
            // outage would otherwise stack-trace on every probe (every ~10s under Kubernetes)
            // for its whole duration — from a library that otherwise never logs. While the
            // failure persists the trace goes to DEBUG (opt-in); recovery re-arms the WARN, so
            // each new outage announces itself once.
            if (probeFailing.compareAndSet(false, true)) {
                LOG.warn("push2u health check failed: the signer probe threw", e);
            } else {
                LOG.debug("push2u health check still failing: the signer probe threw", e);
            }
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
     * re-read and re-decoded on every probe rather than cached: probes run at most every few seconds, the decode is
     * microseconds of local work, and a custom signer whose advertised key changes (rotation) must be verified against
     * its current key, not the one it advertised at startup.
     */
    private Health verifyAgainstAdvertisedKey(String signerType, byte[] signature) {
        boolean valid;
        try {
            Signature verifier = Signature.getInstance(ES256_P1363);
            verifier.initVerify(decodeUncompressedP256(signer.publicKey()));
            verifier.update(PROBE_SIGNING_INPUT);
            valid = verifier.verify(signature);
        } catch (GeneralSecurityException e) {
            // Verification could not even run: the advertised key is malformed or not usable as a
            // P-256 point, or the platform providers lack raw-format ECDSA (a stock JDK always has
            // it). Same payload discipline as the signing failure above — a fixed reason and the
            // exception type, never the message.
            return Health.down()
                    .withDetail(NAME, signerType)
                    .withDetail("reason", "signer probe signature could not be verified")
                    .withDetail("error", e.getClass().getName())
                    .build();
        }
        if (!valid) {
            return Health.down()
                    .withDetail(NAME, signerType)
                    .withDetail("reason", "signer probe signature does not verify against the advertised public key")
                    .build();
        }
        return Health.up().withDetail(NAME, signerType).build();
    }

    /**
     * Decodes a 65-byte X9.62 uncompressed P-256 point into a public key, through the platform JCA. A local re-spelling
     * of what push2u-core's package-private {@code EcKeys} does — deliberately not widened there: the core's API
     * surface stays minimal, and this is public-key handling only, so duplicating it carries no key-custody risk.
     */
    private static ECPublicKey decodeUncompressedP256(byte[] point) throws GeneralSecurityException {
        if (point.length != UNCOMPRESSED_POINT_LENGTH || point[0] != UNCOMPRESSED_POINT_TAG) {
            throw new InvalidKeyException("the advertised public key is not a 65-byte uncompressed P-256 point");
        }
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec p256 = parameters.getParameterSpec(ECParameterSpec.class);
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(point, 1, 1 + COORDINATE_LENGTH));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(point, 1 + COORDINATE_LENGTH, UNCOMPRESSED_POINT_LENGTH));
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), p256));
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
