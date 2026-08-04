package com.the13haven.push2u.spring;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;

import com.the13haven.push2u.VapidSigner;

/**
 * Reports push2u readiness by exercising the configured {@link VapidSigner}: it signs a small probe and reports
 * {@code UP} only if the signer returns a valid (64-byte raw {@code r||s}) ES256 signature, {@code DOWN} otherwise.
 * This surfaces a failing signer — most usefully a remote one whose backend is unreachable (e.g. Vault). Reports the
 * signer type; never private key material, and never the failure's exception message — signer messages embed internal
 * detail (the Vault address, mount and key name, response body excerpts), which {@code show-details: always} would
 * republish to anyone who can reach the health endpoint. The full exception goes to the log instead, where the operator
 * diagnosing the DOWN already looks — at WARN once per outage (on the transition into failure) and at DEBUG while it
 * persists, because health is polled and re-tracing an unchanged failure every few seconds helps nobody.
 *
 * <p>Registered only when a {@link com.the13haven.push2u.PushSender} is configured (see
 * {@link Push2uHealthAutoConfiguration}), so "the sender is wired" is the precondition and "the signer can sign" is the
 * live check.
 */
public final class Push2uHealthIndicator implements HealthIndicator {

    private static final Log logger = LogFactory.getLog(Push2uHealthIndicator.class);

    private static final String NAME = "signer";
    private static final byte[] LIVENESS_PROBE = "push2u liveness probe".getBytes(StandardCharsets.UTF_8);
    private static final int ES256_SIGNATURE_LENGTH = 64;

    private final VapidSigner signer;
    /**
     * Whether the previous probe threw — the state whose transitions gate the loud logging below. Health endpoints are
     * polled (Kubernetes probes commonly every few seconds), so this is the only thing standing between one Vault
     * outage and an unbounded stream of identical stack traces.
     */
    private final AtomicBoolean probeFailing = new AtomicBoolean();

    /**
     * Creates the indicator over the configured signer.
     *
     * @param signer the configured VAPID signer
     */
    public Push2uHealthIndicator(VapidSigner signer) {
        this.signer = signer;
    }

    @Override
    public Health health() {
        String signerType = signer.getClass().getSimpleName();
        try {
            byte[] signature = signer.sign(LIVENESS_PROBE);
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
            return Health.up().withDetail(NAME, signerType).build();
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
                logger.warn("push2u health check failed: the signer probe threw", e);
            } else {
                logger.debug("push2u health check still failing: the signer probe threw", e);
            }
            return Health.down()
                    .withDetail(NAME, signerType)
                    .withDetail("reason", "signer probe failed")
                    .withDetail("error", e.getClass().getName())
                    .build();
        }
    }
}
