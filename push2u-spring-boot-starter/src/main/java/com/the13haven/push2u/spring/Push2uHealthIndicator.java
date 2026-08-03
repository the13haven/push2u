package com.the13haven.push2u.spring;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;

import com.the13haven.push2u.VapidSigner;

/**
 * Reports push2u readiness by exercising the configured {@link VapidSigner}: it signs a small probe and reports
 * {@code UP} only if the signer returns a valid (64-byte raw {@code r||s}) ES256 signature, {@code DOWN} otherwise.
 * This surfaces a failing signer — most usefully a remote one whose backend is unreachable (e.g. Vault). Reports the
 * signer type; never private key material.
 *
 * <p>Registered only when a {@link com.the13haven.push2u.PushSender} is configured (see
 * {@link Push2uHealthAutoConfiguration}), so "the sender is wired" is the precondition and "the signer can sign" is the
 * live check.
 */
public final class Push2uHealthIndicator implements HealthIndicator {

    private static final String NAME = "signer";
    private static final byte[] LIVENESS_PROBE = "push2u liveness probe".getBytes(StandardCharsets.UTF_8);
    private static final int ES256_SIGNATURE_LENGTH = 64;

    private final VapidSigner signer;

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
            // Throwable.getMessage() is null for an exception built without one, and
            // Health.Builder.withDetail rejects a null value with IllegalArgumentException — the
            // health check would throw instead of reporting DOWN, precisely when the signer is
            // already broken. Fall back to the exception type, which always names something.
            String error = Objects.requireNonNullElseGet(
                    e.getMessage(), () -> e.getClass().getName());
            return Health.down()
                    .withDetail(NAME, signerType)
                    .withDetail("error", error)
                    .build();
        }
    }
}
