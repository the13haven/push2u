/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.spring;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import com.the13haven.push2u.EndpointPolicies;
import com.the13haven.push2u.EndpointPolicy;
import com.the13haven.push2u.JdkPushHttpClient;
import com.the13haven.push2u.LocalEcVapidSigner;
import com.the13haven.push2u.PushHttpClient;
import com.the13haven.push2u.PushSender;
import com.the13haven.push2u.RetryPolicy;
import com.the13haven.push2u.VapidKeys;
import com.the13haven.push2u.VapidSigner;

/**
 * Autoconfigures a ready {@link PushSender} from {@code push2u.*} properties: an in-JVM VAPID signer when keys are
 * present, the JDK HTTP transport, and the send facade. Each bean is {@link ConditionalOnMissingBean}, so any of them
 * can be replaced by an application-supplied bean — chiefly a remote {@link VapidSigner} (e.g. Vault Transit). The
 * Actuator health indicator is added by {@link Push2uHealthAutoConfiguration}.
 */
@AutoConfiguration
@EnableConfigurationProperties(Push2uProperties.class)
public final class Push2uAutoConfiguration {

    Push2uAutoConfiguration() {
        // Explicit + package-private: the autoconfiguration is framework plumbing, not public API;
        // Spring still instantiates it reflectively. (This also avoids an undocumented public
        // default constructor that Javadoc/doclint flags.)
    }

    /**
     * The in-JVM VAPID signer, built from {@code push2u.vapid.public-key} / {@code .private-key}. Absent unless both
     * keys are set, and yields to an application-supplied {@link VapidSigner} (so a remote signer wins).
     *
     * @param properties the bound configuration
     * @return the local signer
     */
    @Bean
    @ConditionalOnMissingBean(VapidSigner.class)
    @ConditionalOnProperty(
            prefix = "push2u.vapid",
            name = {"public-key", "private-key"})
    public VapidSigner push2uVapidSigner(Push2uProperties properties) {
        Push2uProperties.Vapid vapid = properties.vapid();
        // @ConditionalOnProperty already gates this bean on both keys being set; restated as a
        // check so the contract holds in the type system too, and so a future change to the
        // condition fails here with the property name rather than with a NullPointerException.
        String publicKey = Objects.requireNonNull(vapid.publicKey(), "push2u.vapid.public-key");
        String privateKey = Objects.requireNonNull(vapid.privateKey(), "push2u.vapid.private-key");
        return new LocalEcVapidSigner(VapidKeys.fromBase64(publicKey, privateKey));
    }

    /**
     * The HTTP transport; defaults to {@link JdkPushHttpClient}, overridable by an application bean.
     *
     * @return the transport
     */
    @Bean
    @ConditionalOnMissingBean
    public PushHttpClient push2uPushHttpClient() {
        return new JdkPushHttpClient();
    }

    /**
     * The send facade, wired from the {@link VapidSigner} (local or application-supplied), the transport, and the
     * properties. Created only once a signer is available, and only when the application has not supplied its own
     * {@link PushSender} bean — an application-supplied {@code PushSender} bypasses this method entirely, so none of
     * the checks below apply to it.
     *
     * <p>{@code push2u.vapid.subject} is required for this autoconfigured sender even when the signer itself comes from
     * another starter (e.g. the Vault Transit signer starter, which supplies only key custody, not a contact address):
     * it is checked here, with a message naming the property, so a missing subject fails with an actionable diagnostic
     * rather than {@link PushSender#builder(VapidSigner, String)}'s generic {@code "contact is required"}.
     *
     * <p>{@code push2u.jwt-expiry}, {@code push2u.default-ttl}, {@code push2u.record-size} and
     * {@code push2u.max-encrypted-body-bytes} failures from {@link PushSender.Builder#jwtExpiry(Duration)},
     * {@link PushSender.Builder#defaultTtl(Duration)}, {@link PushSender.Builder#recordSize(int)} and
     * {@link PushSender.Builder#maxEncryptedBodyBytes(int)} are re-thrown with the property name prefixed, since the
     * builder's own message names its camelCase parameter, not the YAML property. All three {@code push2u.retry.*} keys
     * get the same treatment ahead of {@link RetryPolicy}'s own constructor, which validates the attempt count and both
     * backoff bounds together — and reports the two bounds through one shared message — so it cannot be blamed on a
     * single property by its message alone; see {@link #retryPolicy}.
     *
     * <p>The {@link EndpointPolicy} comes from either {@code push2u.allowed-origins} (bound to
     * {@link EndpointPolicies#allowedOrigins}) or an application-supplied {@code EndpointPolicy} bean. Setting both
     * fails the context, naming the property and the bean: the two express a security control, and silently letting one
     * win could leave the operator believing the ignored one is in force. The single exception is a property explicitly
     * set to an <em>empty</em> value alongside a bean — that is the escape hatch for a service inheriting
     * {@code push2u.allowed-origins} from a shared configuration it does not own: it cannot unset the property, so
     * emptying it means "deliberately not using the property here" and the bean wins. An empty value <em>alone</em>
     * still fails ("requires at least one origin"), so the control cannot be disabled by accident. Configuring neither
     * keeps {@link PushSender}'s default of no policy.
     *
     * @param signer the VAPID signer
     * @param httpClient the HTTP transport
     * @param endpointPolicy an application-supplied endpoint policy, if any
     * @param beanFactory the bean factory, used to name the conflicting {@code EndpointPolicy} bean in the failure
     * @param properties the bound configuration
     * @return the configured sender
     * @throws IllegalStateException if {@code push2u.vapid.subject} is unset or blank, or if both a non-empty
     *     {@code push2u.allowed-origins} and an {@code EndpointPolicy} bean are configured
     * @throws IllegalArgumentException if {@code push2u.jwt-expiry}, {@code push2u.default-ttl},
     *     {@code push2u.record-size}, {@code push2u.max-encrypted-body-bytes}, any {@code push2u.retry.*} key or
     *     {@code push2u.allowed-origins} is set to a value the builder, {@link RetryPolicy} or the policy factory
     *     rejects
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(VapidSigner.class)
    public PushSender pushSender(
            VapidSigner signer,
            PushHttpClient httpClient,
            ObjectProvider<EndpointPolicy> endpointPolicy,
            ListableBeanFactory beanFactory,
            Push2uProperties properties) {
        String subject = properties.vapid().subject();
        if (subject == null || subject.isBlank()) {
            throw new IllegalStateException(
                    "push2u.vapid.subject is required (the VAPID 'sub' claim: optional in RFC 8292 §2.1,"
                            + " required by push2u). Set it even when the signer itself comes from another"
                            + " starter, e.g. the Vault Transit signer starter, which supplies only key"
                            + " custody, not a contact address");
        }
        PushSender.Builder builder =
                PushSender.builder(signer, subject).httpClient(httpClient).retryPolicy(retryPolicy(properties.retry()));
        // Every optional property is applied through the same translate-the-error helper, so a
        // rejected value fails naming the YAML key instead of the builder's camelCase parameter.
        applyIfPresent(properties.jwtExpiry(), builder::jwtExpiry, "push2u.jwt-expiry");
        applyIfPresent(properties.defaultTtl(), builder::defaultTtl, "push2u.default-ttl");
        applyIfPresent(properties.recordSize(), builder::recordSize, "push2u.record-size");
        applyIfPresent(
                properties.maxEncryptedBodyBytes(), builder::maxEncryptedBodyBytes, "push2u.max-encrypted-body-bytes");
        EndpointPolicy policy = resolveEndpointPolicy(endpointPolicy, beanFactory, properties.allowedOrigins());
        if (policy != null) {
            builder.endpointPolicy(policy);
        }
        return builder.build();
    }

    /**
     * Builds the {@link RetryPolicy} from {@code push2u.retry.*}, naming whichever of the three keys is the reason a
     * value is rejected. {@link RetryPolicy}'s compact constructor validates all three components together and reports
     * both backoff bounds through one shared message, so the only way to attribute a failure to a key is to offer the
     * constructor one real value at a time.
     *
     * <p>Each probe fills the two components it is <em>not</em> testing with {@code 1} and {@link Duration#ZERO} — the
     * triple {@link RetryPolicy#none()} is built from. That is the invariant this rests on: those filler values must
     * stay unconditionally acceptable, including in combination with any {@code maxAttempts}. It does <em>not</em> rest
     * on the order of the checks inside the compact constructor; reordering them changes nothing here. Were
     * {@code RetryPolicy} ever to gain a constraint <em>between</em> components, a probe would blame the wrong key —
     * {@code probeFillerValuesAreUnconditionallyAccepted} in the starter's tests exists to fail when that happens.
     *
     * <p>Probing rather than restating the bounds keeps the core the authority on what a legal value is: no {@code >=
     * 1} or non-negative check is duplicated here, so none can drift.
     */
    private static RetryPolicy retryPolicy(Push2uProperties.Retry retry) {
        requireValid(
                "push2u.retry.max-attempts", () -> new RetryPolicy(retry.maxAttempts(), Duration.ZERO, Duration.ZERO));
        requireValid("push2u.retry.initial-backoff", () -> new RetryPolicy(1, retry.initialBackoff(), Duration.ZERO));
        requireValid("push2u.retry.max-backoff", () -> new RetryPolicy(1, Duration.ZERO, retry.maxBackoff()));
        return new RetryPolicy(retry.maxAttempts(), retry.initialBackoff(), retry.maxBackoff());
    }

    /**
     * Runs one {@link #retryPolicy} probe, re-throwing its rejection with {@code property} prefixed. The probe's result
     * is deliberately discarded — it is constructed to make the compact constructor speak, not to be used.
     */
    private static void requireValid(String property, Runnable probe) {
        try {
            probe.run();
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(property + ": " + e.getMessage(), e);
        }
    }

    /**
     * Applies {@code value} to {@code setter} unless it is {@code null} (meaning the property was left unset, so the
     * {@link PushSender} default applies), re-throwing a rejection with {@code property} prefixed — the builder step's
     * own message names its camelCase parameter, not the YAML property.
     */
    private static <T> void applyIfPresent(@Nullable T value, Consumer<T> setter, String property) {
        if (value != null) {
            try {
                setter.accept(value);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(property + ": " + e.getMessage(), e);
            }
        }
    }

    /**
     * Resolves the endpoint policy from its two possible sources — the {@code push2u.allowed-origins} property and an
     * application-supplied {@link EndpointPolicy} bean — or {@code null} for none (the {@link PushSender} default).
     * Both at once fails, naming the property and the bean: they express the same security control, and silently
     * preferring one would leave the operator believing the ignored one is in force. An <em>empty</em> property beside
     * a bean is the deliberate exception (the bean wins): a service inheriting {@code push2u.allowed-origins} from a
     * shared configuration cannot unset it, so explicitly emptying it is its only way to cede to a bean — while an
     * empty property alone still fails below ("requires at least one origin"), so nobody disables the control by
     * accident.
     */
    @Nullable
    private static EndpointPolicy resolveEndpointPolicy(
            ObjectProvider<EndpointPolicy> endpointPolicy,
            ListableBeanFactory beanFactory,
            @Nullable List<String> allowedOrigins) {
        EndpointPolicy applicationPolicy = endpointPolicy.getIfAvailable();
        if (allowedOrigins != null && !allowedOrigins.isEmpty() && applicationPolicy != null) {
            // Named, not just described: any autoconfiguration could contribute the bean, so the
            // failure must say which one collided — turning a hunt into a fix.
            throw new IllegalStateException("push2u.allowed-origins and the application-supplied EndpointPolicy bean"
                    + " '" + String.join("', '", beanFactory.getBeanNamesForType(EndpointPolicy.class))
                    + "' are both configured — they express the same security control, and silently preferring one"
                    + " would leave the other believed-active but ignored. Configure exactly one; if"
                    + " push2u.allowed-origins is inherited from configuration you do not own, set it to an empty"
                    + " value to cede to the bean.");
        }
        if (applicationPolicy != null) {
            return applicationPolicy;
        }
        if (allowedOrigins == null) {
            return null;
        }
        try {
            return EndpointPolicies.allowedOrigins(allowedOrigins);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("push2u.allowed-origins: " + e.getMessage(), e);
        }
    }
}
