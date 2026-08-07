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
import com.the13haven.push2u.PushCryptoException;
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
     * @throws IllegalArgumentException if either key is not valid base64url, has the wrong length, is a public key that
     *     does not encode a point on P-256 ({@code VapidKeys} validates the point on construction), or is a pair whose
     *     halves do not belong together — {@link LocalEcVapidSigner}'s construction-time key-pair self-test treats a
     *     mismatch as bad input, the same category {@code VapidKeys.fromBase64} already reports every other rejection
     *     as, rather than as a failure of an otherwise well-formed pair — with {@code push2u.vapid.public-key} /
     *     {@code .private-key} named, since the core's own message names only the half
     * @throws PushCryptoException if the values are individually well-formed and belong together but no signer can
     *     still be built from them — a private scalar outside {@code [1, n-1]}, or the configured JCA provider unable
     *     to supply what the signer needs. Both arrive the same way, which is why the message says the signer could not
     *     be built rather than blaming the properties
     */
    @Bean
    @ConditionalOnMissingBean(VapidSigner.class)
    @ConditionalOnProperty(
            prefix = "push2u.vapid",
            name = {"public-key", "private-key"})
    VapidSigner push2uVapidSigner(Push2uProperties properties) {
        Push2uProperties.Vapid vapid = properties.vapid();
        // @ConditionalOnProperty already gates this bean on both keys being set; restated as a
        // check so the contract holds in the type system too, and so a future change to the
        // condition fails here with the property name rather than with a NullPointerException.
        String publicKey = Objects.requireNonNull(vapid.publicKey(), "push2u.vapid.public-key");
        String privateKey = Objects.requireNonNull(vapid.privateKey(), "push2u.vapid.private-key");
        try {
            return new LocalEcVapidSigner(VapidKeys.fromBase64(publicKey, privateKey));
        } catch (IllegalArgumentException e) {
            // The core names which half it rejected; this adds the YAML keys those halves came from,
            // the same translation the pushSender properties get. Not one key or the other, because
            // the core's message already says which half when it is one of them. This branch also
            // carries the off-curve typo — one character changed in the middle of the public key
            // keeps its length and its 0x04 tag, and fails VapidKeys' own curve check instead — and
            // a pair whose halves do not belong together, which LocalEcVapidSigner's construction-time
            // self-test rejects as bad input rather than as a crypto failure of a well-formed pair.
            throw new IllegalArgumentException(
                    "push2u.vapid.public-key / push2u.vapid.private-key: " + e.getMessage(), e);
        } catch (PushCryptoException e) {
            // What remains crypto-shaped: a private scalar no provider accepts, and a provider
            // missing what the signer needs — never a mismatched pair, which the key-pair self-test
            // reports as IllegalArgumentException and the catch above already handles. Rethrown as
            // the same type on purpose: IllegalArgumentException here would put a provider failure,
            // which arrives the same way, into the bad-input category it deliberately stays out of.
            //
            // And phrased as "building the signer from", not as a property prefix: the same branch
            // carries a JVM with no EC KeyFactory or no ES256 Signature, where the two properties
            // are perfectly correct and blaming them would send the operator to the wrong place.
            throw new PushCryptoException(
                    "while building the VAPID signer from push2u.vapid.public-key and" + " push2u.vapid.private-key: "
                            + e.getMessage(),
                    e);
        }
    }

    /**
     * The HTTP transport; defaults to {@link JdkPushHttpClient}, overridable by an application bean.
     *
     * @return the transport
     */
    @Bean
    @ConditionalOnMissingBean
    PushHttpClient push2uPushHttpClient() {
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
     * rather than {@link PushSender#builder(VapidSigner, String, EndpointPolicy)}'s generic {@code "contact is
     * required"}.
     *
     * <p>{@code push2u.jwt-expiry}, {@code push2u.default-ttl}, {@code push2u.record-size} and
     * {@code push2u.max-encrypted-body-bytes} failures from {@link PushSender.Builder#jwtExpiry(Duration)},
     * {@link PushSender.Builder#defaultTtl(Duration)}, {@link PushSender.Builder#recordSize(int)} and
     * {@link PushSender.Builder#maxEncryptedBodyBytes(int)} are re-thrown with the property name prefixed, since the
     * builder's own message names its camelCase parameter, not the YAML property. All three {@code push2u.retry.*} keys
     * get the same treatment ahead of {@link RetryPolicy}'s own constructor, which validates the attempt count and both
     * backoff bounds together — and reports the two bounds through one shared message — so it cannot be blamed on a
     * single property by its message alone; {@code retryPolicy(…)} below carries the reasoning.
     *
     * <p>The {@link EndpointPolicy} comes from either {@code push2u.allowed-origins} (bound to
     * {@link EndpointPolicies#allowedOrigins}) or an application-supplied {@code EndpointPolicy} bean, and exactly one
     * of them is required. Setting both fails the context, naming the property and the bean: the two express a security
     * control, and silently letting one win could leave the operator believing the ignored one is in force. The single
     * exception is a property explicitly set to an <em>empty</em> value alongside a bean — that is the escape hatch for
     * a service inheriting {@code push2u.allowed-origins} from a shared configuration it does not own: it cannot unset
     * the property, so emptying it means "deliberately not using the property here" and the bean wins. An empty value
     * <em>alone</em> still fails ("requires at least one origin"), so the control cannot be disabled by accident.
     * Configuring neither also fails: which hosts this application server may POST to is a decision the deployment has
     * to express, and a sender built without it would POST to whatever endpoint an attacker-influenced subscription
     * names.
     *
     * @param signer the VAPID signer
     * @param httpClient the HTTP transport
     * @param endpointPolicy an application-supplied endpoint policy, if any
     * @param beanFactory the bean factory, used to name the conflicting {@code EndpointPolicy} bean in the failure
     * @param properties the bound configuration
     * @return the configured sender
     * @throws IllegalStateException if {@code push2u.vapid.subject} is unset or blank, if both a non-empty
     *     {@code push2u.allowed-origins} and an {@code EndpointPolicy} bean are configured, or if neither is
     * @throws IllegalArgumentException if {@code push2u.jwt-expiry}, {@code push2u.default-ttl},
     *     {@code push2u.record-size}, {@code push2u.max-encrypted-body-bytes}, any {@code push2u.retry.*} key or
     *     {@code push2u.allowed-origins} is set to a value the builder, {@link RetryPolicy} or the policy factory
     *     rejects
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(VapidSigner.class)
    PushSender pushSender(
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
        EndpointPolicy policy = resolveEndpointPolicy(endpointPolicy, beanFactory, properties.allowedOrigins());
        PushSender.Builder builder = PushSender.builder(signer, subject, policy)
                .httpClient(httpClient)
                .retryPolicy(retryPolicy(properties.retry()));
        // Every optional property is applied through the same translate-the-error helper, so a
        // rejected value fails naming the YAML key instead of the builder's camelCase parameter.
        applyIfPresent(properties.jwtExpiry(), builder::jwtExpiry, "push2u.jwt-expiry");
        applyIfPresent(properties.defaultTtl(), builder::defaultTtl, "push2u.default-ttl");
        applyIfPresent(properties.recordSize(), builder::recordSize, "push2u.record-size");
        applyIfPresent(
                properties.maxEncryptedBodyBytes(), builder::maxEncryptedBodyBytes, "push2u.max-encrypted-body-bytes");
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
     * stay acceptable beside any value of the component being probed. It does <em>not</em> rest on the order of the
     * checks inside the compact constructor; reordering them changes nothing here.
     *
     * <p>A constraint <em>between</em> components would make a probe blame the wrong key.
     * {@code probeFillersStayAcceptableBesideARealValue} in the starter's tests samples that invariant at the point
     * each probe depends on, so the cheap version of that mistake fails the build — but it samples rather than decides,
     * and a constraint that only bites above some threshold would pass it. No black-box check can do better; changing
     * {@code RetryPolicy}'s constructor means revisiting this method.
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
     * application-supplied {@link EndpointPolicy} bean — of which exactly one is required. Both at once fails, naming
     * the property and the bean: they express the same security control, and silently preferring one would leave the
     * operator believing the ignored one is in force. An <em>empty</em> property beside a bean is the deliberate
     * exception (the bean wins): a service inheriting {@code push2u.allowed-origins} from a shared configuration cannot
     * unset it, so explicitly emptying it is its only way to cede to a bean — while an empty property alone still fails
     * below ("requires at least one origin"), so nobody disables the control by accident.
     *
     * <p>Neither source fails too, and that is the point of the check: the endpoint a send POSTs to comes from the
     * subscription, which is attacker-influenced wherever subscriptions are registered by clients, so a deployment that
     * has not said which endpoints it will contact has not made a decision the library can make for it. The failure
     * names both ways to make one — including the deliberate opt-out, which is a bean rather than a property so that
     * choosing it is a code change someone reviews rather than a line copied between profiles.
     */
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
            // Not "an empty allowlist": an unset property with no bean beside it means the question
            // was never asked. An explicitly empty value falls through to allowedOrigins() below,
            // which refuses it in its own words.
            throw new IllegalStateException("push2u.allowed-origins is not set and no EndpointPolicy bean is"
                    + " supplied — a sender needs one of them, because the endpoint it POSTs to comes from the"
                    + " subscription, and a subscription registered by a client can name any address this process"
                    + " can reach, including loopback, private-range and cloud-metadata ones. Set"
                    + " push2u.allowed-origins to the push service origins you expect (e.g."
                    + " https://fcm.googleapis.com), or define an EndpointPolicy bean — one returning"
                    + " EndpointPolicies.unrestricted() if this deployment deliberately applies no restriction,"
                    + " which is safe only where subscriptions never arrive from untrusted clients.");
        }
        try {
            return EndpointPolicies.allowedOrigins(allowedOrigins);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("push2u.allowed-origins: " + e.getMessage(), e);
        }
    }
}
