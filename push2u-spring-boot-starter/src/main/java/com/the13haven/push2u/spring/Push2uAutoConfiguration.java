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
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.type.AnnotatedTypeMetadata;

import com.the13haven.push2u.EndpointPolicy;
import com.the13haven.push2u.JdkPushHttpClient;
import com.the13haven.push2u.LocalEcVapidSigner;
import com.the13haven.push2u.PushCryptoException;
import com.the13haven.push2u.PushHttpClient;
import com.the13haven.push2u.PushSender;
import com.the13haven.push2u.VapidKeys;
import com.the13haven.push2u.VapidSigner;

/**
 * Autoconfigures a ready {@link PushSender} from {@code push2u.*} properties: an in-JVM VAPID signer when keys are
 * present, the JDK HTTP transport, and the send facade. Each bean is {@link ConditionalOnMissingBean}, so any of them
 * can be replaced by an application-supplied bean — chiefly a remote {@link VapidSigner} (e.g. Vault Transit). The
 * endpoint policy the sender enforces is not built here: {@link Push2uEndpointPolicyAutoConfiguration} publishes it as
 * a bean, so the application code that accepts subscriptions can apply the same policy, and the sender takes it from
 * the context like any other collaborator. The Actuator health indicator is added by
 * {@link Push2uHealthAutoConfiguration}.
 *
 * <p><b>The whole class answers {@code push2u.enabled}.</b> Off, this deployment contributes no signer, no transport
 * and no sender — the statement a deployment makes when it does not send, and the one thing that keeps "does not send"
 * distinguishable from "silently fails to send". The switch reaches the delivery path and nothing else: it is not a
 * master switch over {@code push2u.*}, it leaves an application's own {@link PushSender} alone, and it deliberately
 * does not reach the endpoint policy, whose auto-configuration a deployment that accepts subscriptions and sends
 * nothing still needs. Anything other than {@code true} or {@code false} leaves this class inactive and fails the
 * context from {@link Push2uStartupChecksAutoConfiguration}, naming the property: a mistyped switch must not build a
 * signer for a context that is about to fail, least of all one whose construction reads a remote custodian.
 */
@AutoConfiguration
@ConditionalOnProperty(
        name = Push2uActivation.DELIVERY_SWITCH,
        havingValue = Push2uActivation.ON,
        matchIfMissing = true)
@EnableConfigurationProperties(Push2uProperties.class)
public final class Push2uAutoConfiguration {

    Push2uAutoConfiguration() {
        // Explicit + package-private: the autoconfiguration is framework plumbing, not public API;
        // Spring still instantiates it reflectively. (This also avoids an undocumented public
        // default constructor that Javadoc/doclint flags.)
    }

    /**
     * The in-JVM VAPID signer, built from {@code push2u.vapid.public-key} / {@code .private-key}. Absent unless both
     * keys are stated — and a blank value is not a statement, so the {@code ${VAPID_PUBLIC_KEY:}} shape that resolves
     * to nothing leaves the signer absent rather than activating one that cannot be built. What answers such a context
     * is the refusal over a missing signer, which names these two keys among the ways to fix it. Yields to an
     * application-supplied {@link VapidSigner} (so a remote signer wins).
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
    @Conditional(OnLocalVapidKeys.class)
    VapidSigner push2uVapidSigner(Push2uProperties properties) {
        Push2uProperties.Vapid vapid = properties.vapid();
        // The condition already gates this bean on both keys being stated; restated as a check so
        // the contract holds in the type system too, and so a future change to the condition fails
        // here with the property name rather than with a NullPointerException.
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
     * <p>{@code push2u.jwt-expiry}, {@code push2u.jwt-renew-before}, {@code push2u.jwt-cache-size},
     * {@code push2u.default-ttl} and {@code push2u.max-encrypted-body-bytes} failures from
     * {@link PushSender.Builder#jwtExpiry(Duration)}, {@link PushSender.Builder#jwtRenewBefore(Duration)},
     * {@link PushSender.Builder#jwtCacheSize(int)}, {@link PushSender.Builder#defaultTtl(Duration)} and
     * {@link PushSender.Builder#maxEncryptedBodyBytes(int)} are re-thrown with the property name prefixed, since the
     * builder's own message names its camelCase parameter, not the YAML property. {@code push2u.jwt-reuse} takes the
     * same route although {@link PushSender.Builder#jwtReuse(boolean)} has no value to reject: a boolean the binder
     * accepted is always legal, and routing it with its siblings is what keeps a later constraint on it from arriving
     * unnamed.
     *
     * <p>The {@link EndpointPolicy} arrives as an ordinary dependency: the starter's own bean, which
     * {@link Push2uEndpointPolicyAutoConfiguration} builds from {@code push2u.allowed-origins} and
     * {@code push2u.allowed-domains} when at least one of them has an entry, or an application-supplied bean, which
     * suppresses the starter's. The refusals about the allowlist's <em>values</em> — a malformed entry, and a non-empty
     * property beside an application bean — are startup checks hosted in {@link Push2uStartupChecksAutoConfiguration}
     * and have already run by the time this method does, whether or not the context builds a sender. What this method
     * still refuses is the unexpressed <em>obligation</em>, which is the sender's own: a deployment that sends has to
     * say which hosts it will POST to, because a sender built without that decision would POST to whatever endpoint an
     * attacker-influenced subscription names.
     *
     * <p>Two ways of expressing nothing fail differently, and deliberately. With no bean and both properties unset, the
     * failure names the three ways to fix it — either property, or a bean, including one returning
     * {@code EndpointPolicies.unrestricted()} as the named opt-out. With no bean and every set property empty, the
     * failure names both keys: an explicitly empty property is the per-property escape hatch, ceding an inherited key
     * to a bean or to the sibling property, and here neither is there to receive it.
     *
     * @param signer the VAPID signer
     * @param httpClient the HTTP transport
     * @param endpointPolicy the endpoint policy bean — the starter's own or an application-supplied one
     * @param properties the bound configuration
     * @return the configured sender
     * @throws IllegalStateException if {@code push2u.vapid.subject} is unset or blank; if no {@code EndpointPolicy}
     *     bean exists and neither allowlist property is set; if no bean exists and every set allowlist property is
     *     empty; or if a non-empty allowlist property meets a context that excluded the auto-configuration turning it
     *     into the policy bean
     * @throws IllegalArgumentException if {@code push2u.jwt-expiry}, {@code push2u.jwt-renew-before},
     *     {@code push2u.jwt-cache-size}, {@code push2u.default-ttl} or {@code push2u.max-encrypted-body-bytes} is set
     *     to a value the builder rejects
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(VapidSigner.class)
    PushSender pushSender(
            VapidSigner signer,
            PushHttpClient httpClient,
            ObjectProvider<EndpointPolicy> endpointPolicy,
            Push2uProperties properties) {
        String subject = properties.vapid().subject();
        if (subject == null || subject.isBlank()) {
            throw new IllegalStateException(
                    "push2u.vapid.subject is required (the VAPID 'sub' claim: optional in RFC 8292 §2.1,"
                            + " required by push2u). Set it even when the signer itself comes from another"
                            + " starter, e.g. the Vault Transit signer starter, which supplies only key"
                            + " custody, not a contact address");
        }
        EndpointPolicy policy =
                resolveEndpointPolicy(endpointPolicy, properties.allowedOrigins(), properties.allowedDomains());
        PushSender.Builder builder = PushSender.builder(signer, subject, policy).httpClient(httpClient);
        // Every optional property is applied through the same translate-the-error helper, so a
        // rejected value fails naming the YAML key instead of the builder's camelCase parameter.
        applyIfPresent(properties.jwtExpiry(), builder::jwtExpiry, "push2u.jwt-expiry");
        applyIfPresent(properties.jwtRenewBefore(), builder::jwtRenewBefore, "push2u.jwt-renew-before");
        applyIfPresent(properties.jwtReuse(), builder::jwtReuse, "push2u.jwt-reuse");
        applyIfPresent(properties.jwtCacheSize(), builder::jwtCacheSize, "push2u.jwt-cache-size");
        applyIfPresent(properties.defaultTtl(), builder::defaultTtl, "push2u.default-ttl");
        applyIfPresent(
                properties.maxEncryptedBodyBytes(), builder::maxEncryptedBodyBytes, "push2u.max-encrypted-body-bytes");
        return builder.build();
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
     * Resolves the endpoint policy the sender requires, from the one the context holds: the starter's own bean, built
     * from the allowlist properties by {@link Push2uEndpointPolicyAutoConfiguration}, or an application-supplied
     * {@link EndpointPolicy} bean, which suppresses the starter's. The refusals about the allowlist's values — a
     * malformed entry, and a non-empty property beside an application bean — are startup checks hosted in
     * {@link Push2uStartupChecksAutoConfiguration}, apart from the bean they guard so that excluding the bean's class
     * cannot silence them, and they have already run by the time this method executes.
     *
     * <p>What stays here is the <em>obligation</em>, because the obligation is the sender's: which hosts this
     * application server may POST to is a decision a sending deployment has to express — the endpoint a send POSTs to
     * comes from the subscription, which is attacker-influenced wherever subscriptions are registered by clients — and
     * a deployment that does not send is owed no such demand, which is why these two refusals are not startup checks of
     * the context. What the refusal <em>says</em> is not written here: the states an absent policy can be in, and the
     * answer each one is owed, are stated once in {@link MissingEndpointPolicy} and shared with the analysis that
     * answers the same absence to a deployment which only accepts subscriptions and injects the bean directly. One
     * question asked from two places deserves one answer, and two copies of it would be two answers within a release or
     * so.
     *
     * <p>This method never builds the policy from the properties itself, whichever state they are in, because the
     * allowlist is one definition, published where the code that accepts subscriptions can reach it, and a second
     * construction here would be a second place the same rule is stated.
     */
    private static EndpointPolicy resolveEndpointPolicy(
            ObjectProvider<EndpointPolicy> endpointPolicy,
            @Nullable List<String> allowedOrigins,
            @Nullable List<String> allowedDomains) {
        EndpointPolicy policy = endpointPolicy.getIfAvailable();
        if (policy != null) {
            return policy;
        }
        throw new IllegalStateException(
                MissingEndpointPolicy.of(allowedOrigins, allowedDomains).refusalMessage());
    }

    /**
     * The condition under which this starter contributes its in-JVM signer: both {@code push2u.vapid.public-key} and
     * {@code push2u.vapid.private-key} state a value. A <em>blank</em> value states nothing — the shape a deployment
     * writes as {@code ${VAPID_PUBLIC_KEY:}} so that a missing variable does not stop the container from starting — and
     * the framework's own property condition would take it for a stated one, activate the signer, and refuse it for the
     * length of a point the empty string never carried. Reading blank as unset trades that failure for one that names
     * the configuration which is actually missing; no blank value could have produced a signer either way.
     */
    static final class OnLocalVapidKeys extends SpringBootCondition {

        /** The two keys this module owns, in the spelling its refusals use. */
        static final String PUBLIC_KEY = "push2u.vapid.public-key";

        /** The private half of the same pair. */
        static final String PRIVATE_KEY = "push2u.vapid.private-key";

        @Override
        public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
            Binder binder = Binder.get(context.getEnvironment());
            ConditionMessage.Builder message = ConditionMessage.forCondition("push2u local VAPID keys");
            boolean publicKey = Push2uActivation.isStated(binder, PUBLIC_KEY);
            boolean privateKey = Push2uActivation.isStated(binder, PRIVATE_KEY);
            if (publicKey && privateKey) {
                return ConditionOutcome.match(message.because(PUBLIC_KEY + " and " + PRIVATE_KEY + " are both set"));
            }
            String missing = publicKey ? PRIVATE_KEY : (privateKey ? PUBLIC_KEY : PUBLIC_KEY + " and " + PRIVATE_KEY);
            return ConditionOutcome.noMatch(message.because(missing + " unset or blank"));
        }
    }
}
