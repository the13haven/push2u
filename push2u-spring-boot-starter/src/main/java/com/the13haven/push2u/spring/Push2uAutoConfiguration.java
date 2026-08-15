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
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

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
     * property beside an application bean — are startup checks of that auto-configuration and have already run by the
     * time this method does, whether or not the context builds a sender. What this method still refuses is the
     * unexpressed <em>obligation</em>, which is the sender's own: a deployment that sends has to say which hosts it
     * will POST to, because a sender built without that decision would POST to whatever endpoint an attacker-influenced
     * subscription names.
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
     * malformed entry, and a non-empty property beside an application bean — live with that auto-configuration's
     * startup checks and have already run by the time this method executes.
     *
     * <p>What stays here is the <em>obligation</em>, because the obligation is the sender's: which hosts this
     * application server may POST to is a decision a sending deployment has to express — the endpoint a send POSTs to
     * comes from the subscription, which is attacker-influenced wherever subscriptions are registered by clients — and
     * a deployment that does not send is owed no such demand, which is why these two refusals are not startup checks of
     * the context. Two ways of expressing nothing are answered separately. Both properties unset with no bean means the
     * question was never asked, and the failure offers the three ways to answer it — either property, or a bean,
     * including one returning {@code EndpointPolicies.unrestricted()}, which is the named opt-out and exists only as a
     * bean so that choosing it is a code change someone reviews rather than a line copied between profiles. Every set
     * property empty with no bean is a different statement — the operator emptied a key, which cedes to a bean or to
     * the other property, and neither of those is there to receive it — and this starter owns that message, naming both
     * keys: the emptiness is a fact about the pair, and neither core factory can speak for both.
     *
     * <p>The remaining branch — a non-empty property with no policy bean — is unreachable while
     * {@link Push2uEndpointPolicyAutoConfiguration} is active, since a non-empty property is exactly its bean's
     * condition. It is answered rather than assumed away because an application can exclude that auto-configuration;
     * this method never builds the policy from the properties itself, because the allowlist is one definition,
     * published where the code that accepts subscriptions can reach it, and a second construction here would be a
     * second place the same rule is stated.
     */
    private static EndpointPolicy resolveEndpointPolicy(
            ObjectProvider<EndpointPolicy> endpointPolicy,
            @Nullable List<String> allowedOrigins,
            @Nullable List<String> allowedDomains) {
        EndpointPolicy policy = endpointPolicy.getIfAvailable();
        if (policy != null) {
            return policy;
        }
        if (allowedOrigins == null && allowedDomains == null) {
            throw noDecisionExpressed();
        }
        boolean originsExpressed = allowedOrigins != null && !allowedOrigins.isEmpty();
        boolean domainsExpressed = allowedDomains != null && !allowedDomains.isEmpty();
        if (!originsExpressed && !domainsExpressed) {
            throw everyConfiguredAllowlistEmpty();
        }
        throw allowlistExpressedWithoutItsAutoConfiguration();
    }

    /** Both allowlist properties unset and no bean: the decision was never made, so name every way to make it. */
    private static IllegalStateException noDecisionExpressed() {
        return new IllegalStateException("neither push2u.allowed-origins nor push2u.allowed-domains is set, and no"
                + " EndpointPolicy bean is supplied — a sender needs one of them, because the endpoint it POSTs to"
                + " comes from the subscription, and a subscription registered by a client can name any address this"
                + " process can reach, including loopback, private-range and cloud-metadata ones. Set"
                + " push2u.allowed-origins to the push service origins you expect (e.g. https://fcm.googleapis.com);"
                + " or set push2u.allowed-domains to a zone whose hostnames the service operator documents as varying"
                + " (e.g. notify.windows.com, which admits every subdomain of it too); or define an EndpointPolicy"
                + " bean — one returning EndpointPolicies.unrestricted() if this deployment deliberately applies no"
                + " restriction, which is safe only where subscriptions never arrive from untrusted clients.");
    }

    /**
     * Every allowlist property that is set is empty, and there is no bean. Emptying a property cedes it to a bean, so
     * with no bean there is nothing to cede to and an empty allowlist would reject every send.
     */
    private static IllegalStateException everyConfiguredAllowlistEmpty() {
        return new IllegalStateException("neither push2u.allowed-origins nor push2u.allowed-domains has an entry, and"
                + " no EndpointPolicy bean is supplied — an empty allowlist would reject every send, which is far more"
                + " likely a wiring bug than a policy. Emptying one of these properties states that this deployment"
                + " does not use it and cedes the decision to an EndpointPolicy bean; with no bean there is nothing to"
                + " cede to. List at least one entry under push2u.allowed-origins or push2u.allowed-domains, or define"
                + " an EndpointPolicy bean — one returning EndpointPolicies.unrestricted() if this deployment"
                + " deliberately applies no restriction.");
    }

    /**
     * A non-empty allowlist property, but no policy bean in the context: reachable only when the auto-configuration
     * whose bean's condition is exactly a non-empty allowlist has been excluded. Refused rather than rebuilt here — the
     * allowlist is one definition, published where the code that accepts subscriptions can reach it, and a second
     * construction inside the sender's factory would be a second place the same rule is stated.
     */
    private static IllegalStateException allowlistExpressedWithoutItsAutoConfiguration() {
        return new IllegalStateException("push2u.allowed-origins / push2u.allowed-domains is non-empty, but no"
                + " EndpointPolicy bean exists in this context — the allowlist becomes one only through"
                + " Push2uEndpointPolicyAutoConfiguration, which is not active here (most likely excluded). Restore"
                + " that auto-configuration, or supply an EndpointPolicy bean.");
    }
}
