/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.spring;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Function;

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
import com.the13haven.push2u.EndpointRule;
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
     * <p>The {@link EndpointPolicy} comes from one of two sources, and exactly one of them: the allowlist properties,
     * {@code push2u.allowed-origins} and {@code push2u.allowed-domains}, or an application-supplied
     * {@code EndpointPolicy} bean. <b>The two properties are not two sources.</b> They are two halves of one statement:
     * their entries become {@link EndpointRule#origin} and {@link EndpointRule#domain} rules and are unioned into a
     * single {@link EndpointPolicies#allowedEndpoints} allowlist, which is the ordinary cross-browser shape — a few
     * exact origins beside one service whose hostnames vary within a DNS zone — so the two are never in conflict with
     * each other. The decision is <em>expressed</em> when at least one of them is non-empty.
     *
     * <p>Expressing it <em>and</em> supplying a bean fails the context, naming whichever property is non-empty and
     * naming the bean, because the two sources express one security control and silently letting one win could leave
     * the operator believing the ignored one is in force. The escape hatch is a property explicitly set to an
     * <em>empty</em> value, and it is per property — a service inheriting a key from shared configuration it does not
     * own cannot unset it, so emptying it means "deliberately not using this property here": beside a bean the bean
     * wins, and beside the other property that property carries the allowlist alone.
     *
     * <p>Two ways of expressing nothing fail differently, and deliberately. With no bean and every set property empty,
     * the failure is this starter's own and names both keys: emptiness is now a statement about the pair, and no single
     * core factory can speak for both. With no bean and both properties unset, the failure instead names the three ways
     * to fix it — either property, or a bean, including one returning {@link EndpointPolicies#unrestricted()} as the
     * named opt-out. Which hosts this application server may POST to is a decision the deployment has to express: a
     * sender built without it would POST to whatever endpoint an attacker-influenced subscription names.
     *
     * @param signer the VAPID signer
     * @param httpClient the HTTP transport
     * @param endpointPolicy an application-supplied endpoint policy, if any
     * @param beanFactory the bean factory, used to name the conflicting {@code EndpointPolicy} bean in the failure
     * @param properties the bound configuration
     * @return the configured sender
     * @throws IllegalStateException if {@code push2u.vapid.subject} is unset or blank; if a non-empty
     *     {@code push2u.allowed-origins} or {@code push2u.allowed-domains} is configured beside an
     *     {@code EndpointPolicy} bean; if neither property nor a bean is configured; or if neither property has an
     *     entry and no bean is configured
     * @throws IllegalArgumentException if {@code push2u.jwt-expiry}, {@code push2u.jwt-renew-before},
     *     {@code push2u.jwt-cache-size}, {@code push2u.default-ttl} or {@code push2u.max-encrypted-body-bytes} is set
     *     to a value the builder rejects, or if an entry of {@code push2u.allowed-origins} or
     *     {@code push2u.allowed-domains} is not a well-formed origin or domain — the failure names the property and the
     *     index of the entry
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
        EndpointPolicy policy = resolveEndpointPolicy(
                endpointPolicy, beanFactory, properties.allowedOrigins(), properties.allowedDomains());
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
     * Resolves the endpoint policy from one of its two sources, and exactly one of them: the allowlist properties
     * {@code push2u.allowed-origins} and {@code push2u.allowed-domains}, or an application-supplied
     * {@link EndpointPolicy} bean. <b>The two properties are not two sources</b> — they are halves of one statement,
     * unioned into a single allowlist, so they are never in conflict with each other, and the decision counts as
     * expressed when at least one of them is non-empty. The exclusivity is between the properties and the bean:
     * expressing the decision beside a bean fails, naming whichever property is non-empty and naming the bean, because
     * they express the same security control and silently preferring one would leave the operator believing the ignored
     * one is in force. An <em>empty</em> property is the deliberate exception, per property: a service inheriting a key
     * from a shared configuration cannot unset it, so explicitly emptying it is its only way to cede — to a bean, or to
     * the other property.
     *
     * <p>Two ways of expressing nothing are answered separately. Both properties unset with no bean means the question
     * was never asked, and the failure offers the three ways to answer it — either property, or a bean, including one
     * returning {@code EndpointPolicies.unrestricted()}, which is the named opt-out and exists only as a bean so that
     * choosing it is a code change someone reviews rather than a line copied between profiles. Every set property empty
     * with no bean is a different statement — the operator emptied a key, which cedes to a bean or to the other
     * property, and neither of those is there to receive it — and this starter owns that message: with two properties
     * the emptiness is a fact about the pair, and neither core factory can speak for both.
     *
     * <p>The check exists because the endpoint a send POSTs to comes from the subscription, which is
     * attacker-influenced wherever subscriptions are registered by clients: a deployment that has not said which
     * endpoints it will contact has not made a decision the library can make for it.
     */
    private static EndpointPolicy resolveEndpointPolicy(
            ObjectProvider<EndpointPolicy> endpointPolicy,
            ListableBeanFactory beanFactory,
            @Nullable List<String> allowedOrigins,
            @Nullable List<String> allowedDomains) {
        EndpointPolicy applicationPolicy = endpointPolicy.getIfAvailable();
        boolean originsExpressed = allowedOrigins != null && !allowedOrigins.isEmpty();
        boolean domainsExpressed = allowedDomains != null && !allowedDomains.isEmpty();
        if (applicationPolicy != null) {
            if (originsExpressed || domainsExpressed) {
                throw bothSourcesConfigured(beanFactory, originsExpressed, domainsExpressed);
            }
            return applicationPolicy;
        }
        if (allowedOrigins == null && allowedDomains == null) {
            throw noDecisionExpressed();
        }
        if (!originsExpressed && !domainsExpressed) {
            throw everyConfiguredAllowlistEmpty();
        }
        List<EndpointRule> rules = new ArrayList<>();
        addRules(rules, allowedOrigins, "push2u.allowed-origins", EndpointRule::origin);
        addRules(rules, allowedDomains, "push2u.allowed-domains", EndpointRule::domain);
        return EndpointPolicies.allowedEndpoints(rules);
    }

    /**
     * Turns one property's entries into rules, one entry at a time, so a refusal can name the property and the index of
     * the entry that earned it. Handing a whole list to a single factory could not: its message describes the bad entry
     * without saying which of the two properties it came from, or where in that list to look.
     */
    private static void addRules(
            List<EndpointRule> rules,
            @Nullable List<String> entries,
            String property,
            Function<String, EndpointRule> factory) {
        if (entries == null) {
            return;
        }
        for (int index = 0; index < entries.size(); index++) {
            try {
                rules.add(factory.apply(entries.get(index)));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(property + "[" + index + "]: " + e.getMessage(), e);
            }
        }
    }

    /** A non-empty allowlist property beside an {@link EndpointPolicy} bean: two spellings of one security control. */
    private static IllegalStateException bothSourcesConfigured(
            ListableBeanFactory beanFactory, boolean originsExpressed, boolean domainsExpressed) {
        // The bean is named, not merely described: any autoconfiguration could have contributed it,
        // so the failure has to say which one collided — turning a hunt into a fix. The property is
        // named for the same reason, since with two of them "a property" would leave half the search.
        String expressed = originsExpressed && domainsExpressed
                ? "push2u.allowed-origins and push2u.allowed-domains are non-empty"
                : (originsExpressed ? "push2u.allowed-origins" : "push2u.allowed-domains") + " is non-empty";
        return new IllegalStateException(expressed + ", and the application-supplied EndpointPolicy bean '"
                + String.join("', '", beanFactory.getBeanNamesForType(EndpointPolicy.class))
                + "' is configured too — they express the same security control, and silently preferring one would"
                + " leave the other believed-active but ignored. Configure exactly one; if an allowlist property is"
                + " inherited from configuration you do not own, set it to an empty value to cede to the bean.");
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
}
