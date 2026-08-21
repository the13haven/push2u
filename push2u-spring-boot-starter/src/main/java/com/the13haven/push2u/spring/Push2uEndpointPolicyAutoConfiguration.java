/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.spring;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import org.jspecify.annotations.Nullable;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.BindResult;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.type.AnnotatedTypeMetadata;

import com.the13haven.push2u.EndpointPolicies;
import com.the13haven.push2u.EndpointPolicy;
import com.the13haven.push2u.EndpointRule;
import com.the13haven.push2u.PushSender;

/**
 * Publishes the deployment's {@link EndpointPolicy} as a bean, built from {@code push2u.allowed-origins} and
 * {@code push2u.allowed-domains}. The policy is one decision applied at both points of a subscription's life — where a
 * subscription is accepted, and before every send — so the value the properties express has to be reachable by the
 * application code that accepts subscriptions, not only by the autoconfigured {@link PushSender}, which takes it from
 * the context like any other collaborator.
 *
 * <p><b>Deliberately not part of {@link Push2uAutoConfiguration}.</b> A deployment that accepts subscriptions and
 * leaves the sending to another service holds this policy and has no sender — it validates each offered subscription's
 * endpoint against the same allowlist its sending counterpart enforces — and nothing that turns the delivery path off
 * may take the policy away from it. That deployment is exactly the one that states {@code push2u.enabled: false}: it
 * accepts subscriptions, holds a policy and sends nothing, and what it keeps by making that statement is the policy its
 * allowlist states. So this class carries no {@code push2u.enabled} condition, and may never gain one. <b>Being outside
 * the class that carries the sender is not what makes it safe</b> — the health indicator is outside it too and is gated
 * all the same. What makes it safe is that the condition is not applied here.
 *
 * <p><b>And deliberately hosting no startup check.</b> The two refusals that guard these properties' values — a
 * malformed entry, and an allowlist stated beside an application-supplied policy bean — live in
 * {@link Push2uStartupChecksAutoConfiguration}, because an auto-configuration that contributes a bean an operator might
 * want to remove may not also host a check: excluding a class is the framework's ordinary tool for removing its
 * contribution, and a check riding beside the bean would vanish with it — silencing exactly the refusal that operator
 * was owed. Excluding <em>this</em> class therefore removes only the bean, and every check keeps running.
 *
 * <p><b>The bean exists when the allowlist is expressed</b> — at least one of the two properties has an entry — and an
 * application-supplied {@link EndpointPolicy} bean suppresses it. The condition is the allowlist and not a signer,
 * because a signer condition would withhold the policy from exactly the registration-only deployment above; and it is
 * not "nothing", because a deployment that merely carries this starter on its classpath must not be refused for want of
 * an allowlist nobody asked it for. The bean is built from the two properties and from nothing else, so no
 * configuration-only path to unrestricted egress appears: a deployment that wants
 * {@link EndpointPolicies#unrestricted()} writes that bean itself, as application code someone reviews.
 */
@AutoConfiguration
@EnableConfigurationProperties(Push2uProperties.class)
public final class Push2uEndpointPolicyAutoConfiguration {

    /**
     * The name of the policy bean this class contributes. Package-private on purpose: publishing it would offer an
     * application a constant to match on, and the starter's own bean is never identified by its name — an application
     * is equally free to choose this string — but by the definition it came from, which is what
     * {@link Push2uStartupChecksAutoConfiguration.AllowlistBesidePolicyBeanCheck} reads.
     */
    static final String ENDPOINT_POLICY_BEAN_NAME = "push2uEndpointPolicy";

    /** The origins half of the allowlist statement; the checks guarding it read the same name. */
    static final String ALLOWED_ORIGINS = "push2u.allowed-origins";

    /** The domains half of the allowlist statement; the checks guarding it read the same name. */
    static final String ALLOWED_DOMAINS = "push2u.allowed-domains";

    Push2uEndpointPolicyAutoConfiguration() {
        // Explicit + package-private: the autoconfiguration is framework plumbing, not public API;
        // Spring still instantiates it reflectively. (This also avoids an undocumented public
        // default constructor that Javadoc/doclint flags.)
    }

    /**
     * The endpoint policy the allowlist properties express: entries of {@code push2u.allowed-origins} and
     * {@code push2u.allowed-domains} become origin and domain rules, unioned into one allowlist — the ordinary
     * cross-browser shape, a few exact origins beside a service whose hostnames vary within a DNS zone. Present when at
     * least one of the two properties has an entry; absent when neither is set and when every set property is empty;
     * suppressed by an application-supplied {@link EndpointPolicy} bean.
     *
     * <p>An application that accepts subscriptions injects this bean and applies it at that boundary — building the
     * {@code Subscription} first, validating the endpoint it carries second, storing the row third — so what it refuses
     * to store and what the sender refuses to POST to can never drift: both read this one definition.
     *
     * @param properties the bound configuration
     * @return the allowlist policy
     * @throws IllegalArgumentException if an entry is not a well-formed origin or domain, naming the property and the
     *     entry's index — ordinarily pre-empted by
     *     {@link Push2uStartupChecksAutoConfiguration.MalformedAllowlistEntryCheck}, which reports the same entry ahead
     *     of every bean-creation failure
     */
    @Bean(ENDPOINT_POLICY_BEAN_NAME)
    @ConditionalOnMissingBean
    @Conditional(OnAllowlistExpressed.class)
    EndpointPolicy push2uEndpointPolicy(Push2uProperties properties) {
        List<EndpointRule> rules = new ArrayList<>();
        addRules(rules, properties.allowedOrigins(), ALLOWED_ORIGINS, EndpointRule::origin);
        addRules(rules, properties.allowedDomains(), ALLOWED_DOMAINS, EndpointRule::domain);
        return EndpointPolicies.allowedEndpoints(rules);
    }

    /**
     * Turns one property's entries into rules, one entry at a time, so a refusal can name the property and the index of
     * the entry that earned it. Handing a whole list to a single factory could not: its message describes the bad entry
     * without saying which of the two properties it came from, or where in that list to look. The startup check over
     * malformed entries runs this same construction and discards the result, which is what keeps the two readings of "a
     * well-formed entry" from ever disagreeing.
     */
    static void addRules(
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

    /**
     * Whether {@code property} has at least one entry in the bound environment — bound through {@link Binder} so every
     * spelling relaxed binding accepts is read, exactly as the properties record binds it. An unset property and a
     * property set to an explicitly empty value both answer no: neither expresses an allowlist.
     */
    static boolean hasEntry(Binder binder, String property) {
        return !boundEntries(binder, property).isEmpty();
    }

    /** The bound entries of {@code property}; an unset property and an explicitly empty one both bind to none. */
    static List<String> boundEntries(Binder binder, String property) {
        List<String> stated = statedEntries(binder, property);
        return stated != null ? stated : List.of();
    }

    /**
     * The bound entries of {@code property}, or {@code null} where the property is not set at all — the one reading
     * that tells an unset key from a key set to an explicitly empty value, which are different statements about this
     * allowlist and are answered differently. It is the same distinction the properties record's nullable component
     * carries, read straight from the environment for the code that has no bound record to ask.
     */
    static @Nullable List<String> statedEntries(Binder binder, String property) {
        BindResult<List<String>> bound = binder.bind(property, Bindable.listOf(String.class));
        return bound.isBound() ? bound.get() : null;
    }

    /**
     * The condition under which the starter contributes the policy bean: at least one of the two allowlist properties
     * has an entry. A deployment that stated the rule holds it as a value, whether or not it sends; nothing stated
     * means no bean, and a context that also builds no sender starts exactly as it would without this class. The
     * <em>obligation</em> to state the rule stays with the sender's own factory method, which still fails a sending
     * deployment that expressed nothing.
     */
    static final class OnAllowlistExpressed extends SpringBootCondition {

        @Override
        public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
            Binder binder = Binder.get(context.getEnvironment());
            boolean origins = hasEntry(binder, ALLOWED_ORIGINS);
            boolean domains = hasEntry(binder, ALLOWED_DOMAINS);
            ConditionMessage.Builder message = ConditionMessage.forCondition("push2u allowlist expressed");
            if (origins || domains) {
                String expressed = origins && domains
                        ? ALLOWED_ORIGINS + " and " + ALLOWED_DOMAINS + " have entries"
                        : (origins ? ALLOWED_ORIGINS : ALLOWED_DOMAINS) + " has an entry";
                return ConditionOutcome.match(message.because(expressed));
            }
            return ConditionOutcome.noMatch(
                    message.because("neither " + ALLOWED_ORIGINS + " nor " + ALLOWED_DOMAINS + " has an entry"));
        }
    }
}
