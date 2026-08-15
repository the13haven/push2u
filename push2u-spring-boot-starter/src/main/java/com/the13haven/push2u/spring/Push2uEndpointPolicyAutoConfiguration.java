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
import org.springframework.beans.factory.annotation.AnnotatedBeanDefinition;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.Ordered;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.core.type.MethodMetadata;

import com.the13haven.push2u.EndpointPolicies;
import com.the13haven.push2u.EndpointPolicy;
import com.the13haven.push2u.EndpointRule;
import com.the13haven.push2u.PushSender;

/**
 * Publishes the deployment's {@link EndpointPolicy} as a bean, built from {@code push2u.allowed-origins} and
 * {@code push2u.allowed-domains}, and carries the two startup checks that guard those properties' values. The policy is
 * one decision applied at both points of a subscription's life — where a subscription is accepted, and before every
 * send — so the value the properties express has to be reachable by the application code that accepts subscriptions,
 * not only by the autoconfigured {@link PushSender}, which takes it from the context like any other collaborator.
 *
 * <p><b>Deliberately not part of {@link Push2uAutoConfiguration}.</b> A deployment that accepts subscriptions and
 * leaves the sending to another service holds this policy and has no sender — it validates each offered subscription's
 * endpoint against the same allowlist its sending counterpart enforces — and nothing that turns the delivery path off
 * may take the policy away from it. The class carrying the sender is where such a switch would apply; this class is
 * where it must not. For the same reason the class carries no condition of its own, and the two checks below carry none
 * at all: a condition on a class, a bean or a property would silently narrow the set of deployments they protect.
 *
 * <p><b>The bean exists when the allowlist is expressed</b> — at least one of the two properties has an entry — and an
 * application-supplied {@link EndpointPolicy} bean suppresses it. The condition is the allowlist and not a signer,
 * because a signer condition would withhold the policy from exactly the registration-only deployment above; and it is
 * not "nothing", because a deployment that merely carries this starter on its classpath must not be refused for want of
 * an allowlist nobody asked it for. The bean is built from the two properties and from nothing else, so no
 * configuration-only path to unrestricted egress appears: a deployment that wants
 * {@link EndpointPolicies#unrestricted()} writes that bean itself, as application code someone reviews.
 *
 * <p><b>The two checks are refusals about values, not about the delivery path</b>, which is why they run in every
 * deployment, sender or no sender. Both are raised from post-processors of the bean factory, ahead of every
 * bean-creation failure, and their positions among this starter family's startup checks are declared in
 * {@link StartupCheckOrder}: a malformed allowlist entry is refused naming the property and the index, and an allowlist
 * stated beside an application-supplied policy bean is refused as the contradiction it is, naming both. A contradiction
 * does not become acceptable in a context that happens not to send — left with the sender, that check would be
 * unreachable exactly where the stated allowlist would otherwise be ignored without a word.
 */
@AutoConfiguration
@EnableConfigurationProperties(Push2uProperties.class)
public final class Push2uEndpointPolicyAutoConfiguration {

    /**
     * The name of the policy bean this class contributes. Package-private on purpose: publishing it would offer an
     * application a constant to match on, and the starter's own bean is never identified by its name — an application
     * is equally free to choose this string — but by the definition it came from, which is what
     * {@link AllowlistBesidePolicyBeanCheck} reads.
     */
    static final String ENDPOINT_POLICY_BEAN_NAME = "push2uEndpointPolicy";

    private static final String ALLOWED_ORIGINS = "push2u.allowed-origins";
    private static final String ALLOWED_DOMAINS = "push2u.allowed-domains";

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
     *     entry's index — ordinarily pre-empted by {@link MalformedAllowlistEntryCheck}, which reports the same entry
     *     ahead of every bean-creation failure
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
     * The check refusing a malformed allowlist entry, ahead of every broader refusal.
     *
     * <p>{@code static}, and declaring the concrete class as its return type, both deliberately: the framework fetches
     * a post-processor bean before the configuration class is instantiated, and it chooses the sorting bucket from the
     * method's <em>declared</em> type — a method returning the post-processor interface would land the check in the
     * bucket that is never sorted, carrying an order nothing reads.
     *
     * @param environment the environment whose bound allowlist properties the check reads
     * @return the check
     */
    @Bean
    static MalformedAllowlistEntryCheck push2uMalformedAllowlistEntryCheck(Environment environment) {
        return new MalformedAllowlistEntryCheck(environment);
    }

    /**
     * The check refusing an allowlist stated beside an application-supplied {@link EndpointPolicy} bean.
     *
     * <p>{@code static} and declaring the concrete return type for the same reason as the check above: the sorting
     * bucket is chosen from the method's declared type, before the configuration class is instantiated.
     *
     * @param environment the environment whose bound allowlist properties the check reads
     * @return the check
     */
    @Bean
    static AllowlistBesidePolicyBeanCheck push2uAllowlistBesidePolicyBeanCheck(Environment environment) {
        return new AllowlistBesidePolicyBeanCheck(environment);
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

    /**
     * Whether {@code property} has at least one entry in the bound environment — bound through {@link Binder} so every
     * spelling relaxed binding accepts is read, exactly as the properties record binds it. An unset property and a
     * property set to an explicitly empty value both answer no: neither expresses an allowlist.
     */
    private static boolean hasEntry(Binder binder, String property) {
        return !boundEntries(binder, property).isEmpty();
    }

    /** The bound entries of {@code property}; an unset property and an explicitly empty one both bind to none. */
    private static List<String> boundEntries(Binder binder, String property) {
        return binder.bind(property, Bindable.listOf(String.class)).orElse(List.of());
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

    /**
     * Refuses a context whose allowlist holds an entry that is not a well-formed origin or domain, naming the property
     * and the entry's index. Raised here rather than left to the {@code push2uEndpointPolicy} factory method because a
     * {@code @Bean} method runs at singleton pre-instantiation, behind every post-processor in the context: a malformed
     * entry reported from there would arrive after any broader refusal, and the operator would read a message about a
     * signer or a contradiction while holding a value error nothing had pointed at yet.
     *
     * <p>The check performs the same rule construction the factory method performs — through the one implementation of
     * each rule kind, so the two cannot disagree about what a well-formed entry is — and discards the result.
     * Constructing a handful of rules twice at startup is the whole of the price, and nothing is cached or shared
     * between the two constructions.
     *
     * <p>{@link Ordered} is implemented on the class — not declared on the factory method — because the framework
     * buckets a post-processor by what its class implements and would not read an annotation on the method.
     */
    static final class MalformedAllowlistEntryCheck implements BeanFactoryPostProcessor, Ordered {

        private final Environment environment;

        MalformedAllowlistEntryCheck(Environment environment) {
            this.environment = environment;
        }

        @Override
        public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
            Binder binder = Binder.get(environment);
            checkEntries(binder, ALLOWED_ORIGINS, EndpointRule::origin);
            checkEntries(binder, ALLOWED_DOMAINS, EndpointRule::domain);
        }

        /** Builds {@code property}'s entries into rules exactly as the factory method will, and discards them. */
        private static void checkEntries(Binder binder, String property, Function<String, EndpointRule> factory) {
            addRules(new ArrayList<>(), boundEntries(binder, property), property, factory);
        }

        @Override
        public int getOrder() {
            return StartupCheckOrder.MALFORMED_ALLOWLIST_ENTRY;
        }
    }

    /**
     * Refuses a context that states the allowlist in properties while also holding an application-supplied
     * {@link EndpointPolicy} bean: the two express one security control, and silently preferring either would leave the
     * other believed-active but ignored. The check is about the context, not about the sender — a contradiction does
     * not become acceptable in a deployment that happens not to send, and that registration-only deployment is exactly
     * where an ignored allowlist would go unnoticed, since the application bean suppresses the starter's policy and
     * nothing else reads the properties. It reads bean <em>definitions</em> rather than instances, so nothing is forced
     * into existence to answer it.
     *
     * <p>Which bean is whose is answered by where its definition came from, never by its name. The definition this
     * class registered carries the metadata of the factory method that declared it, so "the starter's own" is a
     * question about the declaring class — while a bean name is a string an application is equally free to choose, and
     * an application naming its own bean {@code push2uEndpointPolicy} has supplied a bean like any other, whose
     * non-empty allowlist property still fails here. A definition whose origin cannot be established counts as the
     * application's: that errs towards a startup failure naming the conflicting bean rather than towards silently
     * dropping a stated allowlist.
     *
     * <p>{@link Ordered} is implemented on the class — not declared on the factory method — because the framework
     * buckets a post-processor by what its class implements and would not read an annotation on the method.
     */
    static final class AllowlistBesidePolicyBeanCheck implements BeanFactoryPostProcessor, Ordered {

        private final Environment environment;

        AllowlistBesidePolicyBeanCheck(Environment environment) {
            this.environment = environment;
        }

        @Override
        public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
            Binder binder = Binder.get(environment);
            boolean originsExpressed = hasEntry(binder, ALLOWED_ORIGINS);
            boolean domainsExpressed = hasEntry(binder, ALLOWED_DOMAINS);
            if (!originsExpressed && !domainsExpressed) {
                return;
            }
            List<String> applicationBeans = applicationSuppliedPolicyDefinitions(beanFactory);
            if (!applicationBeans.isEmpty()) {
                throw bothSourcesConfigured(applicationBeans, originsExpressed, domainsExpressed);
            }
        }

        /**
         * The names of every {@link EndpointPolicy} bean definition the application supplied — every one in the factory
         * except the definition this auto-configuration's own factory method declared. Type matching reads the
         * definitions ({@code allowEagerInit} off), so no bean is created to answer the question.
         */
        private static List<String> applicationSuppliedPolicyDefinitions(ConfigurableListableBeanFactory beanFactory) {
            List<String> names = new ArrayList<>();
            for (String name : beanFactory.getBeanNamesForType(EndpointPolicy.class, true, false)) {
                if (!isThisStartersOwnDefinition(beanFactory, name)) {
                    names.add(name);
                }
            }
            return names;
        }

        /**
         * Whether {@code name}'s definition is the one this auto-configuration contributed, decided by the declaring
         * class of the factory method the definition records — never by the bean's name, which an application is free
         * to reuse. A registered singleton with no definition, or a definition carrying no factory-method metadata,
         * answers no: where the origin cannot be established, the bean counts as the application's.
         */
        private static boolean isThisStartersOwnDefinition(ConfigurableListableBeanFactory beanFactory, String name) {
            if (!beanFactory.containsBeanDefinition(name)) {
                return false;
            }
            BeanDefinition definition = beanFactory.getBeanDefinition(name);
            if (definition instanceof AnnotatedBeanDefinition annotated) {
                MethodMetadata factoryMethod = annotated.getFactoryMethodMetadata();
                return factoryMethod != null
                        && Push2uEndpointPolicyAutoConfiguration.class
                                .getName()
                                .equals(factoryMethod.getDeclaringClassName());
            }
            return false;
        }

        /**
         * A non-empty allowlist property beside an application {@link EndpointPolicy} bean: two spellings of one
         * security control.
         */
        private static IllegalStateException bothSourcesConfigured(
                List<String> applicationBeanNames, boolean originsExpressed, boolean domainsExpressed) {
            // The bean is named, not merely described: any configuration could have contributed it,
            // so the failure has to say which one collided — turning a hunt into a fix. The property
            // is named for the same reason, since with two of them "a property" would leave half the
            // search.
            String expressed = originsExpressed && domainsExpressed
                    ? ALLOWED_ORIGINS + " and " + ALLOWED_DOMAINS + " are non-empty"
                    : (originsExpressed ? ALLOWED_ORIGINS : ALLOWED_DOMAINS) + " is non-empty";
            return new IllegalStateException(expressed + ", and the application-supplied EndpointPolicy bean '"
                    + String.join("', '", applicationBeanNames)
                    + "' is configured too — they express the same security control, and silently preferring one would"
                    + " leave the other believed-active but ignored. Configure exactly one; if an allowlist property is"
                    + " inherited from configuration you do not own, set it to an empty value to cede to the bean.");
        }

        @Override
        public int getOrder() {
            return StartupCheckOrder.ALLOWLIST_BESIDE_POLICY_BEAN;
        }
    }
}
