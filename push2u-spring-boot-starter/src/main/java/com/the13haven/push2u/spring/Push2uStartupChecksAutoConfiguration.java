/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.spring;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.AnnotatedBeanDefinition;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.env.Environment;
import org.springframework.core.type.MethodMetadata;

import com.the13haven.push2u.EndpointPolicy;
import com.the13haven.push2u.EndpointRule;

/**
 * This starter's startup checks — the refusals raised from post-processors of the bean factory, ahead of every
 * application singleton and every bean-creation failure, at the positions {@link StartupCheckOrder} declares — and
 * nothing else. Today that is one refusal over every property a release removed, a malformed allowlist entry, and an
 * allowlist stated beside an application-supplied {@link EndpointPolicy} bean.
 *
 * <p><b>An auto-configuration that contributes a bean an operator might want to remove may not also host a check.</b>
 * Excluding an auto-configuration is the framework's ordinary tool for removing what it contributes, and a check riding
 * in the same class vanishes with the contribution — the refusal disappears in exactly the deployment whose operator
 * reached for the standard tool, without anyone deciding to disable it. So the checks live here, in a class that
 * contributes nothing an application wires against: excluding the class that publishes the endpoint-policy bean leaves
 * every check running, and excluding <em>this</em> class says precisely what it does — it switches these checks off,
 * deliberately and visibly in the exclusion line that names it.
 *
 * <p>For the same reason this class carries no condition of its own, and no check in it carries one — not on a class, a
 * bean or a property: anything standing between a check and the context narrows the set of deployments it protects, and
 * the deployment most in need of one is often the one where nothing else reads the configuration at all. A delivery
 * switch that one day conditions the class carrying the sender must leave this class alone: whether a value in the
 * configuration is wrong does not depend on whether this context sends.
 */
// UseUtilityClass: every member is static because the @Bean methods must be — the framework
// instructs that for a method producing a bean-factory post-processor, so the enclosing
// auto-configuration is not instantiated in that early phase. It is still no utility class: Spring
// instantiates it reflectively, so the constructor stays package-private rather than private.
@SuppressWarnings("PMD.UseUtilityClass")
@AutoConfiguration
public final class Push2uStartupChecksAutoConfiguration {

    Push2uStartupChecksAutoConfiguration() {
        // Explicit + package-private: the autoconfiguration is framework plumbing, not public API;
        // Spring still instantiates it reflectively. (This also avoids an undocumented public
        // default constructor that Javadoc/doclint flags.)
    }

    /**
     * The one check carrying every tombstone: a refusal over each property a release removed, raised together so an
     * operator holding several dead keys reads all of them, edits once and starts once.
     *
     * <p>{@code static}, and declaring the concrete class as its return type, both deliberately: the framework fetches
     * a post-processor bean before the configuration class is instantiated, and it chooses the sorting bucket from the
     * method's <em>declared</em> type — a method returning the post-processor interface would land the check in the
     * bucket that is never sorted, carrying an order nothing reads.
     *
     * @param environment the environment whose bound {@code push2u.*} keys the tombstones inspect
     * @return the check
     */
    @Bean
    static RemovedPropertyTombstones push2uRemovedPropertyTombstones(Environment environment) {
        return new RemovedPropertyTombstones(environment);
    }

    /**
     * The check refusing a malformed allowlist entry, ahead of every broader refusal.
     *
     * <p>{@code static} and declaring the concrete return type for the same reason as the tombstone's method: the
     * sorting bucket is chosen from the method's declared type, before the configuration class is instantiated.
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
     * <p>{@code static} and declaring the concrete return type for the same reason as the two methods above.
     *
     * @param environment the environment whose bound allowlist properties the check reads
     * @return the check
     */
    @Bean
    static AllowlistBesidePolicyBeanCheck push2uAllowlistBesidePolicyBeanCheck(Environment environment) {
        return new AllowlistBesidePolicyBeanCheck(environment);
    }

    /**
     * Fails the context at startup while any {@code push2u.*} key a release removed is still present, naming every one
     * it finds and where each key's effect went. Binding ignores an unknown key silently, so without this refusal an
     * operator upgrading past a removal would keep a setting in their YAML that configures nothing and reads as though
     * it were in force. The check reads the <em>bound environment</em> at context refresh, so it catches each key
     * however it is spelled — the kebab-case name a guide prints, the camelCase form, and the upper-case
     * environment-variable form — and it publishes nothing: no property component retained to be rejected, no public
     * type, no public constant.
     *
     * <p><b>Every dead key present is named in one refusal, from one check.</b> The keys a release removes are commonly
     * held together, because they were copied together out of the guide that release replaced — so refusing them one
     * startup at a time would cost that operator a failed start per key, each one hiding the next. A check per key
     * could not fix that either: tombstones are neither more nor less specific than each other, so they would share a
     * position, and the one heard would be whichever the framework happened to register first. The entries below are
     * therefore per key while the raising is shared.
     *
     * <p><b>A tombstone has an end, and the end belongs to the entry</b> rather than to this check or to the class
     * hosting it: each key is carried for one minor release after the release that removed it, and the release adding
     * an entry opens the work item that removes it. Entries added by different releases therefore end at different
     * times. Each entry says what removed its key, which is what a reader needs in order to recognise it; <em>when</em>
     * that happened is deliberately not written here, because the release a window is counted from has no number until
     * its tag exists. Once it does, the number is in the work item that release opened. Retiring a key is deleting its
     * entry, keys removed by one change go together, and the check goes when the last entry does. They exist to catch a
     * configuration written against the previous release, not to accumulate for the life of the library.
     *
     * <p><b>Every entry is declared here rather than beside the feature whose key it names</b>, and the difference is
     * not organisational. The health keys are the worked case: the autoconfiguration that owns that feature exists only
     * where Spring Boot's health classes are on the classpath, while a deployment that dropped them and kept the keys
     * holds exactly the same dead configuration — so a check standing behind that condition would let through the case
     * it was written for. Nothing else may stand between a tombstone and the context either: whether a key still in the
     * YAML configures anything is not a question about what this deployment sends, probes or wires.
     *
     * <p>{@link Ordered} is implemented on the class — not declared on the factory method — because the framework
     * buckets a post-processor by what its class implements and would not read an annotation on the method.
     */
    static final class RemovedPropertyTombstones implements BeanFactoryPostProcessor, Ordered {

        /**
         * One entry per removed key, each carrying the whole of its own refusal: the key, that it configures nothing
         * now, and what to write instead. Adding a tombstone is adding an entry here; retiring one when its window
         * closes is deleting that entry, and nothing around it moves.
         */
        static final List<RemovedProperty> REMOVED_PROPERTIES = List.of(
                // Removed when the aes128gcm record size became a value derived from the body
                // ceiling, so that one property answers the size question.
                new RemovedProperty(
                        "push2u.record-size",
                        "push2u.record-size was removed and no longer configures anything — delete the key. The"
                                + " aes128gcm record size (RFC 8188 rs) is now derived from the one size property,"
                                + " push2u.max-encrypted-body-bytes: that ceiling less 85, which declares exactly the"
                                + " plaintext capacity the ceiling admits. If record-size was raised to carry larger"
                                + " payloads, raise push2u.max-encrypted-body-bytes instead; the derived record size"
                                + " follows it."),
                // Removed when the health indicator took Spring Boot's own switch for a contributor
                // and both of its keys moved to the prefix the framework gives one. Losing either
                // silently costs in the same direction: a probe switched off starts probing again,
                // and a lengthened cache reverts to the default — with a remote signer, more real
                // signing operations against whatever holds the key, written to an audit device,
                // counted against a quota, billed where the key is HSM-backed, and found by reading
                // that log rather than by anything failing.
                new RemovedProperty(
                        "push2u.health.enabled",
                        "push2u.health.enabled was removed and no longer configures anything — delete the key. The"
                                + " push2u health indicator now takes the switch every Spring Boot health contributor"
                                + " takes, so set management.health.push2u.enabled instead. That is also the key"
                                + " management.health.defaults.enabled reaches when it turns contributors off"
                                + " wholesale, which the removed one never did."),
                // Removed by that same change: the two health keys moved together, and this entry
                // carries its own note so that an entry inserted above it cannot leave it explained
                // by a comment that is no longer next to it.
                new RemovedProperty(
                        "push2u.health.cache-ttl",
                        "push2u.health.cache-ttl was removed and no longer configures anything — delete the key. The"
                                + " probe's result cache is configured beside that switch now: set"
                                + " management.health.push2u.cache-ttl instead, with the same value and the same"
                                + " meaning."));

        private final Environment environment;

        RemovedPropertyTombstones(Environment environment) {
            this.environment = environment;
        }

        @Override
        public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
            // Binder.get(environment) applies relaxed matching against the canonical kebab-case
            // name; Environment.getProperty would see only the literal spelling.
            Binder binder = Binder.get(environment);
            List<String> refusals = new ArrayList<>();
            for (RemovedProperty removed : REMOVED_PROPERTIES) {
                if (binder.bind(removed.key(), String.class).isBound()) {
                    refusals.add(removed.refusal());
                }
            }
            if (!refusals.isEmpty()) {
                throw new IllegalStateException(String.join(" ", refusals));
            }
        }

        @Override
        public int getOrder() {
            return StartupCheckOrder.REMOVED_PROPERTY_TOMBSTONE;
        }

        /** A key a release removed, with the whole of what an operator still holding it is told. */
        // Package-private rather than private so the suite can drive its completeness case off the
        // entries themselves: a list of today's keys written into a test would leave the next entry
        // uncovered while the test went on passing.
        record RemovedProperty(String key, String refusal) {}
    }

    /**
     * Refuses a context whose allowlist holds an entry that is not a well-formed origin or domain, naming the property
     * and the entry's index. Raised here rather than left to the policy bean's factory method because a {@code @Bean}
     * method runs at singleton pre-instantiation, behind every post-processor in the context: a malformed entry
     * reported from there would arrive after any broader refusal, and the operator would read a message about a signer
     * or a contradiction while holding a value error nothing had pointed at yet.
     *
     * <p>The check performs the same rule construction the bean's factory method performs — through the one
     * implementation of each rule kind, so the two cannot disagree about what a well-formed entry is — and discards the
     * result. Constructing a handful of rules twice at startup is the whole of the price, and nothing is cached or
     * shared between the two constructions.
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
            checkEntries(binder, Push2uEndpointPolicyAutoConfiguration.ALLOWED_ORIGINS, EndpointRule::origin);
            checkEntries(binder, Push2uEndpointPolicyAutoConfiguration.ALLOWED_DOMAINS, EndpointRule::domain);
        }

        /**
         * Builds {@code property}'s entries into rules exactly as the bean's factory method will, and discards them.
         */
        private static void checkEntries(Binder binder, String property, Function<String, EndpointRule> factory) {
            Push2uEndpointPolicyAutoConfiguration.addRules(
                    new ArrayList<>(),
                    Push2uEndpointPolicyAutoConfiguration.boundEntries(binder, property),
                    property,
                    factory);
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
     * <p>Which bean is whose is answered by where its definition came from, never by its name. The definition
     * {@link Push2uEndpointPolicyAutoConfiguration} registered carries the metadata of the factory method that declared
     * it, so "the starter's own" is a question about the declaring class — while a bean name is a string an application
     * is equally free to choose, and an application naming its own bean {@code push2uEndpointPolicy} has supplied a
     * bean like any other, whose non-empty allowlist property still fails here. A definition whose origin cannot be
     * established counts as the application's: that errs towards a startup failure naming the conflicting bean rather
     * than towards silently dropping a stated allowlist.
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
            boolean originsExpressed = Push2uEndpointPolicyAutoConfiguration.hasEntry(
                    binder, Push2uEndpointPolicyAutoConfiguration.ALLOWED_ORIGINS);
            boolean domainsExpressed = Push2uEndpointPolicyAutoConfiguration.hasEntry(
                    binder, Push2uEndpointPolicyAutoConfiguration.ALLOWED_DOMAINS);
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
         * except the definition the policy auto-configuration's own factory method declared. Type matching reads the
         * definitions ({@code allowEagerInit} off), so no bean is created to answer the question.
         */
        private static List<String> applicationSuppliedPolicyDefinitions(ConfigurableListableBeanFactory beanFactory) {
            List<String> names = new ArrayList<>();
            for (String name : beanFactory.getBeanNamesForType(EndpointPolicy.class, true, false)) {
                if (!isTheStartersOwnDefinition(beanFactory, name)) {
                    names.add(name);
                }
            }
            return names;
        }

        /**
         * Whether {@code name}'s definition is the one {@link Push2uEndpointPolicyAutoConfiguration} contributed,
         * decided by the declaring class of the factory method the definition records — never by the bean's name, which
         * an application is free to reuse. A registered singleton with no definition, or a definition carrying no
         * factory-method metadata, answers no: where the origin cannot be established, the bean counts as the
         * application's.
         */
        private static boolean isTheStartersOwnDefinition(ConfigurableListableBeanFactory beanFactory, String name) {
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
                    ? Push2uEndpointPolicyAutoConfiguration.ALLOWED_ORIGINS + " and "
                            + Push2uEndpointPolicyAutoConfiguration.ALLOWED_DOMAINS + " are non-empty"
                    : (originsExpressed
                                    ? Push2uEndpointPolicyAutoConfiguration.ALLOWED_ORIGINS
                                    : Push2uEndpointPolicyAutoConfiguration.ALLOWED_DOMAINS)
                            + " is non-empty";
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
