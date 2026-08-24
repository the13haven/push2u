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
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.env.Environment;
import org.springframework.core.type.MethodMetadata;

import com.the13haven.push2u.EndpointPolicy;
import com.the13haven.push2u.EndpointRule;
import com.the13haven.push2u.PushSender;
import com.the13haven.push2u.VapidSigner;

/**
 * This starter's startup checks — the refusals raised from post-processors of the bean factory, ahead of every
 * application singleton and every bean-creation failure, at the positions {@link StartupCheckOrder} declares — and
 * nothing else. Today that is the value of {@code push2u.enabled} itself, a malformed allowlist entry, an allowlist
 * stated beside an application-supplied {@link EndpointPolicy} bean, and the general refusal over a deployment that is
 * on and holds no signer.
 *
 * <p><b>An auto-configuration that contributes a bean an operator might want to remove may not also host a check.</b>
 * Excluding an auto-configuration is the framework's ordinary tool for removing what it contributes, and a check riding
 * in the same class vanishes with the contribution — the refusal disappears in exactly the deployment whose operator
 * reached for the standard tool, without anyone deciding to disable it. So the checks live here, in a class that
 * contributes nothing an application wires against: excluding the class that publishes the endpoint-policy bean leaves
 * every check running, and excluding <em>this</em> class says precisely what it does — it switches these checks off,
 * deliberately and visibly in the exclusion line that names it.
 *
 * <p><b>The class carries no condition, and a check carries one only where what it is about says so.</b> Anything
 * standing between a check and the context narrows the set of deployments it protects, and the deployment most in need
 * of one is often the one where nothing else reads the configuration at all — so {@code push2u.enabled} does not
 * condition this class, and the refusals about a <em>value</em> (the switch's own spelling, a malformed allowlist
 * entry, an allowlist contradicting a bean) run on both sides of the switch. An entry that is not an origin is not an
 * origin in a context that sends nothing either. The one check that answers the switch is the general refusal below,
 * and it answers it because of what it asks: whether this deployment can sign is a question a deployment that has said
 * it does not send has already answered.
 *
 * <p>Ordered after {@link Push2uAutoConfiguration} so that the local signer's bean definition is registered before this
 * class is processed — the general refusal's stand-down is a condition decided while the auto-configurations are being
 * processed, and a signer registered afterwards is invisible to it. <b>Nothing fails if that ordering declaration is
 * deleted</b> — the sorter seeds itself with the class names, these two happen to sort the same way, and no test can
 * tell the difference — so it looks redundant and is not: the coincidence is not the contract, and the day either class
 * is renamed the order it states is all that would be left.
 */
// UseUtilityClass: every member is static because the @Bean methods must be — the framework
// instructs that for a method producing a bean-factory post-processor, so the enclosing
// auto-configuration is not instantiated in that early phase. It is still no utility class: Spring
// instantiates it reflectively, so the constructor stays package-private rather than private.
@SuppressWarnings("PMD.UseUtilityClass")
@AutoConfiguration(after = Push2uAutoConfiguration.class)
public final class Push2uStartupChecksAutoConfiguration {

    Push2uStartupChecksAutoConfiguration() {
        // Explicit + package-private: the autoconfiguration is framework plumbing, not public API;
        // Spring still instantiates it reflectively. (This also avoids an undocumented public
        // default constructor that Javadoc/doclint flags.)
    }

    /**
     * The check over the activation switch's own value, ahead of every other refusal in the family.
     *
     * <p>{@code static}, and declaring the concrete class as its return type, both deliberately: the framework fetches
     * a post-processor bean before the configuration class is instantiated, and it chooses the sorting bucket from the
     * method's <em>declared</em> type — a method returning the post-processor interface would land the check in the
     * bucket that is never sorted, carrying an order nothing reads.
     *
     * @param environment the environment the switch's written value is read from
     * @return the check
     */
    @Bean
    static ActivationSwitchValueCheck push2uActivationSwitchValueCheck(Environment environment) {
        return new ActivationSwitchValueCheck(environment);
    }

    /**
     * The check refusing a malformed allowlist entry, ahead of every broader refusal.
     *
     * <p>{@code static} and declaring the concrete return type for the same reason as the switch's method above: the
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
     * The general refusal over a deployment that is on and holds no signer — the least specific finding of the family,
     * so it runs last.
     *
     * <p>Two conditions, and both are load-bearing. {@link ConditionalOnProperty} is the delivery switch: with the
     * statement made, there is no unanswered question left to refuse, and this is the only check in this class the
     * switch reaches. {@link ConditionalOnMissingBean} is the stand-down — a {@link VapidSigner} or a
     * {@link PushSender} from anywhere satisfies it — and it is decided while the auto-configurations are being
     * processed, against the bean <em>definitions</em> registered by then, so nothing is forced into existence to
     * answer it. One price is paid knowingly: that condition sees the application's own configuration, which is
     * processed first, and every signer starter ordered ahead of this class. A signer starter that declares no order is
     * placed by a fallback, and where that puts it afterwards, the context fails demanding a signer it holds. The
     * alternative is a refusal decided late enough to see everything, which is a refusal raised after the application
     * beans it exists to precede — and a starter that omits the order is relying on the same fallback for the sender's
     * own condition already.
     *
     * <p>{@code static} and declaring the concrete return type for the same reason as the methods above.
     *
     * @return the check
     */
    @Bean
    @ConditionalOnProperty(
            name = Push2uActivation.DELIVERY_SWITCH,
            havingValue = Push2uActivation.ON,
            matchIfMissing = true)
    @ConditionalOnMissingBean({VapidSigner.class, PushSender.class})
    static MissingSignerRefusal push2uMissingSignerRefusal() {
        return new MissingSignerRefusal();
    }

    /**
     * Fails the context at startup when {@code push2u.enabled} carries a value that is neither {@code true} nor
     * {@code false}, naming the property.
     *
     * <p>This is the one key where a typo would be free to mean the opposite of what was typed. The framework's usual
     * reading of an {@code enabled} key — anything not literally {@code false} is on — would turn {@code flase} into a
     * deployment that sends although it said not to; reading it the other way turns the same typo into a deployment
     * that silently stops sending, which is the state this whole family of checks exists to make impossible. So neither
     * reading is applied to an unrecognised value: it is refused, and the operator edits one character.
     *
     * <p><b>A blank value is refused too, and that is not the reading the activating properties get.</b> A blank
     * {@code public-key} could never have produced a signer, so reading it as unset only chooses between two failure
     * messages; a blank {@code push2u.enabled} would instead have to be read as one of two opposite statements, which
     * is precisely what this check exists to stop. So {@code PUSH2U_ENABLED=${SOMETHING:}} resolving to nothing is a
     * refusal naming the key rather than a guess about what was meant.
     *
     * <p>The value is read through {@link Binder}, so every spelling relaxed binding accepts is caught — including the
     * upper-case environment-variable form the condition on the delivery path also honours.
     *
     * <p>{@link Ordered} is implemented on the class — not declared on the factory method — because the framework
     * buckets a post-processor by what its class implements and would not read an annotation on the method.
     */
    static final class ActivationSwitchValueCheck implements BeanFactoryPostProcessor, Ordered {

        private final Environment environment;

        ActivationSwitchValueCheck(Environment environment) {
            this.environment = environment;
        }

        @Override
        public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
            String written = Push2uActivation.writtenSwitchValue(Binder.get(environment));
            if (written == null
                    || Push2uActivation.ON.equalsIgnoreCase(written)
                    || Push2uActivation.OFF.equalsIgnoreCase(written)) {
                return;
            }
            // The written value is not quoted back. It is the operator's own text, it reaches a
            // startup log that is commonly shipped whole, and nothing in the fix needs it: the
            // operator is looking at the key they wrote.
            throw new IllegalStateException(Push2uActivation.DELIVERY_SWITCH + " takes " + Push2uActivation.ON
                    + " or " + Push2uActivation.OFF + " and nothing else, and the configured value is neither. It is"
                    + " not read as either of them on purpose: this is the key that decides whether this deployment"
                    + " sends at all, so a typo here would otherwise mean the opposite of what was typed — silently, in"
                    + " whichever direction the guess happened to go. Leave the key out to send (that is the default),"
                    + " or write " + Push2uActivation.DELIVERY_SWITCH + "=" + Push2uActivation.OFF + " to state that"
                    + " this deployment does not. An empty value is refused for the same reason, so a placeholder that"
                    + " resolved to nothing has to be given a value rather than left blank.");
        }

        @Override
        public int getOrder() {
            return StartupCheckOrder.ACTIVATION_SWITCH_VALUE;
        }
    }

    /**
     * Fails the context at startup when delivery is on and the context holds neither a {@link VapidSigner} nor a
     * {@link PushSender} bean: a deployment states that it does not send, or the autoconfigured delivery path is
     * present and usable, and this is the third state.
     *
     * <p><b>Why it is fatal rather than a warning.</b> A deployment that mistypes a property prefix binds nothing,
     * validates nothing, boots green and never sends; no part of the process can tell it from a correctly configured
     * deployment that has had nothing to send yet, and the first symptom is a notification a user did not receive,
     * which nobody reports. A warning would leave that state in place — and would make the switch decorative, since
     * with a log line as the only consequence the statement changes nothing a running process can observe.
     *
     * <p><b>The message enumerates what this deployment may do, and stops at what this module owns.</b> It names the
     * switch, the two key properties of this starter, an application bean of either type, and — for a signer that comes
     * from elsewhere — <em>that</em> starter's own configuration, without naming its prefixes or counting its keys: a
     * message that spelled another module's activation rules would rebuild inside this library the copy a consumer was
     * asked to delete, and would go stale the day that module changed them. The last resort is the framework's
     * condition report, named by the flag that prints it at startup rather than by an Actuator endpoint a context that
     * failed to start cannot serve; the message is not assembled from that report either, whose keys and wording are
     * diagnostics rather than a contract.
     *
     * <p>The stand-down is the {@link ConditionalOnMissingBean} on the factory method, so a context that holds a signer
     * or a sender never registers this check at all. Nothing is re-checked here: by the time a post-processor runs, the
     * only definitions that could have appeared since are from auto-configurations ordered after this one, and that is
     * the price the factory method's documentation states rather than papers over.
     *
     * <p>{@link Ordered} is implemented on the class — not declared on the factory method — because the framework
     * buckets a post-processor by what its class implements and would not read an annotation on the method.
     */
    static final class MissingSignerRefusal implements BeanFactoryPostProcessor, Ordered {

        /**
         * Every way this deployment may answer the question, in one sentence each. Shared with the analyzer that
         * answers the same question from outside a failed context, so the two cannot drift into two enumerations.
         */
        static final String WAYS_TO_ANSWER = "Set " + Push2uActivation.DELIVERY_SWITCH + "="
                + Push2uActivation.OFF + " if this deployment deliberately does not send — it withdraws the delivery"
                + " path and nothing else, so a service that accepts subscriptions and leaves the sending to another"
                + " one keeps the endpoint policy its allowlist states, and every refusal guarding those properties"
                + " keeps running. Or set " + Push2uAutoConfiguration.OnLocalVapidKeys.PUBLIC_KEY + " and "
                + Push2uAutoConfiguration.OnLocalVapidKeys.PRIVATE_KEY + " for the in-JVM signer this module owns; a"
                + " blank value counts as unset there, so a placeholder that resolved to nothing has configured"
                + " nothing. Or configure the signer starter you have on the classpath, following that starter's own"
                + " properties — it names its own keys, and this message deliberately does not. Or define a"
                + " VapidSigner bean, or a PushSender bean of your own: either one answers this check, from anywhere in"
                + " the context. Starting with --debug prints the auto-configuration report, which names every"
                + " condition that did not match and why.";

        @Override
        public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
            throw new IllegalStateException("push2u is on — " + Push2uActivation.DELIVERY_SWITCH + " is unset, which"
                    + " means on, or set to " + Push2uActivation.ON + " — but this context holds no VapidSigner and no"
                    + " PushSender bean, so nothing here can send a web push message. A deployment states that it does"
                    + " not send, or the delivery path is present and usable: without the statement, \"configured and"
                    + " idle\" and \"misconfigured and silently not delivering\" are the same state from inside the"
                    + " process, from outside it, and afterwards. " + WAYS_TO_ANSWER);
        }

        @Override
        public int getOrder() {
            return StartupCheckOrder.MISSING_SIGNER;
        }
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
