/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.spring;

import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.diagnostics.FailureAnalysis;
import org.springframework.boot.diagnostics.analyzer.AbstractInjectionFailureAnalyzer;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;

import com.the13haven.push2u.EndpointPolicy;

/**
 * Answers an application that requires an {@link EndpointPolicy} from a context where the allowlist expressed none, so
 * the framework's generic "required a bean that could not be found" is what the operator would otherwise read.
 *
 * <p><b>The deployment this exists for is the one with no sender in it.</b> A service that accepts subscriptions and
 * leaves the sending to another one injects this bean to assess each offered endpoint against the same allowlist its
 * sending counterpart enforces — and it is precisely the context in which the sender's own refusal over an unexpressed
 * allowlist never runs, because there is no sender being built for it to run inside. What such a service gets instead
 * is an unsatisfied dependency naming a push2u type and nothing else, in the one deployment shape whose whole reason
 * for holding the policy is that a registration endpoint must not store whatever a browser offers it.
 *
 * <p><b>It states the same three states the sender's refusal states, from the same text.</b> Both are one question —
 * this context holds no policy, and what may answer it — asked from two places, so {@link MissingEndpointPolicy}
 * carries the wording and the reading of the properties for each, and neither this analysis nor that refusal restates
 * the other.
 *
 * <p><b>{@code push2u.enabled} is never given as the cause.</b> The switch withdraws the delivery path and deliberately
 * not the policy, whose auto-configuration carries no condition on it — so where a deployment has stated the switch
 * off, this says in one clause that it is not the reason. The clause is worth its space because the analysis of a
 * missing sender beside this one <em>does</em> answer in terms of that switch, and an operator who has read that one
 * will reach for it here: without the clause, the plausible next move is to turn delivery back on in a deployment that
 * deliberately does not send, which fixes nothing and undoes a statement someone made on purpose.
 *
 * <p><b>Nothing it says may be false about the context it is describing.</b> A startup diagnostic that states something
 * untrue about a deployment is this starter's own subject one layer down, so the analysis is declined outright wherever
 * the enumeration would not be a true account: a missing bean of some other type, a bean found more than once rather
 * than not at all, a failure early enough that neither the bean factory nor the environment is there to read, and a
 * context that does hold a definition of {@link EndpointPolicy} — where every one of the three states would be a
 * statement about a context other than this one.
 *
 * <p><b>Precedence is declared rather than taken.</b> The framework ships an analyzer for a missing bean of its own,
 * both recognise the same failure, and what the operator reads is whichever answers first in a sorted list. Losing that
 * race would leave no mark — the output would be correct, generic, and exactly what it was before this analyzer existed
 * — so the position is stated here instead of being inherited from where a factories file happens to list it.
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
final class MissingEndpointPolicyFailureAnalyzer
        extends AbstractInjectionFailureAnalyzer<NoSuchBeanDefinitionException> {

    /**
     * What an injection failure can be answered with that a refusal inside a factory method cannot: the injection point
     * itself. Held apart from the shared enumeration because it is true of this shape of the question only — the
     * sender's refusal has no injection point to withdraw.
     *
     * <p>The condition is <em>accepts subscriptions</em> rather than <em>validates the ones it accepts</em>, and the
     * difference is the whole of the sentence. A service that takes subscriptions from clients and does not check their
     * endpoints is the one deployment this may not invite to withdraw the injection point: it is the one that should
     * start checking them, and what follows would otherwise hand it the shape that lets registration go on storing
     * whatever a browser offers. Neither sending nor accepting leaves nothing for this policy to be applied to.
     */
    private static final String OR_STOP_REQUIRING_IT = "If this deployment neither sends nor accepts subscriptions,"
            + " the injection point is the thing to remove — an ObjectProvider<EndpointPolicy>, or a component that is"
            + " itself conditional, works in a deployment that expresses an allowlist and in one that does not.";

    private final @Nullable ConfigurableListableBeanFactory beanFactory;
    private final @Nullable Environment environment;

    /**
     * Both collaborators are supplied by the framework when it builds its analyzers, and both are absent when a failure
     * happens before there is a context to ask. Held as nullable rather than demanded, so that early case simply
     * declines the analysis and leaves the framework's own answer in place.
     */
    MissingEndpointPolicyFailureAnalyzer(@Nullable BeanFactory beanFactory, @Nullable Environment environment) {
        super();
        this.beanFactory = beanFactory instanceof ConfigurableListableBeanFactory listable ? listable : null;
        this.environment = environment;
    }

    @Override
    protected @Nullable FailureAnalysis analyze(
            Throwable rootFailure, NoSuchBeanDefinitionException cause, @Nullable String description) {
        ConfigurableListableBeanFactory factory = beanFactory;
        Environment env = environment;
        if (factory == null || env == null || !isMissingEndpointPolicy(cause) || hasEndpointPolicyDefinition(factory)) {
            return null;
        }
        Binder binder = Binder.get(env);
        // Read from the environment rather than from a bound properties record, because a context
        // that failed to start may hold neither the record nor the class that enables it — and read
        // through the same two names, and the same unset-against-emptied distinction, that decide
        // whether the policy bean exists at all.
        MissingEndpointPolicy state = MissingEndpointPolicy.of(
                Push2uEndpointPolicyAutoConfiguration.statedEntries(
                        binder, Push2uEndpointPolicyAutoConfiguration.ALLOWED_ORIGINS),
                Push2uEndpointPolicyAutoConfiguration.statedEntries(
                        binder, Push2uEndpointPolicyAutoConfiguration.ALLOWED_DOMAINS));
        String required = (description != null ? description : "A component") + " required an "
                + EndpointPolicy.class.getSimpleName() + " bean that could not be found. ";
        String switchIsNotTheReason = Push2uActivation.isStatedOff(binder) ? deliverySwitchIsNotTheReason() : "";
        return new FailureAnalysis(
                required + switchIsNotTheReason + state.situationSentence(),
                state.waysToAnswer() + " " + OR_STOP_REQUIRING_IT,
                cause);
    }

    /**
     * The clause that heads off the wrong suspicion in a context that stated it does not send. Every word of it is true
     * of that context: the switch is honoured, it withdraws the delivery path, and the policy is outside what it
     * withdraws — which is what that deployment keeps by making the statement.
     */
    private static String deliverySwitchIsNotTheReason() {
        return "This context states " + Push2uActivation.DELIVERY_SWITCH + "=" + Push2uActivation.OFF
                + ", and that is not why the bean is absent: the switch withdraws the delivery path — the signer, the"
                + " transport and the sender — and deliberately not the endpoint policy, which is what a deployment"
                + " that accepts subscriptions and sends nothing keeps by making that statement. Turning delivery back"
                + " on would not produce this bean. ";
    }

    /**
     * Whether {@code cause} is the absence of an {@link EndpointPolicy}, rather than of some other bean or a named one.
     */
    private static boolean isMissingEndpointPolicy(NoSuchBeanDefinitionException cause) {
        return cause.getNumberOfBeansFound() == 0 && EndpointPolicy.class.equals(cause.getBeanType());
    }

    /**
     * Whether this context holds a definition of {@link EndpointPolicy} after all — read as a <em>definition</em>, with
     * eager initialization off, so answering the question creates nothing in a context that has already failed. Where
     * one is registered, every state the enumeration can report is a statement about some other context: the policy is
     * here, and whatever kept this injection point from reaching it is not the absence this analyzer explains.
     */
    private static boolean hasEndpointPolicyDefinition(ConfigurableListableBeanFactory beanFactory) {
        return beanFactory.getBeanNamesForType(EndpointPolicy.class, true, false).length > 0;
    }
}
