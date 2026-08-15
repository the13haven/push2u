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

import com.the13haven.push2u.PushSender;
import com.the13haven.push2u.VapidSigner;

/**
 * Answers the one case this starter's own startup refusal cannot reach: an application that requires a
 * {@link PushSender} from a context where that refusal never ran, so the framework's generic "required a bean that
 * could not be found" is what the operator would otherwise read.
 *
 * <p><b>Three causes, three answers.</b> Reporting all of them as "configure a signer" would put this starter's own
 * subject back one layer down — a deployment that deliberately switched delivery off, told it has a defect:
 *
 * <ol>
 *   <li>{@code push2u.enabled=false} is stated and something still requires a sender. That is a contradiction inside
 *       the application, not a missing signer, and the fix is on one side or the other of it.
 *   <li>The startup checks are not active in this context — excluded, or never imported — so the refusal that would
 *       have named the missing piece while the auto-configurations ran never got the chance.
 *   <li>Everything else: the question is unanswered, and the answer is the same enumeration the refusal itself gives. A
 *       signer bean the context already holds is the one shape of it worth leading with, since the refusal stood down
 *       over exactly that and what is missing is the sender built from it — that case is tested before the one above,
 *       because restoring the checks would not change a thing a signer has already answered.
 * </ol>
 *
 * <p><b>Nothing it says may be false about the context it is describing.</b> A startup diagnostic that states something
 * untrue about a deployment is this starter's own subject one layer down, so where two shapes reach one branch the
 * sentence names both rather than guessing between them — a context holding a signer and no sender is either one whose
 * sender auto-configuration is inactive or one whose sender condition could not see that signer, and the answer covers
 * each.
 *
 * <p><b>Precedence is declared rather than taken.</b> The framework ships an analyzer for a missing bean of its own,
 * both recognise the same failure, and what the operator reads is whichever answers first in a sorted list. Losing that
 * race would leave no mark — the output would be correct, generic, and exactly what it was before this analyzer existed
 * — so the position is stated here instead of being inherited from where a factories file happens to list it.
 * Everything not about a missing {@link PushSender} is declined, so the framework's analyzer keeps every failure this
 * one has nothing to say about.
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
final class MissingPushSenderFailureAnalyzer extends AbstractInjectionFailureAnalyzer<NoSuchBeanDefinitionException> {

    /** The enumeration the refusal itself publishes, so this answer and that one cannot drift into two. */
    private static final String WAYS_TO_ANSWER =
            Push2uStartupChecksAutoConfiguration.MissingSignerRefusal.WAYS_TO_ANSWER;

    private final @Nullable ConfigurableListableBeanFactory beanFactory;
    private final @Nullable Environment environment;

    /**
     * Both collaborators are supplied by the framework when it builds its analyzers, and both are absent when a failure
     * happens before there is a context to ask. Held as nullable rather than demanded, so that early case simply
     * declines the analysis and leaves the framework's own answer in place.
     */
    MissingPushSenderFailureAnalyzer(@Nullable BeanFactory beanFactory, @Nullable Environment environment) {
        super();
        this.beanFactory = beanFactory instanceof ConfigurableListableBeanFactory listable ? listable : null;
        this.environment = environment;
    }

    @Override
    protected @Nullable FailureAnalysis analyze(
            Throwable rootFailure, NoSuchBeanDefinitionException cause, @Nullable String description) {
        ConfigurableListableBeanFactory factory = beanFactory;
        Environment env = environment;
        if (factory == null || env == null || !isMissingPushSender(cause)) {
            return null;
        }
        String required = (description != null ? description : "A component") + " required a "
                + PushSender.class.getSimpleName() + " bean that could not be found. ";
        if (Push2uActivation.isStatedOff(Binder.get(env))) {
            return new FailureAnalysis(
                    required + "This context states " + Push2uActivation.DELIVERY_SWITCH + "="
                            + Push2uActivation.OFF + ", so push2u deliberately contributed no sender, no signer and no"
                            + " transport — the statement is being honoured, and this is not a missing signer. What is"
                            + " left is a contradiction inside the application: something requires a sender in a"
                            + " deployment that has said it does not send.",
                    "Decide which of the two is true. If this deployment really does not send, stop requiring the bean"
                            + " where it is switched off — an ObjectProvider<PushSender> injection point, or a"
                            + " component that is itself conditional, works in both deployments. If it does send,"
                            + " remove " + Push2uActivation.DELIVERY_SWITCH + "=" + Push2uActivation.OFF
                            + " and configure a signer.",
                    cause);
        }
        if (hasDefinition(factory, VapidSigner.class)) {
            // Two shapes reach this branch and the message may not claim one of them. Either
            // Push2uAutoConfiguration is not active, or it is active and its sender's condition did
            // not see this signer — which happens when the auto-configuration contributing the
            // signer is ordered after the one building the sender, since a condition sees only what
            // is registered by the time it runs. Both are true statements about "no sender built
            // from a signer this context holds", and the sentence says exactly that much.
            return new FailureAnalysis(
                    required + "This context holds a VapidSigner bean, so push2u's own refusal over a missing signer"
                            + " stood down — it asks only whether this deployment can sign, and something answered."
                            + " What is missing is the autoconfigured sender built from that signer, which"
                            + " Push2uAutoConfiguration contributes. Either that auto-configuration is not active here,"
                            + " or it is active and the signer was registered too late for it to see: a condition sees"
                            + " only the beans registered by the time it runs, so an auto-configuration contributing a"
                            + " VapidSigner has to declare itself before"
                            + " com.the13haven.push2u.spring.Push2uAutoConfiguration.",
                    "Restore Push2uAutoConfiguration if it was excluded; if it is active, order the auto-configuration"
                            + " contributing the signer before it. Either way, defining a PushSender bean of your own"
                            + " around the signer this context already holds answers it without depending on that"
                            + " order.",
                    cause);
        }
        if (!hasDefinition(factory, Push2uStartupChecksAutoConfiguration.MissingSignerRefusal.class)) {
            return new FailureAnalysis(
                    required + "push2u's startup checks are not active in this context —"
                            + " Push2uStartupChecksAutoConfiguration is excluded, or was never imported — so the"
                            + " refusal that would have named the missing piece while the auto-configurations ran never"
                            + " got the chance, and the framework's generic report is what is left.",
                    "Restore Push2uStartupChecksAutoConfiguration, which fails the context naming exactly what is"
                            + " missing and what may answer it. If the exclusion is deliberate, answer it here"
                            + " instead. " + WAYS_TO_ANSWER,
                    cause);
        }
        // The residue: on, no signer, and the refusal registered — which means it fired and this
        // context failed with its message rather than with a missing bean. Answered anyway, with
        // the same enumeration, so that a route nobody has found yet still gets the useful text.
        return new FailureAnalysis(
                required + "push2u is on and this context holds no signer, so nothing here can send a web push"
                        + " message. A deployment states that it does not send, or the delivery path is present and"
                        + " usable.",
                WAYS_TO_ANSWER,
                cause);
    }

    /** Whether {@code cause} is the absence of a {@link PushSender}, rather than of some other bean or a named one. */
    private static boolean isMissingPushSender(NoSuchBeanDefinitionException cause) {
        return cause.getNumberOfBeansFound() == 0 && PushSender.class.equals(cause.getBeanType());
    }

    /**
     * Whether a definition of {@code type} is registered — read as a <em>definition</em>, with eager initialization
     * off, so answering this question creates nothing in a context that has already failed.
     */
    private static boolean hasDefinition(ConfigurableListableBeanFactory beanFactory, Class<?> type) {
        return beanFactory.getBeanNamesForType(type, true, false).length > 0;
    }
}
