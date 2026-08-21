/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.spring;

import java.util.List;

import org.jspecify.annotations.Nullable;

import com.the13haven.push2u.EndpointPolicy;

/**
 * The three states a context with no {@link EndpointPolicy} bean can be in, and what each one is owed: the situation it
 * is actually in, and every way to answer it.
 *
 * <p><b>Two readers, one text.</b> A sending deployment meets these states as a refusal — the obligation to say which
 * hosts this application server may POST to is the sender's, and its factory method fails the context over an
 * unexpressed one. A deployment that only accepts subscriptions meets the same states as an unsatisfied dependency,
 * because it injects the policy at the boundary where subscriptions arrive and there is no sender in it for that
 * refusal to run inside. The two are one question asked from two places, so the answer is written once here and
 * rendered in whichever shape the asker needs — a refusal folds both halves into one message, an injection-failure
 * analysis wants them apart. Written apart and joined, rather than written joined and split, so that neither shape can
 * be edited without the other following.
 *
 * <p>Which state applies is decided here too, from the two allowlist properties as bound, so the reading and the
 * wording cannot come apart either: a state whose text says the properties are unset is never chosen for a context that
 * emptied one of them.
 *
 * @param situation what is true of this context, as one or more finished sentences
 * @param waysToAnswer every way the deployment may answer it, in one sentence each
 */
record MissingEndpointPolicy(String situation, String waysToAnswer) {

    /** What every key this type names begins with, and the mark of a situation that opens with one. */
    private static final String PROPERTY_PREFIX = "push2u.";

    /**
     * The state the two allowlist properties put this context in, given that it holds no policy bean. Both unset is a
     * decision never made; every set property empty is a decision ceded to something that is not there; anything
     * non-empty is an allowlist that never became a bean, which happens only where the auto-configuration turning it
     * into one was excluded.
     *
     * @param allowedOrigins the entries of {@code push2u.allowed-origins}, or {@code null} where it is unset
     * @param allowedDomains the entries of {@code push2u.allowed-domains}, or {@code null} where it is unset
     * @return the state, with the answer it is owed
     */
    static MissingEndpointPolicy of(@Nullable List<String> allowedOrigins, @Nullable List<String> allowedDomains) {
        if (allowedOrigins == null && allowedDomains == null) {
            return noDecisionExpressed();
        }
        boolean originsExpressed = allowedOrigins != null && !allowedOrigins.isEmpty();
        boolean domainsExpressed = allowedDomains != null && !allowedDomains.isEmpty();
        if (!originsExpressed && !domainsExpressed) {
            return everyConfiguredAllowlistEmpty();
        }
        return allowlistExpressedWithoutItsAutoConfiguration(originsExpressed, domainsExpressed);
    }

    /** Both allowlist properties unset and no bean: the decision was never made, so name every way to make it. */
    private static MissingEndpointPolicy noDecisionExpressed() {
        return new MissingEndpointPolicy(
                "neither push2u.allowed-origins nor push2u.allowed-domains is set, and no EndpointPolicy bean is"
                        + " supplied — a sender needs one of them, because the endpoint it POSTs to comes from the"
                        + " subscription, and a subscription registered by a client can name any address this process"
                        + " can reach, including loopback, private-range and cloud-metadata ones.",
                "Set push2u.allowed-origins to the push service origins you expect (e.g."
                        + " https://fcm.googleapis.com); or set push2u.allowed-domains to a zone whose hostnames the"
                        + " service operator documents as varying (e.g. notify.windows.com, which admits every"
                        + " subdomain of it too); or define an EndpointPolicy bean — one returning"
                        + " EndpointPolicies.unrestricted() if this deployment deliberately applies no restriction,"
                        + " which is safe only where subscriptions never arrive from untrusted clients.");
    }

    /**
     * Every allowlist property that is set is empty, and there is no bean. Emptying a property cedes it to a bean, so
     * with no bean there is nothing to cede to and an empty allowlist would reject every send.
     */
    private static MissingEndpointPolicy everyConfiguredAllowlistEmpty() {
        return new MissingEndpointPolicy(
                "neither push2u.allowed-origins nor push2u.allowed-domains has an entry, and no EndpointPolicy bean is"
                        + " supplied — an empty allowlist would reject every send, which is far more likely a wiring"
                        + " bug than a policy. Emptying one of these properties states that this deployment does not"
                        + " use it and cedes the decision to an EndpointPolicy bean; with no bean there is nothing to"
                        + " cede to.",
                "List at least one entry under push2u.allowed-origins or push2u.allowed-domains, or define an"
                        + " EndpointPolicy bean — one returning EndpointPolicies.unrestricted() if this deployment"
                        + " deliberately applies no restriction.");
    }

    /**
     * A non-empty allowlist property, but no policy bean in the context: reachable only when the auto-configuration
     * whose bean's condition is exactly a non-empty allowlist has been excluded. Refused rather than rebuilt by whoever
     * needs the policy — the allowlist is one definition, published where the code that accepts subscriptions can reach
     * it, and a second construction elsewhere would be a second place the same rule is stated. The message names the
     * property that is actually non-empty, as every sibling refusal does: with two of them, an unnamed one would leave
     * half the search.
     */
    private static MissingEndpointPolicy allowlistExpressedWithoutItsAutoConfiguration(
            boolean originsExpressed, boolean domainsExpressed) {
        String expressed = originsExpressed && domainsExpressed
                ? "push2u.allowed-origins and push2u.allowed-domains are non-empty"
                : (originsExpressed ? "push2u.allowed-origins" : "push2u.allowed-domains") + " is non-empty";
        return new MissingEndpointPolicy(
                expressed + ", but no EndpointPolicy bean exists in this context — the allowlist becomes one only"
                        + " through Push2uEndpointPolicyAutoConfiguration, which is not active here (most likely"
                        + " excluded).",
                "Restore that auto-configuration, or supply an EndpointPolicy bean.");
    }

    /**
     * The two halves as one message, which is the shape a refusal takes: an exception carries one string, and the
     * situation is worth nothing to whoever reads it without the ways out beside it.
     */
    String refusalMessage() {
        return situation + " " + waysToAnswer;
    }

    /**
     * The situation as a sentence that can stand on its own, which is the shape an injection-failure analysis takes:
     * there it follows the framework's account of what went unsatisfied, and has to read as the next sentence rather
     * than as the continuation of a clause.
     *
     * <p>A situation that opens with a configuration key is left exactly as it is. Capitalising it would rewrite the
     * key into one nobody wrote and nothing binds, and a search for the name in the message would come back empty —
     * which costs more than the sentence gains, and is why a lowercase opening is correct here rather than tolerated.
     */
    String situationSentence() {
        return situation.startsWith(PROPERTY_PREFIX)
                ? situation
                : Character.toUpperCase(situation.charAt(0)) + situation.substring(1);
    }
}
