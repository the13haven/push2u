/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

import org.apache.commons.logging.LogFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.boot.diagnostics.FailureAnalysis;
import org.springframework.boot.diagnostics.FailureAnalyzer;
import org.springframework.boot.test.util.TestPropertyValues;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.support.SpringFactoriesLoader;
import org.springframework.core.io.support.SpringFactoriesLoader.ArgumentResolver;
import org.springframework.core.io.support.SpringFactoriesLoader.FailureHandler;

import com.the13haven.push2u.EndpointPolicy;
import com.the13haven.push2u.PushHttpClient;
import com.the13haven.push2u.VapidSigner;

/**
 * The analyzer that answers an application requiring an {@link EndpointPolicy} from a context that expressed no
 * allowlist — the registration-only service, which holds this bean to assess the endpoints it is offered and has no
 * sender in it for the sender's own refusal over the same absence to run inside.
 *
 * <p>Three states need three answers, and every one of them is the sender's refusal read out loud: the point of the
 * last test here is that neither text can be edited without the other following, because a second copy of an
 * enumeration is a second answer to one question within a release or so.
 *
 * <p>The contexts are built by hand rather than through the test runner because the analysis needs the failed context's
 * own bean factory and environment, which the runner does not hand out once a context has failed.
 */
class MissingEndpointPolicyFailureAnalyzerTest {

    /** What every description opens with, and the point at which the state's own account of the context begins. */
    private static final String FOUND = "EndpointPolicy bean that could not be found. ";

    /** A contact address, so a sending context fails over the policy rather than over the VAPID subject. */
    private static final String SUBJECT = "push2u.vapid.subject=mailto:admin@example.test";

    @Test
    void theServiceThatEmptiedItsInheritedAllowlistIsToldWhatEmptyingItMeant() {
        // The deployment this analyzer exists for: a registration-only service that inherits
        // push2u.allowed-origins from a shared configuration, empties it locally, declares no policy
        // bean of its own, and injects the policy where subscriptions arrive. No sender is built
        // here, so nothing this starter refuses over ever ran — before this analyzer, what such a
        // service read was the framework naming a push2u type and nothing else.
        withAnalysisOfARegistrationOnlyContext(
                List.of("push2u.allowed-origins=", "push2u.allowed-domains="), true, analysis -> {
                    assertThat(analysis).isNotNull();
                    assertThat(analysis.getDescription())
                            .contains("required an EndpointPolicy bean that could not be found.")
                            .as("the emptiness case, not the never-decided one beside it")
                            .contains("has an entry")
                            .contains("cede");
                    assertThat(analysis.getAction())
                            .contains("List at least one entry")
                            .contains("EndpointPolicies.unrestricted()")
                            .as("and the answer only an injection failure has: stop requiring it")
                            .contains("ObjectProvider<EndpointPolicy>");
                });
    }

    @Test
    void aContextThatExpressedNothingIsToldEveryWayToExpressIt() {
        // Neither property set and no bean: the decision was never taken, so the answer is the whole
        // enumeration — either property, or a bean, including the named opt-out that exists only as
        // a bean.
        withAnalysisOfARegistrationOnlyContext(List.of(), true, analysis -> {
            assertThat(analysis).isNotNull();
            assertThat(analysis.getDescription())
                    .as("the never-decided case, not the emptiness one beside it")
                    .contains("nor push2u.allowed-domains is set")
                    .contains("cloud-metadata");
            assertThat(analysis.getAction())
                    .contains("Set push2u.allowed-origins")
                    .contains("set push2u.allowed-domains")
                    .contains("EndpointPolicies.unrestricted()");
        });
    }

    @Test
    void anExpressedAllowlistWithNoBeanNamesTheAutoConfigurationThatWouldHaveBuiltIt() {
        // The third state, and the one an operator is least likely to work out alone: the allowlist
        // is stated, and the class that turns it into a bean is not in this context. The property
        // that is actually non-empty is named, and it opens the sentence in the spelling it was
        // written in — a capitalised "Push2u.allowed-origins" would be a key nobody wrote and
        // nothing binds, and a search of the message for the name would come back empty.
        withAnalysisOfARegistrationOnlyContext(
                List.of("push2u.allowed-origins=https://push.example.test"), false, analysis -> {
                    assertThat(analysis).isNotNull();
                    assertThat(analysis.getDescription())
                            .contains("push2u.allowed-origins is non-empty")
                            .as("the property that is actually non-empty, not its neighbour")
                            .doesNotContain("push2u.allowed-domains")
                            .contains("Push2uEndpointPolicyAutoConfiguration");
                    assertThat(analysis.getAction()).contains("Restore that auto-configuration");
                });
    }

    @Test
    void aDeploymentThatStatedFalseIsToldTheSwitchIsNotTheReason() {
        // The switch does not withdraw the policy — its auto-configuration carries no condition on
        // push2u.enabled and may never gain one, because the deployment that states false is exactly
        // the one holding this bean. The clause is here because the missing-sender analysis beside
        // this one does answer in terms of that switch, so an operator arrives already suspecting
        // it; without the clause the plausible next move is to turn delivery back on in a service
        // that deliberately does not send.
        withAnalysisOfARegistrationOnlyContext(
                List.of("push2u.enabled=false", "push2u.allowed-origins=", "push2u.allowed-domains="),
                true,
                analysis -> {
                    assertThat(analysis).isNotNull();
                    assertThat(analysis.getDescription())
                            .contains("This context states push2u.enabled=false, and that is not why the bean is"
                                    + " absent")
                            .contains("Turning delivery back on would not produce this bean")
                            .as("and the state itself is still reported, after the clause")
                            .contains("cede");
                    assertThat(analysis.getAction())
                            .as("the ways to answer are the allowlist's, never the switch's")
                            .contains("List at least one entry")
                            .doesNotContain("push2u.enabled");
                });
    }

    @Test
    void aMissingBeanOfSomeOtherTypeIsLeftToTheFrameworksOwnAnalyzer() {
        // The analyzer declines everything it has nothing to say about, which is what lets it hold
        // the first position in the list without swallowing unrelated failures.
        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            context.register(RequiresTransportConfiguration.class);
            assertThat(catchThrowable(context::refresh)).isNotNull();
            assertThat(analyzerOf(context).analyze(new NoSuchBeanDefinitionException(PushHttpClient.class)))
                    .as("no push2u analysis for a missing PushHttpClient")
                    .isNull();
        }
    }

    @Test
    void aNonUniqueEndpointPolicyIsLeftToTheFrameworksOwnAnalyzerToo() {
        // Two policy beans raise a subclass of the same exception, carrying a count and the
        // candidates, and there the framework's own analyzer — which lists them — is the answer that
        // helps. Every state this one can report would be plainly untrue of a context holding two
        // policies, and stating something untrue about a deployment is what it exists to stop.
        MissingEndpointPolicyFailureAnalyzer analyzer =
                new MissingEndpointPolicyFailureAnalyzer(new DefaultListableBeanFactory(), new StandardEnvironment());

        assertThat(analyzer.analyze(new NoUniqueBeanDefinitionException(
                        EndpointPolicy.class, List.of("push2uEndpointPolicy", "applicationPolicy"))))
                .as("a bean found twice is not a bean not found")
                .isNull();
    }

    @Test
    void aContextThatDoesHoldThePolicyIsDeclinedRatherThanExplained() {
        // The enumeration is an account of why no policy exists. Where one does, every branch of it
        // describes some other context — so whatever kept this injection point from reaching the
        // bean, it is not the absence this analyzer explains, and the framework's own report is the
        // one that stays.
        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            TestPropertyValues.of("push2u.allowed-origins=https://push.example.test")
                    .applyTo(context);
            context.register(Push2uEndpointPolicyAutoConfiguration.class);
            context.refresh();
            assertThat(context.getBeansOfType(EndpointPolicy.class))
                    .as("the context really does hold the bean this analysis would have denied")
                    .isNotEmpty();

            assertThat(analyzerOf(context).analyze(new NoSuchBeanDefinitionException(EndpointPolicy.class)))
                    .isNull();
        }
    }

    @Test
    void withoutTheContextsCollaboratorsTheAnalysisIsDeclined() {
        // Both are supplied by the framework only where there is a context to ask, and a failure
        // early enough has neither. Declining is what leaves the framework's own report standing;
        // anything else would be this analyzer describing a context it cannot read. A BeanFactory
        // that is not a ConfigurableListableBeanFactory is the same case rather than a lesser one —
        // the bean definitions the analysis reads are not reachable through it.
        NoSuchBeanDefinitionException cause = new NoSuchBeanDefinitionException(EndpointPolicy.class);

        assertThat(new MissingEndpointPolicyFailureAnalyzer(null, null).analyze(cause))
                .as("no context to ask")
                .isNull();
        assertThat(new MissingEndpointPolicyFailureAnalyzer(new StaticListableBeanFactory(), new StandardEnvironment())
                        .analyze(cause))
                .as("a BeanFactory that cannot be asked for definitions is no better than none")
                .isNull();
        assertThat(new MissingEndpointPolicyFailureAnalyzer(new DefaultListableBeanFactory(), null).analyze(cause))
                .as("without an environment, what the allowlist properties state cannot be read")
                .isNull();
    }

    @Test
    void aFailureWithNoInjectionPointToDescribeStillReadsAsASentence() {
        // The framework supplies the description of the injection point that went unsatisfied, and
        // supplies null where the failure carries none — an application asking the context for the
        // policy itself rather than having it injected, say. The answer still has to open as a
        // sentence, which is why "A component" stands in.
        withAnalyzerOfARegistrationOnlyContext(List.of(), true, analyzer -> {
            FailureAnalysis analysis = analyzer.analyze(new NoSuchBeanDefinitionException(EndpointPolicy.class));
            assertThat(analysis).isNotNull();
            assertThat(analysis.getDescription())
                    .startsWith("A component required an EndpointPolicy bean that could not be found.")
                    .as("the context is still read, and still answered for what it states")
                    .contains("nor push2u.allowed-domains is set");
        });
    }

    @Test
    void whatThisAnalysisSaysAndWhatTheSendersRefusalSaysAreOneText() {
        // The test this change is really about. The same three states are met from two places — a
        // sending deployment as a refusal inside the sender's factory method, a registration-only
        // one as an unsatisfied dependency — and nothing but a shared source keeps them saying the
        // same thing. So both texts are produced here, from two contexts that share nothing but the
        // properties, and each is checked against the other rather than against a constant: a
        // literal re-inlined into either one fails this, and an edit to the shared source fails
        // nothing, which is exactly the difference worth pinning.
        assertOneText("the decision was never taken", List.of(), true);
        assertOneText(
                "every set property was emptied", List.of("push2u.allowed-origins=", "push2u.allowed-domains="), true);
        assertOneText(
                "the allowlist is stated and its auto-configuration is not here",
                List.of("push2u.allowed-origins=https://push.example.test"),
                false);
    }

    @Test
    void thisAnalyzersTextIsTheOneThatArrives() {
        // The framework ships an analyzer for the same failure and both recognise it, so what the
        // operator reads is whichever answers first in the sorted list the framework builds from
        // every spring.factories on the classpath. This runs that list — loaded and sorted exactly
        // as the framework does it, then walked first-non-null as the framework walks it — rather
        // than asserting anything about an order constant. The starter's other analyzer is in that
        // same list and declines this failure, which is the second thing being checked.
        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            context.register(Push2uEndpointPolicyAutoConfiguration.class, RequiresPolicyConfiguration.class);
            Throwable failure = catchThrowable(context::refresh);
            assertThat(failure).isNotNull();

            List<FailureAnalyzer> analyzers = SpringFactoriesLoader.forDefaultResourceLocation(context.getClassLoader())
                    .load(
                            FailureAnalyzer.class,
                            ArgumentResolver.of(BeanFactory.class, context.getBeanFactory())
                                    .and(Environment.class, context.getEnvironment()),
                            // The framework skips an analyzer it cannot build, and this classpath
                            // has no spring-web for the framework's own routing analyzer to bind to.
                            FailureHandler.logging(LogFactory.getLog(MissingEndpointPolicyFailureAnalyzerTest.class)));
            assertThat(analyzers)
                    .as("both analyzers are really in the list this race is about")
                    .anyMatch(MissingEndpointPolicyFailureAnalyzer.class::isInstance)
                    .anyMatch(analyzer -> analyzer.getClass().getName().contains("NoSuchBeanDefinition"));

            FailureAnalysis arrived = firstAnalysis(analyzers, Objects.requireNonNull(failure));
            assertThat(arrived.getDescription())
                    .as("this analyzer's text, not the framework's generic one")
                    .contains("nor push2u.allowed-domains is set");
            assertThat(arrived.getAction()).doesNotContain("Consider defining a bean of type");
        }
    }

    /**
     * Produces both texts for one state — the refusal a sending context fails with, and the analysis a
     * registration-only context is given — and checks each against the other. Neither is compared with a literal: what
     * is asserted is that the refusal contains the analysis's account of the context, and that what follows that
     * account in the refusal is what the analysis offers as its action.
     */
    private static void assertOneText(String state, List<String> properties, boolean withPolicyAutoConfiguration) {
        String refusal = refusalOfASendingContext(properties, withPolicyAutoConfiguration);
        FailureAnalysis analysis = analysisOfARegistrationOnlyContext(properties, withPolicyAutoConfiguration);
        assertThat(analysis).as(state).isNotNull();

        String description = analysis.getDescription();
        String situation = description.substring(description.indexOf(FOUND) + FOUND.length());
        assertThat(refusal)
                .as("the refusal and the analysis describe " + state + " in one text")
                // Ignoring case for one character: a situation that does not open with a
                // configuration key opens the analysis's sentence capitalised and the refusal's
                // clause lowercase, which is the whole of the difference between the two shapes.
                .containsIgnoringCase(situation);

        String waysToAnswer = refusal.substring(situation.length() + 1);
        assertThat(analysis.getAction())
                .as("and offer the same ways out of " + state)
                .startsWith(waysToAnswer)
                .as("the analysis adds the one answer a refusal cannot have, and adds it after them")
                .hasSizeGreaterThan(waysToAnswer.length())
                .contains("ObjectProvider<EndpointPolicy>");
    }

    /**
     * The message a <em>sending</em> context fails with for these properties: a signer and a subject, so the sender is
     * built and its factory method reaches the policy it has no way to resolve.
     */
    private static String refusalOfASendingContext(List<String> properties, boolean withPolicyAutoConfiguration) {
        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            TestPropertyValues.of(properties.toArray(String[]::new))
                    .and(SUBJECT)
                    .applyTo(context);
            // The signer is registered first, as an application's own configuration really is: the
            // sender's condition sees only what is registered by the time it runs.
            context.register(ApplicationSignerConfiguration.class, Push2uAutoConfiguration.class);
            if (withPolicyAutoConfiguration) {
                context.register(Push2uEndpointPolicyAutoConfiguration.class);
            }
            Throwable failure = catchThrowable(context::refresh);
            assertThat(failure)
                    .as("a sending context with no policy was expected to be refused")
                    .isNotNull();
            return endpointPolicyRefusal(Objects.requireNonNull(failure));
        }
    }

    /** The first {@link IllegalStateException} in the chain that speaks about the policy, unwrapped from the wiring. */
    private static String endpointPolicyRefusal(Throwable failure) {
        for (Throwable current = failure; current != null; current = current.getCause()) {
            String message = current.getMessage();
            if (current instanceof IllegalStateException && message != null && message.contains("EndpointPolicy")) {
                return message;
            }
        }
        throw new AssertionError("no refusal about the endpoint policy in " + failure);
    }

    /** The analysis a registration-only context — no signer, no sender, the policy injected — is given. */
    private static FailureAnalysis analysisOfARegistrationOnlyContext(
            List<String> properties, boolean withPolicyAutoConfiguration) {
        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            TestPropertyValues.of(properties.toArray(String[]::new)).applyTo(context);
            context.register(RequiresPolicyConfiguration.class);
            if (withPolicyAutoConfiguration) {
                context.register(Push2uEndpointPolicyAutoConfiguration.class);
            }
            Throwable failure = catchThrowable(context::refresh);
            assertThat(failure)
                    .as("the context was expected to fail on the policy it injects")
                    .isNotNull();
            return analyzerOf(context).analyze(Objects.requireNonNull(failure));
        }
    }

    /** The same context, with the analysis handed to {@code assertions} — {@code null} where it is declined. */
    private static void withAnalysisOfARegistrationOnlyContext(
            List<String> properties, boolean withPolicyAutoConfiguration, ThrowingConsumer assertions) {
        assertions.accept(analysisOfARegistrationOnlyContext(properties, withPolicyAutoConfiguration));
    }

    /**
     * The same context, with the analyzer built from it handed to {@code assertions}, which supply the failure to
     * analyse themselves — the framework runs its analyzers over whatever startup failure arrives, and some of those
     * are failures the refresh establishing the context does not itself raise.
     */
    private static void withAnalyzerOfARegistrationOnlyContext(
            List<String> properties,
            boolean withPolicyAutoConfiguration,
            Consumer<MissingEndpointPolicyFailureAnalyzer> assertions) {
        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            TestPropertyValues.of(properties.toArray(String[]::new)).applyTo(context);
            context.register(RequiresPolicyConfiguration.class);
            if (withPolicyAutoConfiguration) {
                context.register(Push2uEndpointPolicyAutoConfiguration.class);
            }
            assertThat(catchThrowable(context::refresh))
                    .as("the context was expected to fail")
                    .isNotNull();
            assertions.accept(analyzerOf(context));
        }
    }

    /** The analyzer as the framework builds it: from this context's own bean factory and environment. */
    private static MissingEndpointPolicyFailureAnalyzer analyzerOf(AnnotationConfigApplicationContext context) {
        return new MissingEndpointPolicyFailureAnalyzer(context.getBeanFactory(), context.getEnvironment());
    }

    /** The framework's own algorithm: walk the sorted analyzers and take the first that answers. */
    private static FailureAnalysis firstAnalysis(List<FailureAnalyzer> analyzers, Throwable failure) {
        for (FailureAnalyzer analyzer : analyzers) {
            FailureAnalysis analysis = analyzer.analyze(failure);
            if (analysis != null) {
                return analysis;
            }
        }
        throw new AssertionError("no analyzer answered " + failure);
    }

    /** A consumer of the analysis that may itself throw, so the assertions read as ordinary code. */
    private interface ThrowingConsumer {
        void accept(FailureAnalysis analysis);
    }

    /** The registration-only service: it assesses the endpoints it is offered, and never sends. */
    @Configuration(proxyBeanMethods = false)
    static class RequiresPolicyConfiguration {

        @Bean
        String subscriptionValidator(EndpointPolicy endpointPolicy) {
            // The parameter is the whole of it: it is what leaves this bean unsatisfiable without a policy. Nothing
            // reads what the bean itself is, so it is a constant rather than anything derived from the policy.
            return "subscription-validator";
        }
    }

    /** The control: a component missing a bean this analyzer has nothing to say about. */
    @Configuration(proxyBeanMethods = false)
    static class RequiresTransportConfiguration {

        @Bean
        String transportDependent(PushHttpClient transport) {
            return "transport-dependent";
        }
    }

    /** A signer, so the sending half of the one-text check builds a sender and reaches the policy. */
    @Configuration(proxyBeanMethods = false)
    static class ApplicationSignerConfiguration {

        @Bean
        VapidSigner applicationSigner() {
            return new VapidSigner() {
                @Override
                public byte[] sign(byte[] signingInput) {
                    return new byte[64];
                }

                @Override
                public byte[] publicKey() {
                    byte[] key = new byte[65];
                    key[0] = 0x04;
                    return key;
                }
            };
        }
    }
}
