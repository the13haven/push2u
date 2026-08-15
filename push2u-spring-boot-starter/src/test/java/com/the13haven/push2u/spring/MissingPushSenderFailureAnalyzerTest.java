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

import org.apache.commons.logging.LogFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.boot.diagnostics.FailureAnalysis;
import org.springframework.boot.diagnostics.FailureAnalyzer;
import org.springframework.boot.test.util.TestPropertyValues;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.io.support.SpringFactoriesLoader;
import org.springframework.core.io.support.SpringFactoriesLoader.ArgumentResolver;
import org.springframework.core.io.support.SpringFactoriesLoader.FailureHandler;

import com.the13haven.push2u.PushHttpClient;
import com.the13haven.push2u.PushSender;
import com.the13haven.push2u.VapidSigner;

/**
 * The analyzer that answers the one case the startup refusal cannot reach: an application requiring a
 * {@link PushSender} from a context where that refusal never ran.
 *
 * <p>Three causes need three answers, and the one that matters most is the deployment that switched delivery off:
 * telling it to "configure a signer" would report a deliberate statement as a defect, which is this starter's own
 * subject one layer down. The last case here is the race — the framework ships an analyzer for the same failure, and
 * what an operator reads is whichever answers first in a sorted list, so the position is declared rather than inherited
 * from where a factories file happens to sit on the classpath.
 *
 * <p>The contexts are built by hand rather than through the test runner because the analysis needs the failed context's
 * own bean factory and environment, which the runner does not hand out once a context has failed.
 */
class MissingPushSenderFailureAnalyzerTest {

    @Test
    void aDeploymentThatStatedFalseIsToldItHasAContradictionRatherThanAMissingSigner() {
        withFailedContext(
                List.of("push2u.enabled=false"),
                analysis -> {
                    assertThat(analysis).isNotNull();
                    assertThat(analysis.getDescription())
                            .contains("push2u.enabled=false")
                            .contains("the statement is being honoured")
                            .contains("contradiction inside the application");
                    assertThat(analysis.getAction())
                            .as("the fix is on one side or the other, and neither is \"configure a signer\"")
                            .contains("ObjectProvider<PushSender>")
                            .doesNotContain("push2u.vapid.public-key");
                },
                Push2uAutoConfiguration.class,
                Push2uStartupChecksAutoConfiguration.class,
                RequiresSenderConfiguration.class);
    }

    @Test
    void aContextThatExcludedTheChecksIsToldTheCheckIsMissingRatherThanTheSigner() {
        // The refusal is absent because its auto-configuration is not here, so the operator gets the
        // one fact that explains why nothing said this earlier — and, because the exclusion may be
        // deliberate, the enumeration as well.
        withFailedContext(
                List.of(),
                analysis -> {
                    assertThat(analysis).isNotNull();
                    assertThat(analysis.getDescription())
                            .contains("Push2uStartupChecksAutoConfiguration is excluded, or was never imported");
                    assertThat(analysis.getAction())
                            .contains("Restore Push2uStartupChecksAutoConfiguration")
                            .contains("push2u.enabled=false");
                },
                Push2uAutoConfiguration.class,
                RequiresSenderConfiguration.class);
    }

    @Test
    void aContextHoldingASignerIsToldWhichPieceIsActuallyMissing() {
        // The refusal stood down over a signer this context genuinely holds, so "configure a signer"
        // would be the third wrong answer. What is missing is the sender built from it.
        withFailedContext(
                List.of(),
                analysis -> {
                    assertThat(analysis).isNotNull();
                    assertThat(analysis.getDescription())
                            .contains("holds a VapidSigner bean")
                            .contains("stood down");
                    assertThat(analysis.getAction()).contains("Restore Push2uAutoConfiguration");
                },
                // The signer is registered first, as an application's own configuration really is:
                // the refusal's stand-down is a condition, and a condition sees only what is
                // registered by the time it runs.
                ApplicationSignerConfiguration.class,
                Push2uStartupChecksAutoConfiguration.class,
                RequiresSenderConfiguration.class);
    }

    @Test
    void thatAnswerStaysTrueWhereTheSenderAutoConfigurationIsActiveAndSawNoSigner() {
        // The second shape reaching that same branch, and the one an earlier wording claimed
        // something false about. Here Push2uAutoConfiguration IS active — the signer simply arrived
        // after it, which is what a signer starter declaring itself after the core starter rather
        // than before it produces, and which leaves pushSender's @ConditionalOnBean unable to see a
        // signer the context genuinely holds. A diagnostic that states something untrue about a
        // deployment is this record's own subject one layer down, so the sentence has to cover both.
        withFailedContext(
                List.of(),
                analysis -> {
                    assertThat(analysis).isNotNull();
                    assertThat(analysis.getDescription())
                            .as("the claim is about the sender being missing, never about the class being absent")
                            .contains("Either that auto-configuration is not active here")
                            .contains("registered too late for it to see")
                            .doesNotContain("which is not active here");
                    assertThat(analysis.getAction())
                            .contains("if it is active, order the auto-configuration contributing the signer before it")
                            .contains("without depending on that order");
                },
                // Registration order is the auto-configuration order here: the sender's class is
                // processed before the signer's, exactly as a mis-ordered signer starter would be.
                Push2uAutoConfiguration.class,
                ApplicationSignerConfiguration.class,
                RequiresSenderConfiguration.class);
    }

    @Test
    void aMissingBeanOfSomeOtherTypeIsLeftToTheFrameworksOwnAnalyzer() {
        // The analyzer declines everything it has nothing to say about, which is what lets it hold
        // the first position in the list without swallowing unrelated failures.
        withFailedContext(
                List.of("push2u.enabled=false"),
                analysis -> assertThat(analysis)
                        .as("no push2u analysis for a missing PushHttpClient")
                        .isNull(),
                Push2uStartupChecksAutoConfiguration.class,
                RequiresTransportConfiguration.class);
    }

    @Test
    void thisAnalyzersTextIsTheOneThatArrives() {
        // The framework ships an analyzer for the same failure and both recognise it, so what the
        // operator reads is whichever answers first in the sorted list the framework builds from
        // every spring.factories on the classpath. This runs that list — loaded and sorted exactly
        // as the framework does it, then walked first-non-null as the framework walks it — rather
        // than asserting anything about an order constant.
        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            TestPropertyValues.of("push2u.enabled=false").applyTo(context);
            context.register(
                    Push2uAutoConfiguration.class,
                    Push2uStartupChecksAutoConfiguration.class,
                    RequiresSenderConfiguration.class);
            Throwable failure = catchThrowable(context::refresh);
            assertThat(failure).isNotNull();

            List<FailureAnalyzer> analyzers = SpringFactoriesLoader.forDefaultResourceLocation(context.getClassLoader())
                    .load(
                            FailureAnalyzer.class,
                            ArgumentResolver.of(BeanFactory.class, context.getBeanFactory())
                                    .and(Environment.class, context.getEnvironment()),
                            // The framework skips an analyzer it cannot build, and this classpath
                            // has no spring-web for the framework's own routing analyzer to bind to.
                            FailureHandler.logging(LogFactory.getLog(MissingPushSenderFailureAnalyzerTest.class)));
            assertThat(analyzers)
                    .as("both analyzers are really in the list this race is about")
                    .anyMatch(MissingPushSenderFailureAnalyzer.class::isInstance)
                    .anyMatch(analyzer -> analyzer.getClass().getName().contains("NoSuchBeanDefinition"));

            FailureAnalysis arrived = firstAnalysis(analyzers, Objects.requireNonNull(failure));
            assertThat(arrived).isNotNull();
            assertThat(arrived.getDescription())
                    .as("this analyzer's text, not the framework's generic one")
                    .contains("contradiction inside the application");
            assertThat(arrived.getAction()).doesNotContain("Consider defining a bean of type");
        }
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

    /**
     * Refreshes a context that is expected to fail, and hands this analyzer's answer — or {@code null} where it
     * declines — to {@code assertions}, built from the failed context's own bean factory and environment.
     */
    private static void withFailedContext(
            List<String> properties, ThrowingConsumer assertions, Class<?>... configurations) {
        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            TestPropertyValues.of(properties.toArray(String[]::new)).applyTo(context);
            context.register(configurations);
            Throwable failure = catchThrowable(context::refresh);
            assertThat(failure)
                    .as("the context was expected to fail on a missing bean")
                    .isNotNull();
            MissingPushSenderFailureAnalyzer analyzer =
                    new MissingPushSenderFailureAnalyzer(context.getBeanFactory(), context.getEnvironment());
            assertions.accept(analyzer.analyze(Objects.requireNonNull(failure)));
        }
    }

    /** A consumer of the analysis that may itself throw, so the assertions read as ordinary code. */
    private interface ThrowingConsumer {
        void accept(FailureAnalysis analysis);
    }

    /** An application component that cannot start without a sender. */
    @Configuration(proxyBeanMethods = false)
    static class RequiresSenderConfiguration {

        @Bean
        String senderDependent(PushSender sender) {
            return sender.toString();
        }
    }

    /** The control: a component missing a bean this analyzer has nothing to say about. */
    @Configuration(proxyBeanMethods = false)
    static class RequiresTransportConfiguration {

        @Bean
        String transportDependent(PushHttpClient transport) {
            return transport.toString();
        }
    }

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
