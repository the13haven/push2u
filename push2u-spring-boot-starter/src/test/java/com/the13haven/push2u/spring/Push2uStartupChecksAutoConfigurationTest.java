/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.SystemEnvironmentPropertySource;

import com.the13haven.push2u.PushSender;

/**
 * The tombstones over {@code push2u.record-size}, the {@code push2u.health.*} pair and the {@code push2u.retry.*}
 * block: a key a release removed must fail the context at startup, in every spelling relaxed binding accepts, naming
 * the property and where its effect went — binding ignores an unknown key silently, so without the refusal the setting
 * would read as though it were in force. The refusal is raised from a post-processor of the bean factory, so it
 * precedes every bean-creation failure; and a context without the key starts exactly as before, which the whole of
 * {@link Push2uAutoConfigurationTest} also pins by running with this autoconfiguration present.
 *
 * <p>They are raised together, from one check, and that is what
 * {@link #everyDeadKeyThisCheckKnowsAboutIsNamedInOneFailure()} exists for: the released guide printed all of these
 * keys, so the deployment holding one commonly holds several, and a refusal per startup would charge it a failed start
 * per key.
 *
 * <p>{@link Push2uStartupChecksAutoConfiguration} hosts two more checks, both about the allowlist properties; those are
 * covered in {@link Push2uEndpointPolicyAutoConfigurationTest} beside the bean they guard, including that they survive
 * the exclusion of the auto-configuration contributing that bean — the reason the checks live in this class rather than
 * in that one.
 */
class Push2uStartupChecksAutoConfigurationTest {

    /**
     * The full starter composition, exactly as the imports file ships it, stating that this deployment does not send.
     * The statement is what lets a context configuring no signer start at all, and it is deliberately the harder half
     * of the pair to keep these cases on: every tombstone below therefore fires on the "off" side of the switch, which
     * is the side its row in the decision requires it to run on and the one nothing else here would exercise.
     */
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    Push2uAutoConfiguration.class,
                    Push2uEndpointPolicyAutoConfiguration.class,
                    Push2uHealthAutoConfiguration.class,
                    Push2uStartupChecksAutoConfiguration.class))
            .withPropertyValues("push2u.enabled=false");

    @Test
    void aLeftoverRecordSizeKeyFailsTheContextNamingThePropertyAndItsReplacement() {
        runner.withPropertyValues("push2u.record-size=8192").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("push2u.record-size")
                    .as("the message says where the effect went, so the operator has a move and not only a refusal")
                    .hasMessageContaining("push2u.max-encrypted-body-bytes")
                    .hasMessageContaining("derived");
        });
    }

    @Test
    void theRefusalCatchesTheCamelCaseSpellingRelaxedBindingAccepts() {
        runner.withPropertyValues("push2u.recordSize=8192").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("push2u.record-size");
        });
    }

    @Test
    void theRefusalCatchesTheEnvironmentVariableSpelling() {
        // PUSH2U_RECORD_SIZE arrives through a SystemEnvironmentPropertySource, whose mapping is
        // what Environment.getProperty("push2u.record-size") would NOT apply — this is the case
        // that forces the check through Binder rather than a literal property lookup.
        runner.withInitializer(environmentVariable("PUSH2U_RECORD_SIZE", "8192"))
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("push2u.record-size");
                });
    }

    @Test
    void theRefusalArrivesFromThePostProcessorAheadOfEveryBeanCreationFailure() {
        // A context holding several faults at once: unusable key material that would fail the
        // signer bean, and the removed key. The operator must read the tombstone's message — a key
        // that no longer exists makes every reading of the configuration under it suspect — which
        // is only possible because the check runs in the post-processor phase, before any bean is
        // created. A refusal left inside a bean factory method would lose this race.
        //
        // push2u.enabled=true overrides the runner's statement on purpose: with delivery off there
        // is no signer bean to fail, and the test would pass without proving anything about order.
        runner.withPropertyValues(
                        "push2u.enabled=true",
                        "push2u.record-size=8192",
                        "push2u.vapid.public-key=!!not-base64url!!",
                        "push2u.vapid.private-key=!!not-base64url!!",
                        "push2u.vapid.subject=mailto:ops@example.com",
                        "push2u.allowed-origins=https://push.example.test")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .as("the tombstone's own IllegalStateException, not a bean-creation wrapper")
                            .isInstanceOf(IllegalStateException.class)
                            .isNotInstanceOf(BeanCreationException.class)
                            .hasMessageContaining("push2u.record-size");
                });
    }

    @Test
    void theRefusalDoesNotDependOnAnyOtherConfiguration() {
        // The check runs whether or not a signer, a sender or any push2u.* sibling is configured:
        // nothing standing between it and the context may narrow the set of deployments it
        // protects, since the deployment most in need of it is one where nothing else reads the
        // namespace at all.
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(Push2uStartupChecksAutoConfiguration.class))
                .withPropertyValues("push2u.record-size=8192")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("push2u.record-size");
                });
    }

    @Test
    void aLeftoverHealthEnabledKeyFailsTheContextNamingItsReplacement() {
        // The dangerous direction is the one this refusal exists for: an ignored push2u.health
        // .enabled=false would leave the deployment that switched the probe OFF probing again after
        // the upgrade — with a remote signer, a real audited signing operation on every poll,
        // discovered in an audit log rather than by anything failing.
        runner.withPropertyValues("push2u.health.enabled=false").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("push2u.health.enabled")
                    .as("the message says where the switch went, so the operator has a move and not only a refusal")
                    .hasMessageContaining("management.health.push2u.enabled")
                    .hasMessageContaining("management.health.defaults.enabled");
        });
    }

    @Test
    void theRefusalFiresWhateverValueTheOldSwitchCarried() {
        // The key is dead, not wrong: `true` was as much a statement about this probe as `false`,
        // and reading the value would make the refusal depend on the one thing that no longer means
        // anything.
        runner.withPropertyValues("push2u.health.enabled=true").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("management.health.push2u.enabled");
        });
    }

    @Test
    void aLeftoverHealthCacheTtlKeyFailsTheContextNamingItsReplacement() {
        // Same reasoning one key over: a tuned TTL silently reverting to the 30s default is six
        // times the probes a 5s setting configured, and six times the signing operations with it.
        runner.withPropertyValues("push2u.health.cache-ttl=5s").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("push2u.health.cache-ttl")
                    .hasMessageContaining("management.health.push2u.cache-ttl");
        });
    }

    @Test
    void bothHealthKeysAreReportedAtOnce() {
        // They moved in one change and are fixed in one edit. An operator told about the first only
        // to meet the second on the next start has been given half of what was known.
        runner.withPropertyValues("push2u.health.enabled=false", "push2u.health.cache-ttl=5s")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("push2u.health.enabled")
                            .hasMessageContaining("push2u.health.cache-ttl")
                            .hasMessageContaining("management.health.push2u.enabled")
                            .hasMessageContaining("management.health.push2u.cache-ttl");
                });
    }

    @Test
    void aLeftoverRetryMaxAttemptsKeyFailsTheContextNamingWhereTheDecisionWent() {
        // The retry keys are the removal whose silent ignoring changes delivery rather than a
        // diagnostic: a deployment that configured three attempts would start clean and then send
        // once per message, and every message a push service dropped under load would be gone with
        // nothing said about it. So the refusal has to hand the operator the replacement — not a
        // property, but the outcome the caller now schedules from.
        runner.withPropertyValues("push2u.retry.max-attempts=3").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("push2u.retry.max-attempts")
                    .as("the message says where the decision went, so the operator has a move and not only a refusal")
                    .hasMessageContaining("one POST")
                    .hasMessageContaining("RetryableFailure")
                    .hasMessageContaining("Retry-After");
        });
    }

    @Test
    void aLeftoverRetryInitialBackoffKeyFailsTheContextNamingWhereTheWaitWent() {
        runner.withPropertyValues("push2u.retry.initial-backoff=2s").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("push2u.retry.initial-backoff")
                    .hasMessageContaining("RetryableFailure")
                    .hasMessageContaining("Retry-After");
        });
    }

    @Test
    void aLeftoverRetryMaxBackoffKeyFailsTheContextSayingWhereABoundNowBelongs() {
        // This one's operator had decided a bound was needed, and the value they were bounding is
        // now reported with no ceiling applied — so the refusal says where to apply it rather than
        // only that the key is dead.
        runner.withPropertyValues("push2u.retry.max-backoff=60s").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("push2u.retry.max-backoff")
                    .hasMessageContaining("no ceiling applied")
                    .hasMessageContaining("where the repeat is scheduled");
        });
    }

    @Test
    void allThreeRetryKeysAreReportedAtOnce() {
        // They were one block in the released guide, they went in one change, and they are deleted
        // in one edit. An operator told about the first only to meet the second on the next start
        // has been given a third of what was known.
        runner.withPropertyValues(
                        "push2u.retry.max-attempts=3",
                        "push2u.retry.initial-backoff=1s",
                        "push2u.retry.max-backoff=60s")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("push2u.retry.max-attempts")
                            .hasMessageContaining("push2u.retry.initial-backoff")
                            .hasMessageContaining("push2u.retry.max-backoff");
                });
    }

    @Test
    void theRetryRefusalCatchesTheCamelCaseSpellingRelaxedBindingAccepts() {
        runner.withPropertyValues("push2u.retry.maxAttempts=3").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("push2u.retry.max-attempts");
        });
    }

    @Test
    void theRetryRefusalCatchesTheEnvironmentVariableSpelling() {
        // PUSH2U_RETRY_INITIAL_BACKOFF arrives through a SystemEnvironmentPropertySource, whose
        // mapping is what Environment.getProperty("push2u.retry.initial-backoff") would NOT apply —
        // the same case the record-size and health tombstones above are held to, one prefix deeper.
        runner.withInitializer(environmentVariable("PUSH2U_RETRY_INITIAL_BACKOFF", "1s"))
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("push2u.retry.initial-backoff");
                });
    }

    @Test
    void everyDeadKeyThisCheckKnowsAboutIsNamedInOneFailure() {
        // Why one failure at all: the configuration an operator upgrading from the released guide
        // holds is every one of these at once, because the guide printed them together — record-size
        // in the defaults block, the push2u.health block beside it and the push2u.retry block under
        // both. Refused one startup at a time, each key would hide the next and the upgrade would
        // cost a failed start per key.
        //
        // The keys come from the check's own entries rather than from a list written out here, so an
        // entry a later release adds is covered the day it lands. What that buys is bounded, and
        // worth stating exactly: every entry's refusal names its own key, and reaches the one joined
        // failure whole. It does not check what a refusal *says* — the expected text is taken from
        // the same entry the check emits, so it could not — and each entry's wording is pinned by its
        // own test above. The values are arbitrary: the check asks whether a key is bound, never what
        // it was bound to.
        var removedProperties = Push2uStartupChecksAutoConfiguration.RemovedPropertyTombstones.REMOVED_PROPERTIES;
        String[] everyDeadKey = removedProperties.stream()
                .map(removed -> removed.key() + "=whatever-the-operator-wrote")
                .toArray(String[]::new);

        runner.withPropertyValues(everyDeadKey).run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).isInstanceOf(IllegalStateException.class);
            for (var removed : removedProperties) {
                assertThat(removed.refusal())
                        .as("a refusal that never names its own key refuses an operator without telling"
                                + " them which key to delete")
                        .contains(removed.key());
                assertThat(context.getStartupFailure())
                        .as("%s reaches the one failure whole, not trimmed to a list of names", removed.key())
                        .hasMessageContaining(removed.refusal());
            }
        });

        // And one edit is enough: the same context with those keys deleted starts. This is the half
        // that makes the assertion above about the operator's cost rather than about a string.
        runner.run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void theHealthRefusalCatchesTheCamelCaseSpellingRelaxedBindingAccepts() {
        runner.withPropertyValues("push2u.health.cacheTtl=5s").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("push2u.health.cache-ttl");
        });
    }

    @Test
    void theHealthRefusalCatchesTheEnvironmentVariableSpelling() {
        // PUSH2U_HEALTH_ENABLED arrives through a SystemEnvironmentPropertySource, whose mapping is
        // what Environment.getProperty("push2u.health.enabled") would NOT apply — the case that
        // forces this check through Binder rather than a literal property lookup, exactly as the
        // record-size tombstone above.
        runner.withInitializer(environmentVariable("PUSH2U_HEALTH_ENABLED", "false"))
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("management.health.push2u.enabled");
                });
    }

    @Test
    void theHealthRefusalSurvivesAClasspathWithoutSpringBootHealth() {
        // The reason this tombstone is declared here rather than inside the autoconfiguration that
        // registers the indicator. A deployment that dropped Actuator and kept the keys holds
        // exactly the same dead configuration, and a check standing behind that class-level
        // condition would let through the one case it was written for. The context must also still
        // start without the keys — the same classpath, both answers.
        ApplicationContextRunner withoutHealth =
                runner.withClassLoader(new FilteredClassLoader("org.springframework.boot.health"));

        withoutHealth.run(context -> assertThat(context).hasNotFailed());
        withoutHealth.withPropertyValues("push2u.health.enabled=false").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("management.health.push2u.enabled");
        });
    }

    @Test
    void aContextWithoutTheKeyStartsAsBefore() {
        // No push2u.* configuration at all: the tombstone contributes its check and nothing else,
        // so the context starts exactly as it would have without this autoconfiguration.
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(PushSender.class);
        });
    }

    /** Puts one variable into the environment through the source type real environment variables arrive by. */
    private static ApplicationContextInitializer<ConfigurableApplicationContext> environmentVariable(
            String name, String value) {
        return context -> context.getEnvironment()
                .getPropertySources()
                .addFirst(new SystemEnvironmentPropertySource("tombstone-test-environment", Map.of(name, value)));
    }
}
