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
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.SystemEnvironmentPropertySource;

import com.the13haven.push2u.PushSender;

/**
 * The tombstone over {@code push2u.record-size}: a key a release removed must fail the context at startup, in every
 * spelling relaxed binding accepts, naming the property and where its effect went — binding ignores an unknown key
 * silently, so without the refusal the setting would read as though it were in force. The refusal is raised from a
 * post-processor of the bean factory, so it precedes every bean-creation failure; and a context without the key starts
 * exactly as before, which the whole of {@link Push2uAutoConfigurationTest} also pins by running with this
 * autoconfiguration present.
 *
 * <p>{@link Push2uStartupChecksAutoConfiguration} hosts two more checks, both about the allowlist properties; those are
 * covered in {@link Push2uEndpointPolicyAutoConfigurationTest} beside the bean they guard, including that they survive
 * the exclusion of the auto-configuration contributing that bean — the reason the checks live in this class rather than
 * in that one.
 */
class Push2uStartupChecksAutoConfigurationTest {

    /** The full starter composition, exactly as the imports file ships it. */
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    Push2uAutoConfiguration.class,
                    Push2uEndpointPolicyAutoConfiguration.class,
                    Push2uHealthAutoConfiguration.class,
                    Push2uStartupChecksAutoConfiguration.class));

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
        runner.withPropertyValues(
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
