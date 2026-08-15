/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.UnsatisfiedDependencyException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.SystemEnvironmentPropertySource;

import com.the13haven.push2u.EndpointPolicies;
import com.the13haven.push2u.EndpointPolicy;
import com.the13haven.push2u.PushHttpClient;
import com.the13haven.push2u.PushSender;
import com.the13haven.push2u.VapidSigner;

/**
 * {@code push2u.enabled} — the statement a deployment makes about whether it sends — and the refusal that answers the
 * third state: on, with neither a sender nor a signer in the context.
 *
 * <p>The suite is organised as the decision's own table is: what the switch withdraws, what it must not reach, and
 * which startup checks run on which side of it. What it cannot pin from here is the running order across both starters,
 * which needs a context holding every starter that declares a position — that lives in the Vault starter's suite, the
 * only one with both on a classpath.
 */
class Push2uDeliverySwitchTest {

    private static String publicKeyB64;
    private static String privateKeyB64;

    /** The full starter composition, exactly as the imports file ships it. */
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    Push2uAutoConfiguration.class,
                    Push2uEndpointPolicyAutoConfiguration.class,
                    Push2uHealthAutoConfiguration.class,
                    Push2uStartupChecksAutoConfiguration.class));

    @BeforeAll
    static void generateVapidKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = generator.generateKeyPair();
        Base64.Encoder base64Url = Base64.getUrlEncoder().withoutPadding();
        publicKeyB64 = base64Url.encodeToString(uncompressed((ECPublicKey) keyPair.getPublic()));
        privateKeyB64 = base64Url.encodeToString(toFixed32(((ECPrivateKey) keyPair.getPrivate()).getS()));
    }

    @Test
    void unsetMeansOnAndTheWholeDeliveryPathIsContributed() {
        // The default, met the way a deployment actually meets it: no push2u.enabled key at all.
        fullyConfigured().run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(VapidSigner.class);
            assertThat(context).hasSingleBean(PushHttpClient.class);
            assertThat(context).hasSingleBean(PushSender.class);
            assertThat(context).hasSingleBean(Push2uHealthIndicator.class);
            assertThat(context).hasSingleBean(EndpointPolicy.class);
        });
    }

    @Test
    void statedTrueIsTheSameAsUnset() {
        fullyConfigured().withPropertyValues("push2u.enabled=true").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(PushSender.class);
            assertThat(context).hasSingleBean(Push2uHealthIndicator.class);
        });
    }

    @Test
    void offWithdrawsTheSignerTheTransportTheSenderAndTheIndicator() {
        // Every cell of the "off" column at once, on a context that is otherwise completely
        // configured — so nothing here is absent for want of configuration.
        fullyConfigured().withPropertyValues("push2u.enabled=false").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(VapidSigner.class);
            assertThat(context).doesNotHaveBean(PushHttpClient.class);
            assertThat(context).doesNotHaveBean(PushSender.class);
            assertThat(context)
                    .as("the indicator lives in its own auto-configuration and is gated all the same")
                    .doesNotHaveBean(Push2uHealthIndicator.class);
        });
    }

    @Test
    void offDoesNotReachTheEndpointPolicy() {
        // The deployment the policy bean exists for is exactly the one that states `false`: it
        // accepts subscriptions, holds a policy and sends nothing. Being outside the class that
        // carries the sender is not what makes the policy safe — the health indicator is outside it
        // too and is gone above — so this asserts the bean is really there and really enforces the
        // stated allowlist.
        fullyConfigured().withPropertyValues("push2u.enabled=false").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(EndpointPolicy.class);
            assertThat(context.getBean(Push2uProperties.class).allowedOrigins())
                    .containsExactly("https://push.example.test");
        });
    }

    @Test
    void offDoesNotRemoveAnApplicationsOwnSender() {
        // The switch withdraws what this starter contributes. An application's own PushSender is
        // not this starter's to withdraw, and a deployment that states the switch while wiring its
        // own sender has said something about the autoconfigured path alone.
        fullyConfigured()
                .withPropertyValues("push2u.enabled=false")
                .withUserConfiguration(ApplicationSenderConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(PushSender.class);
                    assertThat(context.getBean(PushSender.class)).isSameAs(ApplicationSenderConfiguration.SENDER);
                });
    }

    @Test
    void onWithNoSignerFailsNamingEveryWayToAnswerIt() {
        // The third state, and the whole point of the record: a context that is on, holds no
        // signer, and has said nothing. The message has to be actionable in every direction the
        // deployment actually has.
        runner.withPropertyValues("push2u.allowed-origins=https://push.example.test")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .as("the switch")
                            .hasMessageContaining("push2u.enabled=false")
                            .as("the two key properties this module owns")
                            .hasMessageContaining("push2u.vapid.public-key")
                            .hasMessageContaining("push2u.vapid.private-key")
                            .as("a signer starter's own configuration, without naming its keys")
                            .hasMessageContaining("signer starter")
                            .as("an application bean of either type")
                            .hasMessageContaining("VapidSigner bean")
                            .hasMessageContaining("PushSender bean")
                            .as("the framework's condition report, named by the flag that prints it at startup")
                            .hasMessageContaining("--debug");
                });
    }

    @Test
    void theRefusalNamesNoOtherModulesPropertiesAndNoEndpointAFailedContextCannotServe() {
        // Two things the message must not do. Naming another starter's prefixes would rebuild
        // inside the library the copy the reporting consumer was asked to delete, and would go
        // stale the day that starter changed them. Naming /actuator/conditions would send the
        // operator to an endpoint a context that failed to start does not serve.
        runner.withPropertyValues("push2u.allowed-origins=https://push.example.test")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasMessageNotContaining("push2u.signer.vault")
                            .hasMessageNotContaining("actuator");
                });
    }

    @Test
    void theStatementIsWhatMakesThatContextStart() {
        // The same context, one line added. This is the remedy the transition offers, and it is the
        // whole of it.
        runner.withPropertyValues("push2u.allowed-origins=https://push.example.test", "push2u.enabled=false")
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void theRefusalPrecedesAnApplicationBeansOwnMissingSenderFailure() {
        // A bean that requires a PushSender is instantiated before any ordinary bean an
        // auto-configuration contributes, so a refusal raised as one would lose this race and the
        // operator would read the framework's "required a bean that could not be found" instead.
        // Raised from a post-processor of the bean factory, it wins.
        runner.withPropertyValues("push2u.allowed-origins=https://push.example.test")
                .withUserConfiguration(RequiresSenderConfiguration.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .isNotInstanceOf(UnsatisfiedDependencyException.class)
                            .hasMessageContaining("push2u.enabled=false");
                });
    }

    @Test
    void anApplicationSignerBeanStandsTheRefusalDown() {
        // The stand-down is over a signer from anywhere, because the question the refusal asks is
        // whether this deployment can sign — not where the answer came from.
        runner.withPropertyValues("push2u.allowed-origins=https://push.example.test", "push2u.vapid.subject=mailto:a@b")
                .withUserConfiguration(ApplicationSignerConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(PushSender.class);
                });
    }

    @Test
    void anApplicationSenderBeanStandsTheRefusalDownWithNoSignerAtAll() {
        // A deployment that builds its own sender never had an activation question to answer: the
        // signer lives inside that sender, where nothing in this starter can reach it.
        runner.withUserConfiguration(ApplicationSenderConfiguration.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(VapidSigner.class);
            assertThat(context.getBean(PushSender.class)).isSameAs(ApplicationSenderConfiguration.SENDER);
        });
    }

    @Test
    void theLocalSignerStandsTheRefusalDown() {
        fullyConfigured().run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(PushSender.class);
        });
    }

    @Test
    void aBlankPublicKeyLeavesTheSignerUnconfiguredRatherThanUnbuildable() {
        // The trap the reporting consumer documented in its own YAML: `${PUSH2U_VAPID_PUBLIC_KEY:}`
        // resolving to nothing. Spring counts an empty property as a present one, so the framework's
        // own condition would activate the signer and then refuse it for the length of a point the
        // empty string never carried — a failure describing a shape. Read as unset, the same
        // deployment is told which configuration is missing.
        runner.withPropertyValues(
                        "push2u.allowed-origins=https://push.example.test",
                        "push2u.vapid.public-key=",
                        "push2u.vapid.private-key=" + privateKeyB64,
                        "push2u.vapid.subject=mailto:ops@example.com")
                .run(context -> {
                    // The refusal that arrives is the general one over a missing signer — which is
                    // the proof that the blank key activated nothing — and it names the pair rather
                    // than the shape of an empty string.
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("push2u.vapid.public-key")
                            .as("named as missing configuration, not as a point of the wrong length")
                            .hasMessageNotContaining("65-byte")
                            .hasMessageNotContaining("not valid base64url");
                });
    }

    @Test
    void aBlankPrivateKeyIsReadTheSameWay() {
        runner.withPropertyValues(
                        "push2u.allowed-origins=https://push.example.test",
                        "push2u.vapid.public-key=" + publicKeyB64,
                        "push2u.vapid.private-key= ",
                        "push2u.vapid.subject=mailto:ops@example.com")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("push2u.vapid.private-key")
                            .hasMessageNotContaining("not valid base64url");
                });
    }

    @Test
    void aValueThatIsNeitherFailsTheContextNamingTheProperty() {
        // The one key where a typo would be free to mean the opposite of what was typed. Neither
        // reading is applied: the operator is told which key to look at, and the message that
        // arrives is this one rather than a consequence of it.
        fullyConfigured().withPropertyValues("push2u.enabled=flase").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("push2u.enabled")
                    .hasMessageContaining("true")
                    .hasMessageContaining("false")
                    .as("the typo itself is not quoted back into a log that is shipped whole")
                    .hasMessageNotContaining("flase");
        });
    }

    @Test
    void theValueRefusalOutranksTheRefusalAMistypedSwitchWouldOtherwiseEarn() {
        // A mistyped switch leaves the delivery path inactive, so the context would also hold no
        // signer. The operator must read about the key they mistyped, not about a signer they were
        // never asked for — which is what the declared order buys, pinned by the message.
        runner.withPropertyValues("push2u.enabled=off", "push2u.allowed-origins=https://push.example.test")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasMessageContaining("push2u.enabled")
                            .hasMessageNotContaining("VapidSigner bean");
                });
    }

    @Test
    void aBlankSwitchIsRefusedRatherThanGuessedAt() {
        // Deliberately not the reading the activating properties get. A blank public-key could never
        // have produced a signer, so reading it as unset only chooses between two failure messages;
        // a blank push2u.enabled would have to be read as one of two opposite statements.
        fullyConfigured()
                .withInitializer(environmentVariable("PUSH2U_ENABLED", " "))
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("push2u.enabled");
                });
    }

    @Test
    void theSwitchIsReadInEverySpellingRelaxedBindingAccepts() {
        // The environment-variable form is how a container actually states it.
        fullyConfigured()
                .withInitializer(environmentVariable("PUSH2U_ENABLED", "false"))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(PushSender.class);
                });
        // ...and the value is matched without regard to case, as YAML and the binder both read a
        // boolean, so a deployment writing `FALSE` is not refused for the shift key.
        fullyConfigured().withPropertyValues("push2u.enabled=FALSE").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(PushSender.class);
        });
    }

    @Test
    void everyValueRefusalRunsOnBothSidesOfTheSwitch() {
        // The rows of the table that are about a *value*: an entry that is not an origin is not an
        // origin in a context that sends nothing either, a contradiction does not become acceptable
        // there, and a key a release removed configures nothing on either side. Each is asserted
        // twice, once per side, because "runs / runs" is the claim and half of it is not the claim:
        // off is the side where a check placed by where it happened to be implemented would have
        // gone missing, and on is the side where a check gated by mistake would still have looked
        // fine.
        //
        // On the "on" side these contexts also hold no signer, so the general refusal is registered
        // beside each of them — and the value refusal is still what arrives, which is the declared
        // order doing its work rather than an accident of this configuration.
        for (String side : new String[] {"push2u.enabled=false", "push2u.enabled=true"}) {
            runner.withPropertyValues(side, "push2u.allowed-origins=http://push.example")
                    .run(context -> {
                        assertThat(context).hasFailed();
                        assertThat(context.getStartupFailure())
                                .as(side)
                                .hasMessageContaining("push2u.allowed-origins[0]:");
                    });
            runner.withPropertyValues(side, "push2u.allowed-origins=https://push.example.test")
                    .withUserConfiguration(ApplicationPolicyConfiguration.class)
                    .run(context -> {
                        assertThat(context).hasFailed();
                        assertThat(context.getStartupFailure()).as(side).hasMessageContaining("Configure exactly one");
                    });
            runner.withPropertyValues(side, "push2u.record-size=8192").run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure()).as(side).hasMessageContaining("push2u.record-size");
            });
        }
    }

    @Test
    void theIndicatorsOwnSwitchStaysIndependentOfThisOne() {
        // Two decisions, not one. A deployment that is sending may still decline to tie its health
        // to a signer; a deployment that has switched delivery off has no indicator left to opt out
        // of, so naming the framework's key back in cannot resurrect one.
        fullyConfigured()
                .withPropertyValues("management.health.push2u.enabled=false")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(PushSender.class);
                    assertThat(context).doesNotHaveBean(Push2uHealthIndicator.class);
                });
        fullyConfigured()
                .withPropertyValues("push2u.enabled=false", "management.health.push2u.enabled=true")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(Push2uHealthIndicator.class);
                });
    }

    /** Keys, subject and an allowlist: everything an autoconfigured sender needs, with the switch left unwritten. */
    private ApplicationContextRunner fullyConfigured() {
        return runner.withPropertyValues(
                "push2u.vapid.public-key=" + publicKeyB64,
                "push2u.vapid.private-key=" + privateKeyB64,
                "push2u.vapid.subject=mailto:ops@example.com",
                "push2u.allowed-origins=https://push.example.test");
    }

    /** Puts one variable into the environment through the source type real environment variables arrive by. */
    private static ApplicationContextInitializer<ConfigurableApplicationContext> environmentVariable(
            String name, String value) {
        return context -> context.getEnvironment()
                .getPropertySources()
                .addFirst(new SystemEnvironmentPropertySource("switch-test-environment", Map.of(name, value)));
    }

    /** An application component that cannot start without a sender — the failure the refusal has to precede. */
    @Configuration(proxyBeanMethods = false)
    static class RequiresSenderConfiguration {

        @Bean
        String senderDependent(@Autowired PushSender sender) {
            return sender.toString();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class ApplicationSenderConfiguration {

        static final PushSender SENDER = PushSender.builder(
                        stubSigner(), "mailto:ops@example.com", EndpointPolicies.allowedOrigins("https://push.example"))
                .build();

        @Bean
        PushSender applicationSender() {
            return SENDER;
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class ApplicationSignerConfiguration {

        @Bean
        VapidSigner applicationSigner() {
            return stubSigner();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class ApplicationPolicyConfiguration {

        @Bean
        EndpointPolicy applicationPolicy() {
            return endpoint -> {};
        }
    }

    /** A structurally valid signer: the checks under test are about beans existing, never about signatures. */
    private static VapidSigner stubSigner() {
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

    private static byte[] uncompressed(ECPublicKey key) {
        byte[] out = new byte[65];
        out[0] = 0x04;
        System.arraycopy(toFixed32(key.getW().getAffineX()), 0, out, 1, 32);
        System.arraycopy(toFixed32(key.getW().getAffineY()), 0, out, 33, 32);
        return out;
    }

    private static byte[] toFixed32(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == 32) {
            return bytes;
        }
        byte[] out = new byte[32];
        if (bytes.length > 32) {
            System.arraycopy(bytes, bytes.length - 32, out, 0, 32);
        } else {
            System.arraycopy(bytes, 0, out, 32 - bytes.length, bytes.length);
        }
        return out;
    }
}
