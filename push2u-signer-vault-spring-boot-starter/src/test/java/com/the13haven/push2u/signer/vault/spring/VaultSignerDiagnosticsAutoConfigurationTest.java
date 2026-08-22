/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.the13haven.push2u.EndpointPolicies;
import com.the13haven.push2u.PushSender;
import com.the13haven.push2u.VapidSigner;
import com.the13haven.push2u.signer.vault.VaultHttpResponse;
import com.the13haven.push2u.signer.vault.VaultHttpTransport;
import com.the13haven.push2u.spring.Push2uAutoConfiguration;
import com.the13haven.push2u.spring.Push2uEndpointPolicyAutoConfiguration;
import com.the13haven.push2u.testkit.VapidKeyPairFixture;

/**
 * This starter's diagnostic over a half-stated {@code push2u.signer.vault.*} block: when it fires, when it stands down,
 * and why it lives in an auto-configuration of its own.
 *
 * <p>The stand-down over the core starter's in-JVM signer is the case that decides the split. A diagnostic sharing a
 * class with the contribution would be ordered <em>ahead</em> of the core starter — where the contribution has to be —
 * and could not see the signer it is about to be told to stand down for.
 */
class VaultSignerDiagnosticsAutoConfigurationTest {

    private static String publicKeyB64;
    private static String vapidPublicKeyB64;
    private static String vapidPrivateKeyB64;

    /** This starter as the imports file ships it: the contribution and the diagnostic. */
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    VaultSignerAutoConfiguration.class, VaultSignerDiagnosticsAutoConfiguration.class));

    @BeforeAll
    static void generateKeys() {
        // The supplied Vault key: only its public half is ever configured, the private half being
        // Vault's to hold.
        publicKeyB64 = VapidKeyPairFixture.generate().publicKeyBase64Url();
        VapidKeyPairFixture vapid = VapidKeyPairFixture.generate();
        vapidPublicKeyB64 = vapid.publicKeyBase64Url();
        vapidPrivateKeyB64 = vapid.privateKeyBase64Url();
    }

    @Test
    void aHalfStatedBlockFailsTheContextNamingWhatIsSetAndWhatIsNot() {
        // The shape of a real mistake: a prefix mistyped, a secret that did not reach the container,
        // a block copied without its token. Left alone it contributes no signer and says nothing.
        runner.withPropertyValues("push2u.signer.vault.address=https://vault.example:8200")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("push2u.signer.vault.address")
                            .hasMessageContaining("push2u.signer.vault.key-name")
                            .hasMessageContaining("push2u.signer.vault.token")
                            .hasMessageContaining("set")
                            .hasMessageContaining("unset or blank");
                });
    }

    @Test
    void theDiagnosticNamesNoOtherModulesProperties() {
        // A message that spelled the core starter's prefixes would rebuild inside the library the
        // copy the reporting consumer was asked to delete, and would go stale the day that module
        // changed them. Nothing collects this finding into another module's message either.
        runner.withPropertyValues("push2u.signer.vault.token=test-token").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .hasMessageNotContaining("push2u.vapid")
                    .hasMessageNotContaining("push2u.allowed");
        });
    }

    @Test
    void aBlankActivatingPropertyCountsAsUnsetRatherThanAsAnEmptyValue() {
        // The `${VAULT_TOKEN:}` shape. The framework's own property condition counts a blank as set,
        // which would activate the signer and then refuse it as an empty token — a failure about the
        // shape of an empty string. Read as unset, the same deployment is told which key is missing.
        runner.withPropertyValues(
                        "push2u.signer.vault.address=https://vault.example:8200",
                        "push2u.signer.vault.key-name=vapid",
                        "push2u.signer.vault.token=")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("push2u.signer.vault.token")
                            .as("named as missing configuration, not as a token of the wrong shape")
                            .hasMessageNotContaining("character");
                });
    }

    @Test
    void nothingStatedIsNotAHalfStatedBlock() {
        // A deployment that merely carries this starter on its classpath has stated nothing about
        // Vault, and is owed no complaint about it.
        runner.run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void aCompleteBlockContributesTheSignerAndSaysNothing() {
        runner.withPropertyValues(
                        "push2u.signer.vault.address=https://vault.example:8200",
                        "push2u.signer.vault.key-name=vapid",
                        "push2u.signer.vault.token=test-token",
                        "push2u.signer.vault.public-key=" + publicKeyB64)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(VapidSigner.class);
                });
    }

    @Test
    void anApplicationSignerBeanStandsTheDiagnosticDown() {
        // A stale property is not a broken deployment, and a startup failure over configuration
        // nothing reads would be the same mistake in the opposite direction.
        runner.withPropertyValues("push2u.signer.vault.address=https://vault.example:8200")
                .withUserConfiguration(ApplicationSignerConfiguration.class)
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void anApplicationSenderBeanStandsTheDiagnosticDown() {
        runner.withPropertyValues("push2u.signer.vault.address=https://vault.example:8200")
                .withUserConfiguration(ApplicationSenderConfiguration.class)
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void theCoreStartersLocalSignerStandsTheDiagnosticDown() {
        // The case the split into two auto-configurations exists for: a deployment sending through
        // the in-JVM signer with a forgotten push2u.signer.vault.address. The contribution is
        // ordered ahead of the core starter so the signer it contributes can be found; the
        // diagnostic is ordered behind it so the core starter's own signer can be. Sharing one class
        // would make this stand-down unreachable, and this deployment would be refused over a
        // property nothing reads.
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        VaultSignerAutoConfiguration.class,
                        VaultSignerDiagnosticsAutoConfiguration.class,
                        Push2uAutoConfiguration.class,
                        Push2uEndpointPolicyAutoConfiguration.class))
                .withPropertyValues(
                        "push2u.vapid.public-key=" + vapidPublicKeyB64,
                        "push2u.vapid.private-key=" + vapidPrivateKeyB64,
                        "push2u.vapid.subject=mailto:ops@example.com",
                        "push2u.allowed-origins=https://fcm.googleapis.com",
                        "push2u.signer.vault.address=https://vault.example:8200")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(PushSender.class);
                });
    }

    @Test
    void theDiagnosticIsGatedByTheDeliverySwitch() {
        // Not a contribution, and gated all the same. Its stand-down is over a signer or sender bean,
        // and the switch is precisely what keeps those from existing — so with delivery off the
        // stand-down could not reach the case, and a deployment that switched delivery off with half
        // a push2u.signer.vault.* block left over would be refused over configuration nothing reads.
        runner.withPropertyValues("push2u.enabled=false", "push2u.signer.vault.address=https://vault.example:8200")
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void theSwitchWithdrawsTheSignerAndWithItTheStartupReadOfVault() {
        // The fetched mode reads transit/keys/<key> while the context starts. A deployment that has
        // declared the custodian unused should pay for no such call, so the assertion is over the
        // transport: not one request.
        RecordingTransportConfiguration.CALLS.clear();
        runner.withPropertyValues(
                        "push2u.enabled=false",
                        "push2u.signer.vault.address=https://vault.example:8200",
                        "push2u.signer.vault.key-name=vapid",
                        "push2u.signer.vault.token=test-token")
                .withUserConfiguration(RecordingTransportConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(VapidSigner.class);
                    assertThat(RecordingTransportConfiguration.CALLS)
                            .as("no Vault call at all in a deployment that stated it does not send")
                            .isEmpty();
                });
    }

    @Configuration(proxyBeanMethods = false)
    static class ApplicationSignerConfiguration {

        @Bean
        VapidSigner applicationSigner() {
            return stubSigner();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class ApplicationSenderConfiguration {

        @Bean
        PushSender applicationSender() {
            return PushSender.builder(
                            stubSigner(),
                            "mailto:ops@example.com",
                            EndpointPolicies.allowedOrigins("https://push.example"))
                    .build();
        }
    }

    /** A transport that records every call, so "no Vault call was made" can be asserted rather than assumed. */
    @Configuration(proxyBeanMethods = false)
    static class RecordingTransportConfiguration {

        static final List<String> CALLS = new CopyOnWriteArrayList<>();

        @Bean
        VaultHttpTransport recordingTransport() {
            return new VaultHttpTransport() {
                @Override
                public VaultHttpResponse get(URI uri, Map<String, String> headers) {
                    CALLS.add("GET");
                    throw new AssertionError("no Vault read may happen with delivery switched off");
                }

                @Override
                public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body) {
                    CALLS.add("POST");
                    throw new AssertionError("no Vault call may happen with delivery switched off");
                }
            };
        }
    }

    /** A structurally valid signer: these checks are about beans existing, never about signatures. */
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
}
