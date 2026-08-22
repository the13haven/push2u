/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.the13haven.push2u.VapidSigner;
import com.the13haven.push2u.VapidSignerUnavailableException;
import com.the13haven.push2u.signer.vault.FakeTransitVault;
import com.the13haven.push2u.signer.vault.VaultHttpTransport;
import com.the13haven.push2u.spring.Push2uAutoConfiguration;
import com.the13haven.push2u.spring.Push2uEndpointPolicyAutoConfiguration;
import com.the13haven.push2u.spring.Push2uHealthAutoConfiguration;
import com.the13haven.push2u.spring.Push2uHealthIndicator;
import com.the13haven.push2u.testkit.VapidKeyPairFixture;

/**
 * The four readings of {@code push2u.signer.vault.public-key-fetch}, pinned by behaviour rather than by inspecting a
 * builder: an unset (or blank) key reads eagerly at context refresh, {@code deferred} performs no Vault call until the
 * signer's first use, a written value beside a supplied {@code public-key} fails the context naming both keys, and a
 * value that is neither mode fails naming the key. {@code eager} stays the default and still fails the boot against a
 * Vault that cannot serve the startup read — deferring is opt-in, never a drift.
 */
class VaultSignerPublicKeyFetchModeTest {

    private static String publicKeyB64;

    private final ApplicationContextRunner runner =
            new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(VaultSignerAutoConfiguration.class));

    @BeforeAll
    static void generateSuppliedKey() {
        // Only the public half is configured here: what a supplied key means to this starter is
        // that no Vault read is needed for it, and the private half stays with Vault.
        publicKeyB64 = VapidKeyPairFixture.generate().publicKeyBase64Url();
    }

    @BeforeEach
    void resetTransport() {
        CountingTransitVaultConfiguration.reset();
    }

    @Test
    void unsetReadsEagerly_theMetadataReadHappensInsideContextRefresh() {
        fetchedRunner().run(context -> {
            assertThat(context).hasSingleBean(VapidSigner.class);
            assertThat(CountingTransitVaultConfiguration.vault().keyReads())
                    .as("the default is eager: the read happened while the context refreshed")
                    .isEqualTo(1);
        });
    }

    @Test
    void aBlankValueReadsAsUnset_soTheModeStaysEager() {
        fetchedRunner()
                .withPropertyValues("push2u.signer.vault.public-key-fetch=")
                .run(context -> {
                    assertThat(context).hasSingleBean(VapidSigner.class);
                    assertThat(CountingTransitVaultConfiguration.vault().keyReads())
                            .isEqualTo(1);
                });
    }

    @Test
    void eagerWrittenOutIsTheSameModeAsUnset() {
        fetchedRunner()
                .withPropertyValues("push2u.signer.vault.public-key-fetch=eager")
                .run(context -> {
                    assertThat(context).hasSingleBean(VapidSigner.class);
                    assertThat(CountingTransitVaultConfiguration.vault().keyReads())
                            .isEqualTo(1);
                });
    }

    @Test
    void deferredPerformsNoVaultCallAtStartup_andTheFirstUseReads() {
        fetchedRunner()
                .withPropertyValues("push2u.signer.vault.public-key-fetch=deferred")
                .run(context -> {
                    assertThat(context).hasSingleBean(VapidSigner.class);
                    assertThat(CountingTransitVaultConfiguration.vault().calls())
                            .as("the context refreshed without any Vault call")
                            .isEmpty();

                    byte[] advertised = context.getBean(VapidSigner.class).publicKey();

                    assertThat(advertised)
                            .isEqualTo(CountingTransitVaultConfiguration.vault().publicKeyUncompressed());
                    assertThat(CountingTransitVaultConfiguration.vault().keyReads())
                            .isEqualTo(1);
                });
    }

    @Test
    void deferredIsMatchedTheWayTheBinderMatchesAnEnum_caseDoesNotDecide() {
        fetchedRunner()
                .withPropertyValues("push2u.signer.vault.public-key-fetch=DEFERRED")
                .run(context -> {
                    assertThat(context).hasSingleBean(VapidSigner.class);
                    assertThat(CountingTransitVaultConfiguration.vault().calls())
                            .isEmpty();
                });
    }

    @Test
    void eagerStaysTheDefault_andStillFailsTheBootAgainstAVaultThatCannotServeTheRead() {
        // The same unavailable Vault, three spellings: unset and `eager` fail the context on the
        // startup read — fail-fast is not quietly weakened — while `deferred` starts against it.
        runner.withPropertyValues(vaultProperties())
                .withUserConfiguration(UnavailableTransportConfiguration.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(VapidSignerUnavailableException.class);
                });
        runner.withPropertyValues(vaultProperties())
                .withPropertyValues("push2u.signer.vault.public-key-fetch=eager")
                .withUserConfiguration(UnavailableTransportConfiguration.class)
                .run(context -> assertThat(context).hasFailed());
        runner.withPropertyValues(vaultProperties())
                .withPropertyValues("push2u.signer.vault.public-key-fetch=deferred")
                .withUserConfiguration(UnavailableTransportConfiguration.class)
                .run(context -> assertThat(context).hasSingleBean(VapidSigner.class));
    }

    @Test
    void aValueThatIsNeitherModeFailsTheContextNamingTheKey() {
        fetchedRunner()
                .withPropertyValues("push2u.signer.vault.public-key-fetch=lazy")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasStackTraceContaining("push2u.signer.vault.public-key-fetch")
                            .hasStackTraceContaining("'eager' or 'deferred'")
                            .hasStackTraceContaining("'lazy'");
                });
    }

    @Test
    void anyWrittenValueBesideASuppliedPublicKeyFailsTheContextNamingBothKeys() {
        for (String written : new String[] {"deferred", "eager"}) {
            runner.withPropertyValues(vaultProperties())
                    .withPropertyValues(
                            "push2u.signer.vault.public-key=" + publicKeyB64,
                            "push2u.signer.vault.public-key-fetch=" + written)
                    .run(context -> {
                        assertThat(context).hasFailed();
                        assertThat(context.getStartupFailure())
                                .hasStackTraceContaining("push2u.signer.vault.public-key-fetch")
                                .hasStackTraceContaining("push2u.signer.vault.public-key")
                                .hasStackTraceContaining("never reads");
                    });
        }
    }

    @Test
    void aBlankValueBesideASuppliedPublicKeyIsNotAWrittenOne() {
        runner.withPropertyValues(vaultProperties())
                .withPropertyValues(
                        "push2u.signer.vault.public-key=" + publicKeyB64, "push2u.signer.vault.public-key-fetch=")
                .withUserConfiguration(CountingTransitVaultConfiguration.class)
                .run(context -> {
                    assertThat(context).hasSingleBean(VapidSigner.class);
                    assertThat(CountingTransitVaultConfiguration.vault().calls())
                            .as("the supplied mode performs no metadata read")
                            .isEmpty();
                });
    }

    @Test
    void withDeliveryOff_theModePropertyIsNeverRead() {
        // The readings are decided while the signer is built, which places them on the
        // delivery-path side of push2u.enabled by construction: a deployment that has declared it
        // does not send is not refused over a value nothing reads.
        runner.withPropertyValues(vaultProperties())
                .withPropertyValues("push2u.enabled=false", "push2u.signer.vault.public-key-fetch=lazy")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(VapidSigner.class);
                });
    }

    // ---------------------------------------------------------------------------------------------------------------
    // The health indicator against a deferred signer
    // ---------------------------------------------------------------------------------------------------------------

    @Test
    void theHealthIndicatorWhenDisabledCausesNoFetch() {
        deferredCompositionRunner()
                .withPropertyValues("management.health.push2u.enabled=false")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(Push2uHealthIndicator.class);
                    assertThat(CountingTransitVaultConfiguration.vault().calls())
                            .as("nothing fetched: no probe exists and nothing sent")
                            .isEmpty();
                });
    }

    @Test
    void theHealthIndicatorsFirstProbeInitializesThroughTheSignatureItTakesFirst_thenReadsTheKey() {
        deferredCompositionRunner().run(context -> {
            assertThat(CountingTransitVaultConfiguration.vault().calls()).isEmpty();

            Health health = context.getBean(Push2uHealthIndicator.class).health();

            assertThat(health.getStatus()).isEqualTo(Status.UP);
            assertThat(CountingTransitVaultConfiguration.vault().calls())
                    .as("the probe signs first, and that signature initializes: one metadata read, then the sign"
                            + " POST — and the probe's publicKey() answers from the retained pair with no third call")
                    .satisfies(calls -> {
                        assertThat(calls).hasSize(2);
                        assertThat(calls.get(0)).startsWith("GET ");
                        assertThat(calls.get(1)).startsWith("POST ");
                    });
        });
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Plumbing
    // ---------------------------------------------------------------------------------------------------------------

    private ApplicationContextRunner fetchedRunner() {
        return runner.withPropertyValues(vaultProperties())
                .withUserConfiguration(CountingTransitVaultConfiguration.class);
    }

    private ApplicationContextRunner deferredCompositionRunner() {
        return new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        VaultSignerAutoConfiguration.class,
                        Push2uAutoConfiguration.class,
                        Push2uEndpointPolicyAutoConfiguration.class,
                        Push2uHealthAutoConfiguration.class))
                .withPropertyValues(vaultProperties())
                .withPropertyValues(
                        "push2u.vapid.subject=mailto:ops@example.com",
                        "push2u.allowed-origins=https://fcm.googleapis.com",
                        "push2u.signer.vault.public-key-fetch=deferred")
                .withUserConfiguration(CountingTransitVaultConfiguration.class);
    }

    private static String[] vaultProperties() {
        return new String[] {
            "push2u.signer.vault.address=https://vault.example:8200",
            "push2u.signer.vault.key-name=vapid",
            "push2u.signer.vault.token=test-token"
        };
    }

    /**
     * One healthy fake Transit vault per test, exposed as the application's {@code VaultHttpTransport} bean — first in
     * the starter's transport priority — so a test observes exactly which Vault calls each mode makes and when.
     */
    @Configuration(proxyBeanMethods = false)
    static class CountingTransitVaultConfiguration {

        private static FakeTransitVault vault = new FakeTransitVault();

        static void reset() {
            vault = new FakeTransitVault();
        }

        static FakeTransitVault vault() {
            return vault;
        }

        @Bean
        VaultHttpTransport countingTransitVault() {
            return vault;
        }
    }

    /** A Vault that cannot serve any call now — the startup outage the deferred mode exists to survive. */
    @Configuration(proxyBeanMethods = false)
    static class UnavailableTransportConfiguration {

        @Bean
        VaultHttpTransport unavailableTransport() {
            return new VaultHttpTransport() {
                @Override
                public com.the13haven.push2u.signer.vault.VaultHttpResponse get(URI uri, Map<String, String> headers) {
                    throw new VapidSignerUnavailableException("Vault is sealing: connection refused", null);
                }

                @Override
                public com.the13haven.push2u.signer.vault.VaultHttpResponse post(
                        URI uri, Map<String, String> headers, byte[] body) {
                    throw new VapidSignerUnavailableException("Vault is sealing: connection refused", null);
                }
            };
        }
    }
}
