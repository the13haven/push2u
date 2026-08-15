/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.the13haven.push2u.EndpointPolicy;
import com.the13haven.push2u.PushSender;
import com.the13haven.push2u.VapidSigner;
import com.the13haven.push2u.signer.vault.VaultTransitVapidSigner;
import com.the13haven.push2u.spring.Push2uAutoConfiguration;
import com.the13haven.push2u.spring.Push2uEndpointPolicyAutoConfiguration;
import com.the13haven.push2u.spring.Push2uHealthAutoConfiguration;
import com.the13haven.push2u.spring.Push2uStartupChecksAutoConfiguration;

/**
 * The one running order over every startup check the starter family declares, pinned where it can be: this module's
 * suite is the only one with both starters on a classpath, and the order it has to guarantee spans them.
 *
 * <p><b>What is pinned is the message that arrives, never the value of a constant.</b> The positions live in two
 * classes that cannot see each other — a signer starter deliberately does not depend on the core starter — so a test
 * asserting that a constant equals a number written in a document would prove only that someone typed the number twice,
 * and would stay green while the module next door moved its own. A per-module test can pin the positions that module
 * owns; it cannot pin this, and must not be offered as though it had.
 *
 * <p>So the suite walks one deployment down the list. It starts holding every fault at once and the operator reads the
 * first; each case removes exactly the fault the previous one reported and reads the next. The declared order is:
 *
 * <ol>
 *   <li>the value of {@code push2u.enabled};
 *   <li>a tombstone over a removed property;
 *   <li>a malformed allowlist entry;
 *   <li>an allowlist stated beside an application policy bean;
 *   <li>a signer starter's partial-configuration diagnostic;
 *   <li>the general refusal over a missing signer.
 * </ol>
 */
class StartupCheckOrderAcrossStartersTest {

    /** The Vault key the one positive case supplies, so that composition is asserted without a Vault round trip. */
    private static String vaultPublicKeyB64;

    /** Every auto-configuration both starters ship, exactly as their two imports files do. */
    private static final AutoConfigurations BOTH_STARTERS = AutoConfigurations.of(
            VaultSignerAutoConfiguration.class,
            VaultSignerDiagnosticsAutoConfiguration.class,
            Push2uAutoConfiguration.class,
            Push2uEndpointPolicyAutoConfiguration.class,
            Push2uHealthAutoConfiguration.class,
            Push2uStartupChecksAutoConfiguration.class);

    /** A half-stated Vault block: present in every case below until the one that reads it. */
    private static final String PARTIAL_VAULT_BLOCK = "push2u.signer.vault.address=https://vault.example:8200";

    @BeforeAll
    static void generateVaultPublicKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        vaultPublicKeyB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(uncompressed((ECPublicKey)
                generator.generateKeyPair().getPublic()));
    }

    @Test
    void theActivationSwitchsOwnValueIsReadFirst() {
        // Every fault at once. A deployment that mistyped the one key deciding whether any of this
        // applies is owed that sentence, and not a consequence of it — which is what the position
        // above the tombstones buys.
        contextWith(
                        "push2u.enabled=yes",
                        "push2u.record-size=8192",
                        "push2u.allowed-origins=http://push.example",
                        PARTIAL_VAULT_BLOCK)
                .withUserConfiguration(ApplicationPolicyConfiguration.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasMessageContaining("push2u.enabled")
                            .hasMessageNotContaining("push2u.record-size")
                            .hasMessageNotContaining("push2u.allowed-origins[")
                            .hasMessageNotContaining("Configure exactly one")
                            .hasMessageNotContaining("configured by halves")
                            .hasMessageNotContaining("VapidSigner bean");
                });
    }

    @Test
    void aTombstoneIsReadNext() {
        // The switch corrected, the rest untouched. A key that no longer exists makes every reading
        // of the configuration under it a reading of something the operator did not mean to write,
        // so it precedes the value refusals below.
        contextWith("push2u.record-size=8192", "push2u.allowed-origins=http://push.example", PARTIAL_VAULT_BLOCK)
                .withUserConfiguration(ApplicationPolicyConfiguration.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasMessageContaining("push2u.record-size")
                            .hasMessageNotContaining("push2u.allowed-origins[")
                            .hasMessageNotContaining("Configure exactly one")
                            .hasMessageNotContaining("configured by halves")
                            .hasMessageNotContaining("VapidSigner bean");
                });
    }

    @Test
    void aMalformedAllowlistEntryIsReadNext() {
        // A bad value is the sharper finding: fixing or emptying the entry may be what resolves the
        // contradiction below it.
        contextWith("push2u.allowed-origins=http://push.example", PARTIAL_VAULT_BLOCK)
                .withUserConfiguration(ApplicationPolicyConfiguration.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasMessageContaining("push2u.allowed-origins[0]:")
                            .hasMessageNotContaining("Configure exactly one")
                            .hasMessageNotContaining("configured by halves")
                            .hasMessageNotContaining("VapidSigner bean");
                });
    }

    @Test
    void anAllowlistBesideAPolicyBeanIsReadNext() {
        // Two well-formed statements of one security control. It precedes every refusal about
        // signers and the delivery path, which the contradiction is not about.
        contextWith("push2u.allowed-origins=https://fcm.googleapis.com", PARTIAL_VAULT_BLOCK)
                .withUserConfiguration(ApplicationPolicyConfiguration.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasMessageContaining("Configure exactly one")
                            .hasMessageNotContaining("configured by halves")
                            .hasMessageNotContaining("VapidSigner bean");
                });
    }

    @Test
    void aSignerStartersPartialConfigurationIsReadNext() {
        // The application policy bean gone, the allowlist stated once. What is left is a half-stated
        // Vault block and no signer at all — and the specific finding outranks the general one,
        // which is the whole reason both declare a position rather than one of them.
        contextWith("push2u.allowed-origins=https://fcm.googleapis.com", PARTIAL_VAULT_BLOCK)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasMessageContaining("configured by halves")
                            .hasMessageContaining("push2u.signer.vault.address")
                            .as("the general refusal is still pending, and still not what the operator reads")
                            .hasMessageNotContaining("VapidSigner bean");
                });
    }

    @Test
    void theGeneralRefusalIsReadLast() {
        // Every specific finding answered. What remains is the question none of them asked: this
        // deployment is on and cannot sign.
        contextWith("push2u.allowed-origins=https://fcm.googleapis.com").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .hasMessageContaining("VapidSigner bean")
                    .hasMessageContaining("push2u.enabled=false");
        });
    }

    @Test
    void theOneRemainingEditStartsTheContext() {
        // The end of the walk, and the half that makes the cascade above about an operator's cost
        // rather than about six strings: the same deployment, having answered the last finding,
        // starts.
        contextWith("push2u.allowed-origins=https://fcm.googleapis.com", "push2u.enabled=false")
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void aVaultSignerDeploymentStartsUnderTheShippedComposition() {
        // The deployment with the most to lose from this change, and the one no other test in either
        // module puts under the whole shipped composition: delivery on, the only signer the Vault
        // one, and every auto-configuration both starters ship — the general refusal's included.
        //
        // What could go wrong is not subtle. push2uMissingSignerRefusal stands down on a
        // @ConditionalOnMissingBean decided while the auto-configurations are processed, so it needs
        // the Vault contribution registered before the checks class is reached. If that ever stops
        // holding, EVERY Vault deployment is refused at startup by this change's own new refusal,
        // against a configuration that is completely correct.
        //
        // What this test does NOT do is catch the removal of an ordering declaration, and saying so
        // is the point of the comment. Both Vault classes sort ahead of every core one by class name
        // alone (…push2u.signer.vault.spring… before …push2u.spring…), and the checks class sorts
        // last among the core ones, so dropping either the contribution's beforeName or the checks
        // class's `after` leaves this green — verified by doing exactly that. It is the same
        // coincidence VaultSignerAutoConfigurationTest already records for beforeName, and the
        // declarations stay because relying on it would be worse than stating the order. The one
        // ordering declaration in this family that IS load-bearing under the fallback is the
        // diagnostics class's afterName, since that class sorts ahead of Push2uAutoConfiguration by
        // name — and VaultSignerDiagnosticsAutoConfigurationTest fails without it.
        //
        // Explicit mode with a supplied public key, so the composition is asserted without a Vault
        // round trip: what is under test is which beans exist, not what Vault would answer.
        contextWith(
                        "push2u.vapid.subject=mailto:ops@example.com",
                        "push2u.allowed-origins=https://fcm.googleapis.com",
                        "push2u.signer.vault.address=https://vault.example:8200",
                        "push2u.signer.vault.key-name=vapid",
                        "push2u.signer.vault.token=test-token",
                        "push2u.signer.vault.public-key=" + vaultPublicKeyB64)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(PushSender.class);
                    assertThat(context.getBean(VapidSigner.class))
                            .as("the signer under test is the Vault one, not a local fallback")
                            .isInstanceOf(VaultTransitVapidSigner.class);
                });
    }

    private static ApplicationContextRunner contextWith(String... properties) {
        return new ApplicationContextRunner().withConfiguration(BOTH_STARTERS).withPropertyValues(properties);
    }

    /** An application-supplied policy, which a non-empty allowlist property contradicts. */
    @Configuration(proxyBeanMethods = false)
    static class ApplicationPolicyConfiguration {

        @Bean
        EndpointPolicy applicationPolicy() {
            return endpoint -> {};
        }
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
