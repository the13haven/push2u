/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault.spring;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.env.Environment;

import com.the13haven.push2u.PushSender;
import com.the13haven.push2u.VapidSigner;

/**
 * This starter's diagnostic over a half-stated {@code push2u.signer.vault.*} block, and nothing else.
 *
 * <p><b>A starter's diagnostic is not its contribution, and the two cannot sit at the same point.</b>
 * {@link VaultSignerAutoConfiguration} is ordered <em>ahead</em> of the core starter, so that the signer it contributes
 * is there for the sender's own condition to find. A diagnostic has to be ordered <em>behind</em> every contribution,
 * the core starter's in-JVM signer included, or it cannot see whether any signer was contributed at all — and its
 * stand-down is precisely over such a signer. One class cannot be in both places, so this starter carries two: the
 * contribution before, the diagnostic after, and both ahead of the general refusal the core starter raises. Without the
 * split the stand-down would be unreachable: a deployment sending through the local signer with a forgotten
 * {@code push2u.signer.vault.address} would be refused by a check that could not yet see the signer it was about to be
 * told to stand down for.
 *
 * <p><b>The diagnostic answers {@code push2u.enabled} although it is not a contribution.</b> Its stand-down is over an
 * existing {@link VapidSigner} or {@link PushSender} bean, and the switch is precisely what keeps those from existing —
 * so with delivery off the stand-down could not reach the case, and a deployment that switched delivery off with half a
 * {@code push2u.signer.vault.*} block left over would be refused over configuration nothing reads. That is the mistake
 * the stand-down exists to prevent, with the sign reversed. Reading that key is this module's; refusing a value of it
 * that is neither {@code true} nor {@code false} belongs to the module that owns the key, and
 * {@link VaultSignerActivation} states what that costs a composition carrying this starter without that one.
 *
 * <p>This class contributes nothing an application wires against, so excluding it says exactly what it does: it
 * switches this diagnostic off and leaves the signer's own auto-configuration untouched.
 */
// UseUtilityClass: the @Bean method must be static — the framework instructs that for a method
// producing a bean-factory post-processor, so the enclosing auto-configuration is not instantiated
// in that early phase. It is still no utility class: Spring instantiates it reflectively, so the
// constructor stays package-private rather than private.
@SuppressWarnings("PMD.UseUtilityClass")
@AutoConfiguration(afterName = "com.the13haven.push2u.spring.Push2uAutoConfiguration")
@ConditionalOnProperty(
        name = VaultSignerActivation.DELIVERY_SWITCH,
        havingValue = VaultSignerActivation.ON,
        matchIfMissing = true)
public final class VaultSignerDiagnosticsAutoConfiguration {

    VaultSignerDiagnosticsAutoConfiguration() {
        // Explicit + package-private: the autoconfiguration is framework plumbing, not public API;
        // Spring still instantiates it reflectively. (This also avoids an undocumented public
        // default constructor that Javadoc/doclint flags.)
    }

    /**
     * The diagnostic, contributed only where no signer and no sender answer for this context already.
     *
     * <p>{@link ConditionalOnMissingBean} is the stand-down, and it is decided while the auto-configurations are being
     * processed, against the bean <em>definitions</em> registered by then rather than against instances — so nothing is
     * forced into existence to answer it, and a deployment sending through some other signer with a stale
     * {@code push2u.signer.vault.*} key left over is not refused over configuration nothing reads. It sees the
     * application's own beans, which are processed first, and every signer contributed by an auto-configuration ordered
     * ahead of this one, which is what the {@code afterName} on the class buys.
     *
     * <p>{@code static}, and declaring the concrete class as its return type, both deliberately: the framework fetches
     * a post-processor bean before the configuration class is instantiated, and it chooses the sorting bucket from the
     * method's <em>declared</em> type — a method returning the post-processor interface would land the check in the
     * bucket that is never sorted, carrying an order nothing reads.
     *
     * @param environment the environment whose bound {@code push2u.signer.vault.*} keys the diagnostic reads
     * @return the check
     */
    @Bean
    @ConditionalOnMissingBean({VapidSigner.class, PushSender.class})
    static PartiallyConfiguredSignerCheck push2uVaultPartiallyConfiguredSignerCheck(Environment environment) {
        return new PartiallyConfiguredSignerCheck(environment);
    }

    /**
     * Fails the context at startup when some — but not all — of this starter's activating properties are stated, naming
     * which were found and which are missing.
     *
     * <p>A half-stated block is the shape of a real mistake: a prefix mistyped, a secret that did not reach the
     * container, a block copied without its token. Left alone it contributes no signer and says nothing, and the
     * deployment boots green and never sends. The general refusal over a missing signer would eventually catch that,
     * but only in the words it can honestly use — that no signer exists anywhere — while the finding here is specific,
     * and a specific finding outranks the general one.
     *
     * <p><b>It answers for this starter's own properties and no others.</b> The keys it names are the ones this module
     * owns; a message that also named another module's prefixes would rebuild inside the library the copy a consumer
     * was asked to delete, and would freeze that module's activation set into a document it cannot edit. Nothing
     * collects this finding into another module's message either: what an operator holding several faults reads is
     * whichever refusal is declared first, and that is the whole of the coordination between them.
     *
     * <p>{@link Ordered} is implemented on the class — not declared on the factory method — because the framework
     * buckets a post-processor by what its class implements and would not read an annotation on the method.
     */
    static final class PartiallyConfiguredSignerCheck implements BeanFactoryPostProcessor, Ordered {

        private final Environment environment;

        PartiallyConfiguredSignerCheck(Environment environment) {
            this.environment = environment;
        }

        @Override
        public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
            Binder binder = Binder.get(environment);
            List<String> stated = VaultSignerActivation.stated(binder);
            if (stated.isEmpty() || stated.size() == VaultSignerActivation.ACTIVATING_PROPERTIES.size()) {
                return;
            }
            List<String> missing = new ArrayList<>(VaultSignerActivation.ACTIVATING_PROPERTIES);
            missing.removeAll(stated);
            // Only the property names travel: the token is a live credential, the address may carry
            // proxy userinfo, and a startup failure is logged whole.
            throw new IllegalStateException("the Vault Transit signer is configured by halves: " + join(stated)
                    + " set, " + join(missing) + " unset or blank. All three are needed before this starter"
                    + " contributes a signer, so as it stands it contributes none and this deployment cannot send."
                    + " Complete the block, or delete what is left of it and configure whichever signer this"
                    + " deployment actually uses. A blank value counts as unset here, so a placeholder that resolved to"
                    + " nothing is one of the missing ones rather than one of the set ones.");
        }

        /** The property names as a message reads them: {@code a}, {@code a and b}, {@code a, b and c}. */
        private static String join(List<String> properties) {
            if (properties.size() == 1) {
                return properties.get(0);
            }
            return String.join(", ", properties.subList(0, properties.size() - 1)) + " and "
                    + properties.get(properties.size() - 1);
        }

        @Override
        public int getOrder() {
            return VaultStartupCheckOrder.SIGNER_PARTIAL_CONFIGURATION;
        }
    }
}
