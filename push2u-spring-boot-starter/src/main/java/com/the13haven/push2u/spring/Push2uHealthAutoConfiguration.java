/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.spring;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.context.annotation.Bean;

import com.the13haven.push2u.PushSender;
import com.the13haven.push2u.VapidSigner;

/**
 * Registers a push2u {@link HealthIndicator} when Spring Boot Actuator is on the classpath and both a
 * {@link PushSender} and a {@link VapidSigner} have been configured, unless {@code push2u.health.enabled=false} opts
 * out.
 *
 * <p>Both beans are required because the probe signs with the {@code VapidSigner} to find out whether the signing
 * backend answers. An application that supplies its own {@code PushSender} and no signer — the sender carries one
 * internally, so it never has to be a bean — gets no indicator rather than a context that fails to start: there is
 * nothing here to probe, and an indicator reporting health it never established would be worse than its absence.
 * {@code /actuator/conditions} (or {@code --debug}) names the missing bean when the indicator is not there.
 *
 * <p>Two consequences of probing a <em>bean</em> rather than the sender's own signer. A signer registered by an
 * autoconfiguration ordered after this one is invisible to the condition, so an application combining its own
 * {@code PushSender} with such a signer gets no indicator; a signer that is a bean by the time this runs is fine, which
 * covers the local one, the Vault one and any the application declares itself. And when an application supplies both
 * its own {@code PushSender} and {@code push2u.vapid.*}, the probe exercises the bean built from those properties, not
 * whatever signer that sender was built with — the health entry then describes a signer the sender does not use.
 *
 * <p>A separate autoconfiguration ordered {@link AutoConfiguration#after() after} {@link Push2uAutoConfiguration} so
 * the {@code PushSender} and the local {@code VapidSigner} beans already exist when {@link ConditionalOnBean} is
 * evaluated — a condition sees only what is registered by the time it runs. The Vault signer comes from a starter
 * ordered ahead of {@code Push2uAutoConfiguration}, so it is registered by then too; the Vault starter's test suite
 * pins that composition, because a signer arriving too late makes the indicator vanish silently rather than fail.
 * {@link ConditionalOnClass} keeps the starter usable without Actuator on the classpath.
 * {@link EnableConfigurationProperties} is restated here (not only on {@link Push2uAutoConfiguration}) so the
 * indicator's configuration binds even in a context that supplies its own {@code PushSender}/{@code VapidSigner} beans
 * and excludes the main autoconfiguration.
 *
 * <p>The indicator is an ordinary application-scoped contributor: it lands in the health endpoint's primary group (and
 * in {@code readiness} only if the operator includes it there), never in {@code liveness} — Spring Boot's liveness
 * group holds only the application's own {@code LivenessState}, and this autoconfiguration registers no group
 * customization that could change that. Liveness failures restart containers, and no restart fixes an unreachable
 * signer backend.
 */
@AutoConfiguration(after = Push2uAutoConfiguration.class)
@ConditionalOnClass(HealthIndicator.class)
@EnableConfigurationProperties(Push2uProperties.class)
public final class Push2uHealthAutoConfiguration {

    Push2uHealthAutoConfiguration() {
        // Explicit + package-private: the autoconfiguration is framework plumbing, not public API;
        // Spring still instantiates it reflectively. (This also avoids an undocumented public
        // default constructor that Javadoc/doclint flags.)
    }

    /**
     * The push2u health indicator, created once a {@link PushSender} and a {@link VapidSigner} are configured and the
     * probe is not disabled.
     *
     * <p>{@code push2u.health.cache-ttl} failures from the indicator's own validation are re-thrown with the property
     * name prefixed, since the constructor's message cannot know the YAML property — the same convention as
     * {@code push2u.record-size} in {@link Push2uAutoConfiguration}.
     *
     * @param signer the configured VAPID signer
     * @param properties the bound configuration
     * @return the health indicator
     * @throws IllegalArgumentException if {@code push2u.health.cache-ttl} is negative
     */
    @Bean
    @ConditionalOnBean({PushSender.class, VapidSigner.class})
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "push2u.health", name = "enabled", matchIfMissing = true)
    public Push2uHealthIndicator push2uHealthIndicator(VapidSigner signer, Push2uProperties properties) {
        try {
            return new Push2uHealthIndicator(signer, properties.health().cacheTtl());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("push2u.health.cache-ttl: " + e.getMessage(), e);
        }
    }
}
