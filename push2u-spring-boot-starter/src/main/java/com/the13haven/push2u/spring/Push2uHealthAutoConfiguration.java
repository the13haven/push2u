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
 * Registers a push2u {@link HealthIndicator} when Spring Boot Actuator is on the classpath and a {@link VapidSigner}
 * bean exists, unless {@code push2u.health.enabled=false} opts out.
 *
 * <p>The signer is the condition because the signer is the question. A health indicator reports what has stopped
 * working since startup, not what was configured wrongly before it — and the signer is the only part of a
 * {@link PushSender} with anything to lose: it can reach a backend that goes down, holds a token that expires, names a
 * key that gets deleted. Everything else the sender carries is immutable configuration the builder already validated
 * ({@code EndpointPolicy}, {@code RetryPolicy}, sizes, TTLs), and the HTTP client has no address of its own to probe —
 * an endpoint belongs to a subscription, not to the sender. So the probe signs, and the indicator exists exactly when
 * there is a signer bean to sign with.
 *
 * <p>Missing configuration is not this indicator's business, and it does not have to be: an incomplete setup fails at
 * startup instead. While {@link Push2uAutoConfiguration} is active, {@code pushSender} is itself
 * {@code @ConditionalOnBean(VapidSigner.class)} and throws when {@code push2u.vapid.subject} is unset, so a signer bean
 * yields either a sender bean too or a context that never started — never a running context with one and not the other.
 * The case this condition adds is therefore the one where that autoconfiguration is <em>excluded</em> (or absent) and
 * the application wires its own {@code PushSender} around a signer it keeps as a bean: the probe applies to exactly the
 * signer that sender uses. An application whose signer is not a bean gets no indicator, because nothing here can reach
 * it. When the entry is missing unexpectedly, {@code /actuator/conditions} (or {@code --debug}) names the bean the
 * condition did not find.
 *
 * <p>One consequence of probing a <em>bean</em>: an application that supplies its own {@code PushSender} and also
 * configures {@code push2u.vapid.*} gets a probe of the bean built from those properties, not of whatever signer that
 * sender was built with — the health entry then describes a signer the sender does not use.
 *
 * <p>A separate autoconfiguration ordered {@link AutoConfiguration#after() after} {@link Push2uAutoConfiguration} so
 * the local {@code VapidSigner} bean already exists when {@link ConditionalOnBean} is evaluated — a condition sees only
 * what is registered by the time it runs, and a signer registered later is invisible to it. The Vault signer comes from
 * a starter ordered ahead of {@code Push2uAutoConfiguration}, so it is registered by then too; the Vault starter's test
 * suite pins that composition, because a signer arriving too late makes the indicator vanish silently rather than fail.
 * Neither the {@code after} here nor the Vault starter's {@code beforeName} is pinned on its own: remove either and the
 * suite stays green, since the sorter falls back to class name and lands on the same order by coincidence. Both are
 * declared because depending on that coincidence would be worse than stating the order. {@link ConditionalOnClass}
 * keeps the starter usable without Actuator on the classpath. {@link EnableConfigurationProperties} is restated here
 * (not only on {@link Push2uAutoConfiguration}) so the indicator's configuration binds even in a context that supplies
 * its own {@code VapidSigner} bean and excludes the main autoconfiguration.
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
     * The push2u health indicator, created once a {@link VapidSigner} bean exists and the probe is not disabled.
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
    @ConditionalOnBean(VapidSigner.class)
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
