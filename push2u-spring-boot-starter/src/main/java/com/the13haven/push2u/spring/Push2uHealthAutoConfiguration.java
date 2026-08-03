package com.the13haven.push2u.spring;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.context.annotation.Bean;

import com.the13haven.push2u.PushSender;
import com.the13haven.push2u.VapidSigner;

/**
 * Registers a push2u {@link HealthIndicator} when Spring Boot Actuator is on the classpath and a {@link PushSender} has
 * been configured.
 *
 * <p>A separate autoconfiguration ordered {@link AutoConfiguration#after() after} {@link Push2uAutoConfiguration} so
 * the {@code PushSender} bean already exists when {@link ConditionalOnBean} is evaluated; {@link ConditionalOnClass}
 * keeps the starter usable without Actuator on the classpath.
 */
@AutoConfiguration(after = Push2uAutoConfiguration.class)
@ConditionalOnClass(HealthIndicator.class)
public final class Push2uHealthAutoConfiguration {

    Push2uHealthAutoConfiguration() {
        // Explicit + package-private: the autoconfiguration is framework plumbing, not public API;
        // Spring still instantiates it reflectively. (This also avoids an undocumented public
        // default constructor that Javadoc/doclint flags.)
    }

    /**
     * The push2u health indicator, created once a {@link PushSender} is configured.
     *
     * @param signer the configured VAPID signer
     * @return the health indicator
     */
    @Bean
    @ConditionalOnBean(PushSender.class)
    @ConditionalOnMissingBean
    public Push2uHealthIndicator push2uHealthIndicator(VapidSigner signer) {
        return new Push2uHealthIndicator(signer);
    }
}
