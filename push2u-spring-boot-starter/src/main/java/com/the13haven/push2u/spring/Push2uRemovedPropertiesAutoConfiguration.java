/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.spring;

import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.env.Environment;

/**
 * Fails the context at startup while a {@code push2u.*} key a release removed is still present, naming the key and
 * where its effect went. Binding ignores an unknown key silently, so without this refusal an operator upgrading past
 * the removal would keep a setting in their YAML that configures nothing and reads as though it were in force.
 *
 * <p>Deliberately its own auto-configuration, not part of {@link Push2uAutoConfiguration}: a deployment may one day
 * switch delivery off by condition on the class carrying the sender, and a dead key must be reported in exactly that
 * deployment too — a check suppressed together with the delivery path would let the key through where nothing reads it,
 * which is the very state it exists to report. For the same reason it carries no condition of its own, on a class, a
 * bean or a property: anything standing between this check and the context narrows the set of deployments it protects.
 *
 * <p>The check reads the <em>bound environment</em> at context refresh, so it catches the key in every spelling relaxed
 * binding accepts — {@code push2u.record-size}, {@code push2u.recordSize}, {@code PUSH2U_RECORD_SIZE} — and it
 * publishes nothing: no property component retained to be rejected, no public type, no public constant. It is raised
 * from a post-processor of the bean factory so that it precedes every application singleton, and its position among
 * this family's checks is declared in {@link StartupCheckOrder}.
 *
 * <p><b>A tombstone has an end</b>: each one is carried for one minor release after the release that removed its
 * property, and the release that adds one opens the work item that removes it. It exists to catch a configuration
 * written against the previous release, not to accumulate for the life of the library, and the closing release is named
 * in that work item once it exists rather than guessed at here.
 */
// UseUtilityClass: every member is static because the one @Bean method must be — the framework
// instructs that for a method producing a bean-factory post-processor, so the enclosing
// auto-configuration is not instantiated in that early phase. It is still no utility class: Spring
// instantiates it reflectively, so the constructor stays package-private rather than private.
@SuppressWarnings("PMD.UseUtilityClass")
@AutoConfiguration
public final class Push2uRemovedPropertiesAutoConfiguration {

    Push2uRemovedPropertiesAutoConfiguration() {
        // Explicit + package-private: the autoconfiguration is framework plumbing, not public API;
        // Spring still instantiates it reflectively. (This also avoids an undocumented public
        // default constructor that Javadoc/doclint flags.)
    }

    /**
     * The tombstone over {@code push2u.record-size}, whose effect moved into {@code push2u.max-encrypted-body-bytes}
     * when the record size became a derived value.
     *
     * <p>{@code static}, and declaring the concrete class as its return type, both deliberately: the framework fetches
     * a post-processor bean before the configuration class is instantiated, and it chooses the sorting bucket from the
     * method's <em>declared</em> type — a method returning the post-processor interface would land the check in the
     * bucket that is never sorted, carrying an order nothing reads.
     *
     * @param environment the environment whose bound {@code push2u.*} keys the tombstone inspects
     * @return the check
     */
    @Bean
    static RecordSizeTombstone push2uRecordSizeTombstone(Environment environment) {
        return new RecordSizeTombstone(environment);
    }

    /**
     * Refuses a context whose environment still binds {@code push2u.record-size}. {@link Ordered} is implemented on the
     * class — not declared on the factory method — because the framework buckets a post-processor by what its class
     * implements and would not read an annotation on the method.
     */
    static final class RecordSizeTombstone implements BeanFactoryPostProcessor, Ordered {

        private final Environment environment;

        RecordSizeTombstone(Environment environment) {
            this.environment = environment;
        }

        @Override
        public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
            // Binder.get(environment) applies relaxed matching against the canonical kebab-case
            // name; Environment.getProperty would see only the literal spelling.
            if (Binder.get(environment).bind("push2u.record-size", String.class).isBound()) {
                throw new IllegalStateException(
                        "push2u.record-size was removed and no longer configures anything — delete the key. The"
                                + " aes128gcm record size (RFC 8188 rs) is now derived from the one size property,"
                                + " push2u.max-encrypted-body-bytes: the largest payload that ceiling admits, plus the"
                                + " fixed record overhead. If record-size was raised to carry larger payloads, raise"
                                + " push2u.max-encrypted-body-bytes instead; the derived record size follows it.");
            }
        }

        @Override
        public int getOrder() {
            return StartupCheckOrder.REMOVED_PROPERTY_TOMBSTONE;
        }
    }
}
