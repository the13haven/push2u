/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * The configuration metadata this module publishes must carry the keys no properties record binds. Two of them exist —
 * {@code push2u.enabled} and {@code management.health.push2u.enabled} — and both are read by the framework rather than
 * bound here, so the annotation processor cannot discover either. They are written by hand into
 * {@code META-INF/additional-spring-configuration-metadata.json}, which the processor merges only if it finds that file
 * on the classpath it runs with.
 *
 * <p>That merge is what this pins, and it is worth a test because its failure is completely silent: with the resources
 * unavailable to annotation processing, the processor produces metadata without the hand-written half, no task fails,
 * and the keys are simply absent from the published jar. An operator then sees the deployment's own on/off switch
 * flagged as an unknown property by their IDE, which is the one place metadata is read at all. Asserting the keys
 * rather than the wiring keeps this a statement about what the jar contains.
 */
class ConfigurationMetadataTest {

    @Test
    void theGeneratedMetadataCarriesTheKeysNoPropertiesRecordBinds() throws IOException {
        String metadata = generatedMetadata();

        // The activation switch: a @ConditionalOnProperty key, read by the framework and bound
        // nowhere, so nothing generates it.
        assertThat(metadata).contains("\"name\": \"push2u.enabled\"");
        // The health indicator's own switch: @ConditionalOnEnabledHealthIndicator reads it, and
        // Spring Boot ships metadata for management.health.<name>.enabled only for its own
        // contributors, named one by one. A third-party contributor gets none.
        assertThat(metadata).contains("\"name\": \"management.health.push2u.enabled\"");
    }

    @Test
    void theGeneratedMetadataAlsoCarriesWhatTheProcessorDiscovers() throws IOException {
        // The other half, so a failure tells the reader which one broke: a properties record's own
        // component, which needs no hand-written entry. Absent, the processor itself did not run.
        assertThat(generatedMetadata()).contains("\"name\": \"push2u.vapid.public-key\"");
    }

    /** The metadata as it will sit in the jar — read from the classpath rather than from a build path. */
    private static String generatedMetadata() throws IOException {
        try (InputStream in =
                ConfigurationMetadataTest.class.getResourceAsStream("/META-INF/spring-configuration-metadata.json")) {
            assertThat(in)
                    .as("META-INF/spring-configuration-metadata.json on the classpath")
                    .isNotNull();
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
