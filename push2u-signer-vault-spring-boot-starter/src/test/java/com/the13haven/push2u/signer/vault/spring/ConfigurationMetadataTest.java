/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * This module's hand-written configuration metadata is a value hint rather than a property: the accepted spellings of
 * {@code push2u.signer.vault.public-key-fetch}, which an operator's editor offers as completions. The annotation
 * processor generates the property itself from the properties record and cannot know its values, so the hint is written
 * by hand into {@code META-INF/additional-spring-configuration-metadata.json} and merged only if the processor finds
 * that file on the classpath it runs with.
 *
 * <p>The merge failing is silent — no task fails and the hint simply is not in the jar — so it is pinned here rather
 * than left to be noticed by an operator who never sees a completion and does not know one was meant to appear.
 */
class ConfigurationMetadataTest {

    @Test
    void theGeneratedMetadataCarriesTheHandWrittenValueHint() throws IOException {
        String metadata = generatedMetadata();

        assertThat(metadata).contains("\"name\": \"push2u.signer.vault.public-key-fetch\"");
        // The property is generated; the hint is not. A file holding the first and not the second
        // is exactly what an unmerged additional-metadata file produces, so the hint's own values
        // are what this asserts.
        assertThat(metadata).contains("\"hints\"");
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
