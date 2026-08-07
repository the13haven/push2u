/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.http.HttpClient;
import java.time.Duration;

import org.junit.jupiter.api.Test;

/**
 * The transport's timeout invariant. The JDK's {@code HttpRequest.Builder.timeout(Duration)} throws its own
 * {@link IllegalArgumentException} for a non-positive duration, but only once {@code post()} builds the request — the
 * constructor rejects a zero or negative {@code requestTimeout} up front instead, so a misconfiguration surfaces where
 * the value was supplied rather than as a JDK-worded failure on the first delivery attempt.
 */
class JdkPushHttpClientTimeoutTest {

    @Test
    void aZeroRequestTimeoutIsRejectedAtConstruction() {
        HttpClient never = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        assertThatThrownBy(() -> new JdkPushHttpClient(never, Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("requestTimeout must be positive");
    }

    @Test
    void aNegativeRequestTimeoutIsRejectedAtConstruction() {
        HttpClient never = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        assertThatThrownBy(() -> new JdkPushHttpClient(never, Duration.ofSeconds(-1)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("requestTimeout must be positive");
    }

    @Test
    void theNoArgConstructorStillBuilds() {
        assertThatCode(JdkPushHttpClient::new).doesNotThrowAnyException();
    }
}
