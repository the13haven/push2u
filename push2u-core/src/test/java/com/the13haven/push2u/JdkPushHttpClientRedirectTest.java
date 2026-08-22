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
 * The transport's redirect invariant. The push endpoint is a capability URL taken from an untrusted subscription, and
 * {@link EndpointPolicy} vetted exactly the URI the pipeline hands to {@link JdkPushHttpClient#post} — a followed
 * {@code 3xx} would POST the encrypted body and its headers to a host the policy never saw (the JDK strips
 * {@code Authorization} across origins but not custom headers or the body), and would report the redirect target's
 * answer as the delivery result.
 *
 * <p>These tests pin the constructor's refusal, which is this class's own invariant. The wire-level half — the 3xx
 * handed back unfollowed and the Location host never contacted — is the published transport contract's fourth check,
 * which {@link JdkPushHttpClientContractTest} runs against this client; the kit's own suite proves that check fails a
 * redirect-following transport, which is what allowed the equivalent test here to be deleted.
 */
class JdkPushHttpClientRedirectTest {

    @Test
    void aRedirectFollowingClientIsRejectedAtConstruction() {
        for (HttpClient.Redirect policy :
                new HttpClient.Redirect[] {HttpClient.Redirect.ALWAYS, HttpClient.Redirect.NORMAL}) {
            HttpClient following =
                    HttpClient.newBuilder().followRedirects(policy).build();

            assertThatThrownBy(() -> new JdkPushHttpClient(following, Duration.ofSeconds(5)))
                    .as("followRedirects %s", policy)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("must not follow redirects")
                    .hasMessageContaining("EndpointPolicy")
                    .hasMessageContaining("followRedirects(HttpClient.Redirect.NEVER)");
        }
    }

    @Test
    void aNonRedirectingClientIsAccepted() {
        HttpClient never = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        assertThatCode(() -> new JdkPushHttpClient(never, Duration.ofSeconds(5)))
                .doesNotThrowAnyException();
    }
}
