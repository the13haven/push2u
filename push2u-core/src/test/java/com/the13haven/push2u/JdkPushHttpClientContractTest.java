/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.net.http.HttpClient;
import java.time.Duration;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;

import com.the13haven.push2u.testkit.PushHttpClientContractTest;

/**
 * {@link JdkPushHttpClient} satisfies the published {@link PushHttpClientContractTest} — the library's own transport is
 * the contract's first subject, because a contract nothing in this build extends drifts from what the library actually
 * requires. The trust manager goes unused deliberately: the JDK stack is configured through the {@link SSLContext}
 * alone, and the contract hands both halves over because other stacks want the other one.
 */
class JdkPushHttpClientContractTest extends PushHttpClientContractTest {

    @Override
    protected PushHttpClient transport(SSLContext sslContext, X509TrustManager trustManager) {
        return new JdkPushHttpClient(
                HttpClient.newBuilder()
                        .sslContext(sslContext)
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .build(),
                Duration.ofSeconds(30));
    }
}
