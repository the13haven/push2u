/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/**
 * push2u-core — the Web Push protocol (RFC 8030 / 8188 / 8291 / 8292) with no runtime implementation dependencies.
 *
 * <p>The module name is the package name, and both are permanent: changing either after a release breaks every consumer
 * that reads this artifact from the module path (ADR-014).
 */
module com.the13haven.push2u {
    // The JDK HttpClient behind JdkHttpPushClient, the default PushHttpClient. Everything else the
    // core uses — java.security, javax.crypto, java.util.Base64 — is in java.base.
    requires java.net.http;

    // `static`: JSpecify's annotations are CLASS-retention, so they are needed to compile against
    // this module and never at runtime. A consumer that does not care about the nullness contract
    // is not made to resolve the jar for it — which is what keeps ADR-002's zero-dependency claim
    // true on the module path as well as the classpath.
    requires static org.jspecify;

    exports com.the13haven.push2u;
}
