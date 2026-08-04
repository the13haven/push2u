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
    // `transitive`, because HttpClient is not merely behind JdkHttpPushClient — it is in its public
    // constructor, `JdkHttpPushClient(HttpClient, Duration)`, which is the documented way to supply
    // a configured client. Without it a consumer calling that constructor gets "package
    // java.net.http is not visible" until they add the requires themselves. Everything else the
    // core uses — java.security, javax.crypto, java.util.Base64 — is in java.base.
    requires transitive java.net.http;

    // `static`: nothing resolves the JSpecify jar at runtime. Its annotations are RUNTIME-retention,
    // but the JVM silently ignores an annotation whose type it cannot resolve, so a consumer that
    // does not care about the nullness contract never has to supply the jar — which is what keeps
    // ADR-002's zero-dependency claim true on the module path as well as the classpath. A consumer
    // that does care puts it on the path and reads the annotations as usual.
    requires static org.jspecify;

    exports com.the13haven.push2u;
}
