/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/**
 * push2u-signer-vault — a {@code VapidSigner} backed by HashiCorp Vault Transit; the private key never leaves Vault.
 *
 * <p>The module name is the package name, and both are permanent: changing either after a release breaks every consumer
 * that reads this artifact from the module path.
 */
module com.the13haven.push2u.signer.vault {
    // `transitive`: VaultTransitVapidSigner implements com.the13haven.push2u.VapidSigner and the
    // builder returns it, so anyone reading this module reads those types too. It mirrors the
    // `api(project(":push2u-core"))` this module already declares to Gradle.
    requires transitive com.the13haven.push2u;

    // `transitive` for the same reason as the core: HttpClient is a parameter of the public
    // `JdkVaultHttpTransport(HttpClient, Duration, int)`, which is how an application supplies a
    // client configured for mTLS or a proxy. This is the module's own transport seam, deliberately
    // not PushHttpClient — Vault's responses must be read, push responses must not.
    requires transitive java.net.http;

    // `static`: see the core's descriptor — the annotations are RUNTIME-retention, but an
    // unresolvable annotation type is ignored by the JVM rather than fatal.
    requires static org.jspecify;

    exports com.the13haven.push2u.signer.vault;
}
