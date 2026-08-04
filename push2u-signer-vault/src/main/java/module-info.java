/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/**
 * push2u-signer-vault — a {@code VapidSigner} backed by HashiCorp Vault Transit; the private key never leaves Vault.
 *
 * <p>The module name is the package name, and both are permanent (ADR-014).
 */
module com.the13haven.push2u.signer.vault {
    // `transitive`: VaultTransitVapidSigner implements com.the13haven.push2u.VapidSigner and the
    // builder returns it, so anyone reading this module reads those types too. It mirrors the
    // `api(project(":push2u-core"))` this module already declares to Gradle.
    requires transitive com.the13haven.push2u;

    // The JDK HttpClient behind the default VaultHttpTransport — this module's own transport seam,
    // deliberately not PushHttpClient: Vault's responses must be read, push responses must not.
    requires java.net.http;
    requires static org.jspecify;

    exports com.the13haven.push2u.signer.vault;
}
