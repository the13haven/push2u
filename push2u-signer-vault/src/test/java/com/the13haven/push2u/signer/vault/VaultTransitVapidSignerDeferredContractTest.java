/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import java.net.URI;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.testcontainers.vault.VaultContainer;

import com.the13haven.push2u.VapidSigner;
import com.the13haven.push2u.testkit.VapidSignerContractTest;

/**
 * The published conformance kit against a <b>deferred-fetch</b> signer over a real Vault (dev mode): every fresh signer
 * the kit obtains has performed no Vault call yet, so {@code publicKey()} — the call the kit makes first — performs the
 * metadata read itself. A green run proves that a signer whose first answer costs a network round trip still satisfies
 * the whole {@code VapidSigner} contract, and that the lazily fetched public key matches the private key Vault signs
 * with. The eager fetched and explicit modes have their own contract run in
 * {@link VaultTransitVapidSignerContractTest}.
 */
class VaultTransitVapidSignerDeferredContractTest extends VapidSignerContractTest {

    private static final String ROOT_TOKEN = "push2u-test-root";
    private static final String MOUNT = "transit";
    private static final String KEY_NAME = "vapid";

    private static VaultContainer<?> vault;

    @BeforeAll
    @SuppressWarnings("resource") // the container lives across all test methods; it is closed in @AfterAll
    static void startVault() {
        vault = new VaultContainer<>("hashicorp/vault:1.18")
                .withVaultToken(ROOT_TOKEN)
                .withInitCommand(
                        "secrets enable " + MOUNT, "write " + MOUNT + "/keys/" + KEY_NAME + " type=ecdsa-p256");
        vault.start();
    }

    @AfterAll
    static void stopVault() {
        if (vault != null) {
            vault.stop();
        }
    }

    /** Deferred mode — build() performs no Vault call; the kit's first signer call performs the read. */
    @Override
    protected VapidSigner signer() {
        // allowInsecureHttp(): Testcontainers serves the dev Vault over plain http, and its host is
        // a loopback literal only for a local Docker daemon — a remote or rootless daemon reports a
        // routable host, which the scheme rule would refuse. The opt-in keeps this suite about the
        // contract; the scheme rule itself is pinned in VaultTransitVapidSignerAddressTest and in
        // the deferred builder's own unit tests.
        return VaultTransitVapidSigner.builderWithDeferredPublicKeyFetch(
                        URI.create(vault.getHttpHostAddress()),
                        new TransitKeyName(KEY_NAME),
                        new VaultToken(ROOT_TOKEN))
                .mount(MOUNT)
                .allowInsecureHttp()
                .build();
    }
}
