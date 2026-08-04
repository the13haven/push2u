/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

/** {@link LocalEcVapidSigner} satisfies the shared {@link VapidSignerContractTest}. */
class LocalEcVapidSignerContractTest extends VapidSignerContractTest {

    @Override
    protected VapidSigner signer() {
        KeyPair keyPair = EcKeys.generateP256(Jca.platform());
        VapidKeys keys = VapidKeys.of(
                EcKeys.encodeUncompressed((ECPublicKey) keyPair.getPublic()),
                TestVectors.scalar32((ECPrivateKey) keyPair.getPrivate()));
        return new LocalEcVapidSigner(keys);
    }
}
