/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.the13haven.push2u.testkit.VapidSignerContractTest;

/**
 * {@link LocalEcVapidSigner} bound to a stock BouncyCastle provider instance (not registered with
 * {@code java.security.Security}) satisfies the shared {@link VapidSignerContractTest}: bcprov registers raw-format
 * ECDSA, so this runs the direct P1363 path — the contract's verification against a platform P1363 verifier proves the
 * two providers interoperate.
 */
class BouncyCastleLocalEcVapidSignerContractTest extends VapidSignerContractTest {

    @Override
    protected VapidSigner signer() {
        Jca jca = Jca.using(new BouncyCastleProvider());
        KeyPair keyPair = EcKeys.generateP256(jca);
        VapidKeys keys = VapidKeys.of(
                EcKeys.encodeUncompressed((ECPublicKey) keyPair.getPublic()),
                TestVectors.scalar32((ECPrivateKey) keyPair.getPrivate()));
        return new LocalEcVapidSigner(keys, jca);
    }
}
