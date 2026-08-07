/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.spec.ECFieldFp;
import java.security.spec.EllipticCurve;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.junit.jupiter.api.Test;

/**
 * The BC-FIPS side of the {@link P256PublicKeys} constants guard: the hard-coded FIPS 186-4 domain parameters must
 * equal what BC-FIPS answers for {@code secp256r1}, exactly as {@code P256PublicKeysTest} pins against the platform
 * provider in the regular test source set. Two providers agreeing with the same transcription is the point — the
 * constants exist so the full check can run without any provider at all, and this is what keeps them honest.
 */
class BcFipsP256PublicKeysTest {

    @Test
    void everyHardCodedConstantMatchesBcFips() {
        EllipticCurve curve =
                Jca.using(new BouncyCastleFipsProvider()).p256Parameters().getCurve();

        assertThat(curve.getField()).isInstanceOf(ECFieldFp.class);
        assertThat(P256PublicKeys.P).as("field prime p").isEqualTo(((ECFieldFp) curve.getField()).getP());
        assertThat(P256PublicKeys.A).as("curve coefficient a").isEqualTo(curve.getA());
        assertThat(P256PublicKeys.B).as("curve coefficient b").isEqualTo(curve.getB());
    }
}
