package io.push2u;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.Provider;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.junit.jupiter.api.Test;

/**
 * The BC-FIPS side of the ES256 selection matrix (the raw-P1363 providers are covered by {@code JcaEs256SelectionTest}
 * in the regular test source set — bc-fips and stock bcprov ship incompatible
 * {@code org.bouncycastle.crypto.CryptoServicesRegistrar} classes and can never share a classpath, hence this
 * bcprov-free source set).
 *
 * <p>This test doubles as the premise guard for the whole FIPS suite: it FAILS — not skips — if a future BC-FIPS
 * version starts registering the raw P1363 name, so the suite can never silently stop covering the DER fallback.
 */
class BcFipsJcaEs256SelectionTest {

    @Test
    void bcFipsFallsBackToDerFromTheSameProvider() {
        Provider bcFips = new BouncyCastleFipsProvider();

        Jca.EcdsaSignature es256 = Jca.using(bcFips).es256();

        assertThat(es256.encoding())
                .as("BC-FIPS registers only SHA256withECDSA — the DER fallback")
                .isEqualTo(Jca.EcdsaSignature.Encoding.DER);
        assertThat(es256.delegate().getAlgorithm()).isEqualTo("SHA256withECDSA");
        assertThat(es256.delegate().getProvider())
                .as("the fallback must not escape the explicitly configured provider")
                .isSameAs(bcFips);
    }
}
