package io.push2u;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.junit.jupiter.api.Test;

/**
 * The construction-time key-pair self-test of {@link LocalEcVapidSigner} on BC-FIPS, which
 * registers only DER-format ECDSA: the self-test verifies the provider's signature exactly as
 * produced (no DER → P1363 conversion), so it must reject a mismatched pair on the DER branch
 * just as it does on a raw-P1363 provider. The matching-pair side on this provider is covered
 * by {@link BcFipsLocalEcVapidSignerContractTest}, whose signer construction now runs the same
 * self-test.
 */
class BcFipsLocalEcVapidSignerKeyPairTest {

    @Test
    void mismatchedPairIsRejectedOnTheDerOnlyProvider() {
        Jca jca = Jca.using(new BouncyCastleFipsProvider());
        // Guard the premise: the self-test below must exercise the DER branch.
        assertThat(jca.es256().encoding()).isEqualTo(Jca.EcdsaSignature.Encoding.DER);

        KeyPair pairA = EcKeys.generateP256(jca);
        KeyPair pairB = EcKeys.generateP256(jca);
        VapidKeys keys = VapidKeys.of(
            EcKeys.encodeUncompressed((ECPublicKey) pairA.getPublic()),
            TestVectors.scalar32((ECPrivateKey) pairB.getPrivate()));

        assertThatThrownBy(() -> new LocalEcVapidSigner(keys, jca))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("does not correspond");
    }
}
