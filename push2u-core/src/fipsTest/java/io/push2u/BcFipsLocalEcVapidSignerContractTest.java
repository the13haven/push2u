package io.push2u;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

/**
 * {@link LocalEcVapidSigner} bound to a BC-FIPS provider instance (not registered with {@code java.security.Security})
 * satisfies the shared {@link VapidSignerContractTest}. BC-FIPS registers only DER-format ECDSA, so every signature
 * here goes through the strict DER → P1363 conversion — and the contract verifies the converted 64-byte output against
 * a platform P1363 verifier, proving the conversion preserves the signature.
 *
 * <p>Lives in the {@code fipsTest} source set: bc-fips and stock bcprov ship incompatible versions of
 * {@code org.bouncycastle.crypto.CryptoServicesRegistrar} and can never share a classpath, so the BC-FIPS tests run on
 * their own bcprov-free classpath.
 */
class BcFipsLocalEcVapidSignerContractTest extends VapidSignerContractTest {

    @Override
    protected VapidSigner signer() {
        Jca jca = Jca.using(new BouncyCastleFipsProvider());
        // Guard the premise the class doc makes: every signature must go through the DER
        // fallback. FAILS (not skips) if a future BC-FIPS starts registering the raw P1363
        // name, instead of silently migrating this contract run to the other branch.
        assertThat(jca.es256().encoding()).isEqualTo(Jca.EcdsaSignature.Encoding.DER);
        KeyPair keyPair = EcKeys.generateP256(jca);
        VapidKeys keys = VapidKeys.of(
                EcKeys.encodeUncompressed((ECPublicKey) keyPair.getPublic()),
                TestVectors.scalar32((ECPrivateKey) keyPair.getPrivate()));
        return new LocalEcVapidSigner(keys, jca);
    }
}
