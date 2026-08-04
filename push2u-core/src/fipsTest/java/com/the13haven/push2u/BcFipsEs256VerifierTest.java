package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Provider;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.junit.jupiter.api.Test;

/**
 * {@link Es256Verifier} on a DER-only provider: BC-FIPS registers no raw-format ECDSA name, so verification must
 * resolve {@code SHA256withECDSA} and re-encode the raw {@code r || s} signature to minimal DER
 * ({@code EcdsaDer.toDer}) before handing it over. This is the platform the verification helper exists in the core for
 * — a starter-local copy would have shipped without this coverage, and its absence is exactly what would condemn a
 * perfectly healthy signer on a FIPS-restricted JVM to a permanent {@code DOWN} in the health probe.
 */
class BcFipsEs256VerifierTest {

    private static final byte[] SIGNING_INPUT =
            "push2u BC-FIPS Es256Verifier test input".getBytes(StandardCharsets.US_ASCII);

    @Test
    void verifiesRawSignaturesThroughTheDerOnlyProvider() {
        Provider bcFips = new BouncyCastleFipsProvider();
        Jca jca = Jca.using(bcFips);
        // Guard the premise: verification here must go through the DER fallback. FAILS (not
        // skips) if a future BC-FIPS starts registering the raw P1363 name, so the suite can
        // never silently stop covering the toDer re-encoding.
        assertThat(jca.es256().encoding()).isEqualTo(Jca.EcdsaSignature.Encoding.DER);
        assertThat(Es256Verifier.isSupported(jca))
                .as("a DER-only provider still supports verification")
                .isTrue();

        KeyPair keyPair = EcKeys.generateP256(jca);
        VapidKeys keys = VapidKeys.of(
                EcKeys.encodeUncompressed((ECPublicKey) keyPair.getPublic()),
                TestVectors.scalar32((ECPrivateKey) keyPair.getPrivate()));
        VapidSigner signer = new LocalEcVapidSigner(keys, jca);
        byte[] rawSignature = signer.sign(SIGNING_INPUT);
        assertThat(rawSignature).as("the signer already emits raw r||s").hasSize(64);

        assertThat(Es256Verifier.verify(jca, signer.publicKey(), SIGNING_INPUT, rawSignature))
                .as("a genuine raw signature verifies through the DER re-encode")
                .isTrue();
        assertThat(Es256Verifier.verify(
                        jca, signer.publicKey(), "tampered input".getBytes(StandardCharsets.US_ASCII), rawSignature))
                .as("a wrong input still fails — the DER path must not verify vacuously")
                .isFalse();
        byte[] garbage = new byte[64];
        Arrays.fill(garbage, (byte) 0x42);
        assertThat(Es256Verifier.verify(jca, signer.publicKey(), SIGNING_INPUT, garbage))
                .as("garbage of the right length is invalid, not an error, on the strict provider")
                .isFalse();
    }
}
