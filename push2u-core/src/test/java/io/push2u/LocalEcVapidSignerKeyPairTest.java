package io.push2u;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import org.junit.jupiter.api.Test;

/**
 * The construction-time key-pair self-test of {@link LocalEcVapidSigner}: a public key and a private scalar taken from
 * two different P-256 pairs must be rejected when the signer is created, before any send. The happy path — a matching
 * pair signs and the signature verifies against the advertised public key — is covered by the
 * {@link VapidSignerContractTest} subclasses; here only construction itself is asserted.
 */
class LocalEcVapidSignerKeyPairTest {

    @Test
    void matchingPairConstructs() {
        assertThatCode(() -> new LocalEcVapidSigner(PushTestSupport.generateVapidKeys()))
                .doesNotThrowAnyException();
    }

    @Test
    void mismatchedPairIsRejectedAtConstruction() {
        byte[] publicA = publicOf(EcKeys.generateP256(Jca.platform()));
        byte[] privateB = scalarOf(EcKeys.generateP256(Jca.platform()));

        assertThatThrownBy(() -> new LocalEcVapidSigner(VapidKeys.of(publicA, privateB)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("does not correspond")
                .satisfies(e -> assertThat(e.getMessage())
                        .as("the message must stay descriptive — no key bytes, not even the public half")
                        .doesNotContain(Base64Url.encode(publicA))
                        .doesNotContain(Base64Url.encode(privateB)));
    }

    @Test
    void mismatchedBase64PairIsRejectedAtConstruction() {
        String publicA = Base64Url.encode(publicOf(EcKeys.generateP256(Jca.platform())));
        String privateB = Base64Url.encode(scalarOf(EcKeys.generateP256(Jca.platform())));

        // fromBase64 alone accepts the halves (each is individually well-formed); the signer
        // must still reject the combination.
        VapidKeys keys = VapidKeys.fromBase64(publicA, privateB);

        assertThatThrownBy(() -> new LocalEcVapidSigner(keys))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("does not correspond");
    }

    private static byte[] publicOf(KeyPair pair) {
        return EcKeys.encodeUncompressed((ECPublicKey) pair.getPublic());
    }

    private static byte[] scalarOf(KeyPair pair) {
        return TestVectors.scalar32((ECPrivateKey) pair.getPrivate());
    }
}
