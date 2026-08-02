package io.push2u;

import static io.push2u.TestVectors.b64;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import org.junit.jupiter.api.Test;

class EcKeysTest {

    private final Jca jca = Jca.platform();

    @Test
    void uncompressedEncodeDecodeRoundTrips() {
        KeyPair generated = EcKeys.generateP256(jca);
        byte[] encoded = EcKeys.encodeUncompressed((ECPublicKey) generated.getPublic());

        assertThat(encoded).hasSize(65);
        assertThat(encoded[0]).isEqualTo((byte) 0x04);

        ECPublicKey decoded = EcKeys.decodeP256PublicKey(encoded, jca);
        assertThat(EcKeys.encodeUncompressed(decoded)).isEqualTo(encoded);
    }

    @Test
    void ecdhAgreesWithRfc8291SharedSecretFromEitherSide() {
        ECPrivateKey asPrivate = EcKeys.decodeP256PrivateKey(b64(TestVectors.AS_PRIVATE), jca);
        ECPublicKey uaPublic = EcKeys.decodeP256PublicKey(b64(TestVectors.UA_PUBLIC), jca);
        assertThat(EcKeys.ecdh(asPrivate, uaPublic, jca)).isEqualTo(b64(TestVectors.ECDH_SECRET));

        // ECDH is symmetric: the user agent derives the same secret from the other key pair.
        ECPrivateKey uaPrivate = EcKeys.decodeP256PrivateKey(b64(TestVectors.UA_PRIVATE), jca);
        ECPublicKey asPublic = EcKeys.decodeP256PublicKey(b64(TestVectors.AS_PUBLIC), jca);
        assertThat(EcKeys.ecdh(uaPrivate, asPublic, jca)).isEqualTo(b64(TestVectors.ECDH_SECRET));
    }

    @Test
    void decodeRejectsNonUncompressedPoint() {
        assertThatThrownBy(() -> EcKeys.decodeP256PublicKey(new byte[64], jca))
                .isInstanceOf(IllegalArgumentException.class);

        byte[] wrongPrefix = new byte[65];
        wrongPrefix[0] = 0x02;
        assertThatThrownBy(() -> EcKeys.decodeP256PublicKey(wrongPrefix, jca))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void decodePrivateRejectsWrongScalarLength() {
        assertThatThrownBy(() -> EcKeys.decodeP256PrivateKey(new byte[31], jca))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
