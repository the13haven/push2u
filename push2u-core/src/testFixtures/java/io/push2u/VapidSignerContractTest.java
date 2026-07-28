package io.push2u;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/**
 * The conformance contract every {@link VapidSigner} must satisfy: signing produces a raw
 * {@code r || s} ES256 signature (64 bytes) that verifies against the public key the signer
 * advertises. Each implementation extends this and supplies a configured signer via
 * {@link #signer()} — the local signer's unit test and every remote signer's integration test
 * (DESIGN.md §5.1, ROADMAP phase 3).
 *
 * <p>Verification uses only the JDK and the public {@link VapidSigner} surface, so the contract is
 * self-contained and carries no push2u-internal dependency.
 */
public abstract class VapidSignerContractTest {

    /**
     * The signer under test.
     *
     * @return a fully configured {@link VapidSigner}
     */
    protected abstract VapidSigner signer();

    @Test
    void publicKeyIsA65ByteUncompressedPoint() {
        byte[] publicKey = signer().publicKey();
        assertThat(publicKey).hasSize(65);
        assertThat(publicKey[0]).as("X9.62 uncompressed point prefix").isEqualTo((byte) 0x04);
    }

    @Test
    void signatureIsRawRsThatVerifiesAgainstTheAdvertisedPublicKey() throws Exception {
        VapidSigner signer = signer();
        byte[] signingInput = "push2u VapidSigner conformance".getBytes(StandardCharsets.US_ASCII);

        byte[] signature = signer.sign(signingInput);
        assertThat(signature).as("raw r||s, not DER").hasSize(64);

        Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
        verifier.initVerify(decodeP256PublicKey(signer.publicKey()));
        verifier.update(signingInput);
        assertThat(verifier.verify(signature)).as("verifies against the advertised public key").isTrue();
    }

    private static ECPublicKey decodeP256PublicKey(byte[] uncompressed) throws Exception {
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(uncompressed, 1, 33));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(uncompressed, 33, 65));
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec p256 = parameters.getParameterSpec(ECParameterSpec.class);
        return (ECPublicKey) KeyFactory.getInstance("EC")
            .generatePublic(new ECPublicKeySpec(new ECPoint(x, y), p256));
    }
}
