package com.the13haven.push2u;

import static com.the13haven.push2u.TestVectors.b64;
import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;

import org.junit.jupiter.api.Test;

class VapidTest {

    private static final Instant EXPIRY = Instant.ofEpochSecond(TestVectors.VAPID_EXP);
    private final Jca jca = Jca.platform();

    @Test
    void serializesHeaderAndClaimsMatchingRfc8292Example() {
        String[] segments = Vapid.signingInput(TestVectors.VAPID_AUDIENCE, TestVectors.VAPID_SUBJECT, EXPIRY)
                .split("\\.");

        assertThat(segments).hasSize(2);
        assertThat(segments[0]).as("JWT header").isEqualTo(TestVectors.VAPID_HEADER_B64);
        assertThat(segments[1]).as("JWT claims").isEqualTo(TestVectors.VAPID_CLAIMS_B64);
    }

    @Test
    void rfc8292ExampleSignatureVerifiesAgainstTheExamplePublicKey() throws Exception {
        String signingInput = TestVectors.VAPID_HEADER_B64 + "." + TestVectors.VAPID_CLAIMS_B64;
        ECPublicKey publicKey = EcKeys.decodeP256PublicKey(b64(TestVectors.VAPID_PUBLIC_K), jca);

        Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
        verifier.initVerify(publicKey);
        verifier.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        assertThat(verifier.verify(b64(TestVectors.VAPID_SIGNATURE))).isTrue();

        // The advertised "k" is exactly 0x04 || x || y from the JWK.
        assertThat(b64(TestVectors.VAPID_PUBLIC_K))
                .isEqualTo(TestVectors.concat(
                        new byte[] {0x04}, b64(TestVectors.VAPID_JWK_X), b64(TestVectors.VAPID_JWK_Y)));
    }

    @Test
    void localSignerProducesAVerifiableEs256JwtWithTheRfcStructure() throws Exception {
        KeyPair keyPair = EcKeys.generateP256(jca);
        VapidKeys keys = VapidKeys.of(
                EcKeys.encodeUncompressed((ECPublicKey) keyPair.getPublic()),
                TestVectors.scalar32((ECPrivateKey) keyPair.getPrivate()));
        LocalEcVapidSigner signer = new LocalEcVapidSigner(keys);

        assertThat(signer.publicKey()).isEqualTo(EcKeys.encodeUncompressed((ECPublicKey) keyPair.getPublic()));

        String[] parts = Vapid.jwt(signer, TestVectors.VAPID_AUDIENCE, TestVectors.VAPID_SUBJECT, EXPIRY)
                .split("\\.");
        assertThat(parts).hasSize(3);
        assertThat(parts[0]).isEqualTo(TestVectors.VAPID_HEADER_B64);
        assertThat(parts[1]).isEqualTo(TestVectors.VAPID_CLAIMS_B64);

        byte[] signature = b64(parts[2]);
        assertThat(signature).as("raw r||s, not DER").hasSize(64);

        Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
        verifier.initVerify((ECPublicKey) keyPair.getPublic());
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        assertThat(verifier.verify(signature)).isTrue();
    }

    @Test
    void authorizationHeaderUsesVapidSchemeWithTandKParameters() {
        KeyPair keyPair = EcKeys.generateP256(jca);
        VapidKeys keys = VapidKeys.of(
                EcKeys.encodeUncompressed((ECPublicKey) keyPair.getPublic()),
                TestVectors.scalar32((ECPrivateKey) keyPair.getPrivate()));
        LocalEcVapidSigner signer = new LocalEcVapidSigner(keys);

        String header =
                Vapid.authorizationHeader(signer, TestVectors.VAPID_AUDIENCE, TestVectors.VAPID_SUBJECT, EXPIRY);

        assertThat(header).startsWith("vapid t=").contains(", k=" + Base64Url.encode(signer.publicKey()));

        String token = header.substring("vapid t=".length(), header.indexOf(", k="));
        assertThat(token.split("\\.")).as("t is a compact JWT").hasSize(3);
    }
}
