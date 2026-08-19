/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static com.the13haven.push2u.TestVectors.b64;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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

    /**
     * The pair-returning form exists so a caller can file the header under the very key its {@code k} parameter carries
     * — one {@code publicKey()} read feeds both — which the token cache depends on: an entry filed under a key read
     * separately could be stored under an identity the wire does not carry, even against a signer whose answers vary
     * call to call.
     */
    @Test
    void signedAuthorizationHeaderReturnsTheKeyItsOwnHeaderCarries() {
        KeyPair keyPair = EcKeys.generateP256(jca);
        VapidKeys keys = VapidKeys.of(
                EcKeys.encodeUncompressed((ECPublicKey) keyPair.getPublic()),
                TestVectors.scalar32((ECPrivateKey) keyPair.getPrivate()));
        LocalEcVapidSigner signer = new LocalEcVapidSigner(keys);

        Vapid.SignedHeader signed =
                Vapid.signedAuthorizationHeader(signer, TestVectors.VAPID_AUDIENCE, TestVectors.VAPID_SUBJECT, EXPIRY);

        assertThat(signed.headerValue()).startsWith("vapid t=").endsWith(", k=" + signed.publicKeyBase64Url());
        assertThat(signed.publicKeyBase64Url())
                .as("the pair's key is the encoding of the advertised point — the same value k carries")
                .isEqualTo(Base64Url.encode(signer.publicKey()));
    }

    /** The header value is a bearer credential, so the pair's {@code toString} must redact it. */
    @Test
    void signedHeaderToStringRedactsTheBearerCredential() {
        KeyPair keyPair = EcKeys.generateP256(jca);
        VapidKeys keys = VapidKeys.of(
                EcKeys.encodeUncompressed((ECPublicKey) keyPair.getPublic()),
                TestVectors.scalar32((ECPrivateKey) keyPair.getPrivate()));
        LocalEcVapidSigner signer = new LocalEcVapidSigner(keys);

        Vapid.SignedHeader signed =
                Vapid.signedAuthorizationHeader(signer, TestVectors.VAPID_AUDIENCE, TestVectors.VAPID_SUBJECT, EXPIRY);
        String token = signed.headerValue()
                .substring("vapid t=".length(), signed.headerValue().indexOf(", k="));

        assertThat(signed.toString())
                .doesNotContain(token)
                .contains("<redacted>")
                .contains(signed.publicKeyBase64Url());
    }

    /**
     * The {@link VapidSigner} contract is checked where its output is used, because neither half fails visibly on its
     * own: a wrong-shaped signature or key still yields a syntactically valid {@code Authorization} header, and the
     * push service answers 401/403 to every send with nothing naming the signer. RFC 7518 §3.4 fixes the signature at
     * the raw 64-byte {@code r || s}; RFC 8292 §3.2 fixes the key at the 65-byte uncompressed point.
     */
    @Test
    void aSignatureOfTheWrongLengthIsRejectedBeforeItBecomesAJwt() {
        for (int length : new int[] {0, 63, 65, 71}) {
            assertThatThrownBy(() -> Vapid.jwt(
                            signerReturning(new byte[length], validPoint()),
                            TestVectors.VAPID_AUDIENCE,
                            TestVectors.VAPID_SUBJECT,
                            EXPIRY))
                    .as("%d-byte signature", length)
                    .isInstanceOf(PushCryptoException.class)
                    .hasMessageContaining("VapidSigner.sign returned " + length + " bytes")
                    .hasMessageContaining("RFC 7518");
        }
    }

    @Test
    void aDerSignatureSaysSoRatherThanJustCountingBytes() {
        // The mistake an implementation actually makes: JCA's SHA256withECDSA returns DER, and a
        // signer forwarding it unconverted looks right everywhere except on the wire. Counting the
        // bytes would be true but useless; naming DER points at the fix.
        byte[] der = new byte[71];
        der[0] = 0x30;

        assertThatThrownBy(() -> Vapid.jwt(
                        signerReturning(der, validPoint()),
                        TestVectors.VAPID_AUDIENCE,
                        TestVectors.VAPID_SUBJECT,
                        EXPIRY))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("looks DER-encoded")
                .hasMessageContaining("SHA256withECDSAinP1363Format");
    }

    @Test
    void aValidSignatureBeginningWith0x30IsNotMistakenForDer() {
        // 0x30 is a legal first byte of r, so the tag alone must not decide anything — the length
        // is what the contract fixes, and a 64-byte signature passes whatever it starts with.
        byte[] signature = new byte[64];
        signature[0] = 0x30;

        assertThatCode(() -> Vapid.jwt(
                        signerReturning(signature, validPoint()),
                        TestVectors.VAPID_AUDIENCE,
                        TestVectors.VAPID_SUBJECT,
                        EXPIRY))
                .doesNotThrowAnyException();
    }

    @Test
    void aPublicKeyOfTheWrongShapeIsRejected() {
        assertThatThrownBy(() -> Vapid.authorizationHeader(
                        signerReturning(new byte[64], new byte[64]),
                        TestVectors.VAPID_AUDIENCE,
                        TestVectors.VAPID_SUBJECT,
                        EXPIRY))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("VapidSigner.publicKey returned 64 bytes")
                .hasMessageContaining("RFC 8292");

        byte[] compressed = new byte[65];
        compressed[0] = 0x02;
        assertThatThrownBy(() -> Vapid.authorizationHeader(
                        signerReturning(new byte[64], compressed),
                        TestVectors.VAPID_AUDIENCE,
                        TestVectors.VAPID_SUBJECT,
                        EXPIRY))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("begins with 0x02")
                .hasMessageContaining("0x04");
    }

    @Test
    void anSpkiWrappedKeySaysSoRatherThanJustCountingBytes() {
        // The key half's counterpart to the DER case: ECPublicKey.getEncoded() returns a
        // SubjectPublicKeyInfo, 91 bytes for P-256 and also opening with 0x30, so a signer that
        // publishes getEncoded() directly gets told what it actually returned.
        byte[] spki = new byte[91];
        spki[0] = 0x30;

        assertThatThrownBy(() -> Vapid.authorizationHeader(
                        signerReturning(new byte[64], spki),
                        TestVectors.VAPID_AUDIENCE,
                        TestVectors.VAPID_SUBJECT,
                        EXPIRY))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("looks wrapped")
                .hasMessageContaining("SubjectPublicKeyInfo");
    }

    private static byte[] validPoint() {
        byte[] point = new byte[65];
        point[0] = 0x04;
        return point;
    }

    private static VapidSigner signerReturning(byte[] signature, byte[] publicKey) {
        return new VapidSigner() {
            @Override
            public byte[] sign(byte[] signingInput) {
                return signature;
            }

            @Override
            public byte[] publicKey() {
                return publicKey;
            }
        };
    }
}
