package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * {@link Es256Verify} answers "is this raw {@code r || s} signature valid for this input and this advertised public
 * key" — true only for the genuine article, false (never an exception) for wrong-but-well-formed signatures, and a
 * clear split between input problems ({@link IllegalArgumentException}) and platform problems
 * ({@link PushCryptoException}). The DER-fallback verification path is pinned separately by the FIPS suite
 * ({@code BcFipsEs256VerifyTest}); the platform here resolves the raw P1363 name.
 */
class Es256VerifyTest {

    private static final byte[] SIGNING_INPUT = "push2u Es256Verify test input".getBytes(StandardCharsets.US_ASCII);

    private static VapidSigner signer;
    /** The public half of an unrelated pair, for the wrong-key case. */
    private static byte[] foreignPublicKey;

    @BeforeAll
    static void generateKeys() {
        signer = new LocalEcVapidSigner(PushTestSupport.generateVapidKeys());
        foreignPublicKey = PushTestSupport.generateVapidKeys().publicKey();
    }

    @Test
    void aGenuineSignatureVerifies() {
        byte[] signature = signer.sign(SIGNING_INPUT);

        assertThat(Es256Verify.verify(signer.publicKey(), SIGNING_INPUT, signature))
                .isTrue();
    }

    @Test
    void aSignatureOverDifferentInputDoesNotVerify() {
        byte[] signature = signer.sign(SIGNING_INPUT);

        assertThat(Es256Verify.verify(
                        signer.publicKey(), "some other input".getBytes(StandardCharsets.US_ASCII), signature))
                .isFalse();
    }

    @Test
    void aForeignPublicKeyDoesNotVerify() {
        byte[] signature = signer.sign(SIGNING_INPUT);

        assertThat(Es256Verify.verify(foreignPublicKey, SIGNING_INPUT, signature))
                .isFalse();
    }

    @Test
    void sixtyFourGarbageBytesAreInvalidNotAnError() {
        // The caller's question is "is this a valid signature" — for garbage of the right length
        // the answer is false, whether the provider reports it by returning false or by throwing
        // SignatureException on an out-of-range value.
        byte[] garbage = new byte[64];
        Arrays.fill(garbage, (byte) 0x42);

        assertThat(Es256Verify.verify(signer.publicKey(), SIGNING_INPUT, garbage))
                .isFalse();
    }

    @Test
    void anAllZeroSignatureIsInvalidNotAnError() {
        // r = s = 0 can never verify; some providers throw rather than return false — either way
        // the API answer is false.
        assertThat(Es256Verify.verify(signer.publicKey(), SIGNING_INPUT, new byte[64]))
                .isFalse();
    }

    @Test
    void rejectsAWrongLengthSignature() {
        assertThatThrownBy(() -> Es256Verify.verify(signer.publicKey(), SIGNING_INPUT, new byte[63]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("64-byte");
    }

    @Test
    void rejectsAMalformedPublicKey() {
        byte[] signature = signer.sign(SIGNING_INPUT);

        assertThatThrownBy(() -> Es256Verify.verify(new byte[10], SIGNING_INPUT, signature))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("uncompressed P-256 point");
    }

    @Test
    void theStockPlatformIsSupported() {
        assertThat(Es256Verify.isSupported()).isTrue();
    }

    @Test
    void aProviderWithoutEcdsaIsUnsupportedAndVerifyNamesTheGap() {
        // "Unsupported" is a platform-capability statement the caller can query up front; calling
        // verify anyway must fail naming the missing primitive, not whichever input-processing
        // step would have run first.
        Provider empty = new Provider("push2u-test-empty", "1.0", "registers no services") {};
        Jca jca = Jca.using(empty);
        byte[] signature = signer.sign(SIGNING_INPUT);

        assertThat(Es256Verify.isSupported(jca)).isFalse();
        assertThatThrownBy(() -> Es256Verify.verify(jca, signer.publicKey(), SIGNING_INPUT, signature))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("ES256");
    }
}
