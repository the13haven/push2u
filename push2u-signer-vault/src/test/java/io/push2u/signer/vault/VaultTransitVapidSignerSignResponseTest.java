package io.push2u.signer.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.push2u.PushCryptoException;
import io.push2u.PushHttpClient;
import io.push2u.PushResponse;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * {@link VaultTransitVapidSigner#sign} against synthetic Transit {@code sign} response bodies, via
 * a stub {@link PushHttpClient} — no Vault. Two properties a real dev-mode Vault never exercises:
 *
 * <ul>
 *   <li><b>Signature shape:</b> a decoded signature that is not the 64-byte ES256 {@code r || s}
 *       pair must fail loudly at the signer — otherwise the malformed blob rides into the VAPID JWT
 *       and surfaces only as an opaque push-service rejection, far from the cause.</li>
 *   <li><b>Anchored extraction:</b> the {@code signature} lookup must bind to the direct member of
 *       {@code data} — a string <em>value</em> that merely equals {@code "signature"}, or a
 *       lookalike member nested deeper, must never hijack it.</li>
 * </ul>
 */
class VaultTransitVapidSignerSignResponseTest {

    private static final String TOKEN = "s.push2u-test-vault-token";
    private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();

    /** An explicit-mode signer whose Vault always answers {@code responseBody} (HTTP 200). */
    private static VaultTransitVapidSigner signer(String responseBody) {
        byte[] publicKey = new byte[65];
        publicKey[0] = 0x04;
        PushHttpClient stub = (endpoint, headers, body) -> new PushResponse(200, Map.of(), responseBody);
        return new VaultTransitVapidSigner(
            URI.create("http://vault.test:8200"), "transit", "vapid", TOKEN, publicKey, stub);
    }

    private static byte[] sign(String responseBody) {
        return signer(responseBody).sign("probe".getBytes(StandardCharsets.UTF_8));
    }

    /** 64 distinguishable bytes standing in for a real {@code r || s} pair. */
    private static byte[] wellFormedSignature() {
        byte[] signature = new byte[64];
        for (int i = 0; i < signature.length; i++) {
            signature[i] = (byte) i;
        }
        return signature;
    }

    @Test
    void aWellFormedSignatureIsDecodedVerbatim() {
        byte[] expected = wellFormedSignature();
        String body = "{\"data\":{\"signature\":\"vault:v1:" + BASE64_URL.encodeToString(expected) + "\"}}";

        assertThat(sign(body)).isEqualTo(expected);
    }

    @Test
    void anEmptySignatureFailsLoudlyInsteadOfSigningTheJwtWithNothing() {
        // "vault:v1:" with nothing after the prefix decodes to zero bytes — historically that
        // zero-length "signature" went straight into the JWT.
        assertThatThrownBy(() -> sign("{\"data\":{\"signature\":\"vault:v1:\"}}"))
            .isInstanceOf(PushCryptoException.class)
            .hasMessageContaining("expected 64 bytes")
            .hasMessageContaining("got 0")
            .satisfies(e -> assertThat(e.getMessage())
                .as("the Vault token never leaks into the error message")
                .doesNotContain(TOKEN));
    }

    @Test
    void aWrongLengthSignatureFailsLoudly() {
        String truncated = BASE64_URL.encodeToString(new byte[32]);

        assertThatThrownBy(() -> sign("{\"data\":{\"signature\":\"vault:v1:" + truncated + "\"}}"))
            .isInstanceOf(PushCryptoException.class)
            .hasMessageContaining("expected 64 bytes")
            .hasMessageContaining("got 32")
            .satisfies(e -> assertThat(e.getMessage())
                .as("the Vault token never leaks into the error message")
                .doesNotContain(TOKEN));
    }

    @Test
    void garbageBase64FailsAsAPushCryptoExceptionNotARawDecoderError() {
        // The decoder's bare IllegalArgumentException must not escape the library — a corrupt
        // payload is a Vault-response failure and reports as such, without echoing the payload.
        assertThatThrownBy(() -> sign("{\"data\":{\"signature\":\"vault:v1:%%not-base64%%\"}}"))
            .isInstanceOf(PushCryptoException.class)
            .hasMessageContaining("not valid base64url")
            .satisfies(e -> assertThat(e.getMessage())
                .as("neither the Vault token nor the payload leaks into the error message")
                .doesNotContain(TOKEN)
                .doesNotContain("%%not-base64%%"));
    }

    @Test
    void stringValueEqualToSignatureDoesNotHijackTheLookup() {
        // A member whose string VALUE is "signature", then a member holding a well-formed impostor
        // — both BEFORE the real field. An unanchored search binds to the string value, takes the
        // next colon and returns the impostor. The lookup must bind to the direct member
        // "signature" of data and return the real signature.
        byte[] impostor = new byte[64];
        Arrays.fill(impostor, (byte) 0xFF);
        byte[] real = wellFormedSignature();
        String body = "{\"data\":{\"alias\":\"signature\","
            + "\"next\":\"vault:v9:" + BASE64_URL.encodeToString(impostor) + "\","
            + "\"signature\":\"vault:v1:" + BASE64_URL.encodeToString(real) + "\"}}";

        assertThat(sign(body)).isEqualTo(real);
    }

    @Test
    void signatureNestedDeeperThanDataIsNotADirectMember() {
        // The only "signature" sits inside a nested object of data, holding a well-formed value a
        // depth-blind search would happily return. It is not a direct member of data, so the
        // extraction must fail loudly instead.
        String nested = "{\"data\":{\"meta\":{\"signature\":\"vault:v1:"
            + BASE64_URL.encodeToString(wellFormedSignature()) + "\"}}}";

        assertThatThrownBy(() -> sign(nested))
            .isInstanceOf(PushCryptoException.class)
            .hasMessageContaining("no 'signature' field");
    }
}
