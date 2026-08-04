/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.the13haven.push2u.PushCryptoException;

/**
 * {@link VaultTransitVapidSigner#sign} against synthetic Transit {@code sign} response bodies, via a stub
 * {@link VaultHttpTransport} — no Vault. Two properties a real dev-mode Vault never exercises:
 *
 * <ul>
 *   <li><b>Signature shape:</b> a decoded signature that is not the 64-byte ES256 {@code r || s} pair must fail loudly
 *       at the signer — otherwise the malformed blob rides into the VAPID JWT and surfaces only as an opaque
 *       push-service rejection, far from the cause.
 *   <li><b>Anchored extraction:</b> the {@code signature} lookup must bind to the direct member of {@code data} — a
 *       string <em>value</em> that merely equals {@code "signature"}, or a lookalike member nested deeper, must never
 *       hijack it.
 * </ul>
 */
class VaultTransitVapidSignerSignResponseTest {

    private static final String TOKEN = "s.push2u-test-vault-token";
    private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();

    /** An explicit-mode signer whose Vault always answers {@code responseBody} (HTTP 200). */
    private static VaultTransitVapidSigner signer(String responseBody) {
        byte[] publicKey = new byte[65];
        publicKey[0] = 0x04;
        VaultHttpTransport stub = new VaultHttpTransport() {
            @Override
            public VaultHttpResponse get(URI uri, Map<String, String> headers) {
                throw new AssertionError("the explicit mode must never read key metadata from Vault");
            }

            @Override
            public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body) {
                return new VaultHttpResponse(200, responseBody);
            }
        };
        return new VaultTransitVapidSigner(
                URI.create("http://vault.test:8200"), "transit", "vapid", TOKEN, publicKey, stub);
    }

    private static byte[] sign(String responseBody) {
        return signer(responseBody).sign("probe".getBytes(StandardCharsets.UTF_8));
    }

    /** An explicit-mode signer pinned to {@code keyVersion}, whose Vault always answers {@code responseBody}. */
    private static VaultTransitVapidSigner pinnedSigner(String responseBody, int keyVersion) {
        byte[] publicKey = new byte[65];
        publicKey[0] = 0x04;
        VaultHttpTransport stub = new VaultHttpTransport() {
            @Override
            public VaultHttpResponse get(URI uri, Map<String, String> headers) {
                throw new AssertionError("the explicit mode must never read key metadata from Vault");
            }

            @Override
            public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body) {
                return new VaultHttpResponse(200, responseBody);
            }
        };
        return new VaultTransitVapidSigner(
                URI.create("http://vault.test:8200"), "transit", "vapid", TOKEN, publicKey, keyVersion, stub);
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
    void theEnvelopeCheckAcceptsAMultiDigitKeyVersionAndPaddedBase64() {
        // Two shapes the previous last-colon strip accepted, which the envelope pattern must not
        // narrow away: a rotated key reaches double-digit versions, and while Vault's jws marshaling
        // emits unpadded base64url, Base64.getUrlDecoder() accepts padding and nothing in the Vault
        // contract forbids it.
        byte[] expected = wellFormedSignature();
        String padded = Base64.getUrlEncoder().encodeToString(expected);

        assertThat(sign("{\"data\":{\"signature\":\"vault:v42:" + BASE64_URL.encodeToString(expected) + "\"}}"))
                .isEqualTo(expected);
        assertThat(padded)
                .as("the padded form is what this test means to exercise")
                .endsWith("==");
        assertThat(sign("{\"data\":{\"signature\":\"vault:v1:" + padded + "\"}}"))
                .isEqualTo(expected);
    }

    @Test
    void aPinnedSignerRejectsAnEnvelopeFromAnotherKeyVersion() {
        // The version pin is the class's whole rotation-safety argument: the published VAPID
        // public key belongs to ONE Transit key version, and a signature from any other version
        // produces JWTs push services reject. A signer pinned to version 3 must therefore refuse
        // a vault:v99: envelope loudly, naming both versions — not silently accept it.
        String body =
                "{\"data\":{\"signature\":\"vault:v99:" + BASE64_URL.encodeToString(wellFormedSignature()) + "\"}}";

        assertThatThrownBy(() -> pinnedSigner(body, 3).sign("probe".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("key version 99")
                .hasMessageContaining("key version 3")
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain(TOKEN));
    }

    @Test
    void aPinnedSignerAcceptsTheEnvelopeOfItsOwnKeyVersion() {
        // The counterpart: the strictness must not reject the version the signer itself pinned
        // into the request.
        byte[] expected = wellFormedSignature();
        String body = "{\"data\":{\"signature\":\"vault:v3:" + BASE64_URL.encodeToString(expected) + "\"}}";

        assertThat(pinnedSigner(body, 3).sign("probe".getBytes(StandardCharsets.UTF_8)))
                .isEqualTo(expected);
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
    void aPayloadOutsideTheBase64UrlAlphabetIsRejectedOnTheEnvelopeShape() {
        // Characters outside the base64url alphabet mean the envelope is not a Transit signature at
        // all, which is caught before decoding — and reported without echoing the payload.
        assertThatThrownBy(() -> sign("{\"data\":{\"signature\":\"vault:v1:%%not-base64%%\"}}"))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("expected 'vault:v<version>:<base64url>'")
                .satisfies(e -> assertThat(e.getMessage())
                        .as("neither the Vault token nor the payload leaks into the error message")
                        .doesNotContain(TOKEN)
                        .doesNotContain("%%not-base64%%"));
    }

    @Test
    void aWellFormedEnvelopeWithAnUndecodablePayloadStillReportsAsADecodeFailure() {
        // Five base64url characters are alphabet-clean but not a whole number of quanta, so the
        // envelope check passes and the decoder's bare IllegalArgumentException must still be
        // converted rather than escaping the library.
        assertThatThrownBy(() -> sign("{\"data\":{\"signature\":\"vault:v1:AAAAA\"}}"))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("not valid base64url")
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain(TOKEN));
    }

    @Test
    void aValueThatIsNotATransitSignatureEnvelopeIsRejectedWholeNotCutAtItsLastColon() {
        // Cutting at the last colon hands whatever followed it to the base64url decoder: a Vault
        // error envelope, a wrapped token, a value from another API — none of them signatures. Each
        // of these tails is alphabet-clean and 64 bytes' worth, so a lastIndexOf(':') strip would
        // decode one and sign the VAPID JWT with it.
        String tail = BASE64_URL.encodeToString(wellFormedSignature());
        for (String value :
                new String[] {"vault:kv:" + tail, "hvs:v1:" + tail, "vault:v1:v2:" + tail, "wrapped:" + tail, tail}) {
            assertThatThrownBy(() -> sign("{\"data\":{\"signature\":\"" + value + "\"}}"))
                    .as("signature: %s", value)
                    .isInstanceOf(PushCryptoException.class)
                    .hasMessageContaining("expected 'vault:v<version>:<base64url>'");
        }
    }

    @Test
    void aHugeResponseBodyIsTruncatedWhenEchoedIntoTheErrorMessage() {
        // The default transport caps responses at 1 MiB, but a custom transport holds that cap
        // only by contract — the error echo must stay a log-safe size regardless.
        String filler = "x".repeat(100_000);

        assertThatThrownBy(() -> sign("{\"data\":{\"filler\":\"" + filler + "\"}}"))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("no 'signature' field")
                .hasMessageContaining("[truncated,")
                .satisfies(e -> assertThat(e.getMessage().length())
                        .as("the echoed body is cut to a few KB")
                        .isLessThan(4096));
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
