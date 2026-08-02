package io.push2u;

import java.security.interfaces.ECPrivateKey;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Published conformance vectors used across the crypto tests, transcribed verbatim from the RFCs (whitespace removed).
 * Decoding these against the production code is what makes the tests <em>conformance</em> checks rather than
 * tautologies.
 */
final class TestVectors {

    private TestVectors() {}

    // ---- RFC 8291 §5 + Appendix A — the Web Push encryption worked example -------------------
    static final String AS_PUBLIC =
            "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
    static final String AS_PRIVATE = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
    static final String UA_PUBLIC =
            "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
    static final String UA_PRIVATE = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94";
    static final String SALT = "DGv6ra1nlYgDCS1FRnbzlw";
    static final String AUTH_SECRET = "BTBZMqHH6r4Tts7J_aSIgg";
    static final String PLAINTEXT = "When I grow up, I want to be a watermelon";

    static final String ECDH_SECRET = "kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs";
    static final String HEADER =
            "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
    static final String CIPHERTEXT = "8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ";

    // ---- RFC 8292 §2.4 — the VAPID worked example --------------------------------------------
    static final String VAPID_AUDIENCE = "https://push.example.net";
    static final String VAPID_SUBJECT = "mailto:push@example.com";
    static final long VAPID_EXP = 1453523768L;
    static final String VAPID_HEADER_B64 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9";
    static final String VAPID_CLAIMS_B64 =
            "eyJhdWQiOiJodHRwczovL3B1c2guZXhhbXBsZS5uZXQiLCJleHAiOjE0NTM1MjM3NjgsInN1YiI6Im1haWx0bzpwdXNoQGV4YW1wbGUuY29tIn0";
    static final String VAPID_SIGNATURE =
            "i3CYb7t4xfxCDquptFOepC9GAu_HLGkMlMuCGSK2rpiUfnK9ojFwDXb1JrErtmysazNjjvW2L9OkSSHzvoD1oA";
    static final String VAPID_PUBLIC_K =
            "BA1Hxzyi1RUM1b5wjxsn7nGxAszw2u61m164i3MrAIxHF6YK5h4SDYic-dRuU_RCPCfA5aq9ojSwk5Y2EmClBPs";
    static final String VAPID_JWK_X = "DUfHPKLVFQzVvnCPGyfucbECzPDa7rWbXriLcysAjEc";
    static final String VAPID_JWK_Y = "F6YK5h4SDYic-dRuU_RCPCfA5aq9ojSwk5Y2EmClBPs";

    static byte[] b64(String value) {
        return Base64.getUrlDecoder().decode(value);
    }

    static byte[] hex(String value) {
        return HexFormat.of().parseHex(value);
    }

    static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] out = new byte[length];
        int position = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, position, part.length);
            position += part.length;
        }
        return out;
    }

    /** Big-endian fixed 32-byte serialization of a P-256 private scalar (for building VapidKeys). */
    static byte[] scalar32(ECPrivateKey key) {
        byte[] bytes = key.getS().toByteArray();
        byte[] out = new byte[32];
        if (bytes.length == 32) {
            return bytes;
        }
        if (bytes.length > 32) {
            System.arraycopy(bytes, bytes.length - 32, out, 0, 32);
        } else {
            System.arraycopy(bytes, 0, out, 32 - bytes.length, bytes.length);
        }
        return out;
    }
}
