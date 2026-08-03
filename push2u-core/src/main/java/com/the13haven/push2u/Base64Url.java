package com.the13haven.push2u;

import java.util.Base64;

/**
 * URL-safe base64 without padding (RFC 4648 §5) — the encoding Web Push and JOSE use for the
 * {@code p256dh}/{@code auth} subscription values, VAPID keys, the JWT segments, and the encrypted body in examples.
 *
 * <p>The decoder tolerates input with or without trailing {@code =} padding, which is what the browser
 * {@code PushSubscription} JSON and the RFC example vectors provide.
 */
final class Base64Url {

    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private Base64Url() {}

    static String encode(byte[] data) {
        return ENCODER.encodeToString(data);
    }

    static byte[] decode(String value) {
        return DECODER.decode(value);
    }
}
