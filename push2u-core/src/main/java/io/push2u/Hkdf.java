package io.push2u;

import java.security.InvalidKeyException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HKDF (RFC 5869) over HMAC-SHA-256, hand-rolled in ~25 lines so the library keeps zero runtime
 * dependencies. It is deliberately NOT an extension point: the bytes are identical regardless of
 * implementation, and a pluggable seam here would fail silently as wrong ciphertext.
 *
 * <p>Pinned by the RFC 5869 Appendix A SHA-256 vectors (and again, end-to-end, by the RFC 8291
 * §5 worked example).
 */
final class Hkdf {

    private static final int HASH_LEN = 32;

    private final Jca jca;

    Hkdf(Jca jca) {
        this.jca = jca;
    }

    /**
     * HKDF-Extract: {@code PRK = HMAC-SHA-256(salt, IKM)}. An absent (null or empty) salt
     * defaults to {@code HashLen} zero octets per RFC 5869 §2.2 — which also sidesteps the JCE
     * "empty key" rejection for a zero-length salt while producing the identical PRK.
     */
    byte[] extract(byte[] salt, byte[] ikm) {
        byte[] key = (salt == null || salt.length == 0) ? new byte[HASH_LEN] : salt;
        return hmac(key, ikm);
    }

    /**
     * HKDF-Expand: {@code T(i) = HMAC-SHA-256(PRK, T(i-1) || info || i)}, output truncated to
     * {@code length}. Web Push only ever needs a single block (L ≤ 32), but the full loop keeps
     * this a faithful RFC 5869 implementation.
     */
    byte[] expand(byte[] prk, byte[] info, int length) {
        if (length < 0 || length > 255 * HASH_LEN) {
            throw new IllegalArgumentException("HKDF length out of range: " + length);
        }
        byte[] safeInfo = info == null ? new byte[0] : info;
        byte[] out = new byte[length];
        byte[] previous = new byte[0];
        int position = 0;
        int counter = 1;
        while (position < length) {
            Mac mac = initMac(prk);
            mac.update(previous);
            mac.update(safeInfo);
            mac.update((byte) counter);
            previous = mac.doFinal();
            int take = Math.min(HASH_LEN, length - position);
            System.arraycopy(previous, 0, out, position, take);
            position += take;
            counter++;
        }
        return out;
    }

    private byte[] hmac(byte[] key, byte[] data) {
        return initMac(key).doFinal(data);
    }

    private Mac initMac(byte[] key) {
        Mac mac = jca.hmacSha256();
        try {
            mac.init(new SecretKeySpec(key, Algorithms.HMAC_SHA256));
        } catch (InvalidKeyException e) {
            throw new PushCryptoException("HMAC-SHA-256 rejected the key", e);
        }
        return mac;
    }
}
