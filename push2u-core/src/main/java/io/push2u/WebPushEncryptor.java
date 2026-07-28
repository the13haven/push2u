package io.push2u;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The RFC 8291 / RFC 8188 message encryptor: turns a plaintext into an {@code aes128gcm} body
 * for a given subscription. This is deliberately concrete, not an extension point (DESIGN.md
 * §5.1) — there is no externalizable secret and a pluggable seam would fail silently as wrong
 * ciphertext.
 *
 * <p>Derivation (RFC 8291 §3.4), single record, sequence number zero:
 * <pre>
 *   ecdh_secret = ECDH(as_private, ua_public)
 *   PRK_key     = HKDF-Extract(salt=auth_secret, IKM=ecdh_secret)
 *   IKM         = HKDF-Expand(PRK_key, "WebPush: info"||0x00||ua_public||as_public, 32)
 *   PRK         = HKDF-Extract(salt, IKM)
 *   CEK         = HKDF-Expand(PRK, "Content-Encoding: aes128gcm"||0x00, 16)
 *   NONCE       = HKDF-Expand(PRK, "Content-Encoding: nonce"||0x00, 12)
 *   body        = header(salt, rs, as_public) || AES-128-GCM(CEK, NONCE, plaintext||0x02)
 * </pre>
 * Pinned end-to-end by the RFC 8291 §5 worked example and its Appendix A intermediates.
 */
final class WebPushEncryptor {

    static final int DEFAULT_RECORD_SIZE = 4096;

    /** The RFC 8188 content coding this encryptor produces — also the {@code Content-Encoding} header value. */
    static final String CONTENT_ENCODING = "aes128gcm";

    private static final int SALT_LENGTH = 16;
    private static final int CEK_LENGTH = 16;
    private static final int NONCE_LENGTH = 12;
    private static final int IKM_LENGTH = 32;
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_TAG_BYTES = 16;
    private static final byte PADDING_DELIMITER = 0x02;

    private static final byte[] KEY_INFO_PREFIX =
        "WebPush: info\0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] CEK_INFO =
        ("Content-Encoding: " + CONTENT_ENCODING + "\0").getBytes(StandardCharsets.US_ASCII);
    private static final byte[] NONCE_INFO =
        "Content-Encoding: nonce\0".getBytes(StandardCharsets.US_ASCII);

    private final Jca jca;
    private final Hkdf hkdf;
    private final SecureRandom random;

    WebPushEncryptor(Jca jca) {
        this(jca, new SecureRandom());
    }

    WebPushEncryptor(Jca jca, SecureRandom random) {
        this.jca = jca;
        this.hkdf = new Hkdf(jca);
        this.random = random;
    }

    /**
     * Encrypt for production: generate a fresh ephemeral application-server key pair and a
     * random salt, returning just the {@code aes128gcm} body.
     */
    byte[] encrypt(byte[] uaPublicKey, byte[] authSecret, byte[] plaintext, int recordSize) {
        KeyPair ephemeral = EcKeys.generateP256(jca);
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        return encrypt(uaPublicKey, authSecret, plaintext, recordSize, ephemeral, salt);
    }

    /**
     * Deterministic core with the ephemeral application-server key pair and salt injected — the
     * form the RFC 8291 §5 vectors exercise. In production the convenience overload above supplies
     * a random pair and salt; a test supplies the fixed RFC values to reproduce the worked example
     * byte-for-byte. Returns the {@code aes128gcm} body.
     */
    byte[] encrypt(byte[] uaPublicKey, byte[] authSecret, byte[] plaintext, int recordSize,
                   KeyPair applicationServerKeyPair, byte[] salt) {
        int minimumRecordSize = plaintext.length + 1 + GCM_TAG_BYTES;
        if (recordSize < minimumRecordSize) {
            throw new IllegalArgumentException(
                "recordSize " + recordSize + " must exceed plaintext + delimiter + tag (" + minimumRecordSize + ")");
        }

        ECPublicKey uaPublic = EcKeys.decodeP256PublicKey(uaPublicKey, jca);
        ECPrivateKey asPrivate = (ECPrivateKey) applicationServerKeyPair.getPrivate();
        byte[] asPublicKey = EcKeys.encodeUncompressed((ECPublicKey) applicationServerKeyPair.getPublic());

        byte[] ecdhSecret = EcKeys.ecdh(asPrivate, uaPublic, jca);
        byte[] prkKey = hkdf.extract(authSecret, ecdhSecret);
        byte[] keyInfo = concat(KEY_INFO_PREFIX, uaPublicKey, asPublicKey);
        byte[] ikm = hkdf.expand(prkKey, keyInfo, IKM_LENGTH);
        byte[] prk = hkdf.extract(salt, ikm);
        byte[] cek = hkdf.expand(prk, CEK_INFO, CEK_LENGTH);
        byte[] nonce = hkdf.expand(prk, NONCE_INFO, NONCE_LENGTH);

        byte[] header = buildHeader(salt, recordSize, asPublicKey);
        byte[] ciphertext = aesGcm(cek, nonce, pad(plaintext));

        return concat(header, ciphertext);
    }

    private byte[] aesGcm(byte[] cek, byte[] nonce, byte[] plaintext) {
        try {
            Cipher cipher = jca.aesGcm();
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, Algorithms.AES), new GCMParameterSpec(GCM_TAG_BITS, nonce));
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new PushCryptoException("AES-128-GCM encryption failed", e);
        }
    }

    private static byte[] pad(byte[] plaintext) {
        byte[] padded = Arrays.copyOf(plaintext, plaintext.length + 1);
        padded[plaintext.length] = PADDING_DELIMITER;
        return padded;
    }

    /** RFC 8188 header: {@code salt(16) || rs(4, big-endian) || idlen(1) || keyid(idlen)}. */
    private static byte[] buildHeader(byte[] salt, int recordSize, byte[] keyId) {
        return ByteBuffer.allocate(SALT_LENGTH + Integer.BYTES + 1 + keyId.length)
            .put(salt)
            .putInt(recordSize)
            .put((byte) keyId.length)
            .put(keyId)
            .array();
    }

    private static byte[] concat(byte[]... parts) {
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
}
