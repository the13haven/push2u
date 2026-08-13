/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

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
 * The RFC 8291 / RFC 8188 message encryptor: turns a plaintext into an {@code aes128gcm} body for a given subscription.
 * This is deliberately concrete, not an extension point — there is no externalizable secret and a pluggable seam would
 * fail silently as wrong ciphertext.
 *
 * <p>Derivation (RFC 8291 §3.4), single record, sequence number zero:
 *
 * <pre>
 *   ecdh_secret = ECDH(as_private, ua_public)
 *   PRK_key     = HKDF-Extract(salt=auth_secret, IKM=ecdh_secret)
 *   IKM         = HKDF-Expand(PRK_key, "WebPush: info"||0x00||ua_public||as_public, 32)
 *   PRK         = HKDF-Extract(salt, IKM)
 *   CEK         = HKDF-Expand(PRK, "Content-Encoding: aes128gcm"||0x00, 16)
 *   NONCE       = HKDF-Expand(PRK, "Content-Encoding: nonce"||0x00, 12)
 *   body        = header(salt, rs, as_public) || AES-128-GCM(CEK, NONCE, plaintext||0x02)
 * </pre>
 *
 * Pinned end-to-end by the RFC 8291 §5 worked example and its Appendix A intermediates.
 */
final class WebPushEncryptor {

    static final int DEFAULT_RECORD_SIZE = 4096;

    /**
     * The default ceiling on the encrypted HTTP entity body, in bytes. RFC 8030 §7.2 lets a push service refuse
     * anything larger than 4096 octets of entity body, so that is what the library assumes by default.
     */
    static final int DEFAULT_MAX_ENCRYPTED_BODY_BYTES = 4096;

    /** The RFC 8188 content coding this encryptor produces — also the {@code Content-Encoding} header value. */
    static final String CONTENT_ENCODING = "aes128gcm";

    private static final int SALT_LENGTH = 16;
    private static final int CEK_LENGTH = 16;
    private static final int NONCE_LENGTH = 12;
    private static final int IKM_LENGTH = 32;
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_TAG_BYTES = 16;
    private static final byte PADDING_DELIMITER = 0x02;
    private static final int PADDING_DELIMITER_LENGTH = 1;
    private static final int KEY_ID_LENGTH_FIELD = 1;

    /**
     * The RFC 8188 §2 header this encryptor emits: {@code salt(16) || rs(4) || idlen(1) || keyid(65)} — 86 octets,
     * fixed because RFC 8291 §3.4 pins the {@code keyid} to the uncompressed application-server public key.
     */
    static final int HEADER_LENGTH = SALT_LENGTH + Integer.BYTES + KEY_ID_LENGTH_FIELD + EcKeys.UNCOMPRESSED_LENGTH;

    /**
     * What one record adds to its plaintext: the padding delimiter (1 octet) plus the AEAD_AES_128_GCM authentication
     * tag (16 octets) — the "sum" RFC 8291 §4 requires {@code rs} to exceed, minus the plaintext itself.
     */
    static final int RECORD_OVERHEAD = PADDING_DELIMITER_LENGTH + GCM_TAG_BYTES;

    /**
     * What the whole single-record body adds to its plaintext: header plus record overhead, 103 octets. With the RFC
     * 8030 §7.2 body ceiling of 4096 this leaves 3993 octets of plaintext — exactly the figure RFC 8291 §4 derives —
     * but the number is computed, never hard-coded, so it follows the body limit a caller configures.
     */
    static final int BODY_OVERHEAD = HEADER_LENGTH + RECORD_OVERHEAD;

    /**
     * The smallest legal {@code rs}. RFC 8188 §2 declares values smaller than 18 invalid, which is exactly the record
     * overhead plus the one octet by which {@code rs} must exceed it (RFC 8291 §4) for a zero-length plaintext.
     */
    static final int MIN_RECORD_SIZE = RECORD_OVERHEAD + 1;

    private static final byte[] KEY_INFO_PREFIX = "WebPush: info\0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] CEK_INFO =
            ("Content-Encoding: " + CONTENT_ENCODING + "\0").getBytes(StandardCharsets.US_ASCII);
    private static final byte[] NONCE_INFO = "Content-Encoding: nonce\0".getBytes(StandardCharsets.US_ASCII);

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
     * Encrypt for production: generate a fresh ephemeral application-server key pair and a random salt, returning just
     * the {@code aes128gcm} body.
     */
    byte[] encrypt(byte[] uaPublicKey, byte[] authSecret, byte[] plaintext, int recordSize) {
        KeyPair ephemeral = EcKeys.generateP256(jca);
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        // The casts cannot fail: generateP256 has already refused any pair whose halves are not
        // EC keys on the published NIST P-256 parameters.
        return encrypt(
                uaPublicKey,
                authSecret,
                plaintext,
                recordSize,
                (ECPrivateKey) ephemeral.getPrivate(),
                (ECPublicKey) ephemeral.getPublic(),
                salt);
    }

    /**
     * Deterministic core with the ephemeral application-server key halves and salt injected — the form the RFC 8291 §5
     * vectors exercise. In production the convenience overload above supplies a freshly generated pair and a random
     * salt; a test supplies the fixed RFC values to reproduce the worked example byte-for-byte. The halves are typed EC
     * parameters rather than a {@link KeyPair} so the compiler, not a runtime cast, guarantees what ECDH and the header
     * encoding need. Returns the {@code aes128gcm} body.
     */
    byte[] encrypt(
            byte[] uaPublicKey,
            byte[] authSecret,
            byte[] plaintext,
            int recordSize,
            ECPrivateKey applicationServerPrivateKey,
            ECPublicKey applicationServerPublicKey,
            byte[] salt) {
        checkRecordSize(plaintext.length, recordSize);

        ECPublicKey uaPublic = EcKeys.decodeP256PublicKey(uaPublicKey, jca);
        byte[] asPublicKey = EcKeys.encodeUncompressed(applicationServerPublicKey);

        byte[] ecdhSecret = EcKeys.ecdh(applicationServerPrivateKey, uaPublic, jca);
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

    /**
     * The RFC 8291 §4 rule, in one place: {@code rs} MUST be <em>greater than</em> the sum of the plaintext, the
     * padding delimiter (1 octet) and the authentication tag (16 octets). Equality is a violation, not the boundary
     * case. Both spellings of the rule go through {@link #maxPlaintextForRecordSize} — this refusal at the moment of
     * encryption, and the maximum {@link PushSender#send}'s pre-flight compares against — so one implementation decides
     * both.
     *
     * <p>The comparison runs in {@code long} because this method takes an arbitrary {@code int}: {@code encrypt} is
     * reachable directly, without the pre-flight that would otherwise bound the plaintext, and {@code int} arithmetic
     * over values near {@link Integer#MAX_VALUE} would wrap and slip past this guard, letting an unencryptable record
     * through.
     *
     * @param plaintextLength the plaintext length in octets
     * @param recordSize the {@code rs} the header would advertise
     */
    static void checkRecordSize(int plaintextLength, int recordSize) {
        if (plaintextLength > maxPlaintextForRecordSize(recordSize)) {
            long recordContentSize = (long) plaintextLength + RECORD_OVERHEAD;
            throw new IllegalArgumentException(
                    "recordSize " + recordSize + " is too small for a " + plaintextLength + "-byte payload: RFC 8291 §4"
                            + " requires rs to be strictly greater than plaintext (" + plaintextLength
                            + ") + padding delimiter (" + PADDING_DELIMITER_LENGTH + ") + authentication tag ("
                            + GCM_TAG_BYTES + ") = " + recordContentSize + "; raise recordSize to at least "
                            + (recordContentSize + 1));
        }
    }

    /**
     * The largest plaintext one configuration carries: the smaller of what the two independent size preconditions each
     * permit — the configured ceiling on the encrypted entity body (RFC 8030 §7.2) less the fixed
     * {@link #BODY_OVERHEAD}, and the RFC 8291 §4 record-size bound of {@link #maxPlaintextForRecordSize}. This is the
     * number {@link PushSender#send} checks a payload against before any cryptography or I/O, and the one it reports
     * when the payload does not fit, because plaintext octets are the unit the caller can act in.
     *
     * <p>Takes the two configured values rather than a payload so the boundaries near {@link Integer#MAX_VALUE} are
     * testable without allocating multi-gigabyte arrays. The subtractions run in {@code long}, and the result is
     * clamped below at zero before it is narrowed back to {@code int}: the builder's own minimums ({@code rs} at least
     * 18, the body ceiling at least 103) keep both operands non-negative on every real sender, but this method takes
     * arbitrary {@code int}s, and a negative {@code long} narrowed to {@code int} can wrap into a large positive
     * maximum — the one failure a size bound must never have. Zero is also the honest answer for such a configuration:
     * no plaintext fits it.
     *
     * @param recordSize the configured {@code rs}
     * @param maxEncryptedBodyBytes the configured ceiling on the encrypted body
     * @return the largest plaintext length, in octets, that both preconditions permit; never negative
     */
    static int maxPlaintextBytes(int recordSize, int maxEncryptedBodyBytes) {
        long fromBodyCeiling = (long) maxEncryptedBodyBytes - BODY_OVERHEAD;
        return (int) Math.max(0, Math.min(fromBodyCeiling, maxPlaintextForRecordSize(recordSize)));
    }

    /**
     * The record-size half of the rule, inverted into a maximum: RFC 8291 §4 requires {@code rs} to be strictly greater
     * than the plaintext plus {@link #RECORD_OVERHEAD}, so the largest plaintext a given {@code rs} carries is
     * {@code rs - RECORD_OVERHEAD - 1}. In {@code long} so that a caller-supplied {@code rs} near either {@code int}
     * extreme cannot wrap the subtraction.
     */
    private static long maxPlaintextForRecordSize(int recordSize) {
        return (long) recordSize - RECORD_OVERHEAD - 1;
    }

    private byte[] aesGcm(byte[] cek, byte[] nonce, byte[] plaintext) {
        try {
            Cipher cipher = jca.aesGcm();
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(cek, Algorithms.AES),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
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
        return ByteBuffer.allocate(SALT_LENGTH + Integer.BYTES + KEY_ID_LENGTH_FIELD + keyId.length)
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
