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

    /**
     * The default ceiling on the encrypted HTTP entity body, in bytes. RFC 8030 §7.2 lets a push service refuse
     * anything larger than 4096 octets of entity body, so that is what the library assumes by default. This is the one
     * configured size: the {@code rs} the header advertises is derived from it via {@link #maxPlaintextBytes} and
     * {@link #recordSizeForMaxPlaintext}, never configured on its own.
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
     * case. Both directions of the rule go through the pair {@link #maxPlaintextForRecordSize} /
     * {@link #recordSizeForMaxPlaintext} — this refusal at the moment of encryption, and the {@code rs}
     * {@link PushSender} derives once at build time — so one place decides the rule whichever way it is asked.
     *
     * <p>This guard stays although production always passes a derived {@code rs} that fits by construction:
     * {@code encrypt} is reachable directly, without the sender's pre-flight, and a direct caller can still hand it an
     * {@code rs} too small for its plaintext. The comparison runs in {@code long} because this method takes an
     * arbitrary {@code int}, and {@code int} arithmetic over values near {@link Integer#MAX_VALUE} would wrap and slip
     * past this guard, letting an unencryptable record through.
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
                            + recordSizeForMaxPlaintext(plaintextLength));
        }
    }

    /**
     * The largest plaintext one configuration carries: the configured ceiling on the encrypted entity body (RFC 8030
     * §7.2) less the fixed {@link #BODY_OVERHEAD}, clamped below at zero. One subtraction, deliberately: the record
     * size is derived from this maximum so that it can never be the bound that binds, and a {@code min} over the two
     * would be a branch no input can select, reading as a live guard. This is the number {@link PushSender} checks a
     * payload against before any cryptography or I/O — and reports when the payload does not fit — because plaintext
     * octets are the unit the caller can act in.
     *
     * <p>Takes the configured value rather than a payload so the boundaries near {@link Integer#MAX_VALUE} are testable
     * without allocating multi-gigabyte arrays. The subtraction runs in {@code long}, and the result is clamped below
     * at zero before it is narrowed back to {@code int}: the builder's own minimum (a body ceiling of at least 103)
     * keeps the operand non-negative on every real sender, but this method takes an arbitrary {@code int}, and a
     * negative {@code long} narrowed to {@code int} can wrap into a large positive maximum — the one failure a size
     * bound must never have. Zero is also the honest answer for such a configuration: no plaintext fits it.
     *
     * @param maxEncryptedBodyBytes the configured ceiling on the encrypted body
     * @return the largest plaintext length, in octets, that the ceiling permits; never negative
     */
    static int maxPlaintextBytes(int maxEncryptedBodyBytes) {
        return (int) Math.max(0, (long) maxEncryptedBodyBytes - BODY_OVERHEAD);
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

    /**
     * The same rule in the other direction, and the exact inverse of {@link #maxPlaintextForRecordSize}: the smallest
     * {@code rs} whose record carries a plaintext of {@code maxPlaintextBytes} — the sum RFC 8291 §4 names, plus the
     * one octet by which the rule requires {@code rs} to exceed it. The second addend is deliberately spelled
     * {@code RECORD_OVERHEAD + 1} and not {@link #MIN_RECORD_SIZE}: the two are the same 18 for different reasons,
     * since the minimum record size is this rule applied to an empty plaintext, and writing the constant here would tie
     * the derivation to an answer about a different question.
     *
     * <p>This is what {@link PushSender} derives its {@code rs} from, once, at build time, so that the advertised
     * record size declares exactly the plaintext capacity the sender is able to use. In {@code long} for the same
     * reason as its inverse — the sum for a plaintext near {@link Integer#MAX_VALUE} exceeds {@code int}, which is also
     * what lets {@link #checkRecordSize}'s diagnostic stay exact there.
     */
    static long recordSizeForMaxPlaintext(int maxPlaintextBytes) {
        return (long) maxPlaintextBytes + RECORD_OVERHEAD + 1;
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
