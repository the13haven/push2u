/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static com.the13haven.push2u.TestVectors.b64;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * Pins the full RFC 8291 / RFC 8188 encryption path against the §5 worked example via a byte-for-byte match of the
 * encrypted body (header || ciphertext). The body is a deterministic function of every derivation step, so this single
 * assertion exercises the whole ECDH → HKDF → AES-128-GCM composition; the building blocks are pinned in isolation by
 * HkdfTest (RFC 5869) and EcKeysTest (the §5 ecdh_secret).
 */
class WebPushEncryptorTest {

    private final Jca jca = Jca.platform();
    private final WebPushEncryptor encryptor = new WebPushEncryptor(jca);

    @Test
    void encryptsRfc8291Section5ExampleByteForByte() {
        byte[] plaintext = TestVectors.PLAINTEXT.getBytes(StandardCharsets.US_ASCII);

        byte[] body = encryptor.encrypt(
                b64(TestVectors.UA_PUBLIC),
                b64(TestVectors.AUTH_SECRET),
                plaintext,
                4096,
                EcKeys.decodeP256PrivateKey(b64(TestVectors.AS_PRIVATE), jca),
                EcKeys.decodeP256PublicKey(b64(TestVectors.AS_PUBLIC), jca),
                b64(TestVectors.SALT));

        // body = header || ciphertext (RFC 8291 §5); a byte-for-byte match pins the whole path.
        assertThat(body)
                .as("RFC 8291 §5 aes128gcm body")
                .isEqualTo(TestVectors.concat(b64(TestVectors.HEADER), b64(TestVectors.CIPHERTEXT)));
    }

    @Test
    void randomPathProducesWellFormedHeaderWithFreshSaltAndFreshEphemeralKeyPerMessage() {
        byte[] uaPublic = b64(TestVectors.UA_PUBLIC);
        byte[] auth = b64(TestVectors.AUTH_SECRET);
        byte[] plaintext = TestVectors.PLAINTEXT.getBytes(StandardCharsets.US_ASCII);

        // 4096 as an rs is just a caller's value here: the sender derives its own, and this test
        // exercises the encryptor's parameter directly.
        byte[] body = encryptor.encrypt(uaPublic, auth, plaintext, 4096);

        ByteBuffer header = ByteBuffer.wrap(body);
        byte[] salt = new byte[16];
        header.get(salt);
        int recordSize = header.getInt();
        int keyIdLength = header.get() & 0xff;
        byte[] keyId = new byte[keyIdLength];
        header.get(keyId);

        assertThat(recordSize).isEqualTo(4096);
        assertThat(keyIdLength).isEqualTo(65);
        assertThat(keyId[0]).as("keyid is an uncompressed point").isEqualTo((byte) 0x04);
        // header(86) + plaintext(41) + delimiter(1) + GCM tag(16)
        assertThat(body).hasSize(86 + plaintext.length + 1 + 16);

        // RFC 8291 §2: a fresh application-server key pair (and salt) per message. Comparing whole
        // bodies would also pass with a reused ephemeral key and only the salt changing, so the
        // salt and the keyid are compared separately.
        byte[] second = encryptor.encrypt(uaPublic, auth, plaintext, 4096);
        assertThat(Arrays.copyOfRange(second, 0, 16))
                .as("fresh salt per message")
                .isNotEqualTo(salt);
        assertThat(Arrays.copyOfRange(second, 21, 86))
                .as("fresh ephemeral application-server key per message (RFC 8291 §2)")
                .isNotEqualTo(keyId);
    }

    @Test
    void writesTheRequestedRecordSizeIntoTheHeaderWithoutPaddingUpToIt() {
        byte[] uaPublic = b64(TestVectors.UA_PUBLIC);
        byte[] auth = b64(TestVectors.AUTH_SECRET);
        byte[] plaintext = TestVectors.PLAINTEXT.getBytes(StandardCharsets.US_ASCII);
        int customRecordSize = 2048;

        byte[] body = encryptor.encrypt(uaPublic, auth, plaintext, customRecordSize);

        // rs is the 4-byte big-endian field right after the 16-byte salt (RFC 8188 header).
        assertThat(ByteBuffer.wrap(body, 16, Integer.BYTES).getInt()).isEqualTo(customRecordSize);
        // rs only advertises a maximum; we send a single minimal record, NOT zero-padded up to
        // rs (a receiver MAY ignore rs — RFC 8291 §4), so the body size is independent of it.
        assertThat(body).hasSize(86 + plaintext.length + 1 + 16);
    }

    @Test
    void rejectsRecordSizeTooSmallForPayload() {
        var asPrivate = EcKeys.decodeP256PrivateKey(b64(TestVectors.AS_PRIVATE), jca);
        var asPublic = EcKeys.decodeP256PublicKey(b64(TestVectors.AS_PUBLIC), jca);
        byte[] uaPublic = b64(TestVectors.UA_PUBLIC);
        byte[] auth = b64(TestVectors.AUTH_SECRET);
        byte[] salt = b64(TestVectors.SALT);
        byte[] plaintext = new byte[100];

        assertThatThrownBy(() -> encryptor.encrypt(uaPublic, auth, plaintext, 50, asPrivate, asPublic, salt))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void recordSizeMustExceedPlaintextPlusDelimiterPlusTagNotMerelyEqualIt() {
        byte[] uaPublic = b64(TestVectors.UA_PUBLIC);
        byte[] auth = b64(TestVectors.AUTH_SECRET);
        byte[] plaintext = new byte[100];

        // RFC 8291 §4: rs MUST be *greater than* plaintext(100) + delimiter(1) + tag(16) = 117.
        assertThatThrownBy(() -> encryptor.encrypt(uaPublic, auth, plaintext, 117))
                .as("rs equal to the sum violates the MUST")
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("strictly greater")
                .hasMessageContaining("RFC 8291 §4");

        assertThat(encryptor.encrypt(uaPublic, auth, plaintext, 118))
                .as("one octet more is the smallest legal rs")
                .hasSize(86 + plaintext.length + 1 + 16);
    }

    @Test
    void bodyOverheadIsTheFixedSingleRecordCostNotAMagicNumber() {
        byte[] body = encryptor.encrypt(b64(TestVectors.UA_PUBLIC), b64(TestVectors.AUTH_SECRET), new byte[0], 4096);

        // header(86) + delimiter(1) + tag(16); the 4096-byte body ceiling minus this is the
        // 3993-octet plaintext maximum RFC 8291 §4 derives.
        assertThat(WebPushEncryptor.HEADER_LENGTH).isEqualTo(86);
        assertThat(WebPushEncryptor.RECORD_OVERHEAD).isEqualTo(17);
        assertThat(WebPushEncryptor.BODY_OVERHEAD).isEqualTo(103);
        assertThat(WebPushEncryptor.MIN_RECORD_SIZE).as("RFC 8188 §2").isEqualTo(18);
        assertThat(body).as("an empty payload costs exactly the overhead").hasSize(WebPushEncryptor.BODY_OVERHEAD);
        assertThat(WebPushEncryptor.DEFAULT_MAX_ENCRYPTED_BODY_BYTES - WebPushEncryptor.BODY_OVERHEAD)
                .as("RFC 8291 §4: at most 3993 octets of plaintext")
                .isEqualTo(3993);
    }

    /**
     * The derivation of {@code rs} from the configured body ceiling, pinned across the whole range the builder admits —
     * including both ends. The derived {@code rs} is {@code maxEncryptedBodyBytes − 85} for every configuration, so the
     * last row is the one to check rather than read: it stays below {@code Integer.MAX_VALUE} by construction and must
     * not wrap.
     */
    @Test
    void derivedRecordSizeDeclaresExactlyThePlaintextCapacityAcrossTheWholeRange() {
        int[][] table = {
            // maxEncryptedBodyBytes, maximumPayloadBytes, derived rs
            {103, 0, 18}, // the minimum the builder accepts: an empty payload, and the smallest legal rs
            {2048, 1945, 1963},
            {4096, 3993, 4011}, // the default
            {8192, 8089, 8107},
            {Integer.MAX_VALUE, Integer.MAX_VALUE - 103, Integer.MAX_VALUE - 85},
        };
        for (int[] row : table) {
            int maximumPayload = WebPushEncryptor.maxPlaintextBytes(row[0]);
            assertThat(maximumPayload)
                    .as("maximum payload for a body ceiling of %d", row[0])
                    .isEqualTo(row[1]);
            assertThat(WebPushEncryptor.recordSizeForMaxPlaintext(maximumPayload))
                    .as("derived rs for a body ceiling of %d", row[0])
                    .isEqualTo(row[2]);
        }
        assertThat(WebPushEncryptor.recordSizeForMaxPlaintext(Integer.MAX_VALUE - 103))
                .as("the top of the range is 2147483562 and does not wrap")
                .isEqualTo(2147483562L)
                .isLessThan(Integer.MAX_VALUE);
    }

    /** The two directions are exact inverses: an rs derived for a maximum carries exactly that maximum, and no more. */
    @Test
    void derivedRecordSizeIsTheExactInverseOfTheRecordSizeRule() {
        byte[] uaPublic = b64(TestVectors.UA_PUBLIC);
        byte[] auth = b64(TestVectors.AUTH_SECRET);
        for (int maximumPayload : new int[] {0, 1, 1945, 3993}) {
            int rs = Math.toIntExact(WebPushEncryptor.recordSizeForMaxPlaintext(maximumPayload));

            assertThat(encryptor.encrypt(uaPublic, auth, new byte[maximumPayload], rs))
                    .as("the derived rs %d carries a plaintext of exactly %d octets", rs, maximumPayload)
                    .hasSize(WebPushEncryptor.BODY_OVERHEAD + maximumPayload);
            assertThatThrownBy(() -> encryptor.encrypt(uaPublic, auth, new byte[maximumPayload + 1], rs))
                    .as("and one octet more violates RFC 8291 §4 under it — the derivation is exact, not padded")
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }
}
