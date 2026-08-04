/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Plays the user agent: decrypts the production {@code aes128gcm} body with a receiver written from the RFCs alone —
 * HKDF hand-rolled on {@link Mac}, ECDH and point codecs on plain {@code java.security}, the info strings retyped from
 * RFC 8291 §3.4 — never the production {@link Hkdf}, {@link EcKeys} or the encryptor's constants. That independence is
 * the point: the §5 vector test pins one fixed-key example, and the random-path test only checks header shape, so a bug
 * that keeps encryption self-consistent for arbitrary keys (swapped CEK/nonce infos, key-info operands in the wrong
 * order, an AAD nobody agreed on) would decrypt fine against a receiver sharing the sender's code — and fail in every
 * real browser. Here a shared bug has nothing to cancel against.
 */
class WebPushEncryptorInteropTest {

    private final WebPushEncryptor encryptor = new WebPushEncryptor(Jca.platform());
    private final SecureRandom random = new SecureRandom();

    /**
     * Lengths straddle the AES block boundaries (15/16/17, 31/32/33) where an off-by-one in padding or a block-oriented
     * bug would first show, plus empty, one byte, and the largest plaintext the default body limit admits (3993 = 4096
     * − 103; the acceptance/rejection of that bound itself is PushSenderPayloadSizeTest's job).
     */
    @ParameterizedTest
    @ValueSource(ints = {0, 1, 15, 16, 17, 31, 32, 33, 3993})
    void anIndependentUserAgentRecoversExactlyThePlaintextPlusTheDelimiter(int length) throws Exception {
        KeyPair receiver = generateReceiverKeyPair();
        byte[] uaPublic = encodeUncompressed((ECPublicKey) receiver.getPublic());
        byte[] authSecret = new byte[16];
        random.nextBytes(authSecret);
        byte[] plaintext = new byte[length];
        for (int i = 0; i < length; i++) {
            plaintext[i] = (byte) i;
        }

        byte[] body = encryptor.encrypt(uaPublic, authSecret, plaintext, WebPushEncryptor.DEFAULT_RECORD_SIZE);

        // Decrypted with no AAD: RFC 8188 §2 feeds AES-GCM the record alone, so any additional
        // authenticated data on the sender side would fail this call in every user agent.
        byte[] recovered = decryptAsUserAgent(body, receiver, uaPublic, authSecret);

        // The delimiter value is the RFC's (0x02 marks the last record, RFC 8188 §2); the absence
        // of anything after it is this library's choice — the RFC permits 0x00 padding there, and
        // this encryptor sends none, so the record is exactly plaintext || 0x02.
        assertThat(recovered).as("plaintext || 0x02, no padding").hasSize(length + 1);
        assertThat(recovered[length]).as("last-record delimiter (RFC 8188 §2)").isEqualTo((byte) 0x02);
        assertThat(Arrays.copyOf(recovered, length)).as("recovered plaintext").isEqualTo(plaintext);
    }

    // ---- The receiver, from the RFCs alone (no production crypto classes below this line) ----

    /** RFC 8188 §2.1 + RFC 8291 §3.4: parse the header, agree the secret, derive CEK/NONCE, decrypt. */
    private static byte[] decryptAsUserAgent(byte[] body, KeyPair receiver, byte[] uaPublic, byte[] authSecret)
            throws GeneralSecurityException {
        // Header (RFC 8188 §2.1): salt(16) || rs(4, big-endian) || idlen(1) || keyid(idlen).
        ByteBuffer buffer = ByteBuffer.wrap(body);
        byte[] salt = new byte[16];
        buffer.get(salt);
        buffer.getInt(); // rs: advertises a maximum; a single record needs no reassembly, so it is not consulted.
        byte[] asPublic = new byte[buffer.get() & 0xff];
        buffer.get(asPublic);
        byte[] ciphertext = new byte[buffer.remaining()];
        buffer.get(ciphertext);

        // ECDH from the receiver's side: our private key against the sender's keyid.
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(receiver.getPrivate());
        agreement.doPhase(decodeUncompressed(asPublic), true);
        byte[] ecdhSecret = agreement.generateSecret();

        // RFC 8291 §3.4, with the info strings typed out from the RFC text.
        byte[] keyInfo = concat("WebPush: info\0".getBytes(StandardCharsets.US_ASCII), uaPublic, asPublic);
        byte[] ikm = hkdf(authSecret, ecdhSecret, keyInfo, 32);
        byte[] cek = hkdf(salt, ikm, "Content-Encoding: aes128gcm\0".getBytes(StandardCharsets.US_ASCII), 16);
        byte[] nonce = hkdf(salt, ikm, "Content-Encoding: nonce\0".getBytes(StandardCharsets.US_ASCII), 12);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(128, nonce));
        return cipher.doFinal(ciphertext);
    }

    /**
     * RFC 5869 over {@link Mac} directly: extract is one HMAC, and every expansion Web Push needs fits a single block,
     * so expand is {@code HMAC(PRK, info || 0x01)} truncated — no loop to accidentally share with production.
     */
    private static byte[] hkdf(byte[] salt, byte[] ikm, byte[] info, int length) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);

        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update(info);
        mac.update((byte) 0x01);
        return Arrays.copyOf(mac.doFinal(), length);
    }

    private static KeyPair generateReceiverKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static ECPublicKey decodeUncompressed(byte[] point) throws GeneralSecurityException {
        // A browser rejects a keyid that is not an X9.62 uncompressed point, so this receiver does too.
        if (point.length != 65 || point[0] != 0x04) {
            throw new InvalidKeySpecException("keyid is not a 65-byte uncompressed P-256 point");
        }
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(point, 1, 33));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(point, 33, 65));
        return (ECPublicKey)
                KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), p256Parameters()));
    }

    /** X9.62 uncompressed point: {@code 0x04 || X(32) || Y(32)}, coordinates left-padded to 32 bytes. */
    private static byte[] encodeUncompressed(ECPublicKey key) {
        byte[] out = new byte[65];
        out[0] = 0x04;
        writeCoordinate(key.getW().getAffineX(), out, 1);
        writeCoordinate(key.getW().getAffineY(), out, 33);
        return out;
    }

    private static void writeCoordinate(BigInteger value, byte[] out, int offset) {
        byte[] bytes = value.toByteArray(); // may carry a 0x00 sign byte or drop leading zeros
        int start = Math.max(0, bytes.length - 32);
        int copied = bytes.length - start;
        System.arraycopy(bytes, start, out, offset + (32 - copied), copied);
    }

    private static ECParameterSpec p256Parameters() throws GeneralSecurityException {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        return parameters.getParameterSpec(ECParameterSpec.class);
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
