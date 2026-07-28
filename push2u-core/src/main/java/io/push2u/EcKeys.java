package io.push2u;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

/**
 * P-256 key import/export and ECDH, all through the JDK ({@link Jca}). Handles the two wire
 * forms Web Push uses: the X9.62 uncompressed point ({@code 0x04 || X || Y}, 65 bytes) for
 * public keys ({@code p256dh}, VAPID {@code k}) and the raw 32-byte scalar for the VAPID
 * private key.
 */
final class EcKeys {

    static final int UNCOMPRESSED_LENGTH = 65;
    static final int COORDINATE_LENGTH = 32;
    private static final byte UNCOMPRESSED_TAG = 0x04;

    private EcKeys() {
    }

    /** Parse a 65-byte uncompressed P-256 point into a public key. */
    static ECPublicKey decodeP256PublicKey(byte[] uncompressed, Jca jca) {
        if (uncompressed.length != UNCOMPRESSED_LENGTH || uncompressed[0] != UNCOMPRESSED_TAG) {
            throw new IllegalArgumentException(
                "Expected a 65-byte uncompressed P-256 point starting with 0x04");
        }
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(uncompressed, 1, 1 + COORDINATE_LENGTH));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(uncompressed, 1 + COORDINATE_LENGTH, UNCOMPRESSED_LENGTH));
        try {
            KeyFactory keyFactory = jca.ecKeyFactory();
            return (ECPublicKey) keyFactory.generatePublic(new ECPublicKeySpec(new ECPoint(x, y), jca.p256Parameters()));
        } catch (GeneralSecurityException e) {
            throw new PushCryptoException("Invalid P-256 public key", e);
        }
    }

    /** Build a private key from the raw 32-byte P-256 scalar {@code d}. */
    static ECPrivateKey decodeP256PrivateKey(byte[] scalar, Jca jca) {
        if (scalar.length != COORDINATE_LENGTH) {
            throw new IllegalArgumentException("Expected a 32-byte P-256 private scalar");
        }
        BigInteger s = new BigInteger(1, scalar);
        try {
            KeyFactory keyFactory = jca.ecKeyFactory();
            return (ECPrivateKey) keyFactory.generatePrivate(new ECPrivateKeySpec(s, jca.p256Parameters()));
        } catch (GeneralSecurityException e) {
            throw new PushCryptoException("Invalid P-256 private key", e);
        }
    }

    /** Encode a public key as the 65-byte X9.62 uncompressed point. */
    static byte[] encodeUncompressed(ECPublicKey key) {
        ECPoint point = key.getW();
        byte[] out = new byte[UNCOMPRESSED_LENGTH];
        out[0] = UNCOMPRESSED_TAG;
        writeFixed(point.getAffineX(), out, 1);
        writeFixed(point.getAffineY(), out, 1 + COORDINATE_LENGTH);
        return out;
    }

    /** Generate a fresh ephemeral P-256 key pair (the per-message application-server key). */
    static KeyPair generateP256(Jca jca) {
        try {
            KeyPairGenerator generator = jca.ecKeyPairGenerator();
            generator.initialize(new ECGenParameterSpec(Algorithms.SECP256R1));
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new PushCryptoException("P-256 key-pair generation failed", e);
        }
    }

    /** ECDH on P-256: the shared secret is the 32-byte X coordinate of the agreed point. */
    static byte[] ecdh(ECPrivateKey privateKey, ECPublicKey publicKey, Jca jca) {
        try {
            var agreement = jca.ecdh();
            agreement.init(privateKey);
            agreement.doPhase(publicKey, true);
            return agreement.generateSecret();
        } catch (GeneralSecurityException e) {
            throw new PushCryptoException("ECDH key agreement failed", e);
        }
    }

    /**
     * Big-endian, fixed 32-byte serialization of a coordinate. {@link BigInteger#toByteArray()}
     * can prepend a 0x00 sign byte (33 bytes) or omit leading zeros (&lt;32 bytes); normalise
     * both to exactly 32 bytes.
     */
    private static void writeFixed(BigInteger value, byte[] out, int offset) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == COORDINATE_LENGTH) {
            System.arraycopy(bytes, 0, out, offset, COORDINATE_LENGTH);
        } else if (bytes.length > COORDINATE_LENGTH) {
            System.arraycopy(bytes, bytes.length - COORDINATE_LENGTH, out, offset, COORDINATE_LENGTH);
        } else {
            System.arraycopy(bytes, 0, out, offset + (COORDINATE_LENGTH - bytes.length), bytes.length);
        }
    }
}
