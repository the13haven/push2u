/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 * Validation of the P-256 public key material Web Push carries on the wire — the 65-byte X9.62 uncompressed point that
 * arrives as a subscription's {@code p256dh} and is published as the VAPID {@code k} value. Two checks, of different
 * strength on purpose:
 *
 * <ul>
 *   <li>{@link #requireUncompressedPoint} is <b>structural</b>: 65 bytes opening with the {@code 0x04} uncompressed
 *       tag. It refuses a compressed point, a raw coordinate pair, or a truncated copy-paste — the wrong <em>shape</em>
 *       — but says nothing about the content. Enough where a stronger check follows elsewhere — the send pipeline's own
 *       decoder applies it first and then re-validates the point against the configured provider's parameters.
 *   <li>{@link #requireOnCurve} is the <b>full</b> check: structural, then both coordinates inside the P-256 prime
 *       field ({@code 0 <= x, y < p}) and the point satisfying the short Weierstrass equation {@code y² = x³ + ax + b
 *       (mod p)}. Only a value passing it can be a P-256 public key at all.
 * </ul>
 *
 * <p>The full check is what closes the key-material half of the boundary {@link Endpoints#requireSecure} closes for the
 * endpoint: a subscription's {@code p256dh} is attacker-supplied input (RFC 8291 §3.1 requires the user agent's key on
 * P-256, but nothing upstream enforces it), and {@link Subscription} applies {@link #requireOnCurve} in its
 * constructor, so a hostile off-curve point is refused where the subscription is accepted rather than surfacing as a
 * crypto failure on every later send. Both methods are public for the same reason {@code requireSecure} is: an
 * application can enforce the contract at its own registration boundary — reject the browser-posted key before
 * persisting it — instead of storing data every later send will refuse.
 *
 * <p>The curve arithmetic runs on the hard-coded P-256 domain parameters below and touches no JCA provider, so it works
 * wherever a {@code Subscription} is created — before and independently of any {@code PushSender} and whatever provider
 * it is configured with. That is sound because P-256 is a fixed named curve: every provider answering the
 * {@code secp256r1} lookup is obliged to hand back these exact values. It is deliberately <em>not</em> the same check
 * as the send pipeline's own: at decode time the point is re-validated against the parameters of the provider that will
 * run ECDH, which fails closed if that provider reports something other than P-256.
 *
 * <p>Rejection messages never quote coordinates — the value is attacker-reachable, and the failure is structural, so
 * the digits would only copy attacker-chosen bytes into logs. Lengths are quoted; a length is not content.
 */
public final class P256PublicKeys {

    /** X9.62 uncompressed-point length for P-256: the {@code 0x04} tag plus two 32-byte coordinates. */
    static final int UNCOMPRESSED_LENGTH = 65;
    /** P-256 field-element width in bytes. */
    static final int COORDINATE_LENGTH = 32;
    /** The X9.62 tag opening an uncompressed point. */
    static final byte UNCOMPRESSED_TAG = 0x04;

    /**
     * The NIST P-256 (secp256r1) prime field modulus {@code p = 2^256 − 2^224 + 2^192 + 2^96 − 1}, transcribed from
     * FIPS 186-4 §D.1.2.3 / SEC 2 v2.0 §2.4.2. Hard-coding the domain parameters is what lets the full check run
     * without a JCA provider; {@code P256PublicKeysTest} (and its BC-FIPS twin) verify each constant against what a
     * provider returns for {@code secp256r1}, so a transcription error cannot survive the build.
     */
    static final BigInteger P = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    /** The P-256 curve coefficient {@code a = p − 3} (FIPS 186-4 §D.1.2.3 / SEC 2 v2.0 §2.4.2). */
    static final BigInteger A = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
    /** The P-256 curve coefficient {@code b} (FIPS 186-4 §D.1.2.3 / SEC 2 v2.0 §2.4.2). */
    static final BigInteger B = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);

    private P256PublicKeys() {}

    /**
     * Requires {@code publicKey} to have the shape of an X9.62 uncompressed P-256 point: exactly 65 bytes, the first of
     * them the {@code 0x04} uncompressed tag. Structure only — the coordinates are not inspected, so a value passing
     * this check may still fail {@link #requireOnCurve}. Use the full check for any value an attacker can supply.
     *
     * @param publicKey the candidate public key bytes
     * @param name what the value is, used to open every rejection message (e.g. {@code "p256dh"})
     * @throws IllegalArgumentException if {@code publicKey} is not 65 bytes opening with {@code 0x04}; the message
     *     names {@code name} and never quotes the key bytes
     */
    public static void requireUncompressedPoint(byte[] publicKey, String name) {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(publicKey, name);
        if (publicKey.length != UNCOMPRESSED_LENGTH) {
            throw new IllegalArgumentException(name + " must be a 65-byte uncompressed P-256 point (0x04 prefix), got "
                    + publicKey.length + " bytes");
        }
        if (publicKey[0] != UNCOMPRESSED_TAG) {
            throw new IllegalArgumentException(name + " must be a 65-byte uncompressed P-256 point (0x04 prefix)");
        }
    }

    /**
     * Requires {@code publicKey} to encode a point on the NIST P-256 curve: the {@link #requireUncompressedPoint
     * structural} shape, both coordinates inside the prime field ({@code 0 <= x, y < p}) and the curve equation
     * {@code y² = x³ + ax + b (mod p)} satisfied. This is the check for attacker-reachable key material — a
     * subscription's {@code p256dh} above all, which {@link Subscription}'s constructor passes through here — and it
     * needs no JCA provider (the P-256 parameters are the fixed FIPS 186-4 values above), so it can run at an
     * application's registration boundary long before any {@code PushSender} exists.
     *
     * <p>All-zero coordinates get no special case: the X9.62 wire format cannot express the point at infinity in 65
     * bytes (it encodes infinity as a single {@code 0x00} byte, which already fails the structural check), so
     * {@code 0x04 || 0^32 || 0^32} is merely the affine point {@code (0, 0)} — off the curve like any other, because
     * P-256's {@code b} is non-zero.
     *
     * @param publicKey the candidate public key bytes
     * @param name what the value is, used to open every rejection message (e.g. {@code "p256dh"})
     * @throws IllegalArgumentException if {@code publicKey} is not a 65-byte uncompressed encoding of a point on P-256;
     *     the message names {@code name} and never quotes the coordinates
     */
    public static void requireOnCurve(byte[] publicKey, String name) {
        requireUncompressedPoint(publicKey, name);
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(publicKey, 1, 1 + COORDINATE_LENGTH));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(publicKey, 1 + COORDINATE_LENGTH, UNCOMPRESSED_LENGTH));
        if (x.compareTo(P) >= 0 || y.compareTo(P) >= 0) {
            throw new IllegalArgumentException(name + " has a coordinate outside the P-256 field (0 <= x, y < p), "
                    + "so it is not a point on the curve");
        }
        if (!satisfiesCurveEquation(x, y, P, A, B)) {
            throw new IllegalArgumentException(name + " does not satisfy the P-256 curve equation (y² = x³ + ax + b), "
                    + "so it is not a point on the curve");
        }
    }

    /**
     * Whether {@code (x, y)} satisfies the short Weierstrass equation {@code y² ≡ x³ + ax + b (mod p)}. The one
     * implementation of the equation in this module: the public check above runs it on the hard-coded P-256 parameters,
     * and {@code EcKeys} runs it on the configured provider's parameters before ECDH — same arithmetic, deliberately
     * different parameter source (see the class Javadoc). Callers ensure {@code 0 <= x, y < p} first; this method only
     * evaluates the equation.
     */
    static boolean satisfiesCurveEquation(BigInteger x, BigInteger y, BigInteger p, BigInteger a, BigInteger b) {
        BigInteger left = y.multiply(y).mod(p);
        BigInteger right = x.multiply(x).multiply(x).add(a.multiply(x)).add(b).mod(p);
        return left.equals(right);
    }
}
