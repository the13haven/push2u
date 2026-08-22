/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import java.math.BigInteger;

/**
 * The one serialization rule every P-256 value in this kit depends on, kept in exactly one place: a non-negative value
 * below 2<sup>256</sup> as exactly 32 big-endian bytes.
 *
 * <p>{@link BigInteger#toByteArray()} answers the <em>minimal</em> two's-complement form, which is almost never 32
 * bytes: a value whose top bit is set gets a 33rd leading {@code 0x00} sign byte, and a value with leading zero bytes
 * comes back short. The sign byte must be dropped and a short value left-padded — each roughly a coin flip per
 * generated key, so a writer that got either case wrong would produce working values most of the time and unusable ones
 * on a schedule no test suite keeps. That failure shape is why both fixtures write through this single method instead
 * of each carrying a writer of its own.
 */
final class FixedWidth {

    /** P-256 coordinates and scalars serialize as exactly this many bytes. */
    private static final int LENGTH = 32;

    private FixedWidth() {}

    /**
     * Writes {@code value} as exactly 32 big-endian bytes: drops the leading sign byte a 33-byte minimal form carries,
     * left-pads a short one with zeros.
     *
     * @param value a non-negative value below 2<sup>256</sup> — a P-256 coordinate or scalar
     * @return a fresh 32-byte array
     */
    static byte[] of(BigInteger value) {
        byte[] minimal = value.toByteArray();
        byte[] fixed = new byte[LENGTH];
        int length = Math.min(minimal.length, LENGTH);
        System.arraycopy(minimal, minimal.length - length, fixed, LENGTH - length, length);
        return fixed;
    }
}
