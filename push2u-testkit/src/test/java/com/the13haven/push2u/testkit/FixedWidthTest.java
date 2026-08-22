/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * The shared fixed-width writer pinned on deterministic values — the complement to the fixtures' generate-until hunts.
 * The hunts prove the composed encodings end to end, but their kill of a mis-padded writer is probabilistic: a 32-byte
 * minimal form whose first byte is a {@code 0x00} sign byte satisfies a leading-zero predicate while being encoded
 * identically by a correct and a wrong-side-padding writer, so a hunt can end on that benign shape before a genuinely
 * short draw exposes the defect. These vectors leave no such escape: each boundary shape of
 * {@code BigInteger.toByteArray()} — the dropped sign byte, one and several bytes of left-padding, the exact-width form
 * — is asserted against its exact 32-byte expectation, so padding on the wrong side fails here on every run.
 */
final class FixedWidthTest {

    @Test
    void aValueWithItsHighBitSetLosesExactlyTheSignByte() {
        byte[] magnitude = new byte[32];
        Arrays.fill(magnitude, (byte) 0xAB);
        magnitude[0] = (byte) 0x80;

        // toByteArray() answers 33 bytes here: 0x00 sign byte + the 32 magnitude bytes.
        assertThat(FixedWidth.of(new BigInteger(1, magnitude))).isEqualTo(magnitude);
    }

    @Test
    void aValueOneByteShortIsLeftPaddedWithOneZero() {
        byte[] magnitude = new byte[31];
        Arrays.fill(magnitude, (byte) 0x7F);

        byte[] fixed = FixedWidth.of(new BigInteger(1, magnitude));

        byte[] expected = new byte[32];
        System.arraycopy(magnitude, 0, expected, 1, 31);
        assertThat(fixed).isEqualTo(expected);
        assertThat(fixed[0]).as("the padding goes on the left").isEqualTo((byte) 0);
        assertThat(fixed[31]).as("the value's last byte stays last").isEqualTo((byte) 0x7F);
    }

    @Test
    void aMuchShorterValueKeepsItsBytesAtTheTail() {
        byte[] fixed = FixedWidth.of(BigInteger.valueOf(0x0102));

        byte[] expected = new byte[32];
        expected[30] = 0x01;
        expected[31] = 0x02;
        assertThat(fixed).isEqualTo(expected);
    }

    @Test
    void oneIsThirtyOneZerosThenOne() {
        byte[] expected = new byte[32];
        expected[31] = 0x01;

        assertThat(FixedWidth.of(BigInteger.ONE)).isEqualTo(expected);
    }

    @Test
    void anExactWidthValueIsUnchanged() {
        byte[] magnitude = new byte[32];
        Arrays.fill(magnitude, (byte) 0x42);

        assertThat(FixedWidth.of(new BigInteger(1, magnitude))).isEqualTo(magnitude);
    }

    /**
     * The benign look-alike the hunts cannot tell apart from real padding: 32 minimal bytes whose first is a
     * {@code 0x00} sign byte (a value just under 2<sup>248</sup> with bit 247 set). Both a correct and a wrong-side
     * writer copy it verbatim — pinned so the shape's existence stays documented next to the vectors that do
     * discriminate.
     */
    @Test
    void aThirtyTwoByteMinimalFormWithALeadingSignByteIsCopiedVerbatim() {
        byte[] minimalForm = new byte[32];
        minimalForm[0] = 0x00;
        minimalForm[1] = (byte) 0x80;
        Arrays.fill(minimalForm, 2, 32, (byte) 0x11);

        assertThat(FixedWidth.of(new BigInteger(1, minimalForm))).isEqualTo(minimalForm);
    }
}
