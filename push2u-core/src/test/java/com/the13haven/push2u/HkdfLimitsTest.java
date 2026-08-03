package com.the13haven.push2u;

import static com.the13haven.push2u.TestVectors.hex;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/**
 * The edges of RFC 5869 §2.3 that the worked vectors do not reach: the {@code L <= 255 * HashLen} ceiling, an absent
 * {@code info}, and the multi-block boundary. Web Push itself never asks for more than one block, but {@link Hkdf} is
 * written as a faithful HKDF rather than as a two-call helper, and an implementation that silently truncates past 255
 * blocks would be wrong in a way no Web Push test would ever notice.
 */
class HkdfLimitsTest {

    private static final int HASH_LEN = 32;

    private final Hkdf hkdf = new Hkdf(Jca.platform());
    private final byte[] prk = hkdf.extract(hex("000102030405060708090a0b0c"), hex("0b".repeat(22)));

    @Test
    void theMaximumOutputLengthIsExactlyTwoHundredFiftyFiveBlocks() {
        int maximum = 255 * HASH_LEN;

        assertThat(hkdf.expand(prk, null, maximum)).hasSize(maximum);

        assertThatThrownBy(() -> hkdf.expand(prk, null, maximum + 1))
                .as("one octet past the ceiling: the counter would wrap and repeat keystream")
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("out of range");
    }

    @Test
    void aNegativeLengthIsRejectedRatherThanTreatedAsZero() {
        assertThatThrownBy(() -> hkdf.expand(prk, null, -1)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void zeroLengthYieldsAnEmptyKeyRatherThanAnError() {
        assertThat(hkdf.expand(prk, new byte[0], 0)).isEmpty();
    }

    /**
     * RFC 5869 §2.3 defines an absent {@code info} as a zero-length string, so both spellings have to agree — otherwise
     * a caller passing {@code null} would derive a different key from one passing an empty array.
     */
    @Test
    void anAbsentInfoIsTheSameAsAnEmptyInfo() {
        assertThat(hkdf.expand(prk, null, 42)).isEqualTo(hkdf.expand(prk, new byte[0], 42));
    }

    /** Same rule on the extract side (§2.2): an absent salt is HashLen zero octets, not an error. */
    @Test
    void anAbsentSaltIsTheSameAsAllZeroSalt() {
        byte[] ikm = hex("0b".repeat(22));

        assertThat(hkdf.extract(null, ikm))
                .isEqualTo(hkdf.extract(new byte[HASH_LEN], ikm))
                .isEqualTo(hkdf.extract(new byte[0], ikm));
    }

    /**
     * The block boundary: output longer than one hash is the first point at which the {@code T(i-1)} chaining and the
     * counter matter at all. RFC 5869 test case 1 asks for 42 octets — two blocks — so the prefix property below is
     * pinned against a vector rather than against the implementation itself.
     */
    @Test
    void aSingleBlockIsThePrefixOfALongerExpansion() {
        byte[] info = hex("f0f1f2f3f4f5f6f7f8f9");

        byte[] oneBlock = hkdf.expand(prk, info, HASH_LEN);
        byte[] twoBlocks = hkdf.expand(prk, info, 42);

        assertThat(java.util.Arrays.copyOf(twoBlocks, HASH_LEN)).isEqualTo(oneBlock);
        assertThat(twoBlocks)
                .isEqualTo(hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
    }
}
