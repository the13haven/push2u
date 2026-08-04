/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Structurally broken DER, which is what a signature from outside this process can be. The DER path exists for signers
 * that only emit DER — BouncyCastle FIPS locally, and Vault's transit engine over HTTP — so the bytes arrive from a
 * remote service or a provider this library does not control, and a truncated or hostile response must not be able to
 * walk the parser off the end of the array.
 *
 * <p>The cases follow the malformed-encoding classes Project Wycheproof enumerates for ECDSA: wrong tags, lengths that
 * disagree with the content, and truncation at each structural boundary.
 */
class EcdsaDerMalformedTest {

    @Test
    void nullIsRejectedAsMalformedRatherThanThrowingNullPointer() {
        assertThatThrownBy(() -> EcdsaDer.toP1363(null))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("too short");
    }

    @ParameterizedTest(name = "{1}")
    @CsvSource({
        "'', an empty array has no SEQUENCE header",
        "30, a bare SEQUENCE tag with no length byte",
    })
    void inputTooShortForASequenceHeaderIsRejected(String hex, String description) {
        assertThatThrownBy(() -> EcdsaDer.toP1363(HexBytes.of(hex)))
                .as(description)
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("too short");
    }

    @Test
    void aSecondElementThatIsNotAnIntegerIsRejected() {
        // SEQUENCE { INTEGER 0x01, OCTET STRING 0x01 } — valid DER, wrong shape for a signature.
        byte[] der = HexBytes.of("3006" + "020101" + "040101");

        assertThatThrownBy(() -> EcdsaDer.toP1363(der))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("expected an INTEGER tag");
    }

    @Test
    void anIntegerLengthReachingPastTheEndOfTheInputIsRejected() {
        // SEQUENCE says 6 bytes and delivers 6, but the second INTEGER claims 32 bytes of content and has 1.
        byte[] der = HexBytes.of("3006" + "020101" + "022001");

        assertThatThrownBy(() -> EcdsaDer.toP1363(der))
                .as("the length field is attacker-controlled; it must be checked against the buffer")
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("exceeds the input");
    }

    @Test
    void aTruncatedSecondIntegerHeaderIsRejected() {
        // SEQUENCE { INTEGER 0x01, 0x02 } — the second element's tag with no length byte after it.
        byte[] der = HexBytes.of("3004" + "020101" + "02");

        assertThatThrownBy(() -> EcdsaDer.toP1363(der))
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("missing INTEGER");
    }

    /** Tiny helper so the cases above read as the DER they are. */
    private static final class HexBytes {
        private HexBytes() {}

        static byte[] of(String hex) {
            return java.util.HexFormat.of().parseHex(hex);
        }
    }
}
