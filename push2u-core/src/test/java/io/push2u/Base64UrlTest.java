package io.push2u;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class Base64UrlTest {

    @Test
    void encodesWithoutPadding() {
        assertThat(Base64Url.encode(new byte[] {0})).isEqualTo("AA");
        assertThat(Base64Url.encode("f".getBytes(StandardCharsets.US_ASCII))).isEqualTo("Zg");
    }

    @Test
    void usesUrlSafeAlphabetNotStandard() {
        byte[] data = {(byte) 0xff, (byte) 0xff, (byte) 0xbf};
        String encoded = Base64Url.encode(data);
        assertThat(encoded).doesNotContain("+").doesNotContain("/");
    }

    @Test
    void roundTripsUrlSafeVectorWithDashAndUnderscore() {
        // The RFC 8291 user-agent public key exercises both '-' and '_' of the URL-safe alphabet.
        String vector = TestVectors.UA_PUBLIC;
        assertThat(Base64Url.encode(Base64Url.decode(vector))).isEqualTo(vector);
        assertThat(Base64Url.decode(vector)).hasSize(65);
    }

    @Test
    void decodesUnpaddedInput() {
        // 16-byte salt encodes to 22 unpadded chars; the decoder must accept the missing '=='.
        assertThat(Base64Url.decode(TestVectors.SALT)).hasSize(16);
    }
}
