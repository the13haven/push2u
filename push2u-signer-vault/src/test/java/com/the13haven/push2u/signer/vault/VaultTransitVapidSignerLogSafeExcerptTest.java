/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.the13haven.push2u.PushCryptoException;

/**
 * What a Vault answer may put into a log line. The body of a failed response is echoed into the exception message —
 * that echo is the whole diagnostic value of the failure — and the message travels on to whoever logs the throwable,
 * the Spring starter's health indicator among them. Whatever answered on the Vault address chose that body, so it is
 * attacker-controlled the moment anything sits between this process and Vault, and a carriage return in it would end
 * the log line and open a forged one below it.
 *
 * <p>These cases pin the escaping rather than the message wording: the excerpt must be one line, must carry no
 * character that steers a terminal, and must stay inside its bound <em>after</em> escaping, since an escape is six
 * characters where the original was one.
 *
 * <p>The characters under test are written as {@link Character#toString(int)} of their code point rather than as
 * literals, so that nothing here depends on an invisible byte surviving an editor.
 */
class VaultTransitVapidSignerLogSafeExcerptTest {

    /** The production cap. Kept as a literal because the constant it mirrors is private on purpose. */
    private static final int ECHO_LIMIT = 2048;

    /** {@code U+001B}, the escape that opens an ANSI sequence. */
    private static final String ESC = Character.toString(0x1B);

    /** {@code U+0085}, the next-line character: a C1 control, and a line terminator to readers that follow Unicode. */
    private static final String NEL = Character.toString(0x85);

    /** {@code U+2028} and {@code U+2029}: punctuation by category, line breaks by the Unicode rules. */
    private static final String LINE_SEPARATOR = Character.toString(0x2028);

    private static final String PARAGRAPH_SEPARATOR = Character.toString(0x2029);

    /** {@code U+0000}. */
    private static final String NUL = Character.toString(0);

    private static final String TOKEN = "s.push2u-test-vault-token";
    private static final URI VAULT = URI.create("https://vault.test:8200");

    @Test
    void aCarriageReturnAndLineFeedCannotForgeASecondLogLine() {
        // The forgery this prevents: a body ending the real line and opening one that reads like a
        // second entry from the application's own logger.
        assertThat(VaultTransitVapidSigner.logSafeExcerpt("error\r\nINFO forged"))
                .isEqualTo("error\\u000d\\u000aINFO forged");
    }

    @Test
    void anAnsiEscapeSequenceCannotSteerATerminal() {
        // A body read in a terminal would otherwise colour — or with a longer sequence, overwrite —
        // what an operator reads around it.
        assertThat(VaultTransitVapidSigner.logSafeExcerpt(ESC + "[31mforged")).isEqualTo("\\u001b[31mforged");
    }

    @Test
    void theNextLineCharacterIsEscapedAsWell() {
        // U+0085 is a C1 control character, so Character.isISOControl covers it — but it is also a
        // line terminator for readers that follow the Unicode rules (BufferedReader.readLine among
        // them), which makes it a line break in disguise rather than an exotic corner.
        assertThat(VaultTransitVapidSigner.logSafeExcerpt(NEL + "forged")).isEqualTo("\\u0085forged");
    }

    @Test
    void theUnicodeLineAndParagraphSeparatorsAreEscaped() {
        // Neither is a control character by category, so a control-character test alone would let
        // both through — and both end a line where the Unicode rules are honoured.
        assertThat(VaultTransitVapidSigner.logSafeExcerpt("a" + LINE_SEPARATOR + "b" + PARAGRAPH_SEPARATOR + "c"))
                .isEqualTo("a\\u2028b\\u2029c");
    }

    @Test
    void aNulAndATabAreEscaped() {
        assertThat(VaultTransitVapidSigner.logSafeExcerpt(NUL)).isEqualTo("\\u0000");
        assertThat(VaultTransitVapidSigner.logSafeExcerpt("a\tb")).isEqualTo("a\\u0009b");
    }

    @Test
    void ordinaryTextIsLeftExactlyAsItArrived() {
        // The escaping must not become a second content policy: a space is not a control character
        // and neither is the punctuation of a Vault error body or a non-ASCII character, so nothing
        // here changes — including leading whitespace, which is not trimmed away.
        for (String unchanged : new String[] {"", " ", " forged", "{\"errors\":[\"permission denied\"]}", "ключ 😀"}) {
            assertThat(VaultTransitVapidSigner.logSafeExcerpt(unchanged))
                    .as("[%s]", unchanged)
                    .isEqualTo(unchanged);
        }
    }

    @Test
    void aBodyWithinTheBoundIsNotMarkedAsTruncated() {
        String body = "A".repeat(1024);

        assertThat(VaultTransitVapidSigner.logSafeExcerpt(body)).isEqualTo(body);
    }

    @Test
    void theBoundHoldsAfterEscapingRatherThanBeforeIt() {
        // The failure this pins: capping the raw text and escaping afterwards would let a body of
        // control characters alone leave with six times the cap — 12k characters of escapes in the
        // very log line the cap exists to keep short.
        String allControl = NUL.repeat(4096);

        String excerpt = VaultTransitVapidSigner.logSafeExcerpt(allControl);

        assertThat(excerpt.length()).isLessThanOrEqualTo(ECHO_LIMIT);
        assertThat(excerpt).startsWith("\\u0000").endsWith("... [truncated, 4096 chars total]");
        assertThat(excerpt.codePoints().noneMatch(Character::isISOControl))
                .as("a truncated excerpt is still an escaped one")
                .isTrue();
    }

    @Test
    void aTruncatedExcerptNeverEndsInsideAnEscapeOrASurrogatePair() {
        // Two ways a cut could produce nonsense: half of an escape, or a lone high surrogate where
        // an astral character was. The excerpt is built one whole code point at a time, so neither
        // can happen — checked by feeding the cap bodies of exactly the two shapes at risk.
        String alternating = (ESC + "A").repeat(4096);
        String astral = "😀".repeat(4096);

        for (String body : new String[] {alternating, astral}) {
            String excerpt = VaultTransitVapidSigner.logSafeExcerpt(body);
            String content = excerpt.substring(0, excerpt.indexOf("... [truncated,"));

            assertThat(excerpt.length()).isLessThanOrEqualTo(ECHO_LIMIT);
            assertThat(Character.isHighSurrogate(content.charAt(content.length() - 1)))
                    .as("no leading half of a surrogate pair may be left behind")
                    .isFalse();
            assertThat(content.endsWith("\\") || content.endsWith("\\u"))
                    .as("no half of an escape may be left behind")
                    .isFalse();
        }
    }

    @Test
    void theMessageOfAFailedSignCarriesTheBodyOnOneLine() {
        // The production path the escaping exists for: a body chosen by whatever answered on the
        // Vault address, echoed into a message the caller hands to a logger.
        String hostile = "error\r\nINFO forged entry" + ESC + "[31m";

        assertThatThrownBy(() -> explicitSigner(new VaultHttpResponse(403, hostile))
                        .sign("probe".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(PushCryptoException.class)
                .satisfies(thrown -> {
                    String message = String.valueOf(thrown.getMessage());
                    assertThat(message)
                            .contains("HTTP 403")
                            .contains("error\\u000d\\u000aINFO forged entry\\u001b[31m");
                    assertThat(message.codePoints().noneMatch(Character::isISOControl))
                            .as("the message is one line")
                            .isTrue();
                });
    }

    // ---- fixtures ---------------------------------------------------------------------------------

    /** An explicit-mode signer whose Vault always answers {@code response} to a sign request. */
    private static VaultTransitVapidSigner explicitSigner(VaultHttpResponse response) {
        // The RFC 8291 §5 user-agent key: a genuine P-256 point, which the supplied mode validates.
        byte[] publicKey = Base64.getUrlDecoder()
                .decode("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4");
        return VaultTransitVapidSigner.builderWithSuppliedPublicKey(
                        VAULT, new TransitKeyName("vapid"), new VaultToken(TOKEN), publicKey)
                .mount("transit")
                .transport(new VaultHttpTransport() {
                    @Override
                    public VaultHttpResponse get(URI uri, Map<String, String> headers) {
                        throw new AssertionError("the explicit mode must never read key metadata");
                    }

                    @Override
                    public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body) {
                        return response;
                    }
                })
                .build();
    }
}
