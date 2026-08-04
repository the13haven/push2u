/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * The VAPID claims JSON is handwritten, which puts the burden of correct escaping on {@code Vapid} itself. Both values
 * it interpolates are configuration a deployment supplies — {@code sub} is typically a {@code mailto:} from a config
 * file, {@code aud} is derived from the subscription endpoint — so a value carrying a quote must not be able to close
 * the string and append claims of its own. That is a JWT claim injection, and the signature would cover the forged
 * claims just as happily as the real ones.
 */
class VapidClaimEscapingTest {

    private static final Instant EXPIRY = Instant.ofEpochSecond(1453523768L);

    @Test
    void aQuoteInTheSubjectCannotCloseTheStringAndOpenANewClaim() {
        String hostile = "mailto:a@b.example\",\"exp\":9999999999,\"x\":\"";

        String json = claims("https://push.example.net", hostile);

        assertThat(json)
                .as("the quote is escaped, so the injected claims stay inside the sub value")
                .contains("\\\"")
                .doesNotContain("\"exp\":9999999999");
        assertThat(occurrences(json, "\"exp\":"))
                .as("exactly one exp claim survives")
                .isEqualTo(1);
    }

    @Test
    void aBackslashCannotEscapeTheClosingQuoteOfTheClaim() {
        // Unescaped, the trailing backslash would escape the closing quote and swallow the rest of the object.
        String json = claims("https://push.example.net", "mailto:a@b.example\\");

        assertThat(json).endsWith("\\\\\"}");
    }

    @ParameterizedTest(name = "{0} is escaped as {1}")
    @CsvSource({
        "'\n', '\\n'",
        "'\r', '\\r'",
        "'\t', '\\t'",
        "'\b', '\\b'",
        "'\f', '\\f'",
    })
    void theJsonControlEscapesAreUsedWhereJsonDefinesThem(String raw, String escaped) {
        String json = claims("https://push.example.net", "mailto:a" + raw + "b@example.com");

        assertThat(json).contains("mailto:a" + escaped + "b@example.com");
    }

    /**
     * JSON forbids raw control characters in strings, and only some of them have a short escape. The rest have to go
     * out as {@code \\u00xx} or the token is not parseable JSON at all — which a push service would reject as a
     * malformed JWT, with no hint as to why.
     */
    @Test
    void otherControlCharactersFallBackToTheUnicodeEscape() {
        String json = claims("https://push.example.net", "mailto:a\u0001\u001fb@example.com");

        assertThat(json).contains("\\u0001").contains("\\u001f").doesNotContain("\u0001");
    }

    @Test
    void ordinaryValuesAreNotMangled() {
        String json = claims("https://push.example.net", "mailto:push@example.com");

        assertThat(json)
                .isEqualTo("{\"aud\":\"https://push.example.net\",\"exp\":1453523768,"
                        + "\"sub\":\"mailto:push@example.com\"}");
    }

    /** Non-ASCII is legal in a JSON string and needs no escaping — but it must survive as UTF-8, not as '?'. */
    @Test
    void nonAsciiSurvivesAsUtf8() {
        byte[] json = Vapid.claimsJson("https://push.example.net", EXPIRY.getEpochSecond(), "mailto:tëst@example.com");

        assertThat(new String(json, StandardCharsets.UTF_8)).contains("tëst");
    }

    private static String claims(String audience, String subject) {
        return new String(Vapid.claimsJson(audience, EXPIRY.getEpochSecond(), subject), StandardCharsets.UTF_8);
    }

    private static int occurrences(String haystack, String needle) {
        int count = 0;
        for (int at = haystack.indexOf(needle); at >= 0; at = haystack.indexOf(needle, at + needle.length())) {
            count++;
        }
        return count;
    }
}
