/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.Optional;

import org.junit.jupiter.api.Test;

/**
 * {@link VaultHttpResponse}'s own guarantees: the two-argument constructor reports no hint (the ordinary case, and the
 * whole constructor for a transport that does not read the {@code Retry-After} header), and the hint's floor — a
 * negative delay reads to a scheduler as "repeat immediately" against a Vault that just declared it cannot serve, so a
 * transport passing one is refused at this boundary rather than believed. Beside those two, the printed form: it
 * describes the body rather than reproducing it, which is what keeps a transport's own logging from putting a whole
 * service answer, and the control characters in it, into a log line.
 */
class VaultHttpResponseTest {

    @Test
    void theTwoArgumentConstructorReportsNoHint() {
        assertThat(new VaultHttpResponse(200, "{}").retryAfter()).isEmpty();
    }

    @Test
    void aZeroHintIsLegalItDeclaresNow() {
        assertThat(new VaultHttpResponse(429, "{}", Optional.of(Duration.ZERO)).retryAfter())
                .contains(Duration.ZERO);
    }

    @Test
    void aNegativeHintIsRefusedAtTheBoundaryThatTookIt() {
        assertThatThrownBy(() -> new VaultHttpResponse(429, "{}", Optional.of(Duration.ofSeconds(-1))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("retryAfter must not be negative");
    }

    @Test
    void aNullBodyIsRefusedABodylessReplyIsTheEmptyString() {
        assertThatThrownBy(() -> new VaultHttpResponse(204, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("body");
    }

    @Test
    void toStringDescribesTheBodyWithoutReproducingIt() {
        // The record-generated toString() prints every component, and one of them is a whole
        // service answer of up to the transport's size limit — a megabyte on the supplied
        // transport. A sentinel stands for anything the answer might hold: another service's
        // error text, an internal path, a token echoed back in a message.
        String sentinel = "push2u-sentinel-8f21c0";
        String body = "{\"errors\":[\"" + sentinel + "\"]}";
        VaultHttpResponse response = new VaultHttpResponse(429, body, Optional.of(Duration.ofSeconds(2)));

        String printed = response.toString();

        assertThat(printed).doesNotContain(sentinel);
        assertThat(printed).contains("429").contains("PT2S").contains("<redacted, " + body.length() + " chars>");
    }

    @Test
    void toStringCarriesNoControlCharacterOutOfTheBody() {
        // Whatever answered on the Vault address chose the body, so it chooses the control
        // characters in it too. Describing the body rather than printing it keeps a carriage
        // return from forging a second log line here, the same way the signer's excerpt does
        // where the body genuinely has to be echoed.
        VaultHttpResponse response = new VaultHttpResponse(500, "denied\r\nINFO forged\u001B[31m\u0000");

        String printed = response.toString();

        assertThat(printed).doesNotContain("forged");
        assertThat(printed.codePoints().noneMatch(Character::isISOControl))
                .as("no control character leaves through toString()")
                .isTrue();
    }
}
