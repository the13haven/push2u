/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

/**
 * A Vault API response: the HTTP status code, the body decoded as UTF-8, and the retry hint where Vault declared one.
 * Vault answers with small JSON documents (<a href="https://developer.hashicorp.com/vault/api-docs">Vault HTTP
 * API</a>), so — unlike push delivery, where the body is hostile bulk and is discarded — the body is the whole point
 * here and is buffered, bounded by the transport's response-size limit.
 *
 * <p><b>The retry hint crosses this record because nothing else can carry it.</b> It arrives as the {@code Retry-After}
 * response header, and a header stops at the transport unless the transport hands it on — which is why the record
 * carries the parsed hint and not the headers: a bag of headers from a service whose answers this library reads under a
 * size bound is more surface than one value is worth. The signer copies the hint into the exception it raises for a
 * Vault that cannot serve the request now, which is the only route by which the one component able to act on it — the
 * caller's scheduler — ever sees it. Empty is the ordinary case, not a surprise: Vault fills the header on a
 * rate-limited answer alone, and only where an operator enabled the rate-limit response headers, which are off by
 * default (<a href="https://developer.hashicorp.com/vault/docs/configuration#enable_rate_limit_response_headers">Vault
 * configuration</a>).
 *
 * <p>A transport that does not read the header — or a response that carries none — uses the two-argument constructor,
 * which reports no hint. The hint must never be negative: a delay pointing into the past reads to whoever schedules the
 * next attempt as "repeat immediately", which is a prompt to hammer a Vault that just said it cannot serve — so a
 * negative value is refused here, at the boundary that took it, as the transport implementation defect it is. Zero is
 * legal; it declares "now".
 *
 * @param statusCode the HTTP status code
 * @param body the response body decoded as UTF-8 (Vault's JSON; empty on a bodyless reply)
 * @param retryAfter how long Vault declared it would be before it can serve again, parsed from the {@code Retry-After}
 *     response header; empty where the response carried none, which is the ordinary case
 */
public record VaultHttpResponse(int statusCode, String body, Optional<Duration> retryAfter) {

    /**
     * Rejects a {@code null} body — a bodyless reply is the empty string, never {@code null} — and a negative retry
     * hint, which would tell a scheduler to repeat immediately against a Vault that just declared it cannot serve.
     */
    public VaultHttpResponse {
        Objects.requireNonNull(body, "body");
        Objects.requireNonNull(retryAfter, "retryAfter");
        if (retryAfter.isPresent() && retryAfter.get().isNegative()) {
            throw new IllegalArgumentException(
                    "retryAfter must not be negative, got " + retryAfter.get() + " — a delay pointing into the past"
                            + " is not a declaration of anything; a response carrying no usable hint reports empty");
        }
    }

    /**
     * A response carrying no retry hint — the ordinary case, and the whole constructor for a transport that does not
     * read the {@code Retry-After} header.
     *
     * @param statusCode the HTTP status code
     * @param body the response body decoded as UTF-8 (Vault's JSON; empty on a bodyless reply)
     */
    public VaultHttpResponse(int statusCode, String body) {
        this(statusCode, body, Optional.empty());
    }
}
