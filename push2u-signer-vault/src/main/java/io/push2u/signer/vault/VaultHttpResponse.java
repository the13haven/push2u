package io.push2u.signer.vault;

import java.util.Objects;

/**
 * A Vault API response: the HTTP status code and the body decoded as UTF-8. Vault answers with
 * small JSON documents (<a href="https://developer.hashicorp.com/vault/api-docs">Vault HTTP API</a>),
 * so — unlike push delivery, where the body is hostile bulk and is discarded — the body is the
 * whole point here and is buffered, bounded by the transport's response-size limit.
 *
 * @param statusCode the HTTP status code
 * @param body       the response body decoded as UTF-8 (Vault's JSON; empty on a bodyless reply)
 */
public record VaultHttpResponse(int statusCode, String body) {

    /** Rejects a {@code null} body — a bodyless reply is the empty string, never {@code null}. */
    public VaultHttpResponse {
        Objects.requireNonNull(body, "body");
    }
}
