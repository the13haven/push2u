/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import java.net.URI;
import java.util.Map;

import com.the13haven.push2u.PushCryptoException;

/**
 * The HTTP transport seam for the Vault API — deliberately separate from push2u-core's {@code PushHttpClient}. The two
 * talk to opposite trust domains with opposite needs: push delivery POSTs to an untrusted capability URL and must never
 * buffer the response body, while the Vault API is an operator-configured service whose small JSON responses must be
 * read — both for the Transit {@code sign} POST and the {@code transit/keys/<name>} metadata GET (see <a
 * href="https://developer.hashicorp.com/vault/api-docs/secret/transit">Vault Transit API</a>). Routing both Vault calls
 * through one seam means an application's mTLS, proxy, or observability setup applies to the startup metadata read too,
 * not only to signing.
 *
 * <p>The default is {@link JdkVaultHttpTransport} over {@code java.net.http}; applications supply another
 * implementation (OkHttp, Apache HttpClient 5, ...) by implementing this interface. Implementations report Vault
 * <em>answering</em> — any status — as a {@link VaultHttpResponse}; only transport failures (no connection, timeout,
 * oversized response) throw. They must enforce a response-size cap and a per-request timeout, must not follow redirects
 * (a redirect, 3xx like any other status, is returned to the caller — following it would replay the request headers,
 * {@code X-Vault-Token} included, against whatever host the {@code Location} names, which for a hijacked or
 * mis-resolved Vault address is an attacker), and must never echo request headers (the Vault token travels in
 * {@code X-Vault-Token}) into exception messages.
 */
public interface VaultHttpTransport {

    /**
     * GET {@code uri} with the given request headers and return the buffered response.
     *
     * @param uri the Vault API URI to GET
     * @param headers the request headers ({@code X-Vault-Token}, ...)
     * @return the response status and UTF-8 body
     * @throws PushCryptoException on a transport failure (not on an HTTP error status)
     */
    VaultHttpResponse get(URI uri, Map<String, String> headers);

    /**
     * POST {@code body} to {@code uri} with the given request headers and return the buffered response.
     *
     * @param uri the Vault API URI to POST to
     * @param headers the request headers ({@code X-Vault-Token}, ...)
     * @param body the request body (Vault's request JSON, UTF-8 encoded)
     * @return the response status and UTF-8 body
     * @throws PushCryptoException on a transport failure (not on an HTTP error status)
     */
    VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body);
}
