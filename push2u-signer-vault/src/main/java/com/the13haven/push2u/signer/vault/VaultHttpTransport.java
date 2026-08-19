/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import java.net.URI;
import java.util.Map;

import com.the13haven.push2u.PushCryptoException;
import com.the13haven.push2u.VapidSignerUnavailableException;

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
 * implementation (OkHttp, Apache HttpClient 5, ...) by implementing this interface.
 *
 * <p><b>Vault answering — any status — is a {@link VaultHttpResponse}</b>, never an exception: classifying a status is
 * the signer's job, not the transport's. The response carries the retry hint where Vault declared one
 * ({@link VaultHttpResponse#retryAfter()}) — it arrives as a response header, and a header stops at the transport
 * unless the transport hands it on, so an implementation that drops it starves the one component able to act on it.
 *
 * <p><b>What throws is an exchange that failed</b>, and it throws in two types, split by whether the failure recurs:
 *
 * <ul>
 *   <li>{@link VapidSignerUnavailableException} for an exchange that produced no response — no connection, a failed TLS
 *       handshake, a timeout, a connection dropped mid-body, an interrupted wait. Nothing about such a failure says it
 *       will happen again: an address with a typo and a Vault that is down for an hour arrive here identically, and the
 *       honest report for both is a custodian that cannot be reached now. That an answer had begun to arrive changes
 *       nothing — begun is not answered.
 *   <li>{@link PushCryptoException} for a failure that is this configuration's own and recurs on every attempt whatever
 *       Vault's health: a request URI that cannot back an HTTP request, a request header carrying a character illegal
 *       in an HTTP field value (a token sourced from a file or a YAML block scalar commonly ends with a newline), and a
 *       response over the implementation's own size cap — that bound is this library's, so a response over it is over
 *       it again next time.
 * </ul>
 *
 * <p><b>An implementation is never asked to recognise an interruption</b> — telling an interrupted exchange apart from
 * any other unanswered one is the caller's job. What it owes is the two things any code catching an
 * {@link InterruptedException} owes: re-set the interrupt status on its own thread, and keep that exception in the
 * cause chain of what it raises. An interruption swallowed without the flag is the one thing that would leave whoever
 * supervises the call unable to see a cancellation.
 *
 * <p>Implementations must enforce a response-size cap and a per-request timeout, must not follow redirects (a redirect,
 * 3xx like any other status, is returned to the caller — following it would replay the request headers,
 * {@code X-Vault-Token} included, against whatever host the {@code Location} names, which for a hijacked or
 * mis-resolved Vault address is an attacker), and must never echo request headers (the Vault token travels in
 * {@code X-Vault-Token}) into exception messages.
 *
 * <p><b>Implementations must be thread-safe.</b> The transport is held by a signer, which is held by a
 * {@code PushSender} shared across threads: with asynchronous sending, concurrent {@link #post} calls are the normal
 * case. Per-request state belongs in the call rather than in a field.
 */
public interface VaultHttpTransport {

    /**
     * GET {@code uri} with the given request headers and return the buffered response.
     *
     * @param uri the Vault API URI to GET
     * @param headers the request headers ({@code X-Vault-Token}, ...)
     * @return the response status, UTF-8 body and retry hint (never an exception for an HTTP error status)
     * @throws VapidSignerUnavailableException if the exchange produced no response — no connection, a failed handshake,
     *     a timeout, an interrupted wait (the interrupt status then re-set, the {@code InterruptedException} kept in
     *     the cause chain)
     * @throws PushCryptoException on a failure that recurs whatever Vault's health — an unusable request URI, an
     *     illegal request header, a response over the size cap
     */
    VaultHttpResponse get(URI uri, Map<String, String> headers);

    /**
     * POST {@code body} to {@code uri} with the given request headers and return the buffered response.
     *
     * @param uri the Vault API URI to POST to
     * @param headers the request headers ({@code X-Vault-Token}, ...)
     * @param body the request body (Vault's request JSON, UTF-8 encoded)
     * @return the response status, UTF-8 body and retry hint (never an exception for an HTTP error status)
     * @throws VapidSignerUnavailableException if the exchange produced no response — no connection, a failed handshake,
     *     a timeout, an interrupted wait (the interrupt status then re-set, the {@code InterruptedException} kept in
     *     the cause chain)
     * @throws PushCryptoException on a failure that recurs whatever Vault's health — an unusable request URI, an
     *     illegal request header, a response over the size cap
     */
    VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body);
}
