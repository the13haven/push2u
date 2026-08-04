/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;

import org.jspecify.annotations.Nullable;

import com.the13haven.push2u.PushCryptoException;

/**
 * The default {@link VaultHttpTransport}, over the JDK's {@code java.net.http.HttpClient} — no third-party HTTP stack.
 * Two hard guarantees on every request:
 *
 * <ul>
 *   <li><b>A per-request timeout</b> ({@link HttpRequest.Builder#timeout}). The client-level {@code connectTimeout}
 *       only bounds establishing the connection — a Vault that accepts the connection and then never answers would
 *       otherwise block the caller forever (in the fetched mode that caller is application startup).
 *   <li><b>A response-size cap, counted in raw bytes as they stream in.</b> A {@code Content-Length} above the cap
 *       fails before the body is read, but the streaming count is authoritative — the header may be absent (chunked) or
 *       lie. Exceeding the cap fails the whole request (fail-closed): a truncated body must never reach the caller,
 *       because a targeted JSON extractor could still find a complete-looking {@code data.signature} before the cut and
 *       treat a mangled response as valid.
 * </ul>
 *
 * <p>A third guarantee holds at construction: <b>the client must not follow redirects.</b> The JDK client re-sends
 * custom headers such as {@code X-Vault-Token} to the redirect target — including a cross-origin one — so a Vault
 * address that resolves to an attacker (DNS hijack, squatted typo host, compromised reverse proxy) could answer 307 and
 * receive the token. A supplied client whose {@link HttpClient#followRedirects()} is not
 * {@link HttpClient.Redirect#NEVER} is rejected; the default client is built that way.
 *
 * <p>Exception messages carry the HTTP method and the request URI without its query (a Vault query can name secrets)
 * and without its userinfo (credentials in the authority — {@code https://user:secret@vault:8200} — are secrets too),
 * and never any request header — the Vault token travels in {@code X-Vault-Token} and must not leak into logs. That
 * includes a header the JDK client itself refuses (e.g. a token with a trailing newline, illegal in an HTTP field
 * value): the client's {@code IllegalArgumentException} spells out the whole value, so it is reported as a
 * {@link PushCryptoException} without the value — and without the original as its cause, whose message would leak into
 * any logged stack trace just the same.
 */
public final class JdkVaultHttpTransport implements VaultHttpTransport {

    // The Vault signer starter restates these three in @DefaultValue literals (it cannot reference
    // module-private constants); keep VaultSignerProperties in step when any of them changes.
    private static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(30);
    /** 1 MiB — two orders of magnitude above any Transit sign/keys response, small enough to cap. */
    private static final int DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;

    private final HttpClient httpClient;
    private final Duration requestTimeout;
    private final int maxResponseBytes;

    /**
     * The defaults: a fresh {@link HttpClient} with a 10-second connect timeout and {@link HttpClient.Redirect#NEVER},
     * a 30-second per-request timeout, and a 1 MiB response-size cap. The redirect policy is set explicitly rather than
     * inherited: it is this class's own invariant, not a JDK default to rely on.
     */
    public JdkVaultHttpTransport() {
        this(
                HttpClient.newBuilder()
                        .connectTimeout(DEFAULT_CONNECT_TIMEOUT)
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .build(),
                DEFAULT_REQUEST_TIMEOUT,
                DEFAULT_MAX_RESPONSE_BYTES);
    }

    /**
     * Uses the given {@link HttpClient} (bring your own mTLS, proxy, or executor configuration) with the given
     * per-request timeout and response-size cap.
     *
     * @param httpClient the HTTP client to send requests with; must be built with {@link HttpClient.Redirect#NEVER}
     * @param requestTimeout the per-request timeout, applied to every request; must be positive
     * @param maxResponseBytes the response-size cap in raw bytes; must be positive
     * @throws IllegalArgumentException if the client follows redirects, or the timeout or the cap is not positive
     */
    public JdkVaultHttpTransport(HttpClient httpClient, Duration requestTimeout, int maxResponseBytes) {
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
        if (httpClient.followRedirects() != HttpClient.Redirect.NEVER) {
            // The JDK client re-sends custom headers — X-Vault-Token included — to a redirect
            // target, cross-origin ones too. Any Vault address that can be made to answer 3xx
            // (DNS hijack, squatted typo host, compromised reverse proxy) would then be handed
            // the live token, so a redirect-following client is a misconfiguration, not a choice.
            throw new IllegalArgumentException("httpClient must not follow redirects (followRedirects() is "
                    + httpClient.followRedirects() + "): the JDK client re-sends X-Vault-Token to the redirect"
                    + " target, handing the token to whatever host a redirecting Vault address names."
                    + " Build the client with followRedirects(HttpClient.Redirect.NEVER); if the redirect you"
                    + " relied on comes from a Vault HA standby, point the Vault address at the active node's"
                    + " api_addr (or a load balancer in front of it), or terminate the redirect in the proxy");
        }
        Objects.requireNonNull(requestTimeout, "requestTimeout");
        if (requestTimeout.isZero() || requestTimeout.isNegative()) {
            throw new IllegalArgumentException("requestTimeout must be positive, got " + requestTimeout);
        }
        if (maxResponseBytes <= 0) {
            throw new IllegalArgumentException("maxResponseBytes must be positive, got " + maxResponseBytes);
        }
        this.requestTimeout = requestTimeout;
        this.maxResponseBytes = maxResponseBytes;
    }

    @Override
    public VaultHttpResponse get(URI uri, Map<String, String> headers) {
        return execute("GET", uri, headers, HttpRequest.BodyPublishers.noBody());
    }

    @Override
    public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body) {
        Objects.requireNonNull(body, "body");
        return execute("POST", uri, headers, HttpRequest.BodyPublishers.ofByteArray(body));
    }

    // PreserveStackTrace: the two IllegalArgumentException conversions drop the cause on purpose —
    // the JDK's message spells out the rejected header value whole (the Vault token, for the
    // X-Vault-Token header this transport exists to carry) or the whole URI including any
    // userinfo, and a cause's message rides into every logged stack trace just like the top-level
    // one. Same reasoning as Endpoints.requireSecure in push2u-core.
    @SuppressWarnings("PMD.PreserveStackTrace")
    private VaultHttpResponse execute(
            String method, URI uri, Map<String, String> headers, HttpRequest.BodyPublisher bodyPublisher) {
        Objects.requireNonNull(uri, "uri");
        Objects.requireNonNull(headers, "headers");
        HttpRequest.Builder request;
        try {
            request = HttpRequest.newBuilder(uri).timeout(requestTimeout).method(method, bodyPublisher);
        } catch (IllegalArgumentException e) {
            // newBuilder rejects a URI without a usable http(s) scheme or host — as a raw
            // IllegalArgumentException, which would contradict this class's PushCryptoException
            // contract. Its message echoes the URI whole, userinfo included, so the original is
            // not attached as the cause either.
            throw new PushCryptoException(
                    "Vault request URI cannot back an HTTP request (scheme or authority is not usable): " + method + " "
                            + redacted(uri));
        }
        try {
            // Inside its own try on purpose — and ALONE in it: header() rejects a value carrying
            // a character illegal in an HTTP field with THE WHOLE VALUE in its message. Outside
            // a try, that exception (holding the Vault token, e.g. one that arrived with a
            // trailing newline from a file-sourced secret) would land verbatim in logs; in a try
            // shared with send(), a client-internal IllegalArgumentException would be relabelled
            // as a header problem and lose its own diagnostic.
            headers.forEach(request::header);
        } catch (IllegalArgumentException e) {
            // Deliberately NOT attached as the cause: the original's message spells out the
            // rejected header value, and a cause's message rides into every logged stack trace
            // just the same as the top-level one.
            throw new PushCryptoException("Vault request was not sent: a request header carries a character that"
                    + " is illegal in an HTTP header value (a token sourced from a file or a YAML block scalar"
                    + " commonly ends with a newline): " + method + " " + redacted(uri));
        }
        try {
            HttpResponse<byte[]> response = httpClient.send(request.build(), this::boundedBody);
            return new VaultHttpResponse(response.statusCode(), new String(response.body(), StandardCharsets.UTF_8));
        } catch (HttpTimeoutException e) {
            throw new PushCryptoException(
                    "Vault request timed out after " + requestTimeout + ": " + method + " " + redacted(uri), e);
        } catch (IOException e) {
            // The JDK client surfaces a body-subscriber failure wrapped in IOException — recover
            // the size-cap violation from the cause chain and report it as what it is, naming the
            // call (method + query-less URI) so operators can tell the sign POST from the keys GET.
            ResponseTooLargeException tooLarge = findTooLarge(e);
            if (tooLarge != null) {
                throw new PushCryptoException(tooLarge.getMessage() + ": " + method + " " + redacted(uri), e);
            }
            throw new PushCryptoException("Vault request failed: " + method + " " + redacted(uri), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new PushCryptoException("Interrupted while waiting for Vault: " + method + " " + redacted(uri), e);
        }
    }

    /**
     * The bounded body handler: rejects a declared {@code Content-Length} above the cap up front (before any body bytes
     * arrive) and counts raw streamed bytes regardless, because the header may be absent or wrong.
     */
    private HttpResponse.BodySubscriber<byte[]> boundedBody(HttpResponse.ResponseInfo responseInfo) {
        long declaredLength =
                responseInfo.headers().firstValueAsLong("Content-Length").orElse(-1L);
        return new BoundedByteArraySubscriber(maxResponseBytes, declaredLength);
    }

    /**
     * The request URI as rendered into exception messages: without query or fragment — a Vault query can name secrets;
     * the path may not — and without userinfo, because credentials smuggled into the authority (e.g.
     * {@code https://user:secret@vault:8200}, basic auth for a fronting proxy) are exactly as secret as a query and
     * would otherwise ride into every transport failure.
     */
    private static String redacted(URI uri) {
        String text = uri.toString();
        int cut = text.length();
        int query = text.indexOf('?');
        if (query >= 0) {
            cut = query;
        }
        int fragment = text.indexOf('#');
        if (fragment >= 0 && fragment < cut) {
            cut = fragment;
        }
        String stripped = text.substring(0, cut);
        // Userinfo sits between "//" and the last "@" of the authority (an "@" may legally recur
        // inside the userinfo itself, so the last one before the path is the delimiter).
        int authorityStart = stripped.indexOf("//");
        if (authorityStart >= 0) {
            int pathStart = stripped.indexOf('/', authorityStart + 2);
            int authorityEnd = pathStart >= 0 ? pathStart : stripped.length();
            int at = stripped.lastIndexOf('@', authorityEnd - 1);
            if (at > authorityStart) {
                stripped = stripped.substring(0, authorityStart + 2) + stripped.substring(at + 1);
            }
        }
        return stripped;
    }

    private static @Nullable ResponseTooLargeException findTooLarge(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof ResponseTooLargeException tooLarge) {
                return tooLarge;
            }
        }
        return null;
    }

    /** Marks a size-cap violation so it can be told apart from genuine I/O failures. */
    private static final class ResponseTooLargeException extends IOException {

        ResponseTooLargeException(int maxResponseBytes) {
            super("Vault response exceeded the configured limit of " + maxResponseBytes + " bytes");
        }
    }

    /**
     * Accumulates the response body while counting raw bytes, and fails the exchange the moment the count would pass
     * the cap — cancelling the subscription so the rest of the body is never pulled off the wire. Exactly-at-the-cap
     * responses succeed.
     */
    private static final class BoundedByteArraySubscriber implements HttpResponse.BodySubscriber<byte[]> {

        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        private final int maxBytes;
        private final long declaredLength;
        // Assigned in onSubscribe, per the Flow.Subscriber contract — null until then.
        private Flow.@Nullable Subscription subscription;

        private long received;

        BoundedByteArraySubscriber(int maxBytes, long declaredLength) {
            this.maxBytes = maxBytes;
            this.declaredLength = declaredLength;
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            // minimalCompletionStage, not the future itself: the caller is the HTTP client, which
            // only ever observes completion. Handing out the CompletableFuture would let it be
            // completed from outside, past the size accounting this subscriber exists to do.
            return result.minimalCompletionStage();
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            this.subscription = subscription;
            if (declaredLength > maxBytes) {
                // Early Content-Length check: fail before reading a body the server itself
                // declares oversized. The streaming count below still guards the actual bytes.
                subscription.cancel();
                result.completeExceptionally(new ResponseTooLargeException(maxBytes));
                return;
            }
            subscription.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(List<ByteBuffer> buffers) {
            // Flow.Subscriber guarantees onSubscribe runs first, so this is non-null in practice —
            // read once into a local so the guarantee is checked rather than assumed, and so a
            // publisher that breaks the contract fails here instead of dereferencing null.
            Flow.Subscription current = Objects.requireNonNull(subscription, "onNext before onSubscribe");
            for (ByteBuffer chunk : buffers) {
                int length = chunk.remaining();
                received += length;
                if (received > maxBytes) {
                    current.cancel();
                    result.completeExceptionally(new ResponseTooLargeException(maxBytes));
                    return;
                }
                byte[] bytes = new byte[length];
                chunk.get(bytes);
                buffer.write(bytes, 0, length);
            }
        }

        @Override
        public void onError(Throwable throwable) {
            result.completeExceptionally(throwable);
        }

        @Override
        public void onComplete() {
            result.complete(buffer.toByteArray());
        }
    }
}
