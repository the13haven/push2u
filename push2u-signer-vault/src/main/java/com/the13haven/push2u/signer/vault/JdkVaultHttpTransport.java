/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serial;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;

import org.jspecify.annotations.Nullable;

import com.the13haven.push2u.PushCryptoException;
import com.the13haven.push2u.VapidSignerUnavailableException;

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
 * <p>What this transport throws follows the seam's contract ({@link VaultHttpTransport}): an exchange that produced no
 * response — no connection, a failed handshake, a timeout, an interrupted wait — leaves as
 * {@link VapidSignerUnavailableException}, because nothing about such a failure says it will happen again; a failure
 * that is this configuration's own and recurs on every attempt whatever Vault's health — the unusable request URI, the
 * illegal request header, and this transport's own response-size cap — stays {@link PushCryptoException}. The
 * {@code Retry-After} header of every response is parsed here (Vault sends delta-seconds and nothing else) and handed
 * on through {@link VaultHttpResponse#retryAfter()}, which is the only way the hint survives past this seam.
 *
 * <p>Exception messages carry the HTTP method and a fail-closed rendering of the request URI: rebuilt from its parsed
 * components without its userinfo (credentials in the authority — {@code https://user:secret@vault:8200} — are secrets
 * too), or replaced whole by a fixed marker when the URI is not a plain {@code scheme://host} shape, carries a query or
 * fragment (a Vault query can name secrets), or carries {@code @} or {@code %} in its raw path (the tail of a
 * credential whose head parsed as {@code host:port}, literal or encoded). They never carry any request header — the
 * Vault token travels in {@code X-Vault-Token} and must not leak into logs. That includes a header the JDK client
 * itself refuses (e.g. a token with a trailing newline, illegal in an HTTP field value): the client's
 * {@code IllegalArgumentException} spells out the whole value, so it is reported as a {@link PushCryptoException}
 * without the value — and without the original as its cause, whose message would leak into any logged stack trace just
 * the same.
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
        // One line decides everything below: HttpClient.send declares IOException and
        // InterruptedException, and anything it throws means it returned no response — so what it
        // throws is an exchange with no answer, and leaves as the custodian-unavailable type. That
        // holds even where an answer had begun to arrive (a connection dropped mid-body, a Vault
        // that sent headers and then stalled into the request timeout): begun is not answered. The
        // single carve-out is this transport's own response-size cap, dug out of the cause chain
        // below — that bound is this library's, so a response over it is over it again on every
        // attempt whatever Vault's health, which is a recurring failure and stays the crypto
        // exception.
        try {
            HttpResponse<byte[]> response = httpClient.send(request.build(), this::boundedBody);
            return new VaultHttpResponse(
                    response.statusCode(),
                    new String(response.body(), StandardCharsets.UTF_8),
                    retryAfterHint(response.headers()));
        } catch (HttpTimeoutException e) {
            throw new VapidSignerUnavailableException(
                    "Vault request timed out after " + requestTimeout + ": " + method + " " + redacted(uri), e);
        } catch (IOException e) {
            // The JDK client surfaces a body-subscriber failure wrapped in IOException — recover
            // the size-cap violation from the cause chain and report it as what it is, naming the
            // call (method + redacted URI) so operators can tell the sign POST from the keys GET.
            ResponseTooLargeException tooLarge = findTooLarge(e);
            if (tooLarge != null) {
                throw new PushCryptoException(tooLarge.getMessage() + ": " + method + " " + redacted(uri), e);
            }
            throw new VapidSignerUnavailableException(
                    "Vault request ended with no response: " + method + " " + redacted(uri), e);
        } catch (InterruptedException e) {
            // Re-setting the flag and keeping the cause is the whole of what this transport owes an
            // interruption: telling an interrupted exchange apart from any other unanswered one is
            // the caller's job, and whoever is supervising tests the flag (or finds the
            // InterruptedException in this chain) before reading the type.
            Thread.currentThread().interrupt();
            throw new VapidSignerUnavailableException(
                    "Interrupted while waiting for Vault: " + method + " " + redacted(uri), e);
        }
    }

    /**
     * The retry hint Vault declared, read from the {@code Retry-After} response header. Vault fills that header in
     * delta-seconds alone — a plain run of ASCII digits, a "suggested time, in seconds" in its own words — and only on
     * a rate-limited answer where an operator set {@code enable_rate_limit_response_headers} in the quota
     * configuration, an API-managed setting on {@code sys/quotas/config} that defaults to false (<a
     * href="https://developer.hashicorp.com/vault/api-docs/system/quotas-config">Vault quotas configuration API</a>) —
     * so empty is the ordinary result, not a surprise. Anything else in the header — an HTTP-date, a sign, non-digits —
     * is not what Vault sends, and yields no hint rather than a guess; the digits-only parse also makes a negative hint
     * unrepresentable, which is the floor {@link VaultHttpResponse} requires. The length bound exists to keep the
     * arithmetic inside a {@code long}, not to cap the value: eighteen digits is some thirty billion years of seconds,
     * and no ceiling is applied to anything that parses.
     */
    private static Optional<Duration> retryAfterHint(HttpHeaders headers) {
        Optional<String> header = headers.firstValue("Retry-After");
        if (header.isEmpty()) {
            return Optional.empty();
        }
        String value = header.get();
        if (value.isEmpty() || value.length() > 18) {
            return Optional.empty();
        }
        long seconds = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < '0' || c > '9') {
                return Optional.empty();
            }
            seconds = seconds * 10 + (c - '0');
        }
        return Optional.of(Duration.ofSeconds(seconds));
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
     * The request URI as rendered into exception messages, composed from its parsed components — never from its string
     * form. A URI Java parsed as {@code scheme://[userinfo@]host[:port][/path]} with no query and no fragment is
     * rebuilt from its scheme, host, port and raw path, without its userinfo: credentials smuggled into the authority
     * ({@code https://user:secret@vault:8200}, basic auth for a fronting proxy) are exactly as secret as the Vault
     * token and would otherwise ride into every transport failure. Dropped rather than masked, because a failure
     * message is most useful as a URI an operator can copy; an empty userinfo ({@code https://@vault:8200}) keeps its
     * {@code @}, which delimits no credential, so the copyable URI stays exactly the configured one.
     *
     * <p>Any other shape renders as the fixed marker {@code <unrenderable address>}, with not one character of the
     * original: once Java has not parsed a server-based authority, a credential can sit anywhere in the text — a
     * password carrying {@code /} or {@code ?} dissolves the authority as Java reads it — and no string-level cut can
     * find it without guessing. A parsed authority alone is not enough, which is why a <em>raw</em> path carrying
     * {@code @} routes to the marker too: when the text before a password's first {@code /} happens to parse as
     * {@code host[:port]} ({@code https://u:1971/restOfPassword@vault:8200}), Java reads the user name as the host and
     * drops the rest of the credential — its {@code @} and the real host included — into the path. A credential in an
     * authority is always delimited by {@code @}, so a raw path with no {@code @} can hide no tail of one — provided
     * the path is literal text, which is what that argument reasons about. A raw path carrying {@code %} is not literal
     * text: it is an encoding, {@code %40} at any encoding depth spells the delimiter without ever showing it, and
     * decoding to some chosen depth before looking would just move the guessing one level down. So {@code %} routes to
     * the marker as well — an encoded path is refused, not reasoned about — and neither guard swallows anything
     * renderable, the signer's address rule admitting neither {@code @} nor {@code %} in an address path. Every URI the
     * signer sends through this transport keeps the marker unreachable twice over: its base address was validated up
     * front, and its request path is concatenated from validated segments (address path, mount, Transit key name) whose
     * allowed characters include neither {@code @} nor {@code %}. The marker therefore exists as defence in depth for
     * any other caller of this public transport, and when it does fire, only the path is withheld — the HTTP method is
     * printed beside the rendering either way, so a sign POST still reads apart from a keys GET.
     *
     * <p>The Vault signer starter renders the address its bound properties print by this same fail-closed rule, the one
     * difference being that it masks a userinfo as {@code ***@} rather than dropping it — a configuration dump has to
     * keep saying that something was configured there. Keep {@code VaultSignerProperties} in step when this changes.
     */
    private static String redacted(URI uri) {
        // A URI with a parsed host always carries a path, possibly empty; the fallback only
        // states that in a form the nullness checker can see.
        String rawPath = Objects.requireNonNullElse(uri.getRawPath(), "");
        if (uri.getScheme() == null
                || uri.getHost() == null
                || uri.getRawQuery() != null
                || uri.getRawFragment() != null
                || rawPath.indexOf('@') >= 0
                || rawPath.indexOf('%') >= 0) {
            return "<unrenderable address>";
        }
        StringBuilder rendered = new StringBuilder(uri.getScheme()).append("://");
        String userInfo = uri.getUserInfo();
        if (userInfo != null && userInfo.isEmpty()) {
            rendered.append('@');
        }
        rendered.append(uri.getHost());
        if (uri.getPort() >= 0) {
            rendered.append(':').append(uri.getPort());
        }
        return rendered.append(rawPath).toString();
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

        // Declared rather than computed, as every exception in this library is: a computed
        // identifier is derived from every non-private constructor and method as well as from the
        // fields, so adding either would move it and make an instance already written to a stream
        // unreadable after an otherwise compatible release. This one never leaves the transport,
        // and the habit is cheaper to keep than to reason about per class.
        @Serial
        private static final long serialVersionUID = 1L;

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
