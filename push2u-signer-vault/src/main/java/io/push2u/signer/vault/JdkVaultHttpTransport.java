package io.push2u.signer.vault;

import io.push2u.PushCryptoException;
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

/**
 * The default {@link VaultHttpTransport}, over the JDK's {@code java.net.http.HttpClient} — no
 * third-party HTTP stack. Two hard guarantees on every request:
 *
 * <ul>
 *   <li><b>A per-request timeout</b> ({@link HttpRequest.Builder#timeout}). The client-level
 *       {@code connectTimeout} only bounds establishing the connection — a Vault that accepts the
 *       connection and then never answers would otherwise block the caller forever (in the fetched
 *       mode that caller is application startup).</li>
 *   <li><b>A response-size cap, counted in raw bytes as they stream in.</b> A {@code Content-Length}
 *       above the cap fails before the body is read, but the streaming count is authoritative — the
 *       header may be absent (chunked) or lie. Exceeding the cap fails the whole request
 *       (fail-closed): a truncated body must never reach the caller, because a targeted JSON
 *       extractor could still find a complete-looking {@code data.signature} before the cut and
 *       treat a mangled response as valid.</li>
 * </ul>
 *
 * <p>Exception messages carry the HTTP method and the request URI without its query (a Vault query
 * can name secrets), and never any request header — the Vault token travels in
 * {@code X-Vault-Token} and must not leak into logs.
 */
public final class JdkVaultHttpTransport implements VaultHttpTransport {

    private static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(30);
    /** 1 MiB — two orders of magnitude above any Transit sign/keys response, small enough to cap. */
    private static final int DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;

    private final HttpClient httpClient;
    private final Duration requestTimeout;
    private final int maxResponseBytes;

    /**
     * The defaults: a fresh {@link HttpClient} with a 10-second connect timeout, a 30-second
     * per-request timeout, and a 1 MiB response-size cap.
     */
    public JdkVaultHttpTransport() {
        this(HttpClient.newBuilder().connectTimeout(DEFAULT_CONNECT_TIMEOUT).build(),
            DEFAULT_REQUEST_TIMEOUT, DEFAULT_MAX_RESPONSE_BYTES);
    }

    /**
     * Uses the given {@link HttpClient} (bring your own mTLS, proxy, or executor configuration)
     * with the given per-request timeout and response-size cap.
     *
     * @param httpClient       the HTTP client to send requests with
     * @param requestTimeout   the per-request timeout, applied to every request; must be positive
     * @param maxResponseBytes the response-size cap in raw bytes; must be positive
     * @throws IllegalArgumentException if the timeout or the cap is not positive
     */
    public JdkVaultHttpTransport(HttpClient httpClient, Duration requestTimeout, int maxResponseBytes) {
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
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

    private VaultHttpResponse execute(String method, URI uri, Map<String, String> headers,
                                      HttpRequest.BodyPublisher bodyPublisher) {
        Objects.requireNonNull(uri, "uri");
        Objects.requireNonNull(headers, "headers");
        HttpRequest.Builder request = HttpRequest.newBuilder(uri)
            .timeout(requestTimeout)
            .method(method, bodyPublisher);
        headers.forEach(request::header);
        try {
            HttpResponse<byte[]> response = httpClient.send(request.build(), this::boundedBody);
            return new VaultHttpResponse(
                response.statusCode(), new String(response.body(), StandardCharsets.UTF_8));
        } catch (HttpTimeoutException e) {
            throw new PushCryptoException("Vault request timed out after " + requestTimeout + ": "
                + method + " " + withoutQuery(uri), e);
        } catch (IOException e) {
            // The JDK client surfaces a body-subscriber failure wrapped in IOException — recover
            // the size-cap violation from the cause chain and report it as what it is, naming the
            // call (method + query-less URI) so operators can tell the sign POST from the keys GET.
            ResponseTooLargeException tooLarge = findTooLarge(e);
            if (tooLarge != null) {
                throw new PushCryptoException(
                    tooLarge.getMessage() + ": " + method + " " + withoutQuery(uri), e);
            }
            throw new PushCryptoException("Vault request failed: " + method + " " + withoutQuery(uri), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new PushCryptoException(
                "Interrupted while waiting for Vault: " + method + " " + withoutQuery(uri), e);
        }
    }

    /**
     * The bounded body handler: rejects a declared {@code Content-Length} above the cap up front
     * (before any body bytes arrive) and counts raw streamed bytes regardless, because the header
     * may be absent or wrong.
     */
    private HttpResponse.BodySubscriber<byte[]> boundedBody(HttpResponse.ResponseInfo responseInfo) {
        long declaredLength = responseInfo.headers().firstValueAsLong("Content-Length").orElse(-1L);
        return new BoundedByteArraySubscriber(maxResponseBytes, declaredLength);
    }

    /** The request URI without query or fragment — a Vault query can name secrets; the path may not. */
    private static String withoutQuery(URI uri) {
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
        return text.substring(0, cut);
    }

    private static ResponseTooLargeException findTooLarge(Throwable failure) {
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
     * Accumulates the response body while counting raw bytes, and fails the exchange the moment
     * the count would pass the cap — cancelling the subscription so the rest of the body is never
     * pulled off the wire. Exactly-at-the-cap responses succeed.
     */
    private static final class BoundedByteArraySubscriber implements HttpResponse.BodySubscriber<byte[]> {

        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        private final int maxBytes;
        private final long declaredLength;
        private Flow.Subscription subscription;
        private long received;

        BoundedByteArraySubscriber(int maxBytes, long declaredLength) {
            this.maxBytes = maxBytes;
            this.declaredLength = declaredLength;
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return result;
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
            for (ByteBuffer chunk : buffers) {
                int length = chunk.remaining();
                received += length;
                if (received > maxBytes) {
                    subscription.cancel();
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
