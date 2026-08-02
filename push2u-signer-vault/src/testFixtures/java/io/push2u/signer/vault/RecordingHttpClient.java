package io.push2u.signer.vault;

import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

/**
 * A delegating {@link HttpClient} that counts synchronous {@link #send} calls — the only way to
 * prove a user-supplied client instance actually carries the transport's requests, since the JDK
 * client has no interceptor hook. Shared as a test fixture between this module's transport tests
 * and the Vault starter's autoconfiguration tests.
 */
public final class RecordingHttpClient extends HttpClient {

    private final AtomicInteger sends = new AtomicInteger();
    private final HttpClient delegate;

    /**
     * Wraps {@code delegate}, forwarding every call while counting synchronous sends.
     *
     * @param delegate the client that actually performs the requests
     */
    public RecordingHttpClient(HttpClient delegate) {
        this.delegate = delegate;
    }

    /**
     * The number of synchronous sends routed through this client since the last {@link #reset}.
     *
     * @return the send count
     */
    public int sends() {
        return sends.get();
    }

    /** Resets the send count — the fixture instances are static and shared between tests. */
    public void reset() {
        sends.set(0);
    }

    @Override
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler)
        throws IOException, InterruptedException {
        sends.incrementAndGet();
        return delegate.send(request, responseBodyHandler);
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
        HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler) {
        return delegate.sendAsync(request, responseBodyHandler);
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
        HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler,
        HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
        return delegate.sendAsync(request, responseBodyHandler, pushPromiseHandler);
    }

    @Override
    public Optional<CookieHandler> cookieHandler() {
        return delegate.cookieHandler();
    }

    @Override
    public Optional<Duration> connectTimeout() {
        return delegate.connectTimeout();
    }

    @Override
    public Redirect followRedirects() {
        return delegate.followRedirects();
    }

    @Override
    public Optional<ProxySelector> proxy() {
        return delegate.proxy();
    }

    @Override
    public SSLContext sslContext() {
        return delegate.sslContext();
    }

    @Override
    public SSLParameters sslParameters() {
        return delegate.sslParameters();
    }

    @Override
    public Optional<Authenticator> authenticator() {
        return delegate.authenticator();
    }

    @Override
    public Version version() {
        return delegate.version();
    }

    @Override
    public Optional<Executor> executor() {
        return delegate.executor();
    }
}
