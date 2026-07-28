package io.push2u;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The default {@link PushHttpClient}, over the JDK's {@code java.net.http.HttpClient} — no third
 * party HTTP stack, keeping {@code core} zero-dependency (DESIGN.md §4). The response body is read
 * as UTF-8 so remote-signer calls can use it; push sends ignore it.
 */
public final class JdkHttpPushClient implements PushHttpClient {

    private static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(30);

    private final HttpClient httpClient;
    private final Duration requestTimeout;

    /** Uses a fresh default {@link HttpClient} and a 30-second per-request timeout. */
    public JdkHttpPushClient() {
        this(HttpClient.newHttpClient(), DEFAULT_REQUEST_TIMEOUT);
    }

    /**
     * Uses the given {@link HttpClient} and per-request timeout.
     *
     * @param httpClient     the HTTP client to send requests with
     * @param requestTimeout the per-request timeout
     */
    public JdkHttpPushClient(HttpClient httpClient, Duration requestTimeout) {
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
        this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout");
    }

    @Override
    public PushResponse post(URI endpoint, Map<String, String> headers, byte[] body) {
        HttpRequest.Builder request = HttpRequest.newBuilder(endpoint)
            .timeout(requestTimeout)
            .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        headers.forEach(request::header);

        try {
            HttpResponse<String> response =
                httpClient.send(request.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return new PushResponse(response.statusCode(), firstValues(response.headers().map()), response.body());
        } catch (IOException e) {
            throw new PushDeliveryException("POST to push endpoint failed: " + endpoint, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new PushDeliveryException("Interrupted while POSTing to push endpoint: " + endpoint, e);
        }
    }

    private static Map<String, String> firstValues(Map<String, List<String>> headers) {
        Map<String, String> flattened = new HashMap<>();
        headers.forEach((name, values) -> {
            if (!values.isEmpty()) {
                flattened.put(name, values.getFirst());
            }
        });
        return flattened;
    }
}
