package io.push2u;

import java.net.URI;
import java.security.Provider;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * The send facade: encrypts a {@link PushMessage} for a {@link Subscription} (RFC 8291), signs
 * the VAPID JWT (RFC 8292), POSTs the {@code aes128gcm} body to the endpoint (RFC 8030), and
 * interprets the HTTP status into a {@link PushResult} with retries.
 *
 * <p>Build it with {@link #builder()}. Exactly one key source is required — {@code .vapid(keys)}
 * (the default in-JVM signer) <em>or</em> {@code .signer(externalSigner)} (which supplies the
 * VAPID public key itself); {@code .contact(...)} is required in both. See DESIGN.md §5.2.
 *
 * <p>A dead subscription (404/410) is a normal {@link PushResult}, not an exception (ADR-007).
 */
public final class PushSender {

    private final VapidSigner signer;
    private final String contact;
    private final WebPushEncryptor encryptor;
    private final PushHttpClient httpClient;
    private final RetryPolicy retryPolicy;
    private final Duration jwtExpiry;
    private final Duration defaultTtl;
    private final int recordSize;
    private final Sleeper sleeper;

    private PushSender(Builder builder) {
        Jca jca = builder.cryptoProvider == null ? Jca.platform() : Jca.using(builder.cryptoProvider);
        this.signer = builder.signer != null ? builder.signer : new LocalEcVapidSigner(builder.vapidKeys, jca);
        this.contact = builder.contact;
        this.encryptor = new WebPushEncryptor(jca);
        this.httpClient = builder.httpClient != null ? builder.httpClient : new JdkHttpPushClient();
        this.retryPolicy = builder.retryPolicy;
        this.jwtExpiry = builder.jwtExpiry;
        this.defaultTtl = builder.defaultTtl;
        this.recordSize = builder.recordSize;
        this.sleeper = builder.sleeper;
    }

    /**
     * A new builder; configure a key source and contact, then call {@link Builder#build()}.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Encrypt, sign, POST (with retries), and interpret the result. Blocks until done.
     *
     * @param subscription the target subscription
     * @param message      the message to send
     * @return the send result
     */
    public PushResult send(Subscription subscription, PushMessage message) {
        Objects.requireNonNull(subscription, "subscription");
        Objects.requireNonNull(message, "message");

        byte[] body = encryptor.encrypt(subscription.p256dh(), subscription.auth(), message.payload(), recordSize);
        URI endpoint = URI.create(subscription.endpoint());
        String authorization =
            Vapid.authorizationHeader(signer, origin(endpoint), contact, Instant.now().plus(jwtExpiry));
        Map<String, String> headers = requestHeaders(authorization, message);

        PushResponse response = null;
        for (int attempt = 1; attempt <= retryPolicy.maxAttempts(); attempt++) {
            response = httpClient.post(endpoint, headers, body);
            int code = response.statusCode();
            if (isDelivered(code)) {
                return new PushResult(PushResult.Status.DELIVERED, code, attempt);
            }
            if (isExpired(code)) {
                return new PushResult(PushResult.Status.SUBSCRIPTION_EXPIRED, code, attempt);
            }
            if (!isRetryable(code) || attempt == retryPolicy.maxAttempts()) {
                return new PushResult(PushResult.Status.FAILED, code, attempt);
            }
            sleeper.sleep(backoff(attempt, code, response));
        }
        // Unreachable: maxAttempts >= 1 guarantees the loop returns.
        return new PushResult(PushResult.Status.FAILED, response == null ? 0 : response.statusCode(),
            retryPolicy.maxAttempts());
    }

    /**
     * {@link #send} on the common ForkJoinPool.
     *
     * @param subscription the target subscription
     * @param message      the message to send
     * @return a future completing with the send result
     */
    public CompletableFuture<PushResult> sendAsync(Subscription subscription, PushMessage message) {
        return CompletableFuture.supplyAsync(() -> send(subscription, message));
    }

    private Map<String, String> requestHeaders(String authorization, PushMessage message) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", authorization);
        headers.put("Content-Encoding", WebPushEncryptor.CONTENT_ENCODING);
        Duration ttl = message.ttl() != null ? message.ttl() : defaultTtl;
        headers.put("TTL", Long.toString(ttl.toSeconds()));
        if (message.urgency() != null) {
            headers.put("Urgency", message.urgency().headerValue());
        }
        if (message.topic() != null) {
            headers.put("Topic", message.topic());
        }
        return headers;
    }

    private Duration backoff(int attempt, int code, PushResponse response) {
        if (code == 429) {
            Optional<Duration> retryAfter = parseRetryAfter(response);
            if (retryAfter.isPresent()) {
                Duration delay = retryAfter.get();
                return delay.compareTo(retryPolicy.maxBackoff()) > 0 ? retryPolicy.maxBackoff() : delay;
            }
        }
        return retryPolicy.backoffFor(attempt);
    }

    private static Optional<Duration> parseRetryAfter(PushResponse response) {
        return response.header("Retry-After")
            .map(String::trim)
            .filter(value -> !value.isEmpty() && value.chars().allMatch(Character::isDigit))
            .map(seconds -> Duration.ofSeconds(Long.parseLong(seconds)));
    }

    private static boolean isDelivered(int code) {
        return code >= 200 && code < 300;
    }

    private static boolean isExpired(int code) {
        return code == 404 || code == 410;
    }

    private static boolean isRetryable(int code) {
        return code == 429 || (code >= 500 && code < 600);
    }

    /** The RFC 8292 {@code aud}: the origin (scheme + host + optional port) of the endpoint. */
    private static String origin(URI endpoint) {
        String scheme = endpoint.getScheme();
        String host = endpoint.getHost();
        if (scheme == null || host == null) {
            throw new IllegalArgumentException("subscription endpoint is not an absolute http(s) URL: " + endpoint);
        }
        int port = endpoint.getPort();
        return port == -1 ? scheme + "://" + host : scheme + "://" + host + ":" + port;
    }

    /**
     * Configures and builds a {@link PushSender}. Required: a key source ({@link #vapid} or
     * {@link #signer}) and a {@link #contact}; everything else has a sensible default.
     */
    public static final class Builder {

        private VapidKeys vapidKeys;
        private VapidSigner signer;
        private String contact;
        private PushHttpClient httpClient;
        private Provider cryptoProvider;
        private RetryPolicy retryPolicy = RetryPolicy.defaults();
        private Duration jwtExpiry = Duration.ofHours(12);
        private Duration defaultTtl = Duration.ofDays(1);
        private int recordSize = WebPushEncryptor.DEFAULT_RECORD_SIZE;
        private Sleeper sleeper = Sleeper.REAL;

        private Builder() {
        }

        /**
         * Hold the VAPID key pair locally and sign in-JVM (the default signer).
         *
         * @param vapidKeys the VAPID key pair
         * @return this builder
         */
        public Builder vapid(VapidKeys vapidKeys) {
            this.vapidKeys = vapidKeys;
            return this;
        }

        /**
         * Delegate VAPID signing to an external signer that also supplies the public key.
         *
         * @param signer the external signer
         * @return this builder
         */
        public Builder signer(VapidSigner signer) {
            this.signer = signer;
            return this;
        }

        /**
         * The VAPID {@code sub} claim — a {@code mailto:} / {@code https:} the push service can reach you at.
         *
         * @param contact the contact URI
         * @return this builder
         */
        public Builder contact(String contact) {
            this.contact = contact;
            return this;
        }

        /**
         * The HTTP transport; defaults to {@link JdkHttpPushClient}.
         *
         * @param httpClient the transport
         * @return this builder
         */
        public Builder httpClient(PushHttpClient httpClient) {
            this.httpClient = httpClient;
            return this;
        }

        /**
         * The JCE provider backing the content-encryption primitives; defaults to the platform
         * provider chain (see DESIGN.md §5.1 and the README for BouncyCastle / FIPS use).
         *
         * @param cryptoProvider the JCE provider, or {@code null} for the platform default
         * @return this builder
         */
        public Builder cryptoProvider(Provider cryptoProvider) {
            this.cryptoProvider = cryptoProvider;
            return this;
        }

        /**
         * The retry policy; defaults to {@link RetryPolicy#defaults()}.
         *
         * @param retryPolicy the retry policy
         * @return this builder
         */
        public Builder retryPolicy(RetryPolicy retryPolicy) {
            this.retryPolicy = Objects.requireNonNull(retryPolicy, "retryPolicy");
            return this;
        }

        /**
         * How far ahead the VAPID {@code exp} is set; must be > 0 and ≤ 24h (RFC 8292 §2).
         *
         * @param jwtExpiry the expiry offset
         * @return this builder
         */
        public Builder jwtExpiry(Duration jwtExpiry) {
            Objects.requireNonNull(jwtExpiry, "jwtExpiry");
            if (jwtExpiry.isNegative() || jwtExpiry.isZero() || jwtExpiry.compareTo(Duration.ofHours(24)) > 0) {
                throw new IllegalArgumentException("jwtExpiry must be > 0 and <= 24h (RFC 8292 §2)");
            }
            this.jwtExpiry = jwtExpiry;
            return this;
        }

        /**
         * The {@code TTL} header used when a message does not set its own.
         *
         * @param defaultTtl the default TTL
         * @return this builder
         */
        public Builder defaultTtl(Duration defaultTtl) {
            Objects.requireNonNull(defaultTtl, "defaultTtl");
            if (defaultTtl.isNegative()) {
                throw new IllegalArgumentException("defaultTtl must not be negative");
            }
            this.defaultTtl = defaultTtl;
            return this;
        }

        /**
         * The {@code aes128gcm} record size advertised in the body header (RFC 8188); default 4096.
         *
         * @param recordSize the record size
         * @return this builder
         */
        public Builder recordSize(int recordSize) {
            this.recordSize = recordSize;
            return this;
        }

        // Package-private test seam: run the retry loop without real backoff sleeps.
        Builder sleeper(Sleeper sleeper) {
            this.sleeper = Objects.requireNonNull(sleeper, "sleeper");
            return this;
        }

        /**
         * Validates the configuration (exactly one key source, plus a contact) and builds the {@link PushSender}.
         *
         * @return the configured sender
         */
        public PushSender build() {
            if (contact == null) {
                throw new IllegalStateException("contact is required (the VAPID 'sub' claim)");
            }
            boolean hasVapid = vapidKeys != null;
            boolean hasSigner = signer != null;
            if (hasVapid == hasSigner) {
                throw new IllegalStateException(
                    "exactly one key source is required: either .vapid(keys) or .signer(externalSigner), not both");
            }
            return new PushSender(this);
        }
    }
}
