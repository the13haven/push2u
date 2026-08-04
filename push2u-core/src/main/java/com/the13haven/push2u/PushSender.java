package com.the13haven.push2u;

import java.net.URI;
import java.security.Provider;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import org.jspecify.annotations.Nullable;

/**
 * The send facade: encrypts a {@link PushMessage} for a {@link Subscription} (RFC 8291), signs the VAPID JWT (RFC
 * 8292), POSTs the {@code aes128gcm} body to the endpoint (RFC 8030), and interprets the HTTP status into a
 * {@link PushResult} with retries.
 *
 * <p>Build it with {@link #builder()}. Exactly one key source is required — {@code .vapid(keys)} (the default in-JVM
 * signer) <em>or</em> {@code .signer(externalSigner)} (which supplies the VAPID public key itself);
 * {@code .contact(...)} is required in both.
 *
 * <p>A dead subscription (404/410) is a normal {@link PushResult}, not an exception: pruning a store on expiry is
 * expected control flow, not an error.
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
    private final int maxEncryptedBodyBytes;
    private final Sleeper sleeper;
    private final Clock clock;
    /** {@code null} selects the library-owned virtual-thread executor; see {@link #sendAsync}. */
    @Nullable
    private final Executor executor;
    /**
     * {@code null} means no policy — the historical any-https-endpoint behaviour; see {@link Builder#endpointPolicy}.
     */
    @Nullable
    private final EndpointPolicy endpointPolicy;

    private PushSender(Builder builder) {
        Jca jca = builder.cryptoProvider == null ? Jca.platform() : Jca.using(builder.cryptoProvider);
        // Builder.build() rejects a missing contact and enforces exactly one key source, so both
        // are present by the time this runs — stated here so the invariant is checked rather than
        // assumed if build() ever changes.
        this.signer = builder.signer != null
                ? builder.signer
                : new LocalEcVapidSigner(Objects.requireNonNull(builder.vapidKeys, "vapidKeys"), jca);
        this.contact = Objects.requireNonNull(builder.contact, "contact");
        this.encryptor = new WebPushEncryptor(jca);
        this.httpClient = builder.httpClient != null ? builder.httpClient : new JdkHttpPushClient();
        this.retryPolicy = builder.retryPolicy;
        this.jwtExpiry = builder.jwtExpiry;
        this.defaultTtl = builder.defaultTtl;
        this.recordSize = builder.recordSize;
        this.maxEncryptedBodyBytes = builder.maxEncryptedBodyBytes;
        this.sleeper = builder.sleeper;
        this.clock = builder.clock;
        this.executor = builder.executor;
        this.endpointPolicy = builder.endpointPolicy;
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
     * <p>The payload is size-checked first, before any cryptography or network I/O, against both
     * {@link Builder#maxEncryptedBodyBytes(int)} and {@link Builder#recordSize(int)}; an oversized payload throws
     * {@link IllegalArgumentException} rather than being sent for the push service to reject with {@code 413}. The
     * {@link Builder#endpointPolicy(EndpointPolicy) endpoint policy}, when one is configured, runs next — still ahead
     * of the encryption, the VAPID signature (which under an external {@link VapidSigner} is a remote Vault/KMS
     * operation) and the HTTP request, so a rejected endpoint costs none of them.
     *
     * @param subscription the target subscription
     * @param message the message to send
     * @return the send result
     * @throws IllegalArgumentException if the payload does not fit the configured body limit, or if the configured
     *     record size is too small for it
     * @throws EndpointRejectedException if the configured endpoint policy rejects the subscription's endpoint
     */
    // PreserveStackTrace / AvoidThrowingNewInstanceOfSameException: URI.create's own
    // IllegalArgumentException carries the raw capability URL, so it is replaced by one built from
    // the redacted endpoint and the cause is deliberately not attached (see Endpoints.redact).
    @SuppressWarnings({"PMD.PreserveStackTrace", "PMD.AvoidThrowingNewInstanceOfSameException"})
    public PushResult send(Subscription subscription, PushMessage message) {
        Objects.requireNonNull(subscription, "subscription");
        Objects.requireNonNull(message, "message");

        byte[] payload = message.payload();
        WebPushEncryptor.checkPayloadFits(payload.length, recordSize, maxEncryptedBodyBytes);

        URI endpoint;
        try {
            endpoint = URI.create(subscription.endpoint());
        } catch (IllegalArgumentException e) {
            // Unreachable after Subscription's constructor validation, but URI.create's own message
            // would carry the raw capability URL — replace it with the redacted form. No cause for
            // the same reason: URISyntaxException's message embeds the raw input.
            throw new IllegalArgumentException(
                    "subscription endpoint is not a valid URI: " + Endpoints.redact(subscription.endpoint()));
        }
        if (endpointPolicy != null) {
            // Before the encryption as well as the signature and the POST: a policy rejection is a
            // verdict on the subscription, and reaching it must not depend on — or pay for — any
            // per-send cryptography. The sender holds no mutable state, so a policy that throws
            // (a rejection or its own defect) leaves nothing to corrupt for later sends.
            endpointPolicy.validate(endpoint);
        }
        byte[] body = encryptor.encrypt(subscription.p256dh(), subscription.auth(), payload, recordSize);
        String authorization = Vapid.authorizationHeader(
                signer, Origin.serialize(endpoint), contact, clock.instant().plus(jwtExpiry));
        Map<String, String> headers = requestHeaders(authorization, message);

        for (int attempt = 1; attempt <= retryPolicy.maxAttempts(); attempt++) {
            PushResponse response = httpClient.post(endpoint, headers, body);
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
            sleeper.sleep(backoff(attempt, response));
        }
        // Unreachable: RetryPolicy enforces maxAttempts >= 1, so the loop body runs at least once
        // and every path through it returns. Fabricating a PushResult here instead would have to
        // invent a status code for a POST that never happened.
        throw new AssertionError("retry loop exited without a result — maxAttempts was " + retryPolicy.maxAttempts());
    }

    /**
     * {@link #send} on the executor configured via {@link Builder#executor(Executor)} — by default a library-owned
     * virtual-thread-per-task executor, never the common ForkJoinPool. Each async send blocks its thread for the whole
     * exchange (synchronous HTTP plus the backoff sleeps between retries), which a virtual thread absorbs by parking
     * without pinning a carrier thread.
     *
     * <p>This governs the send itself. Async continuations the caller chains onto the returned future
     * ({@code thenApplyAsync} and friends without an explicit executor) still use {@link CompletableFuture}'s default —
     * the common ForkJoinPool; pass an executor there too if a continuation blocks.
     *
     * <p>If a caller-supplied executor rejects the task, its {@link java.util.concurrent.RejectedExecutionException}
     * propagates from this call rather than completing the returned future exceptionally. The preconditions
     * {@link #send} checks go the other way: they run inside the queued task, so an oversized payload — or an endpoint
     * the configured {@link Builder#endpointPolicy(EndpointPolicy) endpoint policy} rejects — completes the returned
     * future exceptionally ({@link IllegalArgumentException}, {@link EndpointRejectedException}) instead of throwing
     * from this call. The async path runs through the same {@link #send} pipeline, so the policy guards it identically:
     * there is no way to reach the network that bypasses the policy.
     *
     * @param subscription the target subscription
     * @param message the message to send
     * @return a future completing with the send result
     */
    public CompletableFuture<PushResult> sendAsync(Subscription subscription, PushMessage message) {
        Executor target = executor != null ? executor : DefaultAsyncExecutor.INSTANCE;
        return CompletableFuture.supplyAsync(() -> send(subscription, message), target);
    }

    /**
     * The default {@code sendAsync} executor, created lazily via the holder-class idiom: building a sender that only
     * ever calls the synchronous {@link #send} never touches this class, so no executor is created. A
     * virtual-thread-per-task executor is the right default for a workload of blocking HTTP calls and backoff sleeps —
     * virtual threads park without pinning a carrier thread, and the executor holds no OS threads when idle. The
     * library never shuts it down, which is safe: idle it holds no resources, and its threads are daemons, so it cannot
     * keep the JVM alive.
     */
    private static final class DefaultAsyncExecutor {
        static final Executor INSTANCE = Executors.newVirtualThreadPerTaskExecutor();

        private DefaultAsyncExecutor() {}
    }

    private Map<String, String> requestHeaders(String authorization, PushMessage message) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", authorization);
        headers.put("Content-Encoding", WebPushEncryptor.CONTENT_ENCODING);
        // Each optional header is read once into a local: the accessors are @Nullable, and calling
        // them again after the null check would be a second read for the analysers to reason about.
        Duration messageTtl = message.ttl();
        headers.put("TTL", Long.toString((messageTtl != null ? messageTtl : defaultTtl).toSeconds()));
        Urgency urgency = message.urgency();
        if (urgency != null) {
            headers.put("Urgency", urgency.headerValue());
        }
        String topic = message.topic();
        if (topic != null) {
            headers.put("Topic", topic);
        }
        return headers;
    }

    /**
     * Backoff before the retry that follows {@code attempt}. Only called for retryable statuses (429, 5xx) — RFC 9110
     * §10.2.3 allows {@code Retry-After} on any of them, so an intelligible header always wins over the computed
     * backoff, capped at {@link RetryPolicy#maxBackoff()}; an absent or unparseable header falls back to the
     * exponential schedule.
     */
    private Duration backoff(int attempt, PushResponse response) {
        Optional<Duration> retryAfter =
                response.header("Retry-After").flatMap(value -> RetryAfter.parse(value, clock.instant()));
        if (retryAfter.isPresent()) {
            Duration delay = retryAfter.get();
            return delay.compareTo(retryPolicy.maxBackoff()) > 0 ? retryPolicy.maxBackoff() : delay;
        }
        return retryPolicy.backoffFor(attempt);
    }

    /** Any 2xx counts as accepted — see {@link PushResult.Status#DELIVERED} for why, not just 201. */
    private static boolean isDelivered(int code) {
        return code >= 200 && code < 300;
    }

    private static boolean isExpired(int code) {
        return code == 404 || code == 410;
    }

    private static boolean isRetryable(int code) {
        return code == 429 || (code >= 500 && code < 600);
    }

    /**
     * Configures and builds a {@link PushSender}. Required: a key source ({@link #vapid} or {@link #signer}) and a
     * {@link #contact}; everything else has a sensible default.
     */
    public static final class Builder {

        @Nullable
        private VapidKeys vapidKeys;

        @Nullable
        private VapidSigner signer;

        @Nullable
        private String contact;

        @Nullable
        private PushHttpClient httpClient;

        @Nullable
        private Provider cryptoProvider;

        private RetryPolicy retryPolicy = RetryPolicy.defaults();
        private Duration jwtExpiry = Duration.ofHours(12);
        private Duration defaultTtl = Duration.ofDays(1);
        private int recordSize = WebPushEncryptor.DEFAULT_RECORD_SIZE;
        private int maxEncryptedBodyBytes = WebPushEncryptor.DEFAULT_MAX_ENCRYPTED_BODY_BYTES;
        private Sleeper sleeper = Sleeper.REAL;
        private Clock clock = Clock.systemUTC();

        @Nullable
        private Executor executor;

        @Nullable
        private EndpointPolicy endpointPolicy;

        private Builder() {}

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
         * The VAPID {@code sub} claim — a {@code mailto:} / {@code https:} the push service can reach you at. RFC 8292
         * §2.1 makes {@code sub} optional ({@code MAY}) and only recommends ({@code SHOULD}) those two URI forms when
         * it is present; requiring it is push2u's own contract, because a push service that needs to reach the operator
         * about a misbehaving application server has no other channel. {@link #build()} therefore rejects a
         * {@code null} or blank value: a blank one satisfies that contract no better than an absent one, and the JWT it
         * would produce carries a {@code sub} a push service may well reject, though the RFC obliges no service to.
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
         * The JCE provider backing the <em>entire</em> local cryptographic path: the content-encryption primitives
         * (ECDH, HKDF's HMAC, AES-128-GCM, EC key import) and — when the default in-JVM signer is used — the VAPID
         * ES256 signature. Defaults to the platform provider chain. For the signature the library first asks this
         * provider for raw-format ECDSA ({@code SHA256withECDSAinP1363Format}); if the provider does not register that
         * name (BouncyCastle FIPS registers only {@code SHA256withECDSA}), it falls back to DER-format ECDSA from the
         * <em>same</em> provider and strictly converts the DER output to the raw {@code r || s} JOSE needs — the
         * fallback never resolves against a different provider.
         *
         * @param cryptoProvider the JCE provider, or {@code null} for the platform default
         * @return this builder
         */
        public Builder cryptoProvider(@Nullable Provider cryptoProvider) {
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
         * The {@code aes128gcm} record size advertised in the body header (RFC 8188 {@code rs}); default 4096. The
         * library emits a single record, so {@code rs} must be strictly greater than the plaintext plus the padding
         * delimiter (1 octet) plus the authentication tag (16 octets) — RFC 8291 §4 — otherwise the send is rejected
         * with the payload length it would need.
         *
         * <p>This is a separate protocol parameter from {@link #maxEncryptedBodyBytes(int)} and is never adjusted to
         * follow it: raising the body limit alone leaves {@code rs} where it was and a payload that outgrows it is
         * rejected on the record-size ground instead. Raise both when sending larger payloads.
         *
         * @param recordSize the record size; must be at least 18 (RFC 8188 §2)
         * @return this builder
         * @throws IllegalArgumentException if {@code recordSize} is less than 18
         */
        public Builder recordSize(int recordSize) {
            if (recordSize < WebPushEncryptor.MIN_RECORD_SIZE) {
                throw new IllegalArgumentException("recordSize must be at least "
                        + WebPushEncryptor.MIN_RECORD_SIZE + " — RFC 8188 §2 declares smaller values invalid, was "
                        + recordSize);
            }
            this.recordSize = recordSize;
            return this;
        }

        /**
         * The ceiling on the encrypted HTTP entity body, in bytes; default 4096.
         *
         * <p>RFC 8030 §7.2 lets a push service refuse a body larger than 4096 octets, so the limit is expressed on the
         * body rather than on the plaintext. The single-record {@code aes128gcm} format this library emits adds a fixed
         * 103 octets — an 86-octet RFC 8188 header (salt 16, {@code rs} 4, {@code idlen} 1, {@code keyid} 65), the
         * padding delimiter (1) and the AEAD_AES_128_GCM tag (16) — so the default admits 3993 octets of plaintext, the
         * figure RFC 8291 §4 derives. {@link PushSender#send} rejects anything larger before encrypting or contacting
         * the push service.
         *
         * <p>Raise it only for an endpoint known to accept more (some push services document a larger limit; a
         * self-hosted or intra-organisation service may be configured for one). Doing so does <em>not</em> touch
         * {@link #recordSize(int)}, which stays at whatever it was configured to — raise that too, or the larger
         * payload is rejected for not fitting the record.
         *
         * @param maxEncryptedBodyBytes the maximum encrypted body size in bytes; must be at least the fixed 103-octet
         *     overhead, which is exactly the body an empty payload produces
         * @return this builder
         * @throws IllegalArgumentException if the value cannot hold even an empty payload
         */
        public Builder maxEncryptedBodyBytes(int maxEncryptedBodyBytes) {
            if (maxEncryptedBodyBytes < WebPushEncryptor.BODY_OVERHEAD) {
                throw new IllegalArgumentException("maxEncryptedBodyBytes must be at least the fixed "
                        + WebPushEncryptor.BODY_OVERHEAD + "-byte aes128gcm overhead (RFC 8188 header "
                        + WebPushEncryptor.HEADER_LENGTH + " + record overhead " + WebPushEncryptor.RECORD_OVERHEAD
                        + "), was " + maxEncryptedBodyBytes);
            }
            this.maxEncryptedBodyBytes = maxEncryptedBodyBytes;
            return this;
        }

        /**
         * The executor {@link PushSender#sendAsync} runs sends on. Each queued send blocks its thread for the whole
         * exchange — the synchronous HTTP call plus any backoff sleeps between retries (up to
         * {@link RetryPolicy#maxBackoff()} each) — so the executor must tolerate long-blocking tasks. Defaults to a
         * library-owned virtual-thread-per-task executor, created lazily on the first async send; a caller-supplied
         * executor stays caller-owned — the library never shuts it down.
         *
         * @param executor the executor for async sends
         * @return this builder
         */
        public Builder executor(Executor executor) {
            this.executor = Objects.requireNonNull(executor, "executor");
            return this;
        }

        /**
         * The policy deciding which push endpoints this sender may contact, run on every send (and every
         * {@link PushSender#sendAsync} — the async path goes through the same pipeline) before encryption, before the
         * VAPID signature and before any network I/O; a rejected endpoint throws {@link EndpointRejectedException} and
         * costs none of them.
         *
         * <p>Off by default, for backward compatibility: with no policy configured the sender keeps its historical
         * contract and POSTs to any endpoint satisfying {@link Endpoints#requireSecure} — including loopback,
         * private-range and cloud-metadata addresses. Any integration whose subscriptions arrive from clients should
         * configure one, typically {@link EndpointPolicies#allowedOrigins}; {@link EndpointPolicy} documents the threat
         * model and the limits of a URI-level check.
         *
         * @param endpointPolicy the policy to validate each endpoint against
         * @return this builder
         */
        public Builder endpointPolicy(EndpointPolicy endpointPolicy) {
            this.endpointPolicy = Objects.requireNonNull(endpointPolicy, "endpointPolicy");
            return this;
        }

        // Package-private test seam: run the retry loop without real backoff sleeps.
        Builder sleeper(Sleeper sleeper) {
            this.sleeper = Objects.requireNonNull(sleeper, "sleeper");
            return this;
        }

        // Package-private test seam: pin "now" for Retry-After dates and the VAPID expiry.
        Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /**
         * Validates the configuration (exactly one key source, plus a non-blank contact) and builds the
         * {@link PushSender}.
         *
         * @return the configured sender
         * @throws IllegalStateException if the key source or the contact is missing or invalid
         */
        public PushSender build() {
            if (contact == null || contact.isBlank()) {
                throw new IllegalStateException(
                        "contact is required (the VAPID 'sub' claim: optional in RFC 8292 §2.1, required by push2u)");
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
