/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.io.Serial;
import java.net.URI;
import java.security.Provider;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
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
 * <p>Build it with {@link #builder(VapidKeys, String, EndpointPolicy)} (the default in-JVM signer) or
 * {@link #builder(VapidSigner, String, EndpointPolicy)} (an external signer, which supplies the VAPID public key
 * itself). The key source, the contact and the {@link EndpointPolicy} are the three required values, so they are the
 * factory method's parameters — the overload chooses the key source, and an incomplete sender cannot be expressed;
 * everything on the {@link Builder} is optional.
 *
 * <p>A dead subscription (404/410) is a normal {@link PushResult}, not an exception: pruning a store on expiry is
 * expected control flow, not an error.
 *
 * <p><b>A built sender is thread-safe: built once and shared across every sending thread</b> — {@link #sendAsync} makes
 * concurrent sends the normal case rather than an edge one. Its configuration is immutable; the one thing it holds
 * beyond configuration is an internal bounded cache of the VAPID {@code Authorization} values it has itself signed (see
 * {@link Builder#jwtReuse(boolean)}), safely shared across those same threads and reconstructible at any moment by
 * signing again — losing it costs one signature, never a delivery. The same thread-safety obligation falls on the three
 * SPIs the sender calls ({@link VapidSigner}, {@link PushHttpClient}, {@link EndpointPolicy}), each of which states it.
 */
// CouplingBetweenObjects: this is the facade over the whole send pipeline — the size preconditions,
// the endpoint policy, the encryption, the VAPID signature with its token cache, the transport and
// the retry schedule are its collaborators by design, and carving the coordinator into pieces to
// satisfy the metric would scatter one pipeline across classes that mean nothing on their own.
@SuppressWarnings("PMD.CouplingBetweenObjects")
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
    private final Ticker ticker;
    private final boolean jwtReuse;
    private final Duration jwtRenewBefore;
    /**
     * Signed {@code Authorization} values, one per audience under the key the signer currently advertises, reused until
     * an entry nears its own {@code exp}. Guarded by its own monitor: the map is an access-ordered LRU, so even a
     * lookup mutates it. No signature is ever taken while that monitor is held — a signature may be a remote
     * key-service round trip, and holding the lock across it would queue every send to every audience behind one
     * signature, the exact stall this cache exists to remove. The {@code sub} claim and the expiry offset are
     * deliberately not part of the key: both are final fields of this sender, so one cache belongs to one contact and
     * one expiry by construction — a change that ever made either per-send would have to widen this key.
     */
    private final Map<JwtCacheKey, CachedJwt> jwtCache;
    /** {@code null} selects the library-owned virtual-thread executor; see {@link #sendAsync}. */
    @Nullable
    private final Executor executor;
    /** Always present: a sender cannot be obtained without one, and it runs on every send. */
    private final EndpointPolicy endpointPolicy;

    private PushSender(Builder builder) {
        Jca jca = builder.cryptoProvider == null ? Jca.platform() : Jca.using(builder.cryptoProvider);
        // Each factory overload sets exactly one key source, a validated contact and an endpoint
        // policy, so all three are present by the time this runs — stated here so the invariant is
        // checked rather than assumed if the factories ever change.
        this.signer = builder.signer != null
                ? builder.signer
                : new LocalEcVapidSigner(Objects.requireNonNull(builder.vapidKeys, "vapidKeys"), jca);
        this.contact = builder.contact;
        this.encryptor = new WebPushEncryptor(jca);
        this.httpClient = builder.httpClient != null ? builder.httpClient : new JdkPushHttpClient();
        this.retryPolicy = builder.retryPolicy;
        this.jwtExpiry = builder.jwtExpiry;
        this.defaultTtl = builder.defaultTtl;
        this.recordSize = builder.recordSize;
        this.maxEncryptedBodyBytes = builder.maxEncryptedBodyBytes;
        this.sleeper = builder.sleeper;
        this.clock = builder.clock;
        this.ticker = builder.ticker;
        this.jwtReuse = builder.jwtReuse;
        this.jwtRenewBefore = builder.jwtRenewBefore;
        this.jwtCache = new JwtCache(builder.jwtCacheSize);
        this.executor = builder.executor;
        this.endpointPolicy = builder.endpointPolicy;
    }

    /**
     * A new builder for a sender that holds the VAPID key pair locally and signs in-JVM (the default signer). An
     * overload of {@link #builder(VapidSigner, String, EndpointPolicy)} rather than a differently named method: the two
     * entry points differ only in which required key source they take, not in contract.
     *
     * @param vapidKeys the VAPID key pair
     * @param contact the VAPID {@code sub} claim — a {@code mailto:} / {@code https:} URI the push service can reach
     *     you at. RFC 8292 §2.1 makes {@code sub} optional ({@code MAY}) and only recommends ({@code SHOULD}) those two
     *     URI forms when it is present; requiring it is push2u's own contract, because a push service that needs to
     *     reach the operator about a misbehaving application server has no other channel. A blank value satisfies that
     *     contract no better than an absent one, so it is rejected too.
     * @param endpointPolicy which push endpoints this sender may contact, checked on every send. Required, because the
     *     endpoint inside a {@link Subscription} is attacker-influenced wherever subscriptions arrive from clients and
     *     a sender with no policy will POST anywhere that endpoint names — an outcome nobody should reach by omitting a
     *     step. The library still does not pick the rule: {@link EndpointPolicies#allowedOrigins} names the push
     *     services this deployment expects where each is a fixed host, {@link EndpointPolicies#allowedEndpoints} does
     *     the same where one of them publishes a whole DNS zone whose hostnames vary, and
     *     {@link EndpointPolicies#unrestricted()} states that no restriction is wanted, with the consequences on its
     *     own documentation
     * @return a new builder
     * @throws IllegalArgumentException if {@code contact} is blank
     */
    public static Builder builder(VapidKeys vapidKeys, String contact, EndpointPolicy endpointPolicy) {
        return new Builder(
                Objects.requireNonNull(vapidKeys, "vapidKeys"),
                null,
                requireContact(contact),
                Objects.requireNonNull(endpointPolicy, "endpointPolicy"));
    }

    /**
     * A new builder for a sender that delegates VAPID signing to an external signer — one that also supplies the public
     * key, e.g. Vault Transit.
     *
     * @param signer the external signer
     * @param contact the VAPID {@code sub} claim; see {@link #builder(VapidKeys, String, EndpointPolicy)} for the
     *     contract
     * @param endpointPolicy which push endpoints this sender may contact; see {@link #builder(VapidKeys, String,
     *     EndpointPolicy)} for why it is required
     * @return a new builder
     * @throws IllegalArgumentException if {@code contact} is blank
     */
    public static Builder builder(VapidSigner signer, String contact, EndpointPolicy endpointPolicy) {
        return new Builder(
                null,
                Objects.requireNonNull(signer, "signer"),
                requireContact(contact),
                Objects.requireNonNull(endpointPolicy, "endpointPolicy"));
    }

    /**
     * The factory methods' contact validation. A required-but-invalid value is a legitimate runtime rejection — unlike
     * a <em>missing</em> required value, which the factory signatures make inexpressible.
     */
    private static String requireContact(@Nullable String contact) {
        if (contact == null || contact.isBlank()) {
            throw new IllegalArgumentException(
                    "contact is required (the VAPID 'sub' claim: optional in RFC 8292 §2.1, required by push2u)");
        }
        return contact;
    }

    /**
     * Encrypt, sign, POST (with retries), and interpret the result. Blocks until done.
     *
     * <p>The payload is size-checked first, before any cryptography or network I/O, against both
     * {@link Builder#maxEncryptedBodyBytes(int)} and {@link Builder#recordSize(int)}; an oversized payload throws
     * {@link IllegalArgumentException} rather than being sent for the push service to reject with {@code 413}. The
     * {@link EndpointPolicy} the sender was built with runs next, on every send without exception — still ahead of the
     * encryption, the VAPID signature (which under an external {@link VapidSigner} is a remote Vault/KMS operation) and
     * the HTTP request, so a rejected endpoint costs none of them.
     *
     * @param subscription the target subscription
     * @param message the message to send
     * @return the send result
     * @throws IllegalArgumentException if the payload does not fit the configured body limit, or if the configured
     *     record size is too small for it
     * @throws EndpointRejectedException if this sender's endpoint policy rejects the subscription's endpoint
     * @throws PushCryptoException if the encryption or the VAPID signature cannot be produced — including a
     *     {@link VapidSigner} whose remote key service is unreachable or refuses the operation, which may be transient
     * @throws PushDeliveryException if the transport fails to complete the request; an HTTP error status is not this
     *     but a {@link PushResult}
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
        // Unconditional, and before the encryption as well as the signature and the POST: a policy
        // rejection is a verdict on the subscription, and reaching it must not depend on — or pay
        // for — any per-send cryptography. The policy also runs before the token cache is
        // consulted, and that cache is the sender's only mutable state, so a policy that throws
        // (a rejection or its own defect) leaves nothing to corrupt for later sends.
        endpointPolicy.validate(endpoint);
        byte[] body = encryptor.encrypt(subscription.p256dh(), subscription.auth(), payload, recordSize);
        String authorization = authorization(Origin.serialize(endpoint));
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
     * this sender's {@link EndpointPolicy} rejects — completes the returned future exceptionally
     * ({@link IllegalArgumentException}, {@link EndpointRejectedException}) instead of throwing from this call. The
     * async path runs through the same {@link #send} pipeline, so the policy guards it identically: no send through
     * this sender reaches the network without passing the policy.
     *
     * <p>The same holds for the rest of what {@link #send} throws: a {@link PushCryptoException} or a
     * {@link PushDeliveryException} completes the returned future exceptionally rather than propagating from this call,
     * and reaches the caller wrapped in a {@link java.util.concurrent.CompletionException} on {@code join} or an
     * {@link java.util.concurrent.ExecutionException} on {@code get}. An HTTP error status is not among them — it is a
     * {@link PushResult}, and the future completes normally with it.
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

    /**
     * The {@code Authorization} header value for one send to {@code audience}: a cached one while it is fresh, a newly
     * signed one otherwise — and always a newly signed one when reuse is off. Fresh means both of an entry's bounds
     * still hold; see {@link CachedJwt#isFresh}.
     */
    private String authorization(String audience) {
        if (!jwtReuse) {
            return Vapid.authorizationHeader(
                    signer, audience, contact, clock.instant().plus(jwtExpiry));
        }
        // A fresh publicKey() read on every lookup, encoded exactly as the header's k parameter is
        // encoded: an entry is only ever served to the signer in the identity it currently
        // publishes, so an advertised key that moved since the entry was filed misses here and the
        // stale identity is replaced. Deliberately the raw publicKey() bytes rather than
        // publicKeyBase64Url(), which an implementation may override: the lookup has to track the
        // value the wire carries, not what an override says about it.
        JwtCacheKey key = new JwtCacheKey(audience, Base64Url.encode(signer.publicKey()));
        synchronized (jwtCache) {
            CachedJwt cached = jwtCache.get(key);
            if (cached != null) {
                // Wall reading first, monotonic reading last. Of the two orders this is the one
                // that over-estimates monotonic elapsed time: a pause between the two statements
                // (nothing in Java bounds it) only makes the entry look older, which at worst costs
                // one signature. The opposite order would serve an entry past its monotonic bound
                // by the length of the pause — exactly when a backwards wall step has left that
                // bound the only honest one.
                Instant wallNow = clock.instant();
                long nowNanos = ticker.nanoTime();
                if (cached.isFresh(wallNow, nowNanos)) {
                    return cached.authorization;
                }
                jwtCache.remove(key);
            }
        }
        // Look up, release, sign, publish: the signature runs outside the monitor (see jwtCache's
        // contract for why). Two threads missing on one audience concurrently is a benign race —
        // two independently valid tokens, one published and the other used for its own send only.
        // The monotonic anchor is read before the wall reading exp is computed from: at mint,
        // over-estimating elapsed time means anchoring as early as possible, so that a pause
        // between the two readings can only shorten the entry's life, never let a later backwards
        // wall step lengthen it.
        long anchorNanos = ticker.nanoTime();
        Instant mintWall = clock.instant();
        Instant expiry = mintWall.plus(jwtExpiry);
        Vapid.SignedHeader signed = Vapid.signedAuthorizationHeader(signer, audience, contact, expiry);
        // The claim went on the wire as whole seconds, so staleness is judged against that value —
        // per RFC 7519 §4.1.4 the token is invalid from the second exp names, up to just under a
        // second earlier than the Instant computed above. The renewal margin must not be what
        // hides the difference: this has to be right at jwtRenewBefore ZERO.
        Instant effectiveExpiry = Instant.ofEpochSecond(expiry.getEpochSecond());
        // Compared rather than subtracted first: the margin is bounded below at zero but not above,
        // and a subtraction with an enormous margin would overflow. A margin at or above the
        // token's whole life means nothing is cached and every send signs — a consequence of the
        // configuration, never an error — so the entry is simply not published.
        Duration tokenLife = Duration.between(mintWall, effectiveExpiry);
        if (jwtRenewBefore.compareTo(tokenLife) < 0) {
            // Both bounds allow the same span, and whichever is reached first ends the entry: the
            // wall clock arriving within jwtRenewBefore of the effective exp, or the monotonic
            // clock having run for (effective exp − the wall reading it was computed from) −
            // jwtRenewBefore. Equal spans are the point — a monotonic bound of the whole jwtExpiry
            // would hand a backwards wall step up to jwtRenewBefore of extra life, presenting the
            // token right up to exp with nothing left for the retry window or clock skew.
            Duration span = tokenLife.minus(jwtRenewBefore);
            CachedJwt minted = new CachedJwt(
                    signed.headerValue(), anchorNanos, span.toNanos(), effectiveExpiry.minus(jwtRenewBefore));
            JwtCacheKey mintedKey = new JwtCacheKey(audience, signed.publicKeyBase64Url());
            synchronized (jwtCache) {
                jwtCache.putIfAbsent(mintedKey, minted);
            }
        }
        return signed.headerValue();
    }

    /**
     * The token cache's key: one audience under the signer's currently advertised public key, the key as the base64url
     * string the header's {@code k} parameter carries. A string rather than the raw bytes on purpose:
     * {@link VapidSigner#publicKey()} returns a fresh array on every call by contract, and arrays compare by identity,
     * so a {@code byte[]} component would produce a cache that compiles and silently never hits.
     */
    private record JwtCacheKey(String audience, String publicKeyBase64Url) {}

    /**
     * One cached {@code Authorization} value with the two readings its life is judged by. A plain class rather than a
     * record so that the bearer credential it holds can never reach a generated {@code toString}.
     */
    private static final class CachedJwt {

        /** The full header value — a bearer credential: never in a {@code toString}, a log line or a message. */
        private final String authorization;
        /** The monotonic reading taken at mint, before the wall reading {@code exp} was computed from. */
        private final long anchorNanos;
        /** How long the monotonic clock may run before renewal — the same span the wall bound allows. */
        private final long spanNanos;
        /** The effective (whole-second) {@code exp} less the renewal margin; served strictly before it only. */
        private final Instant wallDeadline;

        private CachedJwt(String authorization, long anchorNanos, long spanNanos, Instant wallDeadline) {
            this.authorization = authorization;
            this.anchorNanos = anchorNanos;
            this.spanNanos = spanNanos;
            this.wallDeadline = wallDeadline;
        }

        /**
         * Whether this entry may still be served. Both bounds are checked and either ends it: the monotonic clock must
         * not have run for the span, and the wall clock must be strictly before the deadline — strictly, because RFC
         * 7519 §4.1.4 makes the token invalid from the second {@code exp} names, not after it. A negative elapsed
         * reading is one from a later timeline, which the JVM's single per-instance origin makes impossible on a
         * conforming platform — it discards the entry for the cost of one comparison.
         */
        private boolean isFresh(Instant wallNow, long nowNanos) {
            long elapsedNanos = nowNanos - anchorNanos;
            return elapsedNanos >= 0 && elapsedNanos < spanNanos && wallNow.isBefore(wallDeadline);
        }
    }

    /**
     * An access-ordered LRU map bounded at the configured capacity. Overflow evicts the least recently used entry, so a
     * full cache degrades to signing per send — today's cost — and never to a refusal: the audience set is chosen by
     * whoever supplies subscriptions, and a bound the deployment configured must not become a delivery failure.
     */
    private static final class JwtCache extends LinkedHashMap<JwtCacheKey, CachedJwt> {

        @Serial
        private static final long serialVersionUID = 1L;

        /** Not named {@code capacity} to keep it apart from {@link LinkedHashMap}'s own notion of capacity. */
        private final int maxEntries;

        private JwtCache(int maxEntries) {
            // Access order is what makes get() move an entry to the tail and eviction pick the head
            // — and also what makes even a read a mutation, hence the monitor around every access.
            super(16, 0.75f, true);
            this.maxEntries = maxEntries;
        }

        @Override
        protected boolean removeEldestEntry(Map.Entry<JwtCacheKey, CachedJwt> eldest) {
            return size() > maxEntries;
        }
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
     * Configures and builds a {@link PushSender}. Everything required — the key source, the contact and the
     * {@link EndpointPolicy} — is a parameter of {@link PushSender#builder(VapidKeys, String, EndpointPolicy)} /
     * {@link PushSender#builder(VapidSigner, String, EndpointPolicy)}, so every step here is optional with a sensible
     * default and {@link #build()} cannot refuse.
     */
    public static final class Builder {

        /** Exactly one of {@code vapidKeys} and {@code signer} is non-null — the factory overload chose which. */
        @Nullable
        private final VapidKeys vapidKeys;

        @Nullable
        private final VapidSigner signer;

        private final String contact;

        private final EndpointPolicy endpointPolicy;

        @Nullable
        private PushHttpClient httpClient;

        @Nullable
        private Provider cryptoProvider;

        private RetryPolicy retryPolicy = RetryPolicy.defaults();
        private Duration jwtExpiry = Duration.ofHours(12);
        private Duration defaultTtl = Duration.ofDays(1);
        private int recordSize = WebPushEncryptor.DEFAULT_RECORD_SIZE;
        private int maxEncryptedBodyBytes = WebPushEncryptor.DEFAULT_MAX_ENCRYPTED_BODY_BYTES;
        private Duration jwtRenewBefore = Duration.ofMinutes(5);
        private boolean jwtReuse = true;
        private int jwtCacheSize = 64;
        private Sleeper sleeper = Sleeper.REAL;
        private Clock clock = Clock.systemUTC();
        private Ticker ticker = Ticker.REAL;

        @Nullable
        private Executor executor;

        private Builder(
                @Nullable VapidKeys vapidKeys,
                @Nullable VapidSigner signer,
                String contact,
                EndpointPolicy endpointPolicy) {
            this.vapidKeys = vapidKeys;
            this.signer = signer;
            this.contact = contact;
            this.endpointPolicy = endpointPolicy;
        }

        /**
         * The HTTP transport; defaults to {@link JdkPushHttpClient}.
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
         * Whether a signed VAPID token is reused for later sends to the same push-service origin until it nears its
         * {@code exp}; default {@code true}. Nothing about the token is per-message — its claims are the origin, the
         * contact and the expiry — and RFC 8292 §5 encourages application servers to reuse tokens, which also lets the
         * push service cache the result of verifying the signature. The reused value is the whole signed
         * {@code Authorization} header, held per origin under the public key the {@link VapidSigner} currently
         * advertises, renewed within {@link #jwtRenewBefore(Duration)} of its {@code exp} and bounded by
         * {@link #jwtCacheSize(int)}.
         *
         * <p>{@code false} is the declared off switch: every send builds and signs a fresh JWT, the behaviour this
         * library always had. It needs no release to reach for — the specification asks for reuse, but should a push
         * service nevertheless refuse a token it has seen before (the shape of that failure: 401 or 403 on every send
         * to an origin after the first, with a signature that verifies), this is the remedy. It also collapses to zero
         * the delay with which a misconfigured signer — one whose signing key rotates under a constant advertised key —
         * surfaces its misconfiguration, and it removes the residency of a bearer credential in process memory for a
         * deployment that treats a heap dump as reachable.
         *
         * @param jwtReuse whether to reuse signed tokens until they near expiry
         * @return this builder
         */
        public Builder jwtReuse(boolean jwtReuse) {
            this.jwtReuse = jwtReuse;
            return this;
        }

        /**
         * The safety margin: how long before a cached token's {@code exp} it stops being served and a fresh one is
         * signed; default 5 minutes, never negative. The margin is what keeps a send that picks a token up just before
         * the boundary still presenting a valid one at its last retry — with {@code Retry-After} honoured up to
         * {@link RetryPolicy#maxBackoff()}, a send can legitimately outlive its token's final minutes — and what covers
         * clock skew against the push service, which checks {@code exp} on its own clock. Both are absolute quantities,
         * which is why this is an absolute duration and not a fraction of {@link #jwtExpiry(Duration)}. A deployment
         * whose retry policy or {@code Retry-After} tolerance allows a much longer send raises it; the library does not
         * derive one knob from the other, because a send's duration also includes HTTP timeouts it does not own.
         *
         * <p>{@link Duration#ZERO} is legal and is <em>not</em> an off switch — zero margin is the most reuse, holding
         * the token to its last second, with the skew consequences of saying so; {@link #jwtReuse(boolean)} is the
         * declared switch. A value at or above {@code jwtExpiry} is legal too and simply means the margin has swallowed
         * the token's whole life, so every send signs afresh — a consequence of the configuration, never an error,
         * which is why {@link #build()} performs no cross-validation between the two.
         *
         * @param jwtRenewBefore the renewal margin before the token's {@code exp}
         * @return this builder
         * @throws IllegalArgumentException if {@code jwtRenewBefore} is negative
         */
        public Builder jwtRenewBefore(Duration jwtRenewBefore) {
            Objects.requireNonNull(jwtRenewBefore, "jwtRenewBefore");
            if (jwtRenewBefore.isNegative()) {
                throw new IllegalArgumentException("jwtRenewBefore must not be negative, was " + jwtRenewBefore);
            }
            this.jwtRenewBefore = jwtRenewBefore;
            return this;
        }

        /**
         * The bound on the token cache, in entries; default 64, evicting least-recently-used. The bound is what makes
         * the cache safe to hold at all rather than a tuning knob: the audiences a sender meets are the origins of the
         * endpoints inside the {@link Subscription}s it is handed, a set exactly as trustworthy as wherever those
         * subscriptions arrive from, and an unbounded map keyed by it would be a memory-exhaustion path under any
         * policy that admits more than a fixed list of origins. Overflow degrades to signing per send — the cost the
         * library always paid — and never to a refusal, because a bound this deployment chose must not become a
         * delivery failure. The default sits well above the four browser push services while leaving room for the
         * vendors whose hostnames vary.
         *
         * <p>Below one is rejected rather than read as "cache nothing": {@link #jwtReuse(boolean)} is the declared way
         * to switch reuse off, and the cap is not a second spelling of it.
         *
         * @param jwtCacheSize the maximum number of cached tokens; at least 1
         * @return this builder
         * @throws IllegalArgumentException if {@code jwtCacheSize} is less than 1
         */
        public Builder jwtCacheSize(int jwtCacheSize) {
            if (jwtCacheSize < 1) {
                throw new IllegalArgumentException("jwtCacheSize must be at least 1, was " + jwtCacheSize
                        + " (to switch token reuse off, use jwtReuse(false) — the cache bound is not the switch)");
            }
            this.jwtCacheSize = jwtCacheSize;
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

        // Package-private test seam: drive the monotonic half of a cached token's two bounds.
        // Without it that bound is untestable — pinning the Clock leaves the monotonic side the
        // test's own real elapsed microseconds, and every case that turns on the bound would pass
        // for the wrong reason.
        Builder ticker(Ticker ticker) {
            this.ticker = Objects.requireNonNull(ticker, "ticker");
            return this;
        }

        /**
         * Builds the {@link PushSender}. There is nothing left to validate: the factory method took everything
         * required, and every optional step validated its value where it was set.
         *
         * @return the configured sender
         */
        public PushSender build() {
            return new PushSender(this);
        }
    }
}
