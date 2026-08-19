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
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import org.jspecify.annotations.Nullable;

/**
 * The send facade: encrypts a {@link PushMessage} for a {@link Subscription} (RFC 8291), signs the VAPID JWT (RFC
 * 8292), POSTs the {@code aes128gcm} body to the endpoint (RFC 8030), and reports what became of the requested send as
 * a {@link PushOutcome}.
 *
 * <p><b>One send is one POST at most, and the library does not retry.</b> Every deployment sending push at volume
 * already owns a retrier — a job engine, a queue with redelivery, a resilience library — and a loop inside this method
 * could see none of what that retrier knows: the deployment's retry budget, its dead-letter path, what survives a
 * restart. So the classification a repeat decision needs is published on the outcome instead, together with what the
 * push service's {@code Retry-After} said, and the schedule is the caller's. A send holds nothing across attempts that
 * a second call would not rebuild: the endpoint policy re-runs, the VAPID token is re-minted or served from its cache,
 * and the body is re-encrypted under a fresh ephemeral key and salt, which RFC 8291 §2 has the application server
 * generate per message in any case.
 *
 * <p>Build it with {@link #builder(VapidKeys, String, EndpointPolicy)} (the default in-JVM signer) or
 * {@link #builder(VapidSigner, String, EndpointPolicy)} (an external signer, which supplies the VAPID public key
 * itself). The key source, the contact and the {@link EndpointPolicy} are the three required values, so they are the
 * factory method's parameters — the overload chooses the key source, and an incomplete sender cannot be expressed;
 * everything on the {@link Builder} is optional.
 *
 * <p>Everything a fan-out meets in normal running arrives as a value of {@link PushOutcome}, a dead subscription and a
 * refused endpoint included: pruning a store on {@link PushOutcome.SubscriptionExpired} is expected control flow, not
 * an error. What still throws is using the API wrongly, a defect the caller cannot act on per send, and cancellation —
 * see {@link #send} for the enumeration.
 *
 * <p><b>A built sender is thread-safe: built once and shared across every sending thread</b> — {@link #sendAsync} makes
 * concurrent sends the normal case rather than an edge one. Its configuration is immutable; the one thing it holds
 * beyond configuration is an internal bounded cache of the VAPID {@code Authorization} values it has itself signed (see
 * {@link Builder#jwtReuse(boolean)}), safely shared across those same threads and reconstructible at any moment by
 * signing again — losing it costs one signature, never a delivery. The same thread-safety obligation falls on the three
 * SPIs the sender calls ({@link VapidSigner}, {@link PushHttpClient}, {@link EndpointPolicy}), each of which states it.
 */
// CouplingBetweenObjects and GodClass: this is the facade over the whole send pipeline — the size
// precondition, the endpoint policy, the encryption, the VAPID signature with its token cache, the
// transport, the status classification and the seam-signal conversions are its collaborators by
// design. Both metrics fire on that coordinator shape; carving it into pieces to satisfy them
// would scatter one pipeline — and the one enumeration of what converts to an outcome — across
// classes that mean nothing on their own.
@SuppressWarnings({"PMD.CouplingBetweenObjects", "PMD.GodClass"})
public final class PushSender {

    /**
     * How many cause-chain elements the interruption walk visits before declaring the chain manufactured. Real chains
     * count their elements in ones and tens — a handful of wrappers around one root failure — so a thousand is not a
     * chain being walked but one being generated, and generous by two orders of magnitude costs no honest diagnostics
     * anything.
     */
    private static final int CAUSE_CHAIN_CEILING = 1000;

    private final VapidSigner signer;
    private final String contact;
    private final WebPushEncryptor encryptor;
    private final PushHttpClient httpClient;
    private final Duration jwtExpiry;
    private final Duration defaultTtl;
    /** Derived once from the configured body ceiling: the ceiling less the fixed 103-octet overhead. */
    private final int maximumPayloadBytes;
    /**
     * Derived once from {@link #maximumPayloadBytes}, never configured: the smallest {@code rs} whose record carries
     * exactly that plaintext, so the advertised record size declares exactly the capacity this sender is able to use
     * and the record-size rule can never be the bound that binds on a send.
     */
    private final int recordSize;

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
        this.jwtExpiry = builder.jwtExpiry;
        this.defaultTtl = builder.defaultTtl;
        this.maximumPayloadBytes = WebPushEncryptor.maxPlaintextBytes(builder.maxEncryptedBodyBytes);
        // Exact narrowing: the maximum above is at most Integer.MAX_VALUE - 103, so the derived rs
        // is at most Integer.MAX_VALUE - 85 and toIntExact cannot throw on any builder-accepted
        // configuration — it is here so a wrap would fail loudly rather than mint a negative rs.
        this.recordSize = Math.toIntExact(WebPushEncryptor.recordSizeForMaxPlaintext(maximumPayloadBytes));
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
     * Encrypt, sign, POST once, and report what became of the requested send. Blocks until done.
     *
     * <p>The payload is size-checked first, before any cryptography or network I/O, against the largest plaintext
     * {@link Builder#maxEncryptedBodyBytes(int)} admits — the ceiling less the fixed 103-octet {@code aes128gcm}
     * overhead; a payload that does not fit is reported as {@link PushOutcome.PayloadRejected}, in plaintext octets,
     * rather than sent for the push service to refuse with {@code 413}. The same question is answerable before a send
     * through {@link #assessPayloadSize(byte[])}, and this check runs whether or not it was asked: an earlier
     * assessment is never trusted in its place. The {@link EndpointPolicy} the sender was built with runs next, on
     * every send without exception — still ahead of the encryption, the VAPID signature (which under an external
     * {@link VapidSigner} is a remote Vault/KMS operation) and the HTTP request, so a rejected endpoint costs none of
     * them and is reported as {@link PushOutcome.EndpointRejected}.
     *
     * <p><b>Three seam signals convert to outcomes, and no others.</b> An {@link EndpointRejectedException} from the
     * policy becomes {@link PushOutcome.EndpointRejected}; a {@link VapidSignerUnavailableException} from the signer
     * becomes {@link PushOutcome.SignerUnavailable}; a {@link PushDeliveryException} from the transport becomes
     * {@link PushOutcome.Indeterminate}. Any other {@code RuntimeException} out of a consumer-written seam is a defect
     * in that implementation, not an operational condition, and propagates unchanged. What this method itself throws:
     *
     * <ul>
     *   <li>{@link PushCryptoException} — the encryption or the signature cannot be produced for a reason that recurs:
     *       a cryptographic defect, an unusable provider, or a key-service misconfiguration. Not a custodian that
     *       cannot sign <em>now</em>, which is the {@link PushOutcome.SignerUnavailable} outcome;
     *   <li>{@link PushInterruptedException} — the sending thread was interrupted. The conversion above is refused, on
     *       the transport and signer paths alike, whenever the seam's exception carries an {@link InterruptedException}
     *       in its cause chain <em>or</em> the current thread's interrupt status is set — neither test alone is sound,
     *       since an interruption can surface as an {@link java.io.InterruptedIOException} with no
     *       {@code InterruptedException} beneath it, and a transport can attach a cause without re-setting the flag.
     *       The interrupt status is re-set on the calling thread before the throw, as that type promises;
     *   <li>{@link IllegalArgumentException} / {@link NullPointerException} — an argument that is not a legal value of
     *       its parameter.
     * </ul>
     *
     * <p><b>Repeating a send is the caller's decision, and a repeated send re-bases the message's lifetime</b>: RFC
     * 8030 §5.2 counts {@code TTL} from the moment the push service receives the message, so an attempt scheduled hours
     * after this one carries a fresh lifetime unless the caller decrements the {@code TTL} it passes by the time
     * already spent.
     *
     * @param subscription the target subscription
     * @param message the message to send
     * @return what became of the requested send
     * @throws PushCryptoException if the encryption or the VAPID signature cannot be produced for a reason that recurs
     * @throws PushInterruptedException if the sending thread was interrupted, with the interrupt status re-set before
     *     the throw
     */
    // PreserveStackTrace / AvoidThrowingNewInstanceOfSameException: URI.create's own
    // IllegalArgumentException carries the raw capability URL, so it is replaced by one built from
    // the redacted endpoint and the cause is deliberately not attached (see Endpoints.redact).
    @SuppressWarnings({"PMD.PreserveStackTrace", "PMD.AvoidThrowingNewInstanceOfSameException"})
    public PushOutcome send(Subscription subscription, PushMessage message) {
        Objects.requireNonNull(subscription, "subscription");
        Objects.requireNonNull(message, "message");

        // The uncopied snapshot: the pipeline only reads it — the pre-flight reads the length, the
        // encryptor copies before padding — and a send leaves it byte-for-byte unchanged.
        byte[] payload = message.uncopiedPayload();
        if (payload.length > maximumPayloadBytes) {
            return new PushOutcome.PayloadRejected(payload.length, maximumPayloadBytes);
        }

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
        try {
            endpointPolicy.validate(endpoint);
        } catch (EndpointRejectedException e) {
            // The policy's contract keeps the raw endpoint out of its message; the redacted form
            // beside it is this library's own rendering, safe whatever the policy wrote.
            String reason;
            try {
                reason = Objects.requireNonNullElse(e.getMessage(), "");
            } catch (RuntimeException defect) {
                // The read is consumer-overridable code, and a rejection the policy already
                // classified must not leave as the accessor's complaint. Nor may that complaint
                // travel: it was written by nobody who accepted the policy seam's redaction
                // contract, so its message, its class name and its rendering may all carry the raw
                // capability URL. The fixed text below is this library's own, distinguishable from
                // "" — what a null message renders as — and there is nowhere to record the defect:
                // this outcome keeps two strings, and the exception is discarded with this
                // conversion.
                reason = "endpoint policy rejected the endpoint; reason unavailable";
            }
            return new PushOutcome.EndpointRejected(Endpoints.redact(subscription.endpoint()), reason);
        }
        byte[] body = encryptor.encrypt(subscription.p256dh(), subscription.auth(), payload, recordSize);
        String authorization;
        try {
            authorization = authorization(Origin.serialize(endpoint));
        } catch (VapidSignerUnavailableException e) {
            // A signing call has no effect on the push service, so whatever became of it, no
            // notification exists to be duplicated — which is what lets an unanswered signing
            // exchange be NotAttempted where the unanswered POST below is Indeterminate.
            if (isInterruption(e)) {
                throw interrupted("send interrupted while obtaining the VAPID signature", e);
            }
            return new PushOutcome.SignerUnavailable(e);
        }
        Map<String, String> headers = requestHeaders(authorization, message);

        PushResponse response;
        try {
            response = httpClient.post(endpoint, headers, body);
        } catch (PushDeliveryException e) {
            if (isInterruption(e)) {
                throw interrupted(
                        "send interrupted during the POST to " + Endpoints.redact(subscription.endpoint()), e);
            }
            return new PushOutcome.Indeterminate(e);
        }
        return classify(response);
    }

    /**
     * Whether {@code payload} fits this sender's configuration, answered before any send so that an application
     * rendering a notification can shorten it rather than discover the limit by outcome — the concrete case is
     * translation, where the same notification fits in one language and not in another. The answer is
     * {@link PayloadSizeAssessment.WithinLimit} or {@link PayloadSizeAssessment.ExceedsLimit}, the latter carrying the
     * payload's size and the budget for the next render, both in plaintext octets — the same pair
     * {@link PushOutcome.PayloadRejected} reports when a send is refused for size.
     *
     * <p>This method reads the array's length, copies nothing and retains nothing. It takes the serialized octets
     * rather than a length so the unit is never something the caller converts to — a hand-written comparison of a
     * string length against a byte budget passes for every non-ASCII notification it should fail — and it takes them
     * rather than a {@link PushMessage} so a payload that will not fit costs no message construction; the reference
     * flow serializes, asks, and only then builds. A caller holding a built message asks through
     * {@link PushMessage#payload()}, which copies.
     *
     * <p>Asking is optional, and being told is not: {@link #send} checks the payload again and reports an oversized one
     * as {@link PushOutcome.PayloadRejected} whether or not it was assessed first.
     *
     * @param payload the serialized payload, exactly as it would be handed to {@link PushMessage}
     * @return whether the payload fits, and if not, the budget to render against
     */
    public PayloadSizeAssessment assessPayloadSize(byte[] payload) {
        Objects.requireNonNull(payload, "payload");
        if (payload.length > maximumPayloadBytes) {
            return new PayloadSizeAssessment.ExceedsLimit(payload.length, maximumPayloadBytes);
        }
        return new PayloadSizeAssessment.WithinLimit();
    }

    /**
     * The status classification, taken per status rather than per class; each carve-out's ground is on the Javadoc of
     * the variant that carries it. The {@code Retry-After} header is parsed once for any answered failure, because it
     * classifies a {@code 413} (RFC 9110 §15.5.14 has a server generate it there only if the condition is temporary)
     * and travels on the retryable variant as the value the caller schedules against.
     */
    private PushOutcome classify(PushResponse response) {
        int code = response.statusCode();
        if (code >= 200 && code < 300) {
            return new PushOutcome.Accepted(code);
        }
        if (code == 404 || code == 410) {
            return new PushOutcome.SubscriptionExpired(code);
        }
        Optional<Duration> retryAfter =
                response.header("Retry-After").flatMap(value -> RetryAfter.parse(value, clock.instant()));
        if (isRetryable(code, retryAfter.isPresent())) {
            return new PushOutcome.RetryableFailure(code, retryAfter);
        }
        return new PushOutcome.NonRetryableFailure(code);
    }

    /**
     * Which answered failures a repeat may be useful for. The named statuses and the five carve-outs each rest on their
     * defining specification's own words — the grounds are spelled out on {@link PushOutcome.RetryableFailure} and
     * {@link PushOutcome.NonRetryableFailure}, where a caller reads them. A 5xx neither list names falls to the class
     * (RFC 9110 §15.6: a statement about the server, not the request), chosen so that an unregistered or
     * later-registered 5xx is never permanent by omission.
     */
    private static boolean isRetryable(int code, boolean parseableRetryAfter) {
        return switch (code) {
            case 408, 421, 429 -> true;
            // RFC 9110 §15.5.14: a Retry-After on a 413 is the server saying it refused this
            // moment, not this request — the header, not the number, classifies here.
            case 413 -> parseableRetryAfter;
            // RFC 9110 §15.6.2 (501) and §15.6.6 (505): a byte-identical POST is answered
            // identically. RFC 2295 §8.1 (506): a configuration error, ended by an edit, not by
            // time. RFC 5842 §7.2 (508): a statement about the resource graph the request named.
            // RFC 6585 §6 (511): an intercepting proxy reporting the sending host has no network
            // access, which no repeat obtains.
            case 501, 505, 506, 508, 511 -> false;
            default -> code >= 500 && code < 600;
        };
    }

    /**
     * The facade's interruption test — a disjunction, because neither half is sound alone: an interruption can surface
     * as a {@link java.nio.channels.ClosedByInterruptException} or an {@link java.io.InterruptedIOException} with no
     * {@link InterruptedException} beneath it (the flag half catches those), and a transport can attach a cause without
     * re-setting the flag (the chain half catches that). Kept here rather than obliged onto the seams, so that no
     * transport has to recognise a cancellation.
     *
     * <p>The chain half runs on consumer-overridable code — {@code getCause()} — and is guarded: where a read throws a
     * {@code RuntimeException}, or the chain outgrows any depth honest diagnostics reach, the walk stops and the defect
     * is recorded as a suppressed exception on the seam's own failure — bounded per instance, so a preallocated
     * exception thrown for every call does not collect one of these per send — which both conversions that reach this
     * test hand to the caller inside the outcome. What is lost at that point is unknowable by anybody: whether an
     * {@link InterruptedException} sat beyond the break in the chain. The conservative answer is chosen — invent
     * nothing, and keep the seam's classification unless the thread's interrupt flag says otherwise. That flag is the
     * method's single exit, asked after the walk however the walk ended, so an interruption arriving while an ordinary
     * walk runs is seen through the same door.
     */
    private static boolean isInterruption(RuntimeException failure) {
        if (Thread.currentThread().isInterrupted()) {
            return true;
        }
        // The walk guards against a defective seam's getCause() in both ways a chain can fail to
        // end — a send must neither spin nor grow the seen-set without bound over someone else's
        // broken diagnostics. The identity set ends a cyclic chain; the ceiling ends an acyclic
        // one that never runs out, which a getCause() fabricating a fresh wrapper on every call
        // produces and no identity test can detect. Hitting the ceiling is treated exactly like a
        // throwing read: record the defect, stop, and let the tail below ask the flag.
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        try {
            for (Throwable cause = failure; cause != null && seen.add(cause); cause = cause.getCause()) {
                if (cause instanceof InterruptedException) {
                    return true;
                }
                if (seen.size() >= CAUSE_CHAIN_CEILING) {
                    Suppression.suppress(
                            failure,
                            new IllegalStateException("cause chain still unfinished after " + CAUSE_CHAIN_CEILING
                                    + " elements; a chain this deep is being generated, not walked, so the walk"
                                    + " stops here"));
                    break;
                }
            }
        } catch (RuntimeException defect) {
            Suppression.suppress(failure, defect);
        }
        return Thread.currentThread().isInterrupted();
    }

    /**
     * Builds the cancellation a send reports, re-setting the interrupt status on the current thread first — the
     * synchronous promise, unconditionally kept even where only the cause chain carried the interruption. On the
     * asynchronous path this runs on the worker, so the worker's flag is re-set before the future completes, which is
     * owed to the executor and to whatever that thread runs next.
     */
    private static PushInterruptedException interrupted(String description, RuntimeException cause) {
        Thread.currentThread().interrupt();
        return new PushInterruptedException(description, cause);
    }

    /**
     * {@link #send} on the executor configured via {@link Builder#executor(Executor)} — by default a library-owned
     * virtual-thread-per-task executor, never the common ForkJoinPool. Each async send blocks its thread for the whole
     * exchange, which a virtual thread absorbs by parking without pinning a carrier thread.
     *
     * <p>This governs the send itself. Async continuations the caller chains onto the returned future
     * ({@code thenApplyAsync} and friends without an explicit executor) still use {@link CompletableFuture}'s default —
     * the common ForkJoinPool; pass an executor there too if a continuation blocks.
     *
     * <p>If a caller-supplied executor rejects the task, its {@link java.util.concurrent.RejectedExecutionException}
     * propagates from this call rather than completing the returned future exceptionally. Everything else runs inside
     * the queued task, through the same {@link #send} pipeline: every outcome — {@link PushOutcome.PayloadRejected} and
     * {@link PushOutcome.EndpointRejected} included — completes the returned future <em>normally</em>, and no send
     * through this sender reaches the network without passing the policy. What {@link #send} throws — a
     * {@link PushCryptoException}, a defect out of a consumer seam — completes the future exceptionally instead, and
     * reaches the caller wrapped in a {@link java.util.concurrent.CompletionException} on {@code join} or an
     * {@link java.util.concurrent.ExecutionException} on {@code get}.
     *
     * <p><b>An interrupted send completes the future exceptionally with {@link PushInterruptedException}, and the
     * future is not cancelled</b>: {@code isCancelled()} answers {@code false}, so a caller's own {@code cancel} stays
     * distinguishable from a worker stopped mid-flight. The interrupt status on whatever thread reads the future is not
     * promised — that thread was never interrupted — and the worker's own flag is re-set on the worker before the
     * future completes. What travels is the type and its cause chain.
     *
     * <p>A fan-out on this path that meets {@link PushOutcome.SignerUnavailable} should stop <em>submitting</em>, which
     * takes more than reacting to the outcome: by the time the first outcome is read, a caller that already handed the
     * whole list to the executor has had its burst against the dead custodian decided. That variant's documentation
     * carries the shape that works — bounded concurrency, rows fed in as outcomes come back.
     *
     * @param subscription the target subscription
     * @param message the message to send
     * @return a future completing with what became of the requested send
     */
    public CompletableFuture<PushOutcome> sendAsync(Subscription subscription, PushMessage message) {
        Executor target = executor != null ? executor : DefaultAsyncExecutor.INSTANCE;
        return CompletableFuture.supplyAsync(() -> send(subscription, message), target);
    }

    /**
     * The default {@code sendAsync} executor, created lazily via the holder-class idiom: building a sender that only
     * ever calls the synchronous {@link #send} never touches this class, so no executor is created. A
     * virtual-thread-per-task executor is the right default for a workload of blocking HTTP calls — virtual threads
     * park without pinning a carrier thread, and the executor holds no OS threads when idle. The library never shuts it
     * down, which is safe: idle it holds no resources, and its threads are daemons, so it cannot keep the JVM alive.
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
            // token right up to exp with nothing left for clock skew.
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

        private Duration jwtExpiry = Duration.ofHours(12);
        private Duration defaultTtl = Duration.ofDays(1);
        private int maxEncryptedBodyBytes = WebPushEncryptor.DEFAULT_MAX_ENCRYPTED_BODY_BYTES;
        private Duration jwtRenewBefore = Duration.ofMinutes(5);
        private boolean jwtReuse = true;
        private int jwtCacheSize = 64;
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
            this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
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
         * signed; default 5 minutes, never negative. The margin covers clock skew against the push service, which
         * checks {@code exp} on its own clock — skew is minutes whatever the token's lifetime is — and the tail of a
         * send that picks a token up just before the renewal boundary and still has to traverse an HTTP exchange whose
         * timeouts this library does not own. Both are absolute quantities, which is why this is an absolute duration
         * and not a fraction of {@link #jwtExpiry(Duration)}; a deployment whose sends can legitimately run much longer
         * — a generous transport timeout, say — raises it, and the library does not derive one knob from the other.
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
         * The ceiling on the encrypted HTTP entity body, in bytes; default 4096. This is the sender's one size
         * parameter.
         *
         * <p>RFC 8030 §7.2 lets a push service refuse a body larger than 4096 octets, so the limit is expressed on the
         * body rather than on the plaintext. The single-record {@code aes128gcm} format this library emits adds a fixed
         * 103 octets — an 86-octet RFC 8188 header (salt 16, {@code rs} 4, {@code idlen} 1, {@code keyid} 65), the
         * padding delimiter (1) and the AEAD_AES_128_GCM tag (16) — so the default admits 3993 octets of plaintext, the
         * figure RFC 8291 §4 derives. {@link PushSender#send} reports anything larger as
         * {@link PushOutcome.PayloadRejected} before encrypting or contacting the push service, and
         * {@link PushSender#assessPayloadSize(byte[])} answers the same question before a send.
         *
         * <p>The record size the RFC 8188 header advertises is derived from this value at {@link #build()} — the
         * largest plaintext the ceiling admits, plus the delimiter, the tag and the one octet RFC 8291 §4 requires
         * {@code rs} to exceed that sum by, which is the ceiling less 85 — so {@code rs} declares exactly the plaintext
         * capacity this sender is able to use and is never configured on its own. Raising this ceiling is therefore the
         * whole of raising the limit.
         *
         * <p>Raise it only for an endpoint known to accept more (some push services document a larger limit; a
         * self-hosted or intra-organisation service may be configured for one). RFC 8030 §7.2 obliges a push service to
         * accept only 4096 octets; beyond that it may answer {@code 413}.
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
         * exchange — a synchronous HTTP call bounded by the transport's per-request timeout — so the executor must
         * tolerate long-blocking tasks. Defaults to a library-owned virtual-thread-per-task executor, created lazily on
         * the first async send; a caller-supplied executor stays caller-owned — the library never shuts it down.
         *
         * @param executor the executor for async sends
         * @return this builder
         */
        public Builder executor(Executor executor) {
            this.executor = Objects.requireNonNull(executor, "executor");
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
