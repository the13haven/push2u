/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;

/**
 * What became of one requested send: accepted, rejected, never attempted, or attempted with no answer.
 * {@link PushSender#send} performs exactly one POST and reports it here — the library does not retry, so deciding
 * whether to repeat a send, and when, belongs to whoever called it, which in a deployment sending at volume is a
 * retrier that can see its own budget, its dead-letter path and what survives a restart. This type exists to hand that
 * caller the classification it would otherwise re-derive from status numbers.
 *
 * <p>The hierarchy is sealed so that a {@code switch} over it is exhaustive: every case is put in front of a caller who
 * has decided to read the outcome, and a new variant in a later release fails compilation instead of falling through.
 * {@link NotAttempted} is a marker interface whose leaves implement it directly, so one {@code switch} chooses its own
 * grain — {@code case NotAttempted n} takes the group, {@code case PayloadRejected p} takes the one carrying sizes.
 *
 * <p><b>Two independent questions, and no single variant name answers both.</b> Whether a repeat is <em>safe</em> —
 * could it duplicate a notification — has one structural answer: under {@link NotAttempted} no POST was made, so a
 * repeat provably duplicates nothing. {@link Indeterminate} is the declared unknown at the other end. The answered
 * failures sit between them: {@link RetryableFailure} states that a repeat may be <em>useful</em> — the service
 * answered about its own moment — and states nothing about whether it is safe; {@link NonRetryableFailure} states that
 * the service has already answered about the request itself, so an identical request buys nothing. Neither is a
 * forecast about the endpoint: a {@code 500} may well be permanent, and neither name promises what the next attempt
 * returns. RFC 9110 §9.2.2 leaves a non-idempotent repeat to a client that knows the first request was never applied,
 * and the caller is the only party here who can know that or price a duplicate.
 *
 * <p>The two class-shaped variants, {@link SignerUnavailable} and {@link Indeterminate}, compare by identity: each
 * carries a {@link Throwable}, and throwables have no value equality, so two outcomes describing the same timeout are
 * not equal. Outcomes are switched on rather than compared, which is why this is accepted — it is written here so
 * nobody keys a map or a deduplication on one.
 *
 * <p>No outcome prints a capability URL. A push endpoint identifies its subscription (RFC 8030 §8.3), so every string
 * an outcome renders by default — {@code toString()}, a record's generated component printing — carries at most a
 * redacted endpoint, a status number or a duration. The one deliberate way to richer diagnostics is a {@code cause()}
 * accessor, whose own contract says what the chain may contain.
 */
public sealed interface PushOutcome {

    /**
     * The push service accepted the message for delivery. RFC 8030 §5 has the service answer {@code 201 Created} and is
     * explicit that this means accepted for delivery, not that a user agent received it — the message may still expire
     * undelivered, and a delivery receipt would need the receipt subscription of RFC 8030 §5.1, which this library does
     * not implement. The whole {@code 2xx} class lands here: a service answering {@code 200} or {@code 202} has
     * accepted the message just the same, and the precise code is in {@code statusCode} for a caller that needs to tell
     * them apart. Repeating an accepted send duplicates the notification by definition.
     *
     * @param statusCode the {@code 2xx} status the push service answered with; never negative
     */
    record Accepted(int statusCode) implements PushOutcome {

        /**
         * Refuses a negative status code, which no HTTP exchange can have produced.
         *
         * @param statusCode the {@code 2xx} status the push service answered with
         * @throws IllegalArgumentException if {@code statusCode} is negative
         */
        public Accepted {
            requireNonNegative(statusCode);
        }
    }

    /**
     * The subscription is gone — the push service answered {@code 404} or {@code 410}. The one correct action is to
     * stop sending to it and delete it wherever it is stored (this library stores nothing): no repeat of this send, on
     * any schedule, comes back different, which is why no retry hint exists on this variant even where the response
     * carried one — a wait would be reported to a caller with nothing left to wait for.
     *
     * @param statusCode the status the push service answered with; never negative
     */
    record SubscriptionExpired(int statusCode) implements PushOutcome {

        /**
         * Refuses a negative status code, which no HTTP exchange can have produced.
         *
         * @param statusCode the status the push service answered with
         * @throws IllegalArgumentException if {@code statusCode} is negative
         */
        public SubscriptionExpired {
            requireNonNegative(statusCode);
        }
    }

    /**
     * The push service answered something about its own moment rather than about the request, so an identical request
     * has not been answered yet and a repeat may be useful. Parts of that classification are specified and the rest is
     * this library's judgement, taken per status rather than per class:
     *
     * <ul>
     *   <li>{@code 429} — RFC 8030 §8.4 has a rate-limited delivery answered with it, and SHOULD carry a
     *       {@code Retry-After};
     *   <li>{@code 408} — RFC 9110 §15.5.9 lets a client repeat the request; {@code 421} — §15.5.20 lets it retry on
     *       another connection; {@code 503} — §15.6.4 says the condition is temporary and MAY carry a
     *       {@code Retry-After};
     *   <li>{@code 413} carrying a parseable {@code Retry-After} — RFC 9110 §15.5.14 has a server refusing a request
     *       for its size generate that header <em>if the condition is temporary</em>, which makes the header the
     *       server's own statement that it refused this moment rather than this request. A bare {@code 413} is
     *       {@link NonRetryableFailure};
     *   <li>the rest of the {@code 5xx} class, including any status the list here does not name: RFC 9110 §15.6 has a
     *       {@code 5xx} say the server "is aware that it has erred or is incapable of performing the requested method"
     *       — a statement about the server, not about the request — and a positive list would make every unregistered
     *       or later-registered {@code 5xx} permanent by omission, which costs a notification nobody sends again. Five
     *       statuses are carved out; {@link NonRetryableFailure} carries each one's ground;
     *   <li>{@code 507} stays here, and is named so that nobody carves it out on the strength of the class: RFC 4918
     *       §11.5 says the server "is unable to store the representation needed to successfully complete the request"
     *       and that "this condition is considered to be temporary". The same section requires that where the refused
     *       request was the result of a user action, it "MUST NOT be repeated until it is requested by a separate user
     *       action" — a condition on what produced the request, not on what executes the repeat, so a scheduler is no
     *       exemption from it, and only the caller knows which of its sends were user actions.
     * </ul>
     *
     * <p>Useful is the whole verdict; this variant does not say a repeat is safe. {@code 502} and {@code 504} are the
     * named edge: RFC 9110 §15.6.3 and §15.6.5 define both as an intermediary reporting no valid, or no timely,
     * response from upstream — the upstream may have applied the POST and answered into a connection nobody read. They
     * are still reported here rather than as {@link Indeterminate}, because nothing can tell an intermediary's
     * {@code 502} from a push service's own, and inventing that distinction would manufacture a false "definitely not
     * sent".
     *
     * <p><b>A repeated send re-bases the message's lifetime.</b> RFC 8030 §5.2 counts {@code TTL} from the moment the
     * push service receives the message, so an attempt scheduled hours after this one carries a fresh lifetime unless
     * the caller decrements the {@code TTL} it passes by the time already spent.
     *
     * @param statusCode the status the push service answered with; never negative
     * @param retryAfter what the response's {@code Retry-After} header said, parsed from delta-seconds or any of the
     *     three HTTP-date forms a recipient must accept, and empty where the header was absent or unparseable — which
     *     is the ordinary case, since most statuses here have no {@code Retry-After} provision in any specification.
     *     <b>Reported with no ceiling applied</b>: the value is the value that arrived, however large, so the only
     *     ceiling on the wait is the one whoever schedules the repeat chooses — repeating before the moment the service
     *     named is the harm the header exists to prevent, and a hostile push service can name any delay, which is one
     *     more reason the caller's own bound has to exist
     */
    record RetryableFailure(int statusCode, Optional<Duration> retryAfter) implements PushOutcome {

        /**
         * Refuses a negative status code and a negative hint, neither of which any response can have produced.
         *
         * @param statusCode the status the push service answered with
         * @param retryAfter what the response's {@code Retry-After} said, or empty
         * @throws NullPointerException if {@code retryAfter} is {@code null}
         * @throws IllegalArgumentException if {@code statusCode} is negative, or the hint holds a negative duration
         */
        public RetryableFailure {
            requireNonNegative(statusCode);
            Objects.requireNonNull(retryAfter, "retryAfter");
            if (retryAfter.isPresent() && retryAfter.get().isNegative()) {
                throw new IllegalArgumentException(
                        "retryAfter must not be negative — a delay into the past declares nothing, was "
                                + retryAfter.get());
            }
        }
    }

    /**
     * The push service answered something about the request itself, so an identical request has been answered already
     * and repeating it buys nothing. This is where every status lands that no other variant claims — a {@code 3xx}
     * (push delivery has no redirect step), a {@code 4xx} other than {@code 404}/{@code 410}/{@code 408}/{@code 421}/
     * {@code 429}, a bare {@code 413} — and five {@code 5xx} statuses carved out of the retryable class, each on its
     * defining specification's own words rather than on a guess about a service:
     *
     * <ul>
     *   <li>{@code 501} — RFC 9110 §15.6.2: the server "does not support the functionality required to fulfill the
     *       request"; a byte-identical POST is answered identically;
     *   <li>{@code 505} — RFC 9110 §15.6.6: the server does not support the major HTTP version the request used;
     *   <li>{@code 506} — RFC 2295 §8.1: "the server has an internal configuration error", a property of a deployment
     *       that ends when someone edits a configuration, not of a moment;
     *   <li>{@code 508} — RFC 5842 §7.2: the server "terminated an operation because it encountered an infinite loop",
     *       a statement about the resource graph the request named, and "the entire operation failed";
     *   <li>{@code 511} — RFC 6585 §6: "SHOULD NOT be generated by origin servers" and is meant for intercepting
     *       proxies controlling network access, so it reports that the <em>sending</em> host has no network access —
     *       which no repeat of this POST obtains and no push service can grant.
     * </ul>
     *
     * <p>The name states a verdict about this response, never a forecast about the endpoint: it does not promise the
     * next attempt fails, only that this request has its answer.
     *
     * @param statusCode the status the push service answered with; never negative
     */
    record NonRetryableFailure(int statusCode) implements PushOutcome {

        /**
         * Refuses a negative status code, which no HTTP exchange can have produced.
         *
         * @param statusCode the status the push service answered with
         * @throws IllegalArgumentException if {@code statusCode} is negative
         */
        public NonRetryableFailure {
            requireNonNegative(statusCode);
        }
    }

    /**
     * No POST was made, so nothing can have been delivered and a repeat cannot duplicate. A marker rather than a
     * wrapper: its leaves implement it directly, so a caller switches once and chooses its own grain — the group here,
     * or the leaf that carries the fields its case has.
     */
    sealed interface NotAttempted extends PushOutcome {}

    /**
     * The key custodian behind the {@link VapidSigner} cannot sign <em>now</em> — unreachable, sealed, not yet
     * initialized, still catching up, or rate-limiting — so no signature was taken and no POST was made. The failure is
     * a state of the custodian, not of anything this deployment configured, and it ends on its own terms: an operator,
     * a replication catching up, a rate window closing. A signing failure that recurs — a wrong key type, a missing
     * mount, a token without the capability — is not this value but a {@link PushCryptoException} out of the send,
     * because waiting cannot clear it.
     *
     * <p><b>A fan-out meeting this outcome should stop</b>, because the alternative is a fan-out that hammers a
     * custodian that is already down: the sender's token cache publishes only after a signature succeeds, so with
     * signing failing it never fills, and every row makes its own round trip to the dead custodian. A sequential loop
     * over a subscription store breaks on the first one. The asynchronous shape needs the same advice in the form it
     * can act on, because by the time the first outcome is read, a fan-out that already submitted every row has had its
     * burst decided: bound the concurrency rather than submitting the whole list at once, feed rows in as outcomes come
     * back, and stop submitting new ones once one of these has arrived. Resume when the custodian is back, and not
     * before {@link #retryAfter()} where it declared one — nothing was sent, so no repeat can duplicate.
     *
     * <p>A class rather than a record, with a written {@link #toString()}, so that nothing here prints a cause chain by
     * default; and with no {@code equals}, so two instances compare by identity — outcomes are switched on, not
     * compared.
     */
    final class SignerUnavailable implements NotAttempted {

        private final VapidSignerUnavailableException cause;
        private final OptionalInt status;
        private final Optional<Duration> retryAfter;

        /**
         * Creates the outcome from the signer's own signal, snapshotting the status and the retry hint the signal
         * declares at this moment. The exception type is extensible and its accessors are not final, so both values are
         * read exactly once, here: what this outcome answers is fixed at construction, and nothing the exception
         * computes or changes afterwards can move it.
         *
         * <p>Each of the two reads is guarded, and guarded independently of the other, because the accessor being read
         * is consumer-overridable code standing between a failure the signer already classified and the value a caller
         * was promised. An accessor that throws a {@code RuntimeException}, or answers {@code null} where its contract
         * requires a value, costs this outcome that one component and nothing else: the component stays empty, the
         * other read's answer is kept, and the defect — the thrown exception, or a {@code NullPointerException}
         * describing the null — is recorded as a suppressed exception on {@code cause}, so an empty component with a
         * broken accessor does not read as a custodian that declared nothing. That recording is bounded per exception
         * instance, since one preallocated exception thrown for every call would otherwise collect one entry per
         * outcome built from it: an exception already carrying a handful of suppressed entries takes no more, and there
         * the empty component is all the caller gets. An {@code Error} is not survived: it leaves this constructor as
         * it arrived. The guard lives here, on the public constructor, so a caller constructing the outcome directly
         * gets it too.
         *
         * @param cause what the {@link VapidSigner} raised
         * @throws NullPointerException if {@code cause} is {@code null}
         */
        public SignerUnavailable(VapidSignerUnavailableException cause) {
            this.cause = Objects.requireNonNull(cause, "cause");
            this.status = readStatus(cause);
            this.retryAfter = readRetryAfter(cause);
        }

        /**
         * The one read of {@code status()}, guarded: the accessor's answer, or empty — with the defect recorded as a
         * suppressed exception on {@code cause}, so far as that exception can still carry one — where the accessor
         * threw or answered {@code null}.
         */
        private static OptionalInt readStatus(VapidSignerUnavailableException cause) {
            try {
                OptionalInt status = cause.status();
                if (status != null) {
                    return status;
                }
                Suppression.suppress(
                        cause,
                        new NullPointerException("status() returned null; its contract has it answer an empty"
                                + " OptionalInt where the custodian answered no number"));
            } catch (RuntimeException defect) {
                Suppression.suppress(cause, defect);
            }
            return OptionalInt.empty();
        }

        /**
         * The one read of {@code retryAfter()}, guarded: the accessor's answer, or empty — with the defect recorded as
         * a suppressed exception on {@code cause}, so far as that exception can still carry one — where the accessor
         * threw or answered {@code null}.
         */
        private static Optional<Duration> readRetryAfter(VapidSignerUnavailableException cause) {
            try {
                Optional<Duration> retryAfter = cause.retryAfter();
                if (retryAfter != null) {
                    return retryAfter;
                }
                Suppression.suppress(
                        cause,
                        new NullPointerException("retryAfter() returned null; its contract has it answer an empty"
                                + " Optional where the custodian declared no delay"));
            } catch (RuntimeException defect) {
                Suppression.suppress(cause, defect);
            }
            return Optional.empty();
        }

        /**
         * The status the custodian answered with, where it answered one — a diagnostic for the log line and the metric
         * label, never a classification to re-derive: the signer classified when it raised the unavailability, which is
         * why this outcome exists at all. It is the <b>custodian's</b> status and never a push service's — a
         * {@code 503} here is a sealed or overloaded custodian and no POST was made, where a {@code 503} on
         * {@link RetryableFailure} is the push service refusing a delivery. Empty for a key held locally, for a PKCS#11
         * token, and for the whole half where nothing answered at all. Snapshotted from the signer's signal when this
         * outcome was constructed, so every read answers the same — and empty where the signal's accessor broke at that
         * moment, with the defect recorded as a suppressed exception on {@link #cause()} so far as it can still carry
         * one.
         *
         * @return the custodian's status, or empty where nothing answered a number
         */
        public OptionalInt status() {
            return status;
        }

        /**
         * How long the custodian declared it would be before it can serve again, empty unless it declared one — most
         * custodians never do. Reported exactly as it arrived, <b>with no ceiling applied</b>, so the only ceiling is
         * the one whoever schedules the next attempt chooses. Also empty where the signal's accessor broke when this
         * outcome was constructed, with the defect recorded as a suppressed exception on {@link #cause()} so far as it
         * can still carry one.
         *
         * <p><b>Nor is it a floor: this value is not checked, and a scheduler reading it guards it.</b> The duration is
         * whatever the {@link VapidSigner} put on its signal, read once when this outcome was constructed and handed
         * across unexamined so that an outage report can never be replaced by a complaint about how it was written —
         * which means a signer that fills the hint badly can hand a caller a zero or negative delay, and the sender
         * will not turn that into a failure. Treat anything at or below zero as no declaration at all rather than as a
         * due time already past. The push service's hint on {@link RetryableFailure} is the deliberate contrast: that
         * one is validated where the outcome is built, so it is never negative.
         *
         * @return the declared delay, or empty where none was declared; not guaranteed to be positive
         */
        public Optional<Duration> retryAfter() {
            return retryAfter;
        }

        /**
         * What the signer raised, with whatever did not complete beneath it. The chain is the diagnostic a person reads
         * to tell an unroutable custodian from a sealed one; the signer's contract keeps key material and push
         * endpoints out of its messages, but the chain beneath it comes from whatever transport failed and is not this
         * library's to vouch for — treat it as diagnostics for a log the deployment already trusts with its stack
         * traces.
         *
         * @return the signer's signal, never {@code null}
         */
        public Throwable cause() {
            return cause;
        }

        /**
         * The class name plus what the custodian declared, where it declared anything — its status, the delay it named,
         * or both. Deliberately nothing further: a status is an integer and a delay is a duration, so this string is
         * safe wherever it lands, where a rendering that reached into the cause chain would not be.
         *
         * @return the class name, plus the custodian's declarations where it made any
         */
        @Override
        public String toString() {
            OptionalInt status = status();
            Optional<Duration> retryAfter = retryAfter();
            String declarations = status.isPresent() ? "custodian status " + status.getAsInt() : "";
            if (retryAfter.isPresent()) {
                declarations += (declarations.isEmpty() ? "" : ", ") + "retry after " + retryAfter.get();
            }
            return "SignerUnavailable[" + declarations + "]";
        }
    }

    /**
     * The payload does not fit this sender's configuration, so nothing was encrypted and no POST was made. It is a fact
     * about one message rather than about the deployment — the concrete case is a translated notification that fits in
     * one language and not another — so it is a value the fan-out records, never a failure that stops it; the remedy is
     * to render the notification smaller.
     *
     * <p>Both numbers are plaintext octets, the unit the caller can act in. Through {@link PushSender} one rule decides
     * the maximum: the configured ceiling on the encrypted body, less the fixed 103 octets of {@code aes128gcm}
     * framing. The record size the sender advertises is derived from that maximum — RFC 8291 §4's rule that {@code rs}
     * strictly exceed the plaintext plus its 17 octets of padding delimiter and authentication tag, applied in reverse
     * — so the record-size rule can never be the bound that binds on a send; it stays enforced inside the encryptor,
     * where a direct caller can still violate it. The same question is answerable <em>before</em> a send through
     * {@link PushSender#assessPayloadSize(byte[])}, whose refusing branch carries this same pair; this outcome is what
     * a caller that did not ask — or asked and then grew the payload — receives anyway.
     *
     * @param payloadBytes the plaintext the caller handed over, in octets; never negative
     * @param maximumPayloadBytes the largest plaintext this sender's configuration would have carried, in octets; never
     *     negative
     */
    record PayloadRejected(int payloadBytes, int maximumPayloadBytes) implements NotAttempted {

        /**
         * Refuses negative sizes, which no payload and no configuration can have produced.
         *
         * @param payloadBytes the plaintext the caller handed over, in octets
         * @param maximumPayloadBytes the largest plaintext this sender's configuration would have carried, in octets
         * @throws IllegalArgumentException if either size is negative
         */
        public PayloadRejected {
            if (payloadBytes < 0) {
                throw new IllegalArgumentException("payloadBytes must not be negative, was " + payloadBytes);
            }
            if (maximumPayloadBytes < 0) {
                throw new IllegalArgumentException(
                        "maximumPayloadBytes must not be negative, was " + maximumPayloadBytes);
            }
        }
    }

    /**
     * The sender's {@link EndpointPolicy} refused the subscription's endpoint, so the request never left. The policy
     * did its job — this is the egress control working, not failing — and one hostile row must not abort a fan-out over
     * a whole subscription store, which is why the refusal is a value: the application records the row as violating its
     * policy, flags or removes the stored subscription, and continues.
     *
     * @param redactedEndpoint the refused endpoint in redacted form — origin plus a short fingerprint, never the
     *     capability path or query — safe to log and enough to find the row
     * @param reason the policy's own account of the refusal. The policy seam's contract requires it to render any
     *     endpoint it mentions in the same redacted form, so this string carries no capability URL from any policy that
     *     honours its contract. One string here is not the policy's account: where that account could not be read — the
     *     exception's {@code getMessage()} threw — {@link PushSender#send} substitutes the fixed text {@code "endpoint
     *     policy rejected the endpoint; reason unavailable"}, this library's own rendering, safe whatever the throwing
     *     accessor would have written; a policy whose message was merely {@code null} renders as {@code ""}, so the two
     *     stay distinguishable
     */
    record EndpointRejected(String redactedEndpoint, String reason) implements NotAttempted {

        /**
         * Refuses {@code null}s; both strings exist for every refusal.
         *
         * @param redactedEndpoint the refused endpoint in redacted form
         * @param reason the policy's own account of the refusal
         * @throws NullPointerException if either component is {@code null}
         */
        public EndpointRejected {
            Objects.requireNonNull(redactedEndpoint, "redactedEndpoint");
            Objects.requireNonNull(reason, "reason");
        }
    }

    /**
     * The POST went out and no answer was obtained — a timeout, a dropped connection — so whether the push service
     * received the message is unknown, and the library refuses to guess. A push POST is not idempotent: RFC 8030 §5 has
     * a successful one create a new push message resource, and RFC 9110 §9.2.2 says a client should not automatically
     * retry a non-idempotent request unless it knows the request was never applied — which is exactly what nobody knows
     * here, so a repeat may deliver a duplicate notification and not repeating may lose one. Neither failure variant
     * can carry this case: both report what an answer said, and here nothing answered, so there is no more ground to
     * call a repeat useful than to call it safe. Pricing the duplicate against the loss is the application's, whose
     * tolerance the library cannot see; a {@code Topic} on the message narrows the duplicate window without closing it.
     *
     * <p>A class rather than a record, with a written {@link #toString()}, because the transport's cause chain can
     * embed the subscription URL and a record's generated rendering would print it; and with no {@code equals}, so two
     * instances compare by identity — outcomes are switched on, not compared.
     */
    final class Indeterminate implements PushOutcome {

        private final Throwable cause;

        /**
         * Creates the outcome for an unanswered POST.
         *
         * @param cause what the transport raised for the exchange that produced no response
         */
        public Indeterminate(Throwable cause) {
            this.cause = Objects.requireNonNull(cause, "cause");
        }

        /**
         * What the transport raised — the one deliberate way to the full diagnostic, and the only reason anything can
         * still say why this send went unanswered, since the sender has not rethrown it. <b>The chain may embed the
         * subscription's push endpoint verbatim</b>: JDK transport exceptions put the request URI into their messages,
         * and that endpoint is a capability URL (RFC 8030 §8.3), so logging this chain verbatim publishes it. Calling
         * this accessor is the same responsibility a caller takes when it catches a transport exception and logs it;
         * everything this outcome prints on its own stays redacted.
         *
         * @return the transport's failure, never {@code null}
         */
        public Throwable cause() {
            return cause;
        }

        /**
         * The class name and the cause's class name, deliberately nothing further: the cause's message can embed the
         * subscription's capability URL, so it is reachable only through {@link #cause()}, never printed by default.
         *
         * @return the class name plus the cause's class name
         */
        @Override
        public String toString() {
            return "Indeterminate[cause=" + cause.getClass().getName() + "]";
        }
    }

    private static void requireNonNegative(int statusCode) {
        if (statusCode < 0) {
            throw new IllegalArgumentException("statusCode must not be negative, was " + statusCode);
        }
    }
}
