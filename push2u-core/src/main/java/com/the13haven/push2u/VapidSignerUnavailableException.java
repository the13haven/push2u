/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.time.Duration;
import java.util.Optional;
import java.util.OptionalInt;

import org.jspecify.annotations.Nullable;

/**
 * Thrown by a {@link VapidSigner} whose key custodian cannot sign <em>now</em>. What this type reports is a state of
 * the custodian — unreachable, sealed, not yet initialized, still catching up, rate-limiting, or waiting on a service
 * it called itself — or of the network between it and this application. Every one of those ends on its own terms: an
 * operator, a replication catching up, a rate window closing, a third party coming back, and none of them needs this
 * deployment to change anything it configured.
 *
 * <p>Nothing was signed, so nothing was sent. A send that fails this way provably delivered no notification, which is
 * what makes trying again later free of any duplicate risk — the cost of waiting is the wait.
 *
 * <p><b>Both halves of an outage take this one type.</b> Nothing answering — a refused connection, a failed TLS
 * handshake, a request timeout — and a custodian answering that it cannot serve this request at the moment are one
 * type, because the code that catches them takes one action and the operator who reads them takes one action. Which of
 * the two happened is in the message and the cause chain, where a person reads it; it is not something a program
 * branches on.
 *
 * <p><b>What it carries, beside the message.</b> The cause is whatever did not complete, where something threw.
 * {@link #retryAfter()} is the moment the custodian declared it would be able to serve again, and is empty unless it
 * declared one — most custodians never do. {@link #status()} is the status the custodian answered with, and is empty
 * for a key held locally, for a PKCS#11 token, for a KMS refusing on quota, and for the whole half where nothing
 * answered at all. Neither optional obliges an implementation to speak HTTP: a signer over an HSM or a smart card fills
 * neither and is fully conformant. Both are diagnostics and a schedule, never a classification to be re-derived — the
 * signer has already classified by raising this type rather than {@link PushCryptoException}.
 *
 * <p><b>The custodian's status is never a push service's</b>, and reading the two as one number is a mistake worth
 * naming: a {@code 503} here is a sealed or overloaded custodian and no push message left this process, where a
 * {@code 503} from a push service is a delivery it refused.
 *
 * <p><b>A startup supervisor's contract.</b> A signer that reads its key from the custodian while it is being built
 * raises this type when the custodian is down at startup, which is a boot worth retrying with backoff — where a
 * {@link PushCryptoException} out of the same call should fail the deployment and stop, because it will answer the same
 * way until a person changes something.
 *
 * <p><b>That contract begins with the interrupt, not with the type.</b> A boot interrupted while the key is being read
 * raises this type as well, because a transport does not sort an incomplete exchange by what made it incomplete. So a
 * supervisor that reads the type first answers a shutdown by looping its own boot, with every backoff it sleeps failing
 * instantly on an interrupt status nobody cleared. Test the interruption first, then the type. The test is a
 * disjunction — the current thread's interrupt status is set, <em>or</em> an {@link InterruptedException} is somewhere
 * in the cause chain — and neither half is sound alone: an interruption can surface as a
 * {@link java.nio.channels.ClosedByInterruptException} or an {@link java.io.InterruptedIOException} with no
 * {@code InterruptedException} beneath it, and a transport may attach a cause without re-setting the flag.
 *
 * <p><b>What an implementation owes that test.</b> Not the sorting: an implementation is never asked to tell an
 * interrupted exchange apart from any other exchange that produced no answer. What it owes is the two things any code
 * catching an {@link InterruptedException} owes — re-set the interrupt status on its own thread, and keep that
 * exception in the cause chain of what it raises. An interruption swallowed without the flag is the oldest defect in
 * the genre, and it is the one thing that would leave the disjunction above unable to see a cancellation.
 *
 * <p>Unchecked, like every exception this library owns, and extending {@code RuntimeException} directly.
 */
public class VapidSignerUnavailableException extends RuntimeException {

    private final boolean hasStatus;

    private final int status;

    private final @Nullable Duration retryAfter;

    /**
     * Creates an exception for a custodian that answered nothing — a refused connection, a failed handshake, a timeout,
     * an interrupted exchange. Neither the status nor the retry hint is reported, because nothing declared either.
     *
     * @param message the detail message, which must not contain key material or a push endpoint
     * @param cause whatever did not complete, or {@code null} where nothing was thrown
     */
    public VapidSignerUnavailableException(String message, @Nullable Throwable cause) {
        super(message, cause);
        this.hasStatus = false;
        this.status = 0;
        this.retryAfter = null;
    }

    /**
     * Creates an exception for a custodian that answered it cannot serve this request now.
     *
     * <p>Both extra values are carried across unexamined, and reporting one that is not a value of the thing it names
     * is an implementation defect this constructor deliberately does not turn into a second failure: whatever else is
     * true, an outage report must not be replaced by a complaint about how it was written. So a custodian that declared
     * no moment gets {@code null} rather than a zero duration, which would say "come back immediately", and a delay
     * pointing into the past is not a declaration of anything and must not be passed here.
     *
     * @param message the detail message, which must not contain key material or a push endpoint
     * @param status the status the custodian answered with
     * @param retryAfter how long the custodian declared it would be before it can serve again, or {@code null} where it
     *     declared nothing — the usual case
     * @param cause whatever did not complete, or {@code null} where the answer itself was the failure
     */
    public VapidSignerUnavailableException(
            String message, int status, @Nullable Duration retryAfter, @Nullable Throwable cause) {
        super(message, cause);
        this.hasStatus = true;
        this.status = status;
        this.retryAfter = retryAfter;
    }

    /**
     * The status the custodian answered with, where it answered one.
     *
     * <p>Empty is the ordinary reading rather than a surprise: a locally held key, a PKCS#11 token and every failure in
     * which nothing answered leave it empty. Present means something answered a number, not that the number is one of
     * HTTP's — a custodian that is not reached over HTTP reports whatever it answers in.
     *
     * @return the custodian's status, or empty where nothing answered a number
     */
    public OptionalInt status() {
        return hasStatus ? OptionalInt.of(status) : OptionalInt.empty();
    }

    /**
     * How long the custodian declared it would be before it can serve again.
     *
     * <p>Reported exactly as it arrived, with no ceiling applied, so that the only ceiling is the one whoever schedules
     * the next attempt chooses. Empty far more often than not: most custodians declare nothing, and a key in a
     * configuration file has no moment at which it becomes available again.
     *
     * @return the declared delay, or empty where none was declared
     */
    public Optional<Duration> retryAfter() {
        return Optional.ofNullable(retryAfter);
    }
}
