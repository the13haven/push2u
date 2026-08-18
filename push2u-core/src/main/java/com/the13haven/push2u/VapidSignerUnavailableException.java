/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.io.Serial;
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
 * signer has already classified by raising this type rather than {@link PushCryptoException} — and both are printed by
 * {@link #toString()}, so a stack trace carries them where nothing called an accessor.
 *
 * <p>There is a constructor for each shape an answer takes: nothing at all, a declared moment without a number, a
 * number, or both. A custodian that names a delay in something other than a status — retry information on a gRPC call,
 * a client library that surfaces a delay and no code — therefore reports the delay rather than inventing a number to
 * carry it or dropping the one value a caller can schedule against.
 *
 * <p><b>Three members must stay readable, and they are named one by one rather than as a class of methods:</b>
 * {@link #status()} and {@link #retryAfter()} must not throw and must not return {@code null} — the empty optional is
 * each one's declared way of saying "nothing declared" — and {@link #getCause()} must not throw. Those three are
 * exactly what {@link PushSender#send} reads while converting this exception into the outcome a caller is promised, and
 * the contract deliberately asks for nothing wider. A subclass that breaks one of them does not cost the caller the
 * classification: the sender guards each read, reports the broken value as absent and records the defect as a
 * suppressed exception on this exception — but what the accessor was meant to say is then lost, and an {@code Error}
 * out of one of them propagates out of the send.
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

    /*
     * Serializable because Throwable is, and the first exception here carrying state of its own, so
     * what crosses a stream is decided rather than inherited by accident: both declared values
     * travel with the exception, since one that arrived without them would say less than the one
     * that was thrown, and a Duration beside two primitives is already serializable as it stands.
     *
     * The identifier is declared rather than left to be computed, because a computed one is not a
     * fingerprint of what gets written. The serialization specification derives it from the class
     * name, its modifiers, its interfaces, its fields AND every non-private constructor and method,
     * so adding a constructor or writing a toString() moves it without changing a single byte of
     * the serialized state. The setting where this type reaches a stream at all is a work queue
     * across a rolling deploy, and there a moved identifier turns an ordinary compatible release
     * into a poison message: the node on the new version reads a task written by a node on the old
     * one and gets an InvalidClassException where it expected the reason a send never happened.
     *
     * A declared identifier is bumped deliberately, when a field keeps its name and type and
     * changes its meaning, which is the one case the runtime cannot catch on its own — fields are
     * matched by name and type, a changed type is refused whatever the identifier says, a removed
     * one is dropped and a new one arrives at its default.
     */

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * Whether the custodian answered a status at all.
     *
     * @serial {@code false} for the half where nothing answered, where {@code status} then means nothing
     */
    private final boolean hasStatus;

    /**
     * The status the custodian answered with.
     *
     * @serial meaningful only where {@code hasStatus} is set
     */
    private final int status;

    /**
     * The delay the custodian declared before it can serve again.
     *
     * @serial {@code null} where the custodian declared no moment, which is the usual case
     */
    private final @Nullable Duration retryAfter;

    /**
     * Creates an exception for a custodian that answered nothing and threw nothing worth carrying.
     *
     * @param message the detail message, which must not contain key material or a push endpoint
     */
    public VapidSignerUnavailableException(String message) {
        this(message, false, 0, null, null);
    }

    /**
     * Creates an exception for a custodian that answered nothing — a refused connection, a failed handshake, a timeout,
     * an interrupted exchange. Neither the status nor the retry hint is reported, because nothing declared either.
     *
     * @param message the detail message, which must not contain key material or a push endpoint
     * @param cause whatever did not complete, or {@code null} where nothing was thrown
     */
    public VapidSignerUnavailableException(String message, @Nullable Throwable cause) {
        this(message, false, 0, null, cause);
    }

    /**
     * Creates an exception for a custodian that declared when to come back without answering in numbers — a gRPC
     * custodian's retry information, or a client library that surfaces a delay and no code. The declaration is what a
     * caller schedules against, so it exists without a status rather than obliging an implementation to invent one.
     *
     * @param message the detail message, which must not contain key material or a push endpoint
     * @param retryAfter how long the custodian declared it would be before it can serve again
     * @param cause whatever did not complete, or {@code null} where the answer itself was the failure
     */
    public VapidSignerUnavailableException(String message, Duration retryAfter, @Nullable Throwable cause) {
        this(message, false, 0, retryAfter, cause);
    }

    /**
     * Creates an exception for a custodian that answered, in numbers, that it cannot serve this request now.
     *
     * <p>Both declared values are carried across unexamined, and reporting one that is not a value of the thing it
     * names is an implementation defect this constructor deliberately does not turn into a second failure: whatever
     * else is true, an outage report must not be replaced by a complaint about how it was written. So a custodian that
     * declared no moment gets {@code null} rather than a zero duration, which would say "come back immediately", and a
     * delay pointing into the past is not a declaration of anything and must not be passed here.
     *
     * @param message the detail message, which must not contain key material or a push endpoint
     * @param status the status the custodian answered with
     * @param retryAfter how long the custodian declared it would be before it can serve again, or {@code null} where it
     *     declared nothing — the usual case
     * @param cause whatever did not complete, or {@code null} where the answer itself was the failure
     */
    public VapidSignerUnavailableException(
            String message, int status, @Nullable Duration retryAfter, @Nullable Throwable cause) {
        this(message, true, status, retryAfter, cause);
    }

    private VapidSignerUnavailableException(
            String message, boolean hasStatus, int status, @Nullable Duration retryAfter, @Nullable Throwable cause) {
        super(message, cause);
        this.hasStatus = hasStatus;
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

    /**
     * The standard rendering — the class name and the detail message — followed by whatever the custodian declared,
     * where it declared anything: its status, the delay it named, or both.
     *
     * <p>Written rather than left to {@code Throwable} because the one place this exception is read with nothing above
     * it to convert it is a startup that failed while fetching the key, and there an operator has the stack trace and
     * nothing else. A value reachable only through an accessor is not in that stack trace.
     *
     * <p>It prints those two and nothing further, which is what makes it safe to print at all: an integer and a
     * duration disclose no capability URL, where a rendering that reached for anything richer might.
     *
     * @return the standard rendering, plus the custodian's declarations where it made any
     */
    // OverrideThrowableToString: enriching getMessage() instead would be the usual advice, and it is
    // the wrong half here. The message is what the signer wrote and stays exactly that, so anything
    // logging it prints one sentence rather than a sentence with values appended twice; what these
    // two values are owed to is the first line of a stack trace, which comes from this method. The
    // standard rendering is kept whole and appended to, never replaced.
    @SuppressWarnings("OverrideThrowableToString")
    @Override
    public String toString() {
        if (!hasStatus && retryAfter == null) {
            return super.toString();
        }
        StringBuilder rendered = new StringBuilder(super.toString()).append(" [");
        if (hasStatus) {
            rendered.append("custodian status ").append(status);
            if (retryAfter != null) {
                rendered.append(", ");
            }
        }
        if (retryAfter != null) {
            rendered.append("retry after ").append(retryAfter);
        }
        return rendered.append(']').toString();
    }
}
