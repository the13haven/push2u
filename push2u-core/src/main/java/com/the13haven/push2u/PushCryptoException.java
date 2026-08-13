/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.io.Serial;

/**
 * Thrown when cryptography this library needs cannot be performed, and repeating the same call would fail in exactly
 * the same way. Three kinds of failure, one remediation, so one type:
 *
 * <ul>
 *   <li><b>A substrate that cannot perform the cryptography</b> — a JCE provider without {@code AES/GCM/NoPadding},
 *       {@code HmacSHA256} or the {@code secp256r1} parameters, a key the provider will not accept, a malformed EC
 *       point.
 *   <li><b>An answer no key custodian could have meant</b> — something that is not an ES256 signature where a signature
 *       was asked for, something that is not a point on P-256 where the VAPID public key was.
 *   <li><b>A misconfiguration that recurs</b> — a mount that is not there, a token without the capability to use the
 *       key, a key of a type VAPID cannot use, a pinned key version the custodian no longer holds.
 * </ul>
 *
 * <p><b>What separates it from {@link VapidSignerUnavailableException} is whose state the answer describes.</b> A
 * custodian that is unreachable, sealed, still catching up or rate-limiting is describing its own condition, or that of
 * a service it called itself, and such a condition ends on its own terms — so the identical request can come back
 * different, and that one is not this type. Everything here answers about the request, about what this deployment
 * supplied, or about this deployment's own substrate, and answers identically until a person changes something. "Until
 * a human acts" is not the line and would sort these wrongly: an operator unseals a custodian too.
 *
 * <p><b>Most of it arises inside a send and not all of it does</b>, which is why nothing above is phrased as a send's
 * failure. {@link Endpoints}, which an application is invited to call at its own registration boundary, and a signer
 * asked to publish the public key a frontend subscribes with are both outside any send, and this type means the same
 * thing there: the substrate or the configuration, never this message.
 *
 * <p>A push service's verdict on a send is never this — that is a value the caller reads, not a failure.
 *
 * <p>Unchecked on purpose: the library's contract is that the public surface throws only on genuine errors, and none of
 * these is something the call site can correct by trying differently. What clears one is a person — a configuration
 * edited, a provider installed, or a defect fixed in whichever implementation answered something impossible. This type
 * says that much and no more; <em>which</em> person and what they change is in the message and the cause chain, which
 * are as specific as the site that threw could make them.
 *
 * <p>The name is kept for what the type still covers rather than out of habit: in every remaining case the cryptography
 * is what could not be performed.
 */
public class PushCryptoException extends RuntimeException {

    // Declared rather than computed. A computed identifier is derived from every non-private
    // constructor and method as well as from the fields, so adding either would move it and make an
    // instance already written to a stream unreadable after an otherwise compatible release.
    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * Creates an exception describing the crypto failure.
     *
     * @param message the detail message
     */
    public PushCryptoException(String message) {
        super(message);
    }

    /**
     * Creates an exception describing the crypto failure, wrapping the underlying cause.
     *
     * @param message the detail message
     * @param cause the underlying cause
     */
    public PushCryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
