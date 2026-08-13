/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.io.Serial;

/**
 * Thrown by an {@link EndpointPolicy} that refuses a subscription's push endpoint. This is the policy seam's signal,
 * and a dedicated type because {@link PushSender#send} recognises a rejection by it and by nothing else: exactly this
 * type is converted into the {@link PushOutcome.EndpointRejected} outcome a caller reads, while any other
 * {@code RuntimeException} out of a policy is a defect in that policy and propagates unchanged. An application calling
 * {@link EndpointPolicy#validate} directly — at its own registration boundary, say — catches this type itself, and it
 * means the same thing there: this endpoint violates the deployment's endpoint policy — flag or remove the stored
 * subscription that carries it.
 *
 * <p>It extends {@code RuntimeException} directly — like every exception this library owns — and deliberately
 * <em>not</em> {@code IllegalArgumentException}. The rejected argument is well-formed; what refuses it is deployment
 * configuration, and nothing the caller can do to the argument fixes that, so the IAE contract ("your argument is
 * broken") would misdirect the remediation. Just as important, web frameworks routinely map
 * {@code IllegalArgumentException} to an HTTP 400 whose body carries {@code getMessage()} — which would echo the
 * refused origin and the stable subscription fingerprint straight back to the caller who registered the hostile
 * subscription. Rejections only exist where a policy was explicitly configured, so no pre-existing handler depends on
 * any other shape: the deployment that opts in is exactly the one that should decide what a rejection means for its
 * subscription store.
 *
 * <p>There is deliberately no cause-taking constructor: the parse and validation exceptions a policy might be tempted
 * to wrap ({@code URISyntaxException} above all) carry the raw endpoint in their message, and a push endpoint is a
 * capability URL that must never travel inside an exception (RFC 8030 §8.3; see {@link Endpoints#redact}).
 */
public class EndpointRejectedException extends RuntimeException {

    // Declared rather than computed. A computed identifier is derived from every non-private
    // constructor and method as well as from the fields, so adding either would move it and make an
    // instance already written to a stream unreadable after an otherwise compatible release.
    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * Creates an exception describing the rejection. The message must not contain the raw endpoint — render it with
     * {@link Endpoints#redact}.
     *
     * @param message the detail message
     */
    public EndpointRejectedException(String message) {
        super(message);
    }
}
