/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.util.Objects;

import org.jspecify.annotations.Nullable;

/**
 * The answer to {@link EndpointPolicy#assess(java.net.URI)}: whether the deployment's endpoint policy permits
 * contacting one push endpoint. A refusal is the boundary working, not failing — at a registration endpoint an
 * inadmissible subscription is an ordinary request from an ordinary client, answered with a refusal and no stored row —
 * so the answer is a value a caller switches on rather than an exception a caller must write control flow around.
 *
 * <p>The hierarchy is sealed and both variants are records, so a {@code switch} over an assessment is exhaustive and
 * neither variant can be subclassed: what travels through this type is exactly what its components carry. A policy
 * whose own boundary wants richer refusal data — a rule, a zone, a ticket reference — keeps that structure beside the
 * assessment, in the implementation that produced it; it does not travel through the library, whose business with a
 * refusal is to report it.
 */
public sealed interface EndpointAssessment {

    /**
     * The policy permits contacting this endpoint; the action is to proceed — store the offered subscription, or let
     * the send continue. Deliberately no components: an admissible endpoint needs no number or string to act on, and a
     * record component added later would change the canonical constructor and every pattern match — a breaking change,
     * unlike the compatible addition of a method — so the empty shape is a commitment rather than an omission. Not a
     * singleton: the canonical constructor is public, all instances are equal, and nothing distinguishes one from
     * another — identity is not part of what the answer means.
     */
    record Allowed() implements EndpointAssessment {}

    /**
     * The policy refuses this endpoint. At a registration boundary the action is to answer the client and store no row;
     * inside a send, {@link PushSender#send} converts this value into {@link PushOutcome.EndpointRejected}, carrying
     * the library's own redaction of the endpoint beside the reason here. Deliberately no endpoint component: both
     * callers hold the endpoint at the moment they ask, and a refused endpoint is a capability URL whose redaction this
     * library performs itself rather than delegating to an implementation.
     *
     * @param reason the policy's own account of the refusal, written for the log line an operator reads — prose, not a
     *     code, because only the policy can say what it knew at the moment it refused. Never {@code null}: a
     *     {@code null} passed to the constructor is stored as {@code ""}. The policy seam's contract keeps the raw
     *     endpoint out of it — an implementation that wants to name the endpoint renders it with
     *     {@link Endpoints#redact} first
     */
    record Refused(String reason) implements EndpointAssessment {

        /**
         * Takes a {@code null} reason and stores {@code ""} for it: the component is non-null, the parameter is not.
         * Deliberately no validation beyond that — a blank or empty reason is permitted, exactly as
         * {@link PushOutcome.EndpointRejected} permits it, because one refusal may not be legal in one of the two types
         * describing it and illegal in the other. A refusal that threw out of the policy seam would be a defect there,
         * and a defect stops the fan-out this value exists to keep running — so a policy's missing reason is rendered,
         * never thrown.
         *
         * @param reason the policy's account of the refusal, or {@code null} to store {@code ""}
         */
        public Refused(@Nullable String reason) {
            this.reason = Objects.requireNonNullElse(reason, "");
        }
    }
}
