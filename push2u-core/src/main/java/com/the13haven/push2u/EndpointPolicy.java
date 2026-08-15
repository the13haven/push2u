/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.net.URI;

/**
 * A deployment's rule for which push endpoints it will contact — one value, applied at both points of a subscription's
 * life: where a subscription is accepted, before the row is stored, and on every send a {@link PushSender} performs,
 * before any cryptography, before the VAPID signature, and before any network I/O.
 *
 * <p><b>Why this exists.</b> The endpoint inside a {@link Subscription} is attacker-influenced data: a typical
 * integration accepts the browser's {@code PushSubscription} JSON at a public registration endpoint, and nothing stops
 * a client from posting a hand-crafted subscription (the {@code p256dh}/{@code auth} key material is trivially
 * self-generated) whose endpoint points into the application's own network — {@code https://10.0.0.5/…}, a loopback
 * port, a cloud metadata service. Every later send then POSTs to that address <em>from inside the network</em>, and the
 * caller-visible {@link PushOutcome} — the status code an answered variant carries versus an unanswered
 * {@link PushOutcome.Indeterminate}, plus how long the attempt took — is a blind server-side request forgery oracle for
 * internal host and port existence. {@link Endpoints#requireSecure} deliberately checks only the RFC 8030 contract
 * (absolute {@code https} URL with a host); which hosts a deployment may talk to is deployment policy, and this
 * interface is where that policy lives. Most deployments want the standard allowlist —
 * {@link EndpointPolicies#allowedOrigins} where every push service is a fixed host, and
 * {@link EndpointPolicies#allowedEndpoints} where one of them is a whole DNS zone instead; a functional interface is
 * kept as the seam so corporate egress rules or custom DNS checks can be expressed too. A policy is a required argument
 * of every {@link PushSender} factory method: the library does not choose a deployment's allowlist, but it does refuse
 * to decide on the deployment's behalf that there is none — a deployment wanting none says so with
 * {@link EndpointPolicies#unrestricted()}. Note the shape of the seam: the policy is fixed when the sender is built and
 * {@link #validate} receives only the endpoint URI, no request or tenant context — a rule that varies by tenant
 * therefore means building one sender per tenant.
 *
 * <p><b>The decision is older than the send.</b> A subscription usually arrives at a public registration endpoint and
 * is written to a store; whether this deployment will ever contact its endpoint is answerable at that moment, from the
 * same rule that will answer it before every send. Answering it there matters because a policy refusal is not a push
 * service's answer: no {@code 404}/{@code 410} ever marks the stored row as expired, so a row whose endpoint the policy
 * refuses fails on every send for the rest of its life while the subscriber's browser reports a healthy subscription.
 * Applying the policy where the subscription is accepted keeps such a row out of the store — build the
 * {@link Subscription} first, which enforces the endpoint and key-material rules, apply this policy to the endpoint it
 * carries second, and store the row only once both have passed. The registration check does not replace the send-time
 * one: the policy is deployment configuration and can change after the row was stored, so the sender validates every
 * send regardless of what was checked when the row was accepted.
 *
 * <p><b>What a URI-level check cannot do.</b> The policy sees a {@link URI}, so it can enforce name and origin rules
 * but not what the name resolves to when the connection is made: DNS rebinding (a hostname resolving to an acceptable
 * address when checked and an internal one when connected to) is out of its reach, as is anything the remote server
 * does after the connection. One gap it would otherwise leave is closed in the transport: redirects are not followed,
 * so a {@code 3xx} surfaces as a failure outcome rather than as a POST to a host this policy never saw.
 * {@link JdkPushHttpClient} builds its client with {@link java.net.http.HttpClient.Redirect#NEVER} and rejects a
 * supplied one that follows redirects, but a custom {@link PushHttpClient} carries that property itself — nothing here
 * can check it. Deployments needing strict guarantees should pin resolution and egress in the transport layer (resolve
 * the name, verify the address, connect to what was verified), per the <a
 * href="https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html">OWASP
 * SSRF Prevention Cheat Sheet</a>. The policy is a coarse filter, not a sandbox.
 *
 * <p><b>Implementations must be thread-safe.</b> One {@link PushSender} is shared across threads and
 * {@link PushSender#sendAsync} makes concurrent {@link #validate} calls the normal case; a policy keeping mutable state
 * — a resolution cache, a counter — has to guard it. The policies {@link EndpointPolicies#allowedOrigins} and
 * {@link EndpointPolicies#allowedEndpoints} return close over an immutable list of immutable rules and need none.
 */
@FunctionalInterface
public interface EndpointPolicy {

    /**
     * Decides whether {@code endpoint} may be contacted: return normally to allow it, throw
     * {@link EndpointRejectedException} to reject it. The sender calls this before encrypting, before asking the
     * {@link VapidSigner} for a signature (which may be a remote Vault/KMS operation), and before any HTTP request — a
     * rejected endpoint costs none of those, and reaches the sender's caller as the
     * {@link PushOutcome.EndpointRejected} value rather than as this exception, so one hostile row never aborts a
     * fan-out over a whole subscription store. An application applying the same policy where it accepts subscriptions
     * calls this method directly, catches the exception at its own boundary, and decides what a refusal answers there —
     * typically a {@code 400} with no row stored.
     *
     * <p>The argument's precondition is part of this seam's contract at both call sites: the endpoint has already
     * passed {@link Endpoints#requireSecure} (an absolute {@code https} URL with a host). The sender guarantees that
     * because a {@link Subscription} cannot carry anything else; a registration boundary keeps the same order by
     * building the {@link Subscription} first — which applies that check together with the key-material and length
     * rules — and applying the policy to the endpoint it carries second.
     *
     * <p>The endpoint is a capability URL (RFC 8030 §8.3): implementations must not put the raw URI into the rejection
     * message — render it with {@link Endpoints#redact} instead. A {@link RuntimeException} of any other type
     * propagates to the caller unchanged: it is a defect in the policy, not a rejection, and must not be mistaken for
     * one.
     *
     * @param endpoint the push endpoint being decided about; already validated against the
     *     {@link Endpoints#requireSecure} contract (absolute {@code https} URL with a host)
     * @throws EndpointRejectedException if the policy refuses this endpoint
     */
    void validate(URI endpoint);
}
