/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.net.URI;

/**
 * A deployment's rule for which push endpoints a {@link PushSender} may contact, applied to every send before any
 * cryptography, before the VAPID signature, and before any network I/O.
 *
 * <p><b>Why this exists.</b> The endpoint inside a {@link Subscription} is attacker-influenced data: a typical
 * integration accepts the browser's {@code PushSubscription} JSON at a public registration endpoint, and nothing stops
 * a client from posting a hand-crafted subscription (the {@code p256dh}/{@code auth} key material is trivially
 * self-generated) whose endpoint points into the application's own network — {@code https://10.0.0.5/…}, a loopback
 * port, a cloud metadata service. Every later send then POSTs to that address <em>from inside the network</em>, and the
 * caller-visible outcome — {@link PushResult#statusCode()} versus {@link PushDeliveryException}, plus how long the
 * attempt took — is a blind server-side request forgery oracle for internal host and port existence.
 * {@link Endpoints#requireSecure} deliberately checks only the RFC 8030 contract (absolute {@code https} URL with a
 * host); which hosts a deployment may talk to is deployment policy, and this interface is where that policy lives. Most
 * deployments want the origin allowlist in {@link EndpointPolicies#allowedOrigins}; a functional interface is kept as
 * the seam so corporate egress rules or custom DNS checks can be expressed too. Note the shape of the seam: the policy
 * is fixed when the sender is built and {@link #validate} receives only the endpoint URI, no request or tenant context
 * — a rule that varies by tenant therefore means building one sender per tenant.
 *
 * <p><b>What a URI-level check cannot do.</b> The policy sees a {@link URI}, so it can enforce name and origin rules
 * but not what the name resolves to when the connection is made: DNS rebinding (a hostname resolving to an acceptable
 * address when checked and an internal one when connected to) is out of its reach, as is anything the remote server
 * does after the connection. One gap it would otherwise leave is closed in the transport: redirects are not followed,
 * so a {@code 3xx} surfaces as a failed {@link PushResult} rather than as a POST to a host this policy never saw.
 * {@link JdkPushHttpClient} builds its client with {@link java.net.http.HttpClient.Redirect#NEVER} and rejects a
 * supplied one that follows redirects, but a custom {@link PushHttpClient} carries that property itself — nothing here
 * can check it. Deployments needing strict guarantees should pin resolution and egress in the transport layer (resolve
 * the name, verify the address, connect to what was verified), per the <a
 * href="https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html">OWASP
 * SSRF Prevention Cheat Sheet</a>. The policy is a coarse filter, not a sandbox.
 */
@FunctionalInterface
public interface EndpointPolicy {

    /**
     * Decides whether {@code endpoint} may be contacted: return normally to allow the send, throw
     * {@link EndpointRejectedException} to reject it. The sender calls this before encrypting, before asking the
     * {@link VapidSigner} for a signature (which may be a remote Vault/KMS operation), and before any HTTP request — a
     * rejected endpoint costs none of those.
     *
     * <p>The endpoint is a capability URL (RFC 8030 §8.3): implementations must not put the raw URI into the rejection
     * message — render it with {@link Endpoints#redact} instead. A {@link RuntimeException} of any other type
     * propagates to the caller unchanged: it is a defect in the policy, not a rejection, and must not be mistaken for
     * one.
     *
     * @param endpoint the push endpoint of the subscription about to be sent to; already validated against the
     *     {@link Endpoints#requireSecure} contract (absolute {@code https} URL with a host)
     * @throws EndpointRejectedException if the policy refuses this endpoint
     */
    void validate(URI endpoint);
}
