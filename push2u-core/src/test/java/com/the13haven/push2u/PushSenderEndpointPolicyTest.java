/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static com.the13haven.push2u.PushTestSupport.generateVapidKeys;
import static com.the13haven.push2u.TestVectors.b64;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

/**
 * Tests for the {@link EndpointPolicy} seam in the send pipeline. The load-bearing property is <em>where</em> the
 * policy runs: a refused endpoint must cost zero signing operations (under an external signer, each one is a remote
 * Vault/KMS call) and zero HTTP requests — proven with a counting signer and a counting client, not asserted from the
 * code's shape. A refusal is a value end to end: the policy answers {@link EndpointAssessment.Refused} and the caller
 * reads {@link PushOutcome.EndpointRejected}, so one hostile row never aborts a fan-out; the policy's own defect — an
 * exception of any type, or a {@code null} answer — propagates or fails as itself. Every sender has a policy, so there
 * is no unguarded path left to test; what is tested instead is that {@link EndpointPolicies#unrestricted()} is
 * genuinely the way to send anywhere, so that nobody is tempted to reintroduce a no-policy sender to get that behaviour
 * back.
 */
class PushSenderEndpointPolicyTest {

    private static final String ALLOWED_ENDPOINT = "https://push.example/send/subscriber-token";
    private static final String FOREIGN_ENDPOINT = "https://internal.example:8443/latest/meta-data?probe=1";

    private final CountingSigner signer = new CountingSigner();
    private final CountingClient client = new CountingClient();

    @Test
    void aRejectedEndpointCostsNoSignatureAndNoHttpRequest() {
        PushSender sender = sender(EndpointPolicies.allowedOrigins("https://push.example"));

        PushOutcome outcome = sender.send(subscription(FOREIGN_ENDPOINT), PushMessage.of(new byte[] {1}));

        assertThat(outcome).isInstanceOf(PushOutcome.EndpointRejected.class);
        assertThat(signer.signs.get())
                .as("no VAPID signature for a rejected endpoint — under an external signer each one is a"
                        + " remote Vault/KMS operation")
                .isZero();
        assertThat(signer.publicKeys.get())
                .as("no publicKey() read for a rejected endpoint — the token cache's lookup starts with one,"
                        + " so a zero count proves the policy ran before the cache was touched at all")
                .isZero();
        assertThat(client.posts.get())
                .as("no HTTP request for a rejected endpoint — the request itself is the SSRF primitive")
                .isZero();
    }

    @Test
    void aRejectedSendTouchesNeitherTheSignerNorTheTokenCacheEvenWhenTheCacheIsWarm() {
        // The cold-cache test above cannot see a lookup that happens before the policy: a lookup
        // alone signs nothing and POSTs nothing. Warm the cache first, then have the policy turn
        // against the same endpoint — now a lookup ahead of the policy is observable twice over, as
        // a publicKey() read on the rejected send (the lookup key is built from a fresh read) and as
        // a mutation of the access-ordered LRU the sender keeps.
        AtomicBoolean rejecting = new AtomicBoolean(false);
        EndpointPolicy statefulPolicy = endpoint -> rejecting.get()
                ? new EndpointAssessment.Refused("endpoint no longer allowed: " + Endpoints.redact(endpoint.toString()))
                : new EndpointAssessment.Allowed();
        PushSender sender = sender(statefulPolicy);
        Subscription subscription = subscription(ALLOWED_ENDPOINT);
        PushMessage message = PushMessage.of(new byte[] {1});

        assertThat(sender.send(subscription, message)).isInstanceOf(PushOutcome.Accepted.class);
        int signsAfterWarming = signer.signs.get();
        int publicKeysAfterWarming = signer.publicKeys.get();
        int postsAfterWarming = client.posts.get();

        rejecting.set(true);
        assertThat(sender.send(subscription, message)).isInstanceOf(PushOutcome.EndpointRejected.class);

        assertThat(signer.signs.get())
                .as("a warm cache makes a hit free of signatures, so this alone cannot distinguish"
                        + " a lookup before the policy from no lookup — the publicKey count below can")
                .isEqualTo(signsAfterWarming);
        assertThat(signer.publicKeys.get())
                .as("no publicKey() read on the rejected send — the cache lookup starts with one, and a"
                        + " lookup would also have reordered the access-ordered LRU before the verdict")
                .isEqualTo(publicKeysAfterWarming);
        assertThat(client.posts.get()).isEqualTo(postsAfterWarming);

        // The zero-lookup assertions above must not be passing because nothing was cached: admit the
        // endpoint again and the next send serves the warmed entry — one more publicKey() read for
        // its lookup, and no new signature.
        rejecting.set(false);
        assertThat(sender.send(subscription, message)).isInstanceOf(PushOutcome.Accepted.class);
        assertThat(signer.signs.get())
                .as("the entry survived the rejection, so the cache was warm all along")
                .isEqualTo(signsAfterWarming);
        assertThat(signer.publicKeys.get()).isEqualTo(publicKeysAfterWarming + 1);
    }

    @Test
    void theRejectionOutcomeOmitsTheCapabilityPathAndQuery() {
        PushSender sender = sender(EndpointPolicies.allowedOrigins("https://push.example"));

        PushOutcome outcome = sender.send(subscription(FOREIGN_ENDPOINT), PushMessage.of(new byte[] {1}));

        assertThat(outcome).isInstanceOf(PushOutcome.EndpointRejected.class);
        PushOutcome.EndpointRejected rejected = (PushOutcome.EndpointRejected) outcome;
        // The record's generated toString prints both components, so asserting on it covers the
        // redacted endpoint, the reason, and the default rendering a log line would carry.
        assertThat(rejected.toString())
                .doesNotContain("meta-data")
                .doesNotContain("probe=1")
                .contains("https://internal.example:8443/…#");
        assertThat(rejected.redactedEndpoint()).startsWith("https://internal.example:8443/…#");
        assertThat(rejected.reason()).contains("not in the allowed set");
    }

    @Test
    void unrestrictedSendsToTheVeryEndpointAnAllowlistRejects() {
        // What the named opt-out buys, and what it costs: the same internal-looking endpoint that
        // allowedOrigins refuses above is POSTed to here. Asserting it against FOREIGN_ENDPOINT
        // specifically is what makes this a statement about the policy rather than about a send.
        PushSender sender = sender(EndpointPolicies.unrestricted());

        PushOutcome outcome = sender.send(subscription(FOREIGN_ENDPOINT), PushMessage.of(new byte[] {1}));

        assertThat(outcome).isInstanceOf(PushOutcome.Accepted.class);
        assertThat(signer.signs.get()).isEqualTo(1);
        assertThat(client.posts.get()).isEqualTo(1);
        assertThat(client.lastEndpoint).isEqualTo(URI.create(FOREIGN_ENDPOINT));
    }

    @Test
    void unrestrictedRefusesNothingAtAll() {
        // Directly against the policy rather than through a sender: no shape of endpoint is
        // refused, loopback and cloud-metadata included, so a reader is not left wondering whether
        // some category is quietly still blocked.
        EndpointPolicy unrestricted = EndpointPolicies.unrestricted();

        for (String endpoint : new String[] {
            "https://127.0.0.1:8443/send/token",
            "https://10.0.0.5/send/token",
            "https://169.254.169.254/latest/meta-data/",
            "https://user@allowed.example/send/token"
        }) {
            assertThat(unrestricted.assess(URI.create(endpoint)))
                    .as("%s", endpoint)
                    .isInstanceOf(EndpointAssessment.Allowed.class);
        }
    }

    @Test
    void anAllowedEndpointGoesThroughTheFullPipelineExactlyOnce() {
        PushSender sender = sender(EndpointPolicies.allowedOrigins("https://push.example"));

        PushOutcome outcome = sender.send(subscription(ALLOWED_ENDPOINT), PushMessage.of(new byte[] {1}));

        assertThat(outcome).isInstanceOf(PushOutcome.Accepted.class);
        assertThat(signer.signs.get()).isEqualTo(1);
        assertThat(client.posts.get()).isEqualTo(1);
        assertThat(client.lastEndpoint).isEqualTo(URI.create(ALLOWED_ENDPOINT));
    }

    @Test
    void sendAsyncRoutesThroughTheSamePolicyAndCompletesNormallyWithTheRejection() throws Exception {
        // The async path delegates to send() inside the queued task, so it cannot bypass the
        // policy — and a rejection is an outcome, so the future completes NORMALLY with the
        // EndpointRejected value rather than exceptionally: a fan-out reads every row's verdict
        // from one channel.
        PushSender sender = sender(EndpointPolicies.allowedOrigins("https://push.example"));
        PushMessage message = PushMessage.of(new byte[] {1});

        PushOutcome rejected =
                sender.sendAsync(subscription(FOREIGN_ENDPOINT), message).get(5, TimeUnit.SECONDS);
        assertThat(rejected).isInstanceOf(PushOutcome.EndpointRejected.class);
        assertThat(signer.signs.get()).isZero();
        assertThat(client.posts.get()).isZero();

        PushOutcome accepted =
                sender.sendAsync(subscription(ALLOWED_ENDPOINT), message).get(5, TimeUnit.SECONDS);
        assertThat(accepted).isInstanceOf(PushOutcome.Accepted.class);
    }

    @Test
    void aPolicyThrowingItsOwnDefectDoesNotCorruptTheSender() {
        // A policy bug (here: an IllegalStateException on the first call only) must propagate as
        // itself — not be dressed up as a refusal outcome: this seam signals by returning, so the
        // facade converts no exception out of it at all and any throw is the defect it looks like.
        // And it must leave the sender fully usable: the policy runs ahead of the token cache, the
        // sender's only mutable state, so a policy that throws has touched nothing and the next
        // send runs normally.
        AtomicInteger calls = new AtomicInteger();
        EndpointPolicy flaky = endpoint -> {
            if (calls.incrementAndGet() == 1) {
                throw new IllegalStateException("policy defect");
            }
            return new EndpointAssessment.Allowed();
        };
        PushSender sender = sender(flaky);
        Subscription subscription = subscription(ALLOWED_ENDPOINT);
        PushMessage message = PushMessage.of(new byte[] {1});

        assertThatThrownBy(() -> sender.send(subscription, message))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("policy defect");
        assertThat(signer.signs.get()).isZero();
        assertThat(client.posts.get()).isZero();

        assertThat(sender.send(subscription, message)).isInstanceOf(PushOutcome.Accepted.class);
        assertThat(signer.signs.get()).isEqualTo(1);
        assertThat(client.posts.get()).isEqualTo(1);
    }

    @Test
    void aPolicyAnsweringNullFailsTheSendAsTheDefectItIs() {
        // The violated non-null contract: reading null as Allowed would fail open on the one
        // egress control, reading it as Refused would invent a decision the deployment never made
        // — so the send fails with the sender's own NullPointerException, which stops a fan-out
        // exactly as any other policy defect does, and nothing downstream was touched.
        EndpointPolicy answersNull = endpoint -> null;
        PushSender sender = sender(answersNull);
        Subscription subscription = subscription(ALLOWED_ENDPOINT);
        PushMessage message = PushMessage.of(new byte[] {1});

        assertThatThrownBy(() -> sender.send(subscription, message))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("endpoint policy returned null");
        assertThat(signer.signs.get()).isZero();
        assertThat(signer.publicKeys.get()).isZero();
        assertThat(client.posts.get()).isZero();
    }

    @Test
    void thePolicySeesTheEndpointUriVerbatim() {
        // The policy receives the endpoint as parsed, un-normalized — normalization is the
        // policy's own business (allowedOrigins normalizes both sides; a custom policy may not
        // want any). Pinned so a future "helpful" pre-normalization shows up as a failure.
        List<URI> seen = new ArrayList<>();
        PushSender sender = sender(endpoint -> {
            seen.add(endpoint);
            return new EndpointAssessment.Allowed();
        });

        sender.send(subscription(ALLOWED_ENDPOINT), PushMessage.of(new byte[] {1}));

        assertThat(seen).containsExactly(URI.create(ALLOWED_ENDPOINT));
    }

    private PushSender sender(EndpointPolicy policy) {
        return PushSender.builder(signer, "mailto:ops@example.com", policy)
                .httpClient(client)
                .build();
    }

    private static Subscription subscription(String endpoint) {
        return new Subscription(endpoint, b64(TestVectors.UA_PUBLIC), b64(TestVectors.AUTH_SECRET));
    }

    /**
     * Delegates to a real in-JVM signer but counts both contract methods — the costs a rejection must not incur.
     * {@code sign} is the obvious one; {@code publicKey} is the subtle one: the token cache's lookup key is built from
     * a fresh {@code publicKey()} read, so a rejected send that performed a cache lookup would show up here even though
     * it signed nothing — and under an external signer that read is allowed to be a remote call.
     */
    private static final class CountingSigner implements VapidSigner {
        private final VapidSigner delegate = new LocalEcVapidSigner(generateVapidKeys());
        private final AtomicInteger signs = new AtomicInteger();
        private final AtomicInteger publicKeys = new AtomicInteger();

        @Override
        public byte[] sign(byte[] signingInput) {
            signs.incrementAndGet();
            return delegate.sign(signingInput);
        }

        @Override
        public byte[] publicKey() {
            publicKeys.incrementAndGet();
            return delegate.publicKey();
        }
    }

    /** Answers 201 to everything and counts the POSTs — zero of which may happen for a rejected endpoint. */
    private static final class CountingClient implements PushHttpClient {
        private final AtomicInteger posts = new AtomicInteger();

        @Nullable
        private volatile URI lastEndpoint;

        @Override
        public PushResponse post(URI endpoint, Map<String, String> headers, byte[] body) {
            posts.incrementAndGet();
            lastEndpoint = endpoint;
            return PushResponse.of(201);
        }
    }
}
