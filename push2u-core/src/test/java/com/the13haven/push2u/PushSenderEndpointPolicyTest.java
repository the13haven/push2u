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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

/**
 * Tests for the {@link EndpointPolicy} seam in the send pipeline. The load-bearing property is <em>where</em> the
 * policy runs: a rejected endpoint must cost zero signing operations (under an external signer, each one is a remote
 * Vault/KMS call) and zero HTTP requests — proven with a counting signer and a counting client, not asserted from the
 * code's shape. Equally load-bearing is what happens when no policy is configured: nothing — the seam must not quietly
 * narrow what a sender without a policy will send to.
 */
class PushSenderEndpointPolicyTest {

    private static final String ALLOWED_ENDPOINT = "https://push.example/send/subscriber-token";
    private static final String FOREIGN_ENDPOINT = "https://internal.example:8443/latest/meta-data?probe=1";

    private final CountingSigner signer = new CountingSigner();
    private final CountingClient client = new CountingClient();

    @Test
    void aRejectedEndpointCostsNoSignatureAndNoHttpRequest() {
        PushSender sender = sender(EndpointPolicies.allowedOrigins("https://push.example"));
        Subscription subscription = subscription(FOREIGN_ENDPOINT);
        PushMessage message = PushMessage.of(new byte[] {1});

        assertThatThrownBy(() -> sender.send(subscription, message)).isInstanceOf(EndpointRejectedException.class);

        assertThat(signer.signs.get())
                .as("no VAPID signature for a rejected endpoint — under an external signer each one is a"
                        + " remote Vault/KMS operation")
                .isZero();
        assertThat(client.posts.get())
                .as("no HTTP request for a rejected endpoint — the request itself is the SSRF primitive")
                .isZero();
    }

    @Test
    void theRejectionSurfacedBySendOmitsTheCapabilityPathAndQuery() {
        PushSender sender = sender(EndpointPolicies.allowedOrigins("https://push.example"));
        Subscription subscription = subscription(FOREIGN_ENDPOINT);
        PushMessage message = PushMessage.of(new byte[] {1});

        assertThatThrownBy(() -> sender.send(subscription, message))
                .isInstanceOf(EndpointRejectedException.class)
                .hasMessageNotContaining("meta-data")
                .hasMessageNotContaining("probe=1")
                .hasMessageContaining("https://internal.example:8443/…#");
    }

    @Test
    void withoutAPolicyAnyHttpsEndpointIsSentTo() {
        // The default-off contract pinned: with no policy configured, any https endpoint that
        // Subscription accepted is sent to, this internal-looking one included.
        PushSender sender = sender(null);

        PushResult result = sender.send(subscription(FOREIGN_ENDPOINT), PushMessage.of(new byte[] {1}));

        assertThat(result.isDelivered()).isTrue();
        assertThat(signer.signs.get()).isEqualTo(1);
        assertThat(client.posts.get()).isEqualTo(1);
    }

    @Test
    void anAllowedEndpointGoesThroughTheFullPipelineExactlyOnce() {
        PushSender sender = sender(EndpointPolicies.allowedOrigins("https://push.example"));

        PushResult result = sender.send(subscription(ALLOWED_ENDPOINT), PushMessage.of(new byte[] {1}));

        assertThat(result.isDelivered()).isTrue();
        assertThat(signer.signs.get()).isEqualTo(1);
        assertThat(client.posts.get()).isEqualTo(1);
        assertThat(client.lastEndpoint).isEqualTo(URI.create(ALLOWED_ENDPOINT));
    }

    @Test
    void sendAsyncRoutesThroughTheSamePolicy() throws Exception {
        // The async path delegates to send() inside the queued task, so the rejection completes
        // the future exceptionally rather than throwing from sendAsync — and cannot bypass the
        // policy. Both halves are pinned here.
        PushSender sender = sender(EndpointPolicies.allowedOrigins("https://push.example"));
        PushMessage message = PushMessage.of(new byte[] {1});

        CompletableFuture<PushResult> rejected = sender.sendAsync(subscription(FOREIGN_ENDPOINT), message);
        assertThatThrownBy(() -> rejected.get(5, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(EndpointRejectedException.class);
        assertThat(signer.signs.get()).isZero();
        assertThat(client.posts.get()).isZero();

        PushResult delivered =
                sender.sendAsync(subscription(ALLOWED_ENDPOINT), message).get(5, TimeUnit.SECONDS);
        assertThat(delivered.isDelivered()).isTrue();
    }

    @Test
    void aPolicyThrowingItsOwnDefectDoesNotCorruptTheSender() {
        // A policy bug (here: an IllegalStateException on the first call only) must propagate as
        // itself — not be dressed up as a rejection — and must leave the sender fully usable: the
        // sender holds no mutable state, so the next send runs the whole pipeline normally.
        AtomicInteger calls = new AtomicInteger();
        EndpointPolicy flaky = endpoint -> {
            if (calls.incrementAndGet() == 1) {
                throw new IllegalStateException("policy defect");
            }
        };
        PushSender sender = sender(flaky);
        Subscription subscription = subscription(ALLOWED_ENDPOINT);
        PushMessage message = PushMessage.of(new byte[] {1});

        assertThatThrownBy(() -> sender.send(subscription, message))
                .isInstanceOf(IllegalStateException.class)
                .isNotInstanceOf(EndpointRejectedException.class)
                .hasMessage("policy defect");
        assertThat(signer.signs.get()).isZero();
        assertThat(client.posts.get()).isZero();

        PushResult result = sender.send(subscription, message);
        assertThat(result.isDelivered()).isTrue();
        assertThat(signer.signs.get()).isEqualTo(1);
        assertThat(client.posts.get()).isEqualTo(1);
    }

    @Test
    void thePolicySeesTheEndpointUriVerbatim() {
        // The policy receives the endpoint as parsed, un-normalized — normalization is the
        // policy's own business (allowedOrigins normalizes both sides; a custom policy may not
        // want any). Pinned so a future "helpful" pre-normalization shows up as a failure.
        List<URI> seen = new ArrayList<>();
        PushSender sender = sender(seen::add);

        sender.send(subscription(ALLOWED_ENDPOINT), PushMessage.of(new byte[] {1}));

        assertThat(seen).containsExactly(URI.create(ALLOWED_ENDPOINT));
    }

    private PushSender sender(@Nullable EndpointPolicy policy) {
        PushSender.Builder builder =
                PushSender.builder(signer, "mailto:ops@example.com").httpClient(client);
        if (policy != null) {
            builder.endpointPolicy(policy);
        }
        return builder.build();
    }

    private static Subscription subscription(String endpoint) {
        return new Subscription(endpoint, b64(TestVectors.UA_PUBLIC), b64(TestVectors.AUTH_SECRET));
    }

    /** Delegates to a real in-JVM signer but counts {@code sign} calls — the cost a rejection must not incur. */
    private static final class CountingSigner implements VapidSigner {
        private final VapidSigner delegate = new LocalEcVapidSigner(generateVapidKeys());
        private final AtomicInteger signs = new AtomicInteger();

        @Override
        public byte[] sign(byte[] signingInput) {
            signs.incrementAndGet();
            return delegate.sign(signingInput);
        }

        @Override
        public byte[] publicKey() {
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
