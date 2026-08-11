/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static com.the13haven.push2u.PushTestSupport.generateVapidKeys;
import static com.the13haven.push2u.TestVectors.b64;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;

import org.assertj.core.api.Assertions;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;

/**
 * The VAPID token cache's ordinary behaviour, observed strictly from outside {@link PushSender}: how many times the
 * signer signed, and what {@code Authorization} value each request carried. RFC 8292 §5 encourages application servers
 * to reuse tokens; these tests pin what reuse must and must not do — hit without signing, key the entry by the identity
 * the header itself carries, survive authentication statuses, degrade to signing on overflow, and keep the cached
 * bearer credential out of every exception a send can throw. The two-clock renewal bounds live in
 * {@link PushSenderJwtRenewalTest}, the locking discipline in {@link PushSenderJwtConcurrencyTest}.
 */
class PushSenderJwtReuseTest {

    private static final String AUDIENCE_A_ENDPOINT = "https://push-a.example/sub/1";
    private static final String AUDIENCE_B_ENDPOINT = "https://push-b.example/sub/2";
    private static final String AUDIENCE_C_ENDPOINT = "https://push-c.example/sub/3";

    private final CapturingClient client = new CapturingClient();
    private final CountingVapidSigner signer = new CountingVapidSigner(new LocalEcVapidSigner(generateVapidKeys()));

    @Test
    void aCacheHitSignsNothingAndServesTheIdenticalHeader() {
        PushSender sender = sender();

        PushResult first = sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message());
        PushResult second = sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message());

        assertThat(first.isDelivered()).isTrue();
        assertThat(second.isDelivered()).isTrue();
        assertThat(signer.signCount())
                .as("the second send to the same audience reuses the token — sign() is not called at all")
                .isEqualTo(1);
        assertThat(client.authorizations()).hasSize(2);
        assertThat(client.authorizations().get(1))
                .as("a hit serves the very value that was minted, not a re-derivation of it")
                .isEqualTo(client.authorizations().get(0));
    }

    @Test
    void distinctAudiencesGetDistinctTokens() {
        PushSender sender = sender();

        sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message());
        sender.send(subscriptionAt(AUDIENCE_B_ENDPOINT), message());

        assertThat(signer.signCount()).isEqualTo(2);
        assertThat(client.authorizations().get(0))
                .as("aud is a claim of the token, so one entry can never serve two origins")
                .isNotEqualTo(client.authorizations().get(1));
    }

    @Test
    void jwtReuseFalseSignsEverySend() {
        PushSender sender = builder().jwtReuse(false).build();

        sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message());
        sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message());

        assertThat(signer.signCount())
                .as("jwtReuse(false) is the declared off switch: every send builds and signs afresh")
                .isEqualTo(2);
    }

    @Test
    void eachSenderHasItsOwnCache() {
        PushSender first = sender();
        PushSender second = sender();

        first.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message());
        second.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message());

        assertThat(signer.signCount())
                .as("two senders sharing one signer still hold two caches — an entry never crosses instances")
                .isEqualTo(2);
    }

    @Test
    void evictionPicksTheLeastRecentlyUsedEntry() {
        PushSender sender = builder().jwtCacheSize(2).build();

        sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message()); // mint A          — signs: 1
        sender.send(subscriptionAt(AUDIENCE_B_ENDPOINT), message()); // mint B          — signs: 2
        sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message()); // hit A (touches) — signs: 2
        sender.send(subscriptionAt(AUDIENCE_C_ENDPOINT), message()); // mint C, evicts B — signs: 3
        assertThat(signer.signCount()).isEqualTo(3);

        sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message());
        assertThat(signer.signCount())
                .as("A was touched most recently, so it survived the eviction")
                .isEqualTo(3);

        sender.send(subscriptionAt(AUDIENCE_B_ENDPOINT), message());
        assertThat(signer.signCount())
                .as("B was the least recently used entry, so B is the one eviction picked")
                .isEqualTo(4);
    }

    @Test
    void aFullCacheSignsInsteadOfRefusing() {
        PushSender sender = builder().jwtCacheSize(1).build();

        for (int round = 0; round < 3; round++) {
            assertThat(sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message())
                            .isDelivered())
                    .isTrue();
            assertThat(sender.send(subscriptionAt(AUDIENCE_B_ENDPOINT), message())
                            .isDelivered())
                    .isTrue();
        }

        assertThat(signer.signCount())
                .as("alternating audiences through a one-entry cache degrades to signing per send — never a failure")
                .isEqualTo(6);
    }

    @Test
    void aChangedAdvertisedKeyGetsANewTokenUnderTheNewKey() {
        SettableKeySigner rotating =
                new SettableKeySigner(signer, generateVapidKeys().publicKey());
        PushSender sender = PushSender.builder(rotating, "mailto:ops@example.com", EndpointPolicies.unrestricted())
                .httpClient(client)
                .build();

        sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message());
        byte[] newKey = generateVapidKeys().publicKey();
        rotating.advertise(newKey);
        sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message());

        assertThat(signer.signCount())
                .as("the lookup reads the advertised key afresh, so a moved key is a miss, not a stale hit")
                .isEqualTo(2);
        assertThat(client.authorizations().get(1))
                .as("the new token is signed under the new k, not the old token re-served")
                .endsWith(", k=" + VapidKeys.encodePublicKey(newKey))
                .isNotEqualTo(client.authorizations().get(0));

        sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message());
        assertThat(signer.signCount())
                .as("the replacement entry serves the new identity from then on")
                .isEqualTo(2);
    }

    /**
     * A signer that answers a different key from every {@code publicKey()} call violates the stability contract, but
     * the cache must still file each entry under the key its own header carries — the mint's single read feeds both the
     * {@code k} parameter and the entry's key, so the two cannot disagree even here. Observable as a hit: the first
     * send's lookup reads one key and its mint reads the next, so if the entry were filed under the lookup's read, the
     * second send (whose lookup reads the mint's key) could never find it.
     */
    @Test
    void anEntryIsFiledUnderTheKeyItsOwnHeaderCarries() {
        byte[] lookupOnlyKey = generateVapidKeys().publicKey();
        byte[] mintedKey = generateVapidKeys().publicKey();
        FirstCallThenSteadyKeySigner drifting = new FirstCallThenSteadyKeySigner(signer, lookupOnlyKey, mintedKey);
        PushSender sender = PushSender.builder(drifting, "mailto:ops@example.com", EndpointPolicies.unrestricted())
                .httpClient(client)
                .build();

        sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message());
        assertThat(client.authorizations().get(0))
                .as("the header carries the key the mint read, not the one the lookup read")
                .endsWith(", k=" + VapidKeys.encodePublicKey(mintedKey));

        sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message());
        assertThat(signer.signCount())
                .as("the entry was filed under the header's own key — the second lookup, reading that key, hits")
                .isEqualTo(1);
    }

    /**
     * The cache's key must be the base64url of the raw {@code publicKey()} bytes — the value the header's {@code k}
     * actually carries — and never {@code publicKeyBase64Url()}, which is a {@code default} an implementation may
     * override. This signer overrides it to a string that names no key at all: if any part of the cache path reached
     * for the override, the lookup key could never match what the mint filed (the header is built from the raw bytes),
     * and every send would miss and sign — a defect only a benchmark would ever surface. A hit is the proof the
     * override is never consulted.
     */
    @Test
    void theCacheKeyComesFromThePublicKeyBytesNotFromTheOverridableEncoding() {
        VapidSigner overriding = new DriftedEncodingSigner(signer);
        PushSender sender = PushSender.builder(overriding, "mailto:ops@example.com", EndpointPolicies.unrestricted())
                .httpClient(client)
                .build();

        sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message());
        sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message());

        assertThat(signer.signCount())
                .as("the second send hits: lookup and filing both encode publicKey()'s bytes, so the drifted"
                        + " publicKeyBase64Url() override can never split them apart")
                .isEqualTo(1);
        assertThat(client.authorizations().getFirst())
                .as("the header's k likewise carries the raw bytes' encoding, not the override's answer")
                .endsWith(", k=" + VapidKeys.encodePublicKey(overriding.publicKey()));
    }

    @Test
    void a401DoesNotEvictTheEntry() {
        authenticationStatusDoesNotEvict(401);
    }

    @Test
    void a403DoesNotEvictTheEntry() {
        authenticationStatusDoesNotEvict(403);
    }

    /**
     * RFC 8292 §4.2 makes "the key doesn't match the one the subscription was created under" a ground for refusing
     * authentication, so a 401/403 is a statement about a subscription at least as often as about the token — and a
     * single hostile subscription could otherwise evict, on every send, the entry every legitimate send to that origin
     * shares. The cache ignores authentication statuses entirely.
     */
    private void authenticationStatusDoesNotEvict(int status) {
        PushSender sender = sender();
        sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message());

        client.respondNextWith(status);
        PushResult refused = sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message());
        assertThat(refused.status()).isEqualTo(PushResult.Status.FAILED);
        assertThat(refused.statusCode()).isEqualTo(status);

        PushResult after = sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message());
        assertThat(after.isDelivered()).isTrue();
        assertThat(signer.signCount())
                .as("the refused send and the one after it both reuse the entry — no eviction on %s", status)
                .isEqualTo(1);
        assertThat(client.authorizations())
                .allSatisfy(header ->
                        assertThat(header).isEqualTo(client.authorizations().getFirst()));
    }

    @Test
    void aRenewMarginAtOrAboveTheExpiryMintsEverySendAndNeverFails() {
        // The last margin is absurd on purpose: however large the value, the arithmetic must reduce
        // it to "every send mints" rather than overflow into a failed send.
        for (Duration margin :
                new Duration[] {Duration.ofHours(12), Duration.ofHours(13), Duration.ofSeconds(Long.MAX_VALUE)}) {
            CapturingClient ownClient = new CapturingClient();
            CountingVapidSigner ownSigner = new CountingVapidSigner(new LocalEcVapidSigner(generateVapidKeys()));
            PushSender sender = PushSender.builder(ownSigner, "mailto:ops@example.com", EndpointPolicies.unrestricted())
                    .httpClient(ownClient)
                    .jwtExpiry(Duration.ofHours(12))
                    .jwtRenewBefore(margin)
                    .build();

            assertThat(sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message())
                            .isDelivered())
                    .isTrue();
            assertThat(sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message())
                            .isDelivered())
                    .isTrue();
            assertThat(ownSigner.signCount())
                    .as(
                            "a margin of %s swallows the whole 12h life: every send mints — a consequence, not an error",
                            margin)
                    .isEqualTo(2);
        }
    }

    /**
     * The cached value is a bearer credential. A universal negative is not provable, so this checks the observable
     * surfaces a caller actually meets: the messages of the exceptions the send path throws once a token is cached —
     * the policy rejection, the size precondition and a transport failure — none of which may quote it.
     */
    @Test
    void theCachedTokenReachesNoExceptionMessageOnTheSendPath() {
        PushSender sender = PushSender.builder(
                        signer, "mailto:ops@example.com", EndpointPolicies.allowedOrigins("https://push-a.example"))
                .httpClient(client)
                .build();
        sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message());
        String token = client.authorizations()
                .getFirst()
                .substring(
                        "vapid t=".length(), client.authorizations().getFirst().indexOf(", k="));

        Throwable rejected = thrownBy(() -> sender.send(subscriptionAt("https://not-allowed.example/sub"), message()));
        assertThat(rejected).isInstanceOf(EndpointRejectedException.class);
        assertNoMessageCarries(rejected, token);

        Throwable oversized =
                thrownBy(() -> sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), PushMessage.of(new byte[5000])));
        assertThat(oversized).isInstanceOf(IllegalArgumentException.class);
        assertNoMessageCarries(oversized, token);

        client.failNextWith(new PushDeliveryException("connection reset by push service", new IOException()));
        Throwable transport = thrownBy(() -> sender.send(subscriptionAt(AUDIENCE_A_ENDPOINT), message()));
        assertThat(transport).isInstanceOf(PushDeliveryException.class);
        assertNoMessageCarries(transport, token);
    }

    private static Throwable thrownBy(ThrowingCallable callable) {
        Throwable thrown = Assertions.catchThrowable(callable);
        assertThat(thrown).isNotNull();
        return thrown;
    }

    private static void assertNoMessageCarries(Throwable thrown, String token) {
        for (Throwable current = thrown; current != null; current = current.getCause()) {
            assertThat(String.valueOf(current.getMessage()))
                    .as("%s must not quote the cached bearer credential", current.getClass())
                    .doesNotContain(token);
            assertThat(current.toString()).doesNotContain(token);
        }
    }

    private PushSender sender() {
        return builder().build();
    }

    private PushSender.Builder builder() {
        return PushSender.builder(signer, "mailto:ops@example.com", EndpointPolicies.unrestricted())
                .httpClient(client);
    }

    private static Subscription subscriptionAt(String endpoint) {
        return new Subscription(endpoint, b64(TestVectors.UA_PUBLIC), b64(TestVectors.AUTH_SECRET));
    }

    private static PushMessage message() {
        return PushMessage.of("x".getBytes(StandardCharsets.UTF_8));
    }

    /** Records every Authorization header; responds 201 unless a status or an exception was scripted. */
    private static final class CapturingClient implements PushHttpClient {
        private final List<String> authorizations = new ArrayList<>();
        private final Deque<Integer> statuses = new ArrayDeque<>();
        private final Deque<PushDeliveryException> failures = new ArrayDeque<>();

        @Override
        public PushResponse post(URI endpoint, Map<String, String> headers, byte[] body) {
            authorizations.add(headers.get("Authorization"));
            PushDeliveryException failure = failures.poll();
            if (failure != null) {
                throw failure;
            }
            Integer status = statuses.poll();
            return PushResponse.of(status != null ? status : 201);
        }

        void respondNextWith(int status) {
            statuses.add(status);
        }

        void failNextWith(PushDeliveryException failure) {
            failures.add(failure);
        }

        List<String> authorizations() {
            return authorizations;
        }
    }

    /** Delegates signing; advertises whatever key it was last told to. */
    private static final class SettableKeySigner implements VapidSigner {
        private final VapidSigner delegate;
        private volatile byte[] advertised;

        SettableKeySigner(VapidSigner delegate, byte[] advertised) {
            this.delegate = delegate;
            this.advertised = advertised;
        }

        void advertise(byte[] key) {
            this.advertised = key;
        }

        @Override
        public byte[] sign(byte[] signingInput) {
            return delegate.sign(signingInput);
        }

        @Override
        public byte[] publicKey() {
            return advertised.clone();
        }
    }

    /**
     * Advertises a steady key from {@code publicKey()} while overriding the {@code default publicKeyBase64Url()} with a
     * string that is not the encoding of anything — the override an implementation may legitimately ship (for a
     * custodian handing the key out pre-encoded) taken to the adversarial extreme the cache must never consult.
     */
    private static final class DriftedEncodingSigner implements VapidSigner {
        private final VapidSigner delegate;

        DriftedEncodingSigner(VapidSigner delegate) {
            this.delegate = delegate;
        }

        @Override
        public byte[] sign(byte[] signingInput) {
            return delegate.sign(signingInput);
        }

        @Override
        public byte[] publicKey() {
            return delegate.publicKey();
        }

        @Override
        public String publicKeyBase64Url() {
            return "not-the-encoding-of-any-key";
        }
    }

    /** Answers one key on the first {@code publicKey()} call and another on every later one. */
    private static final class FirstCallThenSteadyKeySigner implements VapidSigner {
        private final VapidSigner delegate;
        private final byte[] firstKey;
        private final byte[] steadyKey;
        private boolean firstCallTaken;

        FirstCallThenSteadyKeySigner(VapidSigner delegate, byte[] firstKey, byte[] steadyKey) {
            this.delegate = delegate;
            this.firstKey = firstKey;
            this.steadyKey = steadyKey;
        }

        @Override
        public byte[] sign(byte[] signingInput) {
            return delegate.sign(signingInput);
        }

        @Override
        public synchronized byte[] publicKey() {
            if (!firstCallTaken) {
                firstCallTaken = true;
                return firstKey.clone();
            }
            return steadyKey.clone();
        }
    }
}
