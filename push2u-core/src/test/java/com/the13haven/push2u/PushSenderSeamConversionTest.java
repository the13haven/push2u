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

import java.io.InterruptedIOException;
import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.OptionalInt;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

/**
 * The facade's seam-signal conversions (ADR-021): exactly three exception types convert to outcomes —
 * {@link PushDeliveryException} to {@code Indeterminate}, {@link EndpointRejectedException} to
 * {@code EndpointRejected}, {@link VapidSignerUnavailableException} to {@code SignerUnavailable} — and any other
 * {@code RuntimeException} out of a consumer seam propagates as the defect it is. Plus the interruption discipline the
 * enumeration exists for: the conversion is refused, on the push and signer paths alike, when the cause chain carries
 * an {@link InterruptedException} <b>or</b> the thread's interrupt status is set, and what leaves is
 * {@link PushInterruptedException} with the contracts ADR-022 fixes for each send method. Plus the guards on the
 * members those conversions read (issue #155): a defective accessor on a seam's exception costs the caller a
 * diagnostic, never the classification.
 */
class PushSenderSeamConversionTest {

    private static final String ENDPOINT = "https://push.example/sub/1";

    @Test
    void anUnansweredPostBecomesIndeterminateCarryingTheTransportsException() {
        PushDeliveryException raised = new PushDeliveryException("no answer");
        PushSender sender = sender((endpoint, headers, body) -> {
            throw raised;
        });

        PushOutcome outcome = sender.send(subscription(), message());

        assertThat(outcome).isInstanceOf(PushOutcome.Indeterminate.class);
        assertThat(((PushOutcome.Indeterminate) outcome).cause())
                .as("the cause is the transport's own exception, not a wrapper — with it gone, nothing could"
                        + " say why the send went unanswered")
                .isSameAs(raised);
    }

    @Test
    void anyOtherRuntimeExceptionFromTheTransportPropagatesAsADefect() {
        PushSender sender = sender((endpoint, headers, body) -> {
            throw new IllegalStateException("transport bug");
        });
        Subscription subscription = subscription();
        PushMessage message = message();

        assertThatThrownBy(() -> sender.send(subscription, message))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("transport bug");
    }

    @Test
    void anUnavailableSignerBecomesSignerUnavailableCopyingStatusAndHint() {
        VapidSignerUnavailableException raised =
                new VapidSignerUnavailableException("custodian sealed", 503, Duration.ofSeconds(30), null);
        CountingClient client = new CountingClient();
        PushSender sender = PushSender.builder(
                        new FailingSigner(raised), "mailto:ops@example.com", EndpointPolicies.unrestricted())
                .httpClient(client)
                .build();

        PushOutcome outcome = sender.send(subscription(), message());

        assertThat(outcome).isInstanceOf(PushOutcome.SignerUnavailable.class);
        PushOutcome.SignerUnavailable unavailable = (PushOutcome.SignerUnavailable) outcome;
        assertThat(unavailable.status()).hasValue(503);
        assertThat(unavailable.retryAfter()).contains(Duration.ofSeconds(30));
        assertThat(unavailable.cause()).isSameAs(raised);
        assertThat(client.posts.get())
                .as("no signature, no POST — the outcome is NotAttempted and a repeat cannot duplicate")
                .isZero();
    }

    @Test
    void aSignerWithNoStatusAndNoHintReportsBothEmpty() {
        VapidSignerUnavailableException raised = new VapidSignerUnavailableException("nothing answered");
        PushSender sender = PushSender.builder(
                        new FailingSigner(raised), "mailto:ops@example.com", EndpointPolicies.unrestricted())
                .httpClient(new CountingClient())
                .build();

        PushOutcome outcome = sender.send(subscription(), message());

        assertThat(((PushOutcome.SignerUnavailable) outcome).status()).isEqualTo(OptionalInt.empty());
        assertThat(((PushOutcome.SignerUnavailable) outcome).retryAfter()).isEmpty();
    }

    @Test
    void aCryptoDefectFromTheSignerPropagates() {
        // The narrowed contract: PushCryptoException means a failure that recurs, and converting it
        // would bury a defect in a value a fan-out is expected to absorb.
        PushCryptoException raised = new PushCryptoException("key of a type VAPID cannot use");
        PushSender sender = PushSender.builder(
                        new FailingSigner(raised), "mailto:ops@example.com", EndpointPolicies.unrestricted())
                .httpClient(new CountingClient())
                .build();
        Subscription subscription = subscription();
        PushMessage message = message();

        assertThatThrownBy(() -> sender.send(subscription, message)).isSameAs(raised);
    }

    // ---- the interruption discipline -----------------------------------------------------------

    @Test
    void aTransportFailureCarryingAnInterruptedExceptionLeavesAsPushInterrupted() {
        PushDeliveryException raised =
                new PushDeliveryException("interrupted mid-exchange", new InterruptedException("stop"));
        PushSender sender = sender((endpoint, headers, body) -> {
            // The flag is deliberately NOT set: this is the chain half of the disjunction — a
            // transport that attached the cause without re-setting the flag.
            throw raised;
        });
        Subscription subscription = subscription();
        PushMessage message = message();

        try {
            assertThatThrownBy(() -> sender.send(subscription, message))
                    .isInstanceOf(PushInterruptedException.class)
                    .hasCause(raised);
            assertThat(Thread.currentThread().isInterrupted())
                    .as("the synchronous promise: the flag is re-set on the calling thread before the throw,"
                            + " even where only the cause chain carried the interruption")
                    .isTrue();
        } finally {
            // Clear the flag this test deliberately provoked, so later tests on this worker start clean.
            Thread.interrupted();
        }
    }

    @Test
    void aTransportFailureWithTheFlagSetAndNoInterruptedExceptionLeavesAsPushInterrupted() {
        // The flag half of the disjunction: an interruption surfacing as InterruptedIOException
        // carries no InterruptedException beneath it, and the seam re-set the flag as it owes.
        PushDeliveryException raised =
                new PushDeliveryException("interrupted mid-exchange", new InterruptedIOException("closed"));
        PushSender sender = sender((endpoint, headers, body) -> {
            Thread.currentThread().interrupt();
            throw raised;
        });
        Subscription subscription = subscription();
        PushMessage message = message();

        try {
            assertThatThrownBy(() -> sender.send(subscription, message))
                    .isInstanceOf(PushInterruptedException.class)
                    .hasCause(raised);
            assertThat(Thread.currentThread().isInterrupted()).isTrue();
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void aTransportFailureWithNoInterruptionAnywhereStaysIndeterminate() {
        // The control for the two tests above: the same exception type with neither half of the
        // disjunction true converts as usual.
        PushSender sender = sender((endpoint, headers, body) -> {
            throw new PushDeliveryException("plain timeout", new java.io.IOException("timed out"));
        });

        assertThat(sender.send(subscription(), message())).isInstanceOf(PushOutcome.Indeterminate.class);
    }

    @Test
    void aSignerFailureCarryingAnInterruptedExceptionLeavesAsPushInterrupted() {
        VapidSignerUnavailableException raised =
                new VapidSignerUnavailableException("interrupted waiting for custodian", new InterruptedException());
        PushSender sender = PushSender.builder(
                        new FailingSigner(raised), "mailto:ops@example.com", EndpointPolicies.unrestricted())
                .httpClient(new CountingClient())
                .build();
        Subscription subscription = subscription();
        PushMessage message = message();

        try {
            assertThatThrownBy(() -> sender.send(subscription, message))
                    .as("a send reports a cancellation as a cancellation, never as an unavailable custodian")
                    .isInstanceOf(PushInterruptedException.class)
                    .hasCause(raised);
            assertThat(Thread.currentThread().isInterrupted()).isTrue();
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void anInterruptedAsyncSendCompletesTheFutureExceptionallyAndDoesNotCancelIt() throws Exception {
        PushSender sender = sender((endpoint, headers, body) -> {
            throw new PushDeliveryException("interrupted mid-exchange", new InterruptedException("stop"));
        });

        CompletableFuture<PushOutcome> future = sender.sendAsync(subscription(), message());
        assertThatThrownBy(() -> future.get(5, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(PushInterruptedException.class);

        assertThat(future.isCancelled())
                .as("the future completes exceptionally rather than cancelled, so a caller's own cancel()"
                        + " stays distinguishable from a worker stopped mid-flight")
                .isFalse();
        assertThat(Thread.currentThread().isInterrupted())
                .as("the flag on the thread reading the future is not promised — it was never interrupted")
                .isFalse();
    }

    // ---- the guarded reads of seam-exception members -------------------------------------------

    @Test
    void aRejectionWhoseGetMessageThrowsFallsBackToTheLibrarysOwnReason() {
        IllegalStateException defect =
                new IllegalStateException("policy bug mentioning " + ENDPOINT + "/secret-capability-token");
        EndpointRejectedException raised = new EndpointRejectedException("never read") {
            @Override
            public String getMessage() {
                throw defect;
            }
        };
        PushSender sender = PushSender.builder(generateVapidKeys(), "mailto:ops@example.com", endpoint -> {
                    throw raised;
                })
                .httpClient(new CountingClient())
                .build();

        PushOutcome outcome = sender.send(subscription(), message());

        assertThat(outcome).isInstanceOf(PushOutcome.EndpointRejected.class);
        PushOutcome.EndpointRejected rejected = (PushOutcome.EndpointRejected) outcome;
        assertThat(rejected.reason())
                .as("the fallback is the library's own fixed text, distinguishable from the empty string"
                        + " a null message renders as")
                .isEqualTo("endpoint policy rejected the endpoint; reason unavailable");
        // The accessor's complaint was written by nobody who accepted the policy seam's redaction
        // contract — here it carries the raw capability URL — so nothing of it may travel: not its
        // message, not its class name, not its rendering.
        assertThat(rejected.reason())
                .doesNotContain("secret-capability-token")
                .doesNotContain("policy bug")
                .doesNotContain(defect.getClass().getSimpleName())
                .doesNotContain(defect.toString());
        assertThat(rejected.redactedEndpoint()).startsWith("https://push.example/…#");
    }

    @Test
    void aRejectionWithANullMessageStillRendersTheEmptyReason() {
        // The other half of the distinguishability claim above: a policy that wrote no message at
        // all renders as "", not as the fallback text reserved for a broken accessor.
        EndpointRejectedException raised = new EndpointRejectedException("replaced by the override") {
            @Override
            public String getMessage() {
                return null;
            }
        };
        PushSender sender = PushSender.builder(generateVapidKeys(), "mailto:ops@example.com", endpoint -> {
                    throw raised;
                })
                .httpClient(new CountingClient())
                .build();

        PushOutcome outcome = sender.send(subscription(), message());

        assertThat(((PushOutcome.EndpointRejected) outcome).reason()).isEmpty();
    }

    @Test
    void anErrorOutOfASeamAccessorLeavesSendUnclassified() {
        // The guard's boundary is RuntimeException, pinned at the send level: an AssertionError
        // out of consumer code is neither survived nor laundered into an outcome.
        EndpointRejectedException raised = new EndpointRejectedException("never read") {
            @Override
            public String getMessage() {
                throw new AssertionError("invariant failed inside an accessor");
            }
        };
        PushSender sender = PushSender.builder(generateVapidKeys(), "mailto:ops@example.com", endpoint -> {
                    throw raised;
                })
                .httpClient(new CountingClient())
                .build();
        Subscription subscription = subscription();
        PushMessage message = message();

        assertThatThrownBy(() -> sender.send(subscription, message))
                .isInstanceOf(AssertionError.class)
                .hasMessage("invariant failed inside an accessor");
    }

    @Test
    void aSignerFailureWhoseGetCauseThrowsKeepsItsClassificationAndRecordsTheDefect() {
        IllegalStateException defect = new IllegalStateException("getCause broke");
        VapidSignerUnavailableException raised =
                new VapidSignerUnavailableException("custodian sealed", 503, Duration.ofSeconds(30), null) {
                    @Override
                    public synchronized Throwable getCause() {
                        throw defect;
                    }
                };
        PushSender sender = PushSender.builder(
                        new FailingSigner(raised), "mailto:ops@example.com", EndpointPolicies.unrestricted())
                .httpClient(new CountingClient())
                .build();

        PushOutcome outcome = sender.send(subscription(), message());

        assertThat(outcome).isInstanceOf(PushOutcome.SignerUnavailable.class);
        PushOutcome.SignerUnavailable unavailable = (PushOutcome.SignerUnavailable) outcome;
        assertThat(unavailable.cause()).isSameAs(raised);
        assertThat(unavailable.status()).hasValue(503);
        assertThat(raised.getSuppressed())
                .as("the interruption walk stopped on the defect and recorded it where the caller can see it"
                        + " — on the exception the outcome carries")
                .containsExactly(defect);
    }

    @Test
    void aTransportFailureWhoseGetCauseThrowsStaysIndeterminateAndRecordsTheDefect() {
        IllegalStateException defect = new IllegalStateException("getCause broke");
        PushDeliveryException raised = new PushDeliveryException("no answer") {
            @Override
            public synchronized Throwable getCause() {
                throw defect;
            }
        };
        PushSender sender = sender((endpoint, headers, body) -> {
            throw raised;
        });

        PushOutcome outcome = sender.send(subscription(), message());

        assertThat(outcome).isInstanceOf(PushOutcome.Indeterminate.class);
        assertThat(((PushOutcome.Indeterminate) outcome).cause()).isSameAs(raised);
        assertThat(raised.getSuppressed()).containsExactly(defect);
    }

    @Test
    void anInterruptArrivingDuringTheCauseWalkStillLeavesAsPushInterrupted() {
        // The walk's tail asks the flag once more, however the walk ended — so an interruption
        // that lands while consumer code inside getCause() runs is not missed.
        PushDeliveryException raised = new PushDeliveryException("exchange stopped") {
            @Override
            public synchronized Throwable getCause() {
                Thread.currentThread().interrupt();
                return null;
            }
        };
        PushSender sender = sender((endpoint, headers, body) -> {
            throw raised;
        });
        Subscription subscription = subscription();
        PushMessage message = message();

        try {
            assertThatThrownBy(() -> sender.send(subscription, message))
                    .isInstanceOf(PushInterruptedException.class)
                    .hasCause(raised);
            assertThat(Thread.currentThread().isInterrupted()).isTrue();
        } finally {
            Thread.interrupted();
        }
    }

    private static PushSender sender(PushHttpClient client) {
        return PushSender.builder(generateVapidKeys(), "mailto:ops@example.com", EndpointPolicies.unrestricted())
                .httpClient(client)
                .build();
    }

    private static Subscription subscription() {
        return new Subscription(ENDPOINT, b64(TestVectors.UA_PUBLIC), b64(TestVectors.AUTH_SECRET));
    }

    private static PushMessage message() {
        return PushMessage.of(new byte[] {1});
    }

    /** A signer whose custodian never answers: every contract method raises the configured failure. */
    private static final class FailingSigner implements VapidSigner {
        private final RuntimeException failure;

        FailingSigner(RuntimeException failure) {
            this.failure = failure;
        }

        @Override
        public byte[] sign(byte[] signingInput) {
            throw failure;
        }

        @Override
        public byte[] publicKey() {
            throw failure;
        }
    }

    /** Answers 201 and counts POSTs, so a test can assert the wire was never reached. */
    private static final class CountingClient implements PushHttpClient {
        private final AtomicInteger posts = new AtomicInteger();

        @Override
        public PushResponse post(URI endpoint, Map<String, String> headers, byte[] body) {
            posts.incrementAndGet();
            return PushResponse.of(201);
        }
    }
}
