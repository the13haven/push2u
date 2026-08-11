/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static com.the13haven.push2u.PushTestSupport.generateVapidKeys;
import static com.the13haven.push2u.TestVectors.b64;
import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * The two-clock bounds on a cached VAPID token's life. An entry records a monotonic anchor and the wall reading its
 * {@code exp} was computed from, and is renewed when <em>either</em> bound is reached: the wall clock arriving within
 * {@code jwtRenewBefore} of the whole-second (effective) {@code exp}, or the monotonic clock having run for that same
 * span. The tests drive both clocks through the sender's seams over a {@link SimulatedTime} — a shared "true" timeline
 * both sample — because the failure modes here are exactly the ones a real clock never shows a fast test: a backwards
 * NTP step, an unbounded pause between two adjacent statements, a restored VM.
 *
 * <p>The reading order is load-bearing and two tests exist only to pin it: of the two ways to order a pair of readings,
 * the implementation must take the one that over-estimates monotonic elapsed time — anchor first at mint, monotonic
 * value last at lookup — so that a pause between the readings can only cost a signature, never serve a token the push
 * service already considers expired (RFC 8292 §4.2 makes an expired {@code exp} a ground of invalidity). Those tests
 * model a real pause through the seams; with no pause they pass under either order.
 */
class PushSenderJwtRenewalTest {

    private static final Instant BASE = Instant.parse("2030-01-01T00:00:00Z");
    private static final Duration EXPIRY = Duration.ofHours(12);
    private static final Duration MARGIN = Duration.ofMinutes(5);
    private static final String ENDPOINT = "https://push.example/sub/1";

    private final CapturingClient client = new CapturingClient();
    private final CountingVapidSigner signer = new CountingVapidSigner(new LocalEcVapidSigner(generateVapidKeys()));
    private final SimulatedTime time = new SimulatedTime(BASE);

    /**
     * RFC 7519 §4.1.4 requires the current time <em>strictly</em> before {@code exp}, and the claim went on the wire as
     * whole seconds — so at {@code jwtRenewBefore(ZERO)} the entry must serve up to the last nanosecond before the
     * second {@code exp} names, and renew on that second, not on the sub-second instant the sender computed. The mint
     * below lands 300 ms past a whole second precisely so the two differ: an implementation judging staleness against
     * the un-truncated expiry would serve 300 ms too long.
     */
    @Test
    void renewalHappensOnTheSecondExpNamesAndNotAFractionLater() {
        PushSender sender = sender(Duration.ZERO);
        time.advance(Duration.ofMillis(300));
        sender.send(subscription(), message()); // exp = BASE + 12h + 0.3s on the wire as BASE + 12h
        assertThat(signer.signCount()).isEqualTo(1);

        time.advance(EXPIRY.minusMillis(300).minusNanos(1)); // wall: one nanosecond before the effective exp
        sender.send(subscription(), message());
        assertThat(signer.signCount())
                .as("zero margin is the most reuse: served to the last nanosecond before the wire's exp")
                .isEqualTo(1);

        time.advance(Duration.ofNanos(1)); // wall: exactly the second exp names
        sender.send(subscription(), message());
        assertThat(signer.signCount())
                .as("renewed on the second exp names — 300 ms before the un-truncated instant, not after it")
                .isEqualTo(2);
    }

    /**
     * The wall clock is frozen at the mint reading — far short of its own bound — and only the monotonic reading runs.
     * The entry must end when the monotonic clock has run for the span (effective {@code exp} − mint wall reading −
     * margin) and not one nanosecond later: a bound of the whole {@code jwtExpiry} instead of the span is exactly the
     * defect that would hand a backwards wall step extra life.
     */
    @Test
    void theMonotonicBoundEndsAnEntryWhileTheWallClockIsFrozen() {
        PushSender sender = sender(MARGIN);
        time.advance(Duration.ofMillis(700));
        sender.send(subscription(), message());
        Duration span = EXPIRY.minusMillis(700).minus(MARGIN);

        time.stepMonotonicForward(span.minusNanos(1)); // wall untouched
        sender.send(subscription(), message());
        assertThat(signer.signCount())
                .as("one nanosecond short of the span: still served")
                .isEqualTo(1);

        time.stepMonotonicForward(Duration.ofNanos(1));
        sender.send(subscription(), message());
        assertThat(signer.signCount())
                .as("the monotonic clock alone ends the entry at the span, with the wall clock frozen at mint")
                .isEqualTo(2);
    }

    /** A backwards wall step of any size buys the entry nothing: the monotonic bound still ends it at the span. */
    @Test
    void aBackwardsWallStepCannotPushTheEffectiveLifePastTheSpan() {
        PushSender sender = sender(MARGIN);
        sender.send(subscription(), message()); // mint at true 0: anchor 0, wall BASE
        Duration span = EXPIRY.minus(MARGIN);

        time.stepWallBack(Duration.ofHours(1));
        time.advance(span.minusNanos(1));
        sender.send(subscription(), message());
        assertThat(signer.signCount())
                .as("short of the span the entry serves as usual")
                .isEqualTo(1);

        time.advance(Duration.ofNanos(1));
        sender.send(subscription(), message());
        assertThat(signer.signCount())
                .as("the wall bound sits an hour away after the step, but the monotonic bound ends the entry on time")
                .isEqualTo(2);
    }

    /**
     * A pause between the two <em>mint</em> readings must not lengthen the entry's life under a later backwards step.
     * The anchor has to be taken first: taken second, it would date the entry {@code P} later than the wall reading
     * {@code exp} came from, and a subsequent backwards step of Δ ≥ P would extend the entry's life by P — served
     * beyond its span on a wall clock that also stopped objecting. With P ≈ 0 both orders pass; the 10-second pause is
     * what makes this the assertion the wrong order fails.
     */
    @Test
    void aPauseBetweenTheMintReadingsCannotLengthenLifeUnderALaterBackwardsStep() {
        Duration pause = Duration.ofSeconds(10);
        PushSender sender = sender(MARGIN);
        time.pauseBetweenReadings(pause);
        sender.send(subscription(), message()); // anchor at true 0; wall reading 10s later: exp from BASE + 10s
        time.pauseBetweenReadings(Duration.ZERO);
        Duration span = EXPIRY.minus(MARGIN); // BASE + 10s was a whole second, so the span is exp − margin exactly

        time.stepWallBack(Duration.ofHours(1)); // Δ far larger than the pause
        time.advanceTo(span.minusNanos(1)); // true time: one nanosecond before anchor + span
        sender.send(subscription(), message());
        assertThat(signer.signCount()).isEqualTo(1);

        time.advanceTo(span);
        sender.send(subscription(), message());
        assertThat(signer.signCount())
                .as("the entry's life is measured from the anchor taken before the pause, not after it — the pause"
                        + " shortens the life relative to the wall deadline, never lengthens it")
                .isEqualTo(2);
    }

    /**
     * The same order rule at <em>lookup</em>, pointing the other way: the monotonic reading is taken last, after the
     * wall reading, because it is the bound that governs alone once a backwards step has pushed the wall bound out. A
     * stale monotonic reading is permissive on exactly that bound — taken first and then delayed by a pause, it would
     * serve an entry the span has already ended.
     */
    @Test
    void aPauseBetweenTheLookupReadingsCannotServeAnEntryPastItsBound() {
        Duration pause = Duration.ofSeconds(10);
        PushSender sender = sender(MARGIN);
        sender.send(subscription(), message()); // mint at true 0: anchor 0, wall BASE
        Duration span = EXPIRY.minus(MARGIN);

        time.stepWallBack(Duration.ofHours(1));
        time.advanceTo(span.minusSeconds(5)); // inside the span at the lookup's first reading...
        time.pauseBetweenReadings(pause); // ...past it by the time of the reading taken second
        sender.send(subscription(), message());
        assertThat(signer.signCount())
                .as("the monotonic reading taken last sees the span already run out and renews; taken first it"
                        + " would have been 10 seconds stale and served the entry past its bound")
                .isEqualTo(2);
    }

    /**
     * A negative elapsed interval means the anchor was taken on a later timeline than the current reading — a
     * checkpoint/restore or a migration the JDK's single per-instance nanoTime origin says cannot happen on a
     * conforming platform. The entry is discarded for the cost of one comparison rather than trusted with arithmetic
     * that means nothing.
     */
    @Test
    void aMonotonicReadingFromALaterTimelineDiscardsTheEntry() {
        PushSender sender = sender(MARGIN);
        sender.send(subscription(), message());
        assertThat(signer.signCount()).isEqualTo(1);

        time.advance(Duration.ofSeconds(1));
        time.stepMonotonicBack(Duration.ofSeconds(3)); // elapsed since the anchor now reads −2s
        sender.send(subscription(), message());
        assertThat(signer.signCount())
                .as("a reading from before the anchor's timeline discards the entry and mints")
                .isEqualTo(2);

        sender.send(subscription(), message());
        assertThat(signer.signCount())
                .as("the replacement entry, anchored on the current timeline, serves again")
                .isEqualTo(2);
    }

    private PushSender sender(Duration renewBefore) {
        return PushSender.builder(signer, "mailto:ops@example.com", EndpointPolicies.unrestricted())
                .httpClient(client)
                .clock(time.clock())
                .ticker(time.ticker())
                .jwtExpiry(EXPIRY)
                .jwtRenewBefore(renewBefore)
                .build();
    }

    private static Subscription subscription() {
        return new Subscription(ENDPOINT, b64(TestVectors.UA_PUBLIC), b64(TestVectors.AUTH_SECRET));
    }

    private static PushMessage message() {
        return PushMessage.of("x".getBytes(StandardCharsets.UTF_8));
    }

    /** Responds 201 to everything; the assertions here are about the signer, not the wire. */
    private static final class CapturingClient implements PushHttpClient {
        private final List<String> authorizations = new ArrayList<>();

        @Override
        public PushResponse post(URI endpoint, Map<String, String> headers, byte[] body) {
            authorizations.add(headers.get("Authorization"));
            return PushResponse.of(201);
        }
    }

    /**
     * One "true" timeline that both of the sender's clocks sample: the wall clock as {@code base + true + wallOffset}
     * (a backwards step moves the offset), the monotonic clock as {@code true + monotonicOffset}. A configurable pause
     * advances true time after <em>every</em> reading, modelling the unbounded gap between two adjacent statements —
     * which is what makes the reading-order tests able to distinguish the two orders at all.
     */
    private static final class SimulatedTime {
        private final Instant wallBase;
        private long trueNanos;
        private long wallOffsetNanos;
        private long monotonicOffsetNanos;
        private long pauseNanos;

        SimulatedTime(Instant wallBase) {
            this.wallBase = wallBase;
        }

        Ticker ticker() {
            return () -> {
                long reading = trueNanos + monotonicOffsetNanos;
                trueNanos += pauseNanos;
                return reading;
            };
        }

        Clock clock() {
            return new Clock() {
                @Override
                public ZoneId getZone() {
                    return ZoneOffset.UTC;
                }

                @Override
                public Clock withZone(ZoneId zone) {
                    return this;
                }

                @Override
                public Instant instant() {
                    Instant reading = wallBase.plusNanos(trueNanos + wallOffsetNanos);
                    trueNanos += pauseNanos;
                    return reading;
                }
            };
        }

        void advance(Duration duration) {
            trueNanos += duration.toNanos();
        }

        /** Absolute positioning on the true timeline, for tests whose pauses already moved it implicitly. */
        void advanceTo(Duration sinceStart) {
            trueNanos = sinceStart.toNanos();
        }

        void stepWallBack(Duration step) {
            wallOffsetNanos -= step.toNanos();
        }

        void stepMonotonicForward(Duration step) {
            monotonicOffsetNanos += step.toNanos();
        }

        void stepMonotonicBack(Duration step) {
            monotonicOffsetNanos -= step.toNanos();
        }

        void pauseBetweenReadings(Duration pause) {
            pauseNanos = pause.toNanos();
        }
    }
}
