/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.Nullable;

import com.the13haven.push2u.PushDeliveryException;
import com.the13haven.push2u.PushHttpClient;
import com.the13haven.push2u.PushResponse;

/**
 * A {@link PushHttpClient} that answers a declared sequence of responses and records every call — the transport fake
 * for testing the one decision this library hands back to its caller: whether, and when, to POST again. The library
 * itself performs exactly one POST per send, so the {@code 429, 429, 201} shape a caller's repeat loop must handle can
 * only come from a fake that answers differently on consecutive calls.
 *
 * <p>The first response is its own parameter so that an empty script is not writable: the compiler refuses it, rather
 * than a runtime check discovering it later. The {@link PushResponse} form exists beside the status form because a
 * {@code Retry-After} hint belongs to one particular response — the test that needs the second answer to carry a
 * different hint from the first cannot express that through any per-fake header setting.
 *
 * <p><b>An exhausted script raises {@link IllegalStateException}, and it surfaces out of {@code send} itself.</b> The
 * sender converts only a signer's unavailability and the transport's own {@link PushDeliveryException} into outcomes;
 * any other runtime exception from a transport is treated as a defect and propagates unchanged. One POST too many is
 * exactly that — a failure of the test's expectation, not a scenario — so do not wait for an {@code Indeterminate} that
 * will not come: the {@code send} (or the future a {@code sendAsync} answered) fails with this exception.
 *
 * <p><b>{@link #failingWith} is a mode of the whole fake</b>: every call records the attempt and then throws the given
 * failure. A sequence mixing responses and failures is deliberately not expressible here; a test needing one composes
 * its own few-line {@link PushHttpClient}, which is the right tool exactly where the stub is trivial to write.
 *
 * <p><b>Concurrent use is the normal case</b>, because {@code sendAsync} makes concurrent {@link #post} calls ordinary.
 * {@link #post} and {@link #sent()} are safe from several threads: taking the next scripted answer and recording the
 * call are one atomic step, so the recorded order is the order answers were handed out and no call is answered without
 * being recorded — a call that ends in the configured failure, or finds the script exhausted, is recorded before the
 * throw, since the POST was attempted either way. Under a fan-out, though, responses go out in the order calls
 * <em>enter</em> the fake, which is not the order of the subscriptions; a scripted sequence is for the sequential
 * repeat loop over one subscription, and a fan-out test declares one constant answer per expected call and asserts over
 * {@link #sent()} rather than over which subscription drew which status.
 *
 * <p>There is no {@code reset} and no mutable configuration: a fake reused across tests shows one test its neighbour's
 * requests, and a script that can change after declaration is not the script that ran. A fresh fake per test costs one
 * line. The fake also asserts nothing itself — {@link #sent()} answers a plain immutable list, taken as a point-in-time
 * snapshot that cannot change under an assertion even while sends are still running, and the caller's own assertion
 * library does the rest.
 */
public final class ScriptedPushHttpClient implements PushHttpClient {

    /** Guards the script cursor and the recording, so answering and recording stay one atomic step. */
    private final Object lock = new Object();

    private final List<PushResponse> script;
    private final @Nullable PushDeliveryException failure;
    private final List<SentPush> sent = new ArrayList<>();
    private int next;

    private ScriptedPushHttpClient(List<PushResponse> script, @Nullable PushDeliveryException failure) {
        this.script = script;
        this.failure = failure;
    }

    /**
     * A fake answering the given status codes in order, each as a {@link PushResponse} without headers.
     *
     * @param firstStatus the status of the first response — a separate parameter so a script with nothing in it cannot
     *     be declared
     * @param followingStatuses the statuses of the responses after it, in order
     * @return a fresh fake scripted with exactly these answers
     * @throws IllegalArgumentException if any status is negative
     * @throws NullPointerException if {@code followingStatuses} is {@code null}
     */
    public static ScriptedPushHttpClient respondingWith(int firstStatus, int... followingStatuses) {
        Objects.requireNonNull(followingStatuses, "followingStatuses");
        List<PushResponse> script = new ArrayList<>(1 + followingStatuses.length);
        script.add(PushResponse.of(firstStatus));
        for (int status : followingStatuses) {
            script.add(PushResponse.of(status));
        }
        return new ScriptedPushHttpClient(List.copyOf(script), null);
    }

    /**
     * A fake answering the given responses in order — the form for a script whose answers carry headers, since a
     * {@code Retry-After} belongs to one particular response rather than to the fake.
     *
     * @param first the first response — a separate parameter so a script with nothing in it cannot be declared
     * @param following the responses after it, in order
     * @return a fresh fake scripted with exactly these answers
     * @throws NullPointerException if {@code first}, {@code following} or any of its elements is {@code null}
     */
    public static ScriptedPushHttpClient respondingWith(PushResponse first, PushResponse... following) {
        Objects.requireNonNull(first, "first");
        Objects.requireNonNull(following, "following");
        List<PushResponse> script = new ArrayList<>(1 + following.length);
        script.add(first);
        for (PushResponse response : following) {
            script.add(Objects.requireNonNull(response, "following must not contain null"));
        }
        return new ScriptedPushHttpClient(List.copyOf(script), null);
    }

    /**
     * A fake on which every call records the attempt and then throws {@code failure} — the transport's contract for a
     * POST that went out and got no answer, which the sender reports as an {@code Indeterminate} outcome.
     *
     * @param failure the failure every call throws; the same instance each time, so its stack trace is that of its
     *     construction, which is where the test declared it
     * @return a fresh fake in the failing mode
     * @throws NullPointerException if {@code failure} is {@code null}
     */
    public static ScriptedPushHttpClient failingWith(PushDeliveryException failure) {
        Objects.requireNonNull(failure, "failure");
        return new ScriptedPushHttpClient(List.of(), failure);
    }

    /**
     * Records the call, then answers with the next scripted response or throws the configured failure — one atomic
     * step, safe from several threads.
     *
     * @param endpoint the push endpoint the sender is POSTing to, recorded as given
     * @param headers the request headers, recorded as an immutable copy
     * @param body the encrypted body; only its length is recorded
     * @return the next scripted response
     * @throws PushDeliveryException in the {@link #failingWith} mode, after the call is recorded
     * @throws IllegalStateException if the script is exhausted — one POST more than the test declared, recorded and
     *     then reported as the defect it is; it propagates out of {@code send} unconverted
     */
    @Override
    public PushResponse post(URI endpoint, Map<String, String> headers, byte[] body) {
        Objects.requireNonNull(endpoint, "endpoint");
        Objects.requireNonNull(headers, "headers");
        Objects.requireNonNull(body, "body");
        synchronized (lock) {
            sent.add(new SentPush(endpoint, headers, body.length));
            if (failure != null) {
                throw failure;
            }
            if (next >= script.size()) {
                throw new IllegalStateException("script exhausted: " + sent.size() + " calls, but only " + script.size()
                        + " scripted " + (script.size() == 1 ? "response" : "responses")
                        + " — one POST more than this test declared");
            }
            PushResponse response = script.get(next);
            next++;
            return response;
        }
    }

    /**
     * The recorded calls, in the order the fake answered them — every call made so far, including one that drew the
     * configured failure or found the script exhausted, since the POST was attempted either way.
     *
     * @return an immutable point-in-time snapshot, unaffected by calls recorded after it is taken
     */
    public List<SentPush> sent() {
        synchronized (lock) {
            return List.copyOf(sent);
        }
    }
}
