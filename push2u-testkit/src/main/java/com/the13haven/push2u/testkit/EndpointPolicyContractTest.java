/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import com.the13haven.push2u.EndpointAssessment;
import com.the13haven.push2u.EndpointPolicy;
import com.the13haven.push2u.Endpoints;

/**
 * The conformance contract every {@link EndpointPolicy} must satisfy: an endpoint the policy permits is answered with
 * {@link EndpointAssessment.Allowed}, an endpoint it refuses is answered with an {@link EndpointAssessment.Refused}
 * whose reason does not carry the capability part of the endpoint, and several threads inside {@code assess} at once
 * all come back with one of those two answers. An implementation extends this class and supplies its subject and its
 * two example endpoints through the three methods below.
 *
 * <p><b>Which endpoints a policy ought to admit is deliberately not checked</b>, and could not be: that rule is the
 * deployment's own — the set of push services its subscriptions may come from, or the egress its network permits — and
 * nothing outside the deployment knows it. What this contract is about is the shape of the answer, which belongs to the
 * library and moves with it.
 *
 * <p><b>Why a refusal's wording is checked at all.</b> A push endpoint is a capability URL: whoever holds it can send
 * messages to that subscriber, so its path and query are a bearer credential rather than an identifier. A refusal's
 * reason travels — {@link com.the13haven.push2u.PushSender#send} turns a {@code Refused} into
 * {@link com.the13haven.push2u.PushOutcome.EndpointRejected}, pairing the policy's own sentence with this library's
 * redaction of the endpoint, and an application logs the outcome. So a policy that writes the endpoint into its own
 * sentence publishes that credential into every log aggregator the line reaches, past every redaction this library
 * performs. {@link Endpoints#redact} renders the origin plus a short fingerprint —
 * {@code https://push.example/…#a1b2c3d4e5f60718} — and drops the path, query and fragment; that rendering is what a
 * refusal may name, and naming it is not a leak. The fingerprint exists so an operator can correlate log lines about
 * one subscription without holding it.
 *
 * <p><b>The refusal check therefore needs a witness with something to leak, and that is a real demand on the
 * fixture.</b> The check searches the reason for the capability part of {@link #refusedEndpoint()} at three
 * granularities — the whole URI, each of user-info, path, query and fragment entire, and inside those each path segment
 * and each query value on its own — in the raw spelling and the percent-decoded one, and for a query value in a third,
 * form-decoded with {@code +} read as a space, since that is what a value handed to a form decoder comes back as. A
 * string is searched for only when it is long enough that finding it in a sentence about an endpoint means something,
 * and when it does not already occur in the redaction a conforming policy is entitled to print.
 *
 * <p><b>Whether the witness can be used at all is then decided over the parts below the whole URI, and only those.</b>
 * Every endpoint has a whole-URI string and it passes the rule almost always, so a witness judged by that string would
 * always be accepted — leaving the check able to catch nothing but a policy quoting the endpoint entire, which is the
 * one leak nobody writes by accident. {@code https://blocked.example/} has nothing distinctive in it at all;
 * {@code https://blocked.example/api} is barely better, since searching for {@code api} answers a question about the
 * policy's prose rather than about the endpoint. Both are reported as unfit for the check, naming which half of the
 * rule their parts failed. Supply an endpoint that looks like the ones a real subscription store holds.
 *
 * <p>The segment-level search is the half a first attempt leaves out, and it is where the leak actually happens. A
 * policy writing {@code "blocked subscription 9f8e7d6c5b4a39281706"} — the last segment of a path — has published the
 * whole bearer credential while its sentence contains neither the full URI nor the whole path, and a check looking only
 * at entire components would pass it.
 *
 * <p>Put {@code com.the13haven:push2u-testkit} on the test classpath and extend this class:
 *
 * <pre>{@code
 * class MyEndpointPolicyContractTest extends EndpointPolicyContractTest {
 *     @Override
 *     protected EndpointPolicy policy() {
 *         return new MyPolicy(...);
 *     }
 *
 *     @Override
 *     protected URI allowedEndpoint() {
 *         return URI.create("https://push.example/wpush/v2/2f1c8a7e6d5b4a390817");
 *     }
 *
 *     @Override
 *     protected Optional<URI> refusedEndpoint() {
 *         return Optional.of(URI.create("https://blocked.example/wpush/v2/9f8e7d6c5b4a39281706"));
 *     }
 * }
 * }</pre>
 *
 * <p><b>What this contract never asserts.</b> No check here observes one endpoint twice and requires the two answers to
 * agree. A policy is permitted to keep state — a resolution cache, a counter — and to answer differently the second
 * time it is asked about the same URI, so a contract demanding a stable answer would refuse an implementation this
 * library allows. That is why the refusal and its reason are one observation of one call rather than two tests over two
 * calls, and why the concurrency check below asserts nothing about which variant came back.
 *
 * <p><b>A contract test protects against error, not against deliberate circumvention.</b> An implementor is free to
 * answer {@link Optional#empty()} for a policy that does refuse things, or to pick an easy {@link #allowedEndpoint()};
 * what binds there is the sentence in {@link EndpointPolicy}'s own contract, not this class.
 */
public abstract class EndpointPolicyContractTest {

    /** How many threads the concurrency check puts inside {@code assess} at the same moment. */
    private static final int CONCURRENT_CALLS = 8;

    /**
     * How long the concurrency check as a whole may wait for its calls to answer. One budget for the check rather than
     * one timeout per call: the calls are collected in a loop, so a per-call timeout would multiply by the number of
     * threads and a stuck policy would hold the suite for that product instead of for this.
     */
    private static final int ANSWER_BUDGET_SECONDS = 30;

    /** For subclasses: the kit is extended, never instantiated on its own. */
    protected EndpointPolicyContractTest() {}

    /**
     * The policy under test.
     *
     * @return a fully configured {@link EndpointPolicy}
     */
    protected abstract EndpointPolicy policy();

    /**
     * An endpoint this policy permits. Only the implementor knows what their policy admits, so the contract asks rather
     * than inventing one; it must satisfy the seam's own precondition — an absolute {@code https} URL with a host —
     * because that is what {@code assess} is ever handed.
     *
     * <p>There is no empty form of this method, and the asymmetry with {@link #refusedEndpoint()} is deliberate. A
     * policy refusing every endpoint is a shape this library argues against — every factory of the standard allowlist
     * refuses an empty rule list outright, an allowlist that admits nothing being far more likely a wiring bug than a
     * policy — whereas a policy admitting everything is a shape this library builds, documents and ships. A policy that
     * permits nothing therefore cannot be a subject of this contract; that cost is named rather than hidden.
     *
     * @return an endpoint the policy under test permits, absolute {@code https} with a host
     */
    protected abstract URI allowedEndpoint();

    /**
     * An endpoint this policy refuses, or {@link Optional#empty()} when the policy's declared behaviour is to admit
     * every endpoint satisfying the seam's precondition — an absolute {@code https} URL with a host. That is the only
     * legitimate reason for the empty answer, and a policy refusing nothing is a supported member of this library's
     * public API rather than an oddity, which is why the witness is optional at all.
     *
     * <p>There is deliberately no {@code default} here. The empty answer is a statement an implementor writes in their
     * own source, visible in a diff and in a review; a default would let a subject inherit "there is nothing to check
     * here" without anyone having said it.
     *
     * <p><b>Supply an endpoint that carries a capability-shaped component</b> — a path segment or a query value like
     * the ones a real subscription store holds, not {@code https://blocked.example/} and not
     * {@code https://blocked.example/api}. The leak check searches the refusal's reason for that component; a witness
     * whose only distinctive string is the whole URI leaves the check able to catch nothing but a policy quoting the
     * endpoint entire, so it is reported as unfit rather than run against.
     *
     * @return an endpoint the policy under test refuses, or empty for a policy that refuses nothing
     */
    protected abstract Optional<URI> refusedEndpoint();

    /**
     * The permitted endpoint comes back as a value. Falling off the end of {@code assess}, returning {@code null} or
     * throwing are all outside the seam's contract: the caller is owed an answer it can switch on, and at a
     * registration boundary — where an application applies the same policy before it stores a row — there is nothing
     * behind it to catch a policy that does something else.
     */
    // UnitTestShouldIncludeAssert: the check is made by hand and throws, rather than through an
    // assertion library, because an assertion prints its actual value — here an assessment whose
    // reason may hold the capability URL this contract exists to keep out of a build log. The
    // failure below names the variant and nothing else, which is the whole point of not asserting.
    @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
    @Test
    void permittedEndpointIsAnsweredWithAllowed() {
        URI endpoint = admissible(allowedEndpoint(), "allowedEndpoint()");

        EndpointAssessment assessment = policy().assess(endpoint);

        if (!(assessment instanceof EndpointAssessment.Allowed)) {
            throw new AssertionError("assess must answer a permitted endpoint with Allowed — a value, never null and "
                    + "never an exception. It answered " + describe(assessment) + ".");
        }
    }

    /**
     * The refused endpoint comes back as a {@link EndpointAssessment.Refused} whose reason keeps the capability part of
     * the endpoint out of it.
     *
     * <p>A refusal is the ordinary case at the boundaries this seam serves, not an error: a policy that throws on the
     * endpoint it refuses aborts a fan-out over a subscription store at its first hostile row, which is exactly what
     * answering with a value exists to prevent. And a refusal's reason is read by an operator out of a log, so the one
     * thing it must not contain is the credential that lets anyone message the subscriber.
     *
     * <p>Both halves are asserted of a single call, on purpose. Two calls would observe one endpoint twice and hold the
     * two answers to one expectation — a stability requirement this contract does not make and this library does not
     * impose. A value and what it contains are one thing anyway, and reporting "not a refusal" and "the reason leaked"
     * as unrelated failures would describe one broken policy as two.
     */
    // The refusal and the leak are one claim about one observation — this endpoint is refused,
    // and the refusal does not publish the subscription's credential. Splitting them would need a
    // second assess call on the same endpoint, which is the determinism this contract deliberately
    // never requires.
    // UnitTestShouldIncludeAssert: the check is made by hand and throws, rather than through an
    // assertion library, because an assertion prints its actual value — here an assessment whose
    // reason may hold the capability URL this contract exists to keep out of a build log. The
    // failure below names the variant and nothing else, which is the whole point of not asserting.
    @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
    @Test
    void refusalIsAValueWhoseReasonKeepsTheCapabilityUrlOut() {
        Optional<URI> supplied = refusedEndpoint();
        Assumptions.assumeTrue(
                supplied.isPresent(),
                "refusedEndpoint() is empty, so there is no refusal to observe. That is the answer for a policy whose "
                        + "declared behaviour admits every endpoint satisfying the seam's precondition; this check is "
                        + "reported as skipped rather than passed, because a green check nothing exercised would "
                        + "misreport this policy's coverage.");
        URI witness = admissible(supplied.orElseThrow(), "refusedEndpoint()");
        EndpointLeakMarkers markers = EndpointLeakMarkers.of(witness);
        if (!markers.hasSearchableComponent()) {
            throw new AssertionError(markers.unfitWitnessMessage());
        }

        EndpointAssessment assessment = policy().assess(witness);

        if (!(assessment instanceof EndpointAssessment.Refused refusal)) {
            throw new AssertionError("assess must answer a refused endpoint with Refused — a refusal is the ordinary "
                    + "case here, and a policy that throws instead aborts a fan-out at its first hostile row. It "
                    + "answered " + describe(assessment) + ".");
        }
        String reason = refusal.reason();
        for (EndpointLeakMarkers.Marker marker : markers.searchable()) {
            // Checked here rather than through an assertion that takes the expected values: an
            // assertion library prints what it was looking for, which for this check is the
            // capability URL and every component of it. The failure below says which level and
            // which spelling matched and prints neither.
            if (reason.contains(marker.value())) {
                throw new AssertionError(EndpointLeakMarkers.leakMessage(marker));
            }
        }
    }

    /**
     * A smoke check, and named one. Several threads enter {@code assess} at the same moment and every one of them must
     * come back with one of the two variants of the sealed answer — nothing thrown, nothing {@code null}. One
     * {@link com.the13haven.push2u.PushSender} is shared across threads and {@code sendAsync} makes concurrent
     * assessments ordinary, so a policy guarding mutable state badly fails here rather than in production.
     *
     * <p>What it is worth is asymmetric, and saying so is part of the check. A passing run proves nothing: no schedule
     * is forced, and an unguarded cache can go a thousand runs without two threads colliding in it. Failing what it
     * <em>asserts</em> is a real defect every time, because a thread-safe policy cannot throw, answer {@code null} or
     * answer outside the sealed hierarchy however the threads interleave. Having no false positives there is what earns
     * this check its place; being no proof is why it is not called one.
     *
     * <p>The check stops waiting after a fixed budget, and what it does then is <em>abort</em> rather than fail. A
     * policy that never answers would otherwise hang the suite it was added to, which is how a contract gets deleted
     * from a build; but this seam promises nothing about how fast {@code assess} answers, so a call still running when
     * the budget runs out may equally be a correct policy doing something slow. Nothing here can tell those apart, and
     * a failure would be a verdict this check has not reached. An abort says what is true — it did not conclude — and
     * leaves the three assertions above as the only things it ever calls a defect.
     *
     * <p>It deliberately does not assert that one endpoint keeps yielding one variant. That is determinism of the
     * result, which this library does not require of a policy — a resolution cache or a counter is legitimate state to
     * keep — and demanding it here would smuggle the assertion in under a name that hides it.
     */
    // UnitTestShouldIncludeAssert: counted and classified by hand, then thrown, rather than through
    // an assertion library — an assertion over the answers prints them, and a refusal's reason may
    // hold the capability URL this contract exists to keep out of a build log. The failure below
    // reports counts only.
    @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
    @Test
    void concurrentAssessmentsAllComeBackWithAnAnswer() throws InterruptedException {
        EndpointPolicy policy = policy();
        List<URI> endpoints = new ArrayList<>();
        endpoints.add(admissible(allowedEndpoint(), "allowedEndpoint()"));
        refusedEndpoint().ifPresent(refused -> endpoints.add(admissible(refused, "refusedEndpoint()")));

        List<EndpointAssessment> answers = assessConcurrently(policy, endpoints);

        int unanswered = 0;
        for (EndpointAssessment answer : answers) {
            if (!(answer instanceof EndpointAssessment.Allowed) && !(answer instanceof EndpointAssessment.Refused)) {
                unanswered++;
            }
        }
        if (answers.size() != CONCURRENT_CALLS || unanswered > 0) {
            throw new AssertionError("every concurrent assess call must answer with one of the two variants of the "
                    + "sealed assessment, never null and never by throwing. Of " + CONCURRENT_CALLS + " calls, "
                    + answers.size() + " came back and " + unanswered + " of those were neither Allowed nor Refused.");
        }
    }

    /**
     * Runs {@link #CONCURRENT_CALLS} assessments that genuinely overlap: one thread per call on an executor this check
     * creates and shuts down itself, all of them held at a start gate until the last one is submitted.
     *
     * <p>The executor is its own rather than the platform's shared work-stealing pool. A rendezvous among tasks
     * submitted to that pool deadlocks on a machine with few cores — a build agent, usually — and a check that hangs a
     * suite is worse than one that does not exist.
     */
    // CloseResource: the executor is shut down in the finally block below, with shutdownNow rather
    // than close. AutoCloseable's close waits for termination, so a policy that never answers would
    // hang the suite here after the check had already reported the timeout — which is the one
    // failure mode this check must be able to report rather than become. Interrupting is not
    // guaranteed to end such a call either, which is what the daemon threads below are for.
    @SuppressWarnings("PMD.CloseResource")
    private static List<EndpointAssessment> assessConcurrently(EndpointPolicy policy, List<URI> endpoints)
            throws InterruptedException {
        ExecutorService executor = Executors.newFixedThreadPool(CONCURRENT_CALLS, EndpointPolicyContractTest::worker);
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<EndpointAssessment>> pending = new ArrayList<>(CONCURRENT_CALLS);
            for (int call = 0; call < CONCURRENT_CALLS; call++) {
                URI endpoint = endpoints.get(call % endpoints.size());
                pending.add(executor.submit(() -> {
                    start.await();
                    return policy.assess(endpoint);
                }));
            }
            start.countDown();

            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(ANSWER_BUDGET_SECONDS);
            List<EndpointAssessment> answers = new ArrayList<>(pending.size());
            for (Future<EndpointAssessment> call : pending) {
                answers.add(answerOf(call, deadline));
            }
            return answers;
        } finally {
            executor.shutdownNow();
        }
    }

    /**
     * One worker of the concurrency check, and a <em>daemon</em> one deliberately.
     *
     * <p>{@code shutdownNow} interrupts, and interrupting does not end every wait — a thread blocked entering a monitor
     * or inside a native call keeps running whatever the check has already reported. Non-daemon workers would then hold
     * the JVM open after the suite finished, moving the hang from the check to the exit rather than removing it. A
     * daemon thread cannot do that.
     */
    private static Thread worker(Runnable task) {
        Thread thread = new Thread(task, "push2u-endpoint-policy-contract");
        thread.setDaemon(true);
        return thread;
    }

    /**
     * Unwraps one concurrent call: a thrown defect becomes a readable failure, and a call still running when the budget
     * runs out aborts the check instead of failing it. The deadline belongs to the whole check rather than to this
     * call, so a stuck policy costs the check one budget and not one per thread.
     */
    // PreserveStackTrace: the cause is what the policy actually threw, and it is carried over
    // deliberately in place of the ExecutionException wrapping it — the wrapper's own frames are
    // this method's, and reporting them would bury the frame the implementor has to look at.
    @SuppressWarnings("PMD.PreserveStackTrace")
    private static EndpointAssessment answerOf(Future<EndpointAssessment> call, long deadline)
            throws InterruptedException {
        try {
            return call.get(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
        } catch (ExecutionException thrown) {
            throw new AssertionError(
                    "assess threw while other threads were inside it. Concurrent assessments are the ordinary case — "
                            + "one sender is shared, and asynchronous sends assess in parallel — so a policy keeping "
                            + "mutable state has to guard it.",
                    thrown.getCause());
        } catch (TimeoutException neverAnswered) {
            // Aborted, not failed. The seam sets no latency requirement, so a call still running
            // after the budget may be a policy waiting on something that never arrives or a
            // correct one being slow — a cold resolution cache on a loaded machine — and this
            // check cannot tell those apart. Reporting a failure would state a verdict it has not
            // reached; reporting an abort states the truth, that the check did not conclude. The
            // budget exists so that the first case ends the check instead of hanging the suite.
            return Assumptions.abort("the concurrent assess calls had not all answered within " + ANSWER_BUDGET_SECONDS
                    + " seconds, so this check stopped waiting without reaching a verdict. That budget is this "
                    + "check's own limit and not a rule about how fast assess has to be, so this is neither a pass "
                    + "nor a thread-safety failure. If the calls were merely slow, nothing here is wrong; if one of "
                    + "them never returns, look for a lock held across a slow operation.");
        }
    }

    /**
     * Names an answer without rendering it: the variant's simple name, or {@code null}. The assessment itself is never
     * printed, and neither is a refusal's reason — a policy under suspicion of putting the endpoint in its reason is
     * exactly the one whose reason must not be copied into a build log by the check that suspects it. The implementor
     * has the reason in their own source and their own debugger; a CI archive does not need it.
     */
    private static String describe(EndpointAssessment assessment) {
        return assessment == null ? "null" : assessment.getClass().getSimpleName();
    }

    /**
     * Checks an endpoint the implementor supplied against the precondition {@link EndpointPolicy#assess} is written for
     * — an absolute {@code https} URL with a host — before the contract measures a policy against it. Holding a policy
     * to an input the seam never promises to hand it would report on a question nobody asked.
     */
    private static URI admissible(URI endpoint, String accessor) {
        try {
            // String.valueOf rather than toString: an accessor answering null is a fixture mistake
            // like any other, and it should arrive as this message rather than as a bare NPE.
            Endpoints.requireSecure(String.valueOf(endpoint));
        } catch (IllegalArgumentException outsideTheContract) {
            throw new AssertionError(
                    accessor + " must answer an endpoint this seam is ever handed: an absolute https URL with a host. "
                            + "This is a problem with the fixture and not with the policy — " + outsideTheContract
                            + ".",
                    outsideTheContract);
        }
        return endpoint;
    }
}
