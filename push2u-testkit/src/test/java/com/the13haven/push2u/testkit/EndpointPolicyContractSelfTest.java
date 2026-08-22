/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.util.Optional;
import java.util.function.Function;

import org.junit.jupiter.api.Test;
import org.opentest4j.TestAbortedException;

import com.the13haven.push2u.EndpointAssessment;
import com.the13haven.push2u.EndpointPolicy;
import com.the13haven.push2u.Endpoints;

/**
 * The kit checking itself. {@link EndpointPolicyContractTest} is published so that a policy implementation finds out it
 * writes a capability URL into a refusal before that refusal reaches an application's logs — which is worth exactly as
 * much as the contract's ability to fail. So each check is run twice: once against a policy that satisfies it, and once
 * against one that breaks precisely what that check is about.
 *
 * <p>The leak check gets the most attention here, because it is the one that can be wrong in both directions. It has to
 * catch a policy naming one path segment or one query value — the whole of the bearer credential in the spelling a
 * policy is most likely to write — and it must not convict a policy printing the origin and fingerprint it is entitled
 * to print. Both directions are pinned below, along with the two ways a witness can be unfit for the check at all,
 * which the contract must report as a problem with the fixture rather than as a failure of the policy.
 */
final class EndpointPolicyContractSelfTest {

    /** A permitted endpoint: the conforming policies below admit exactly this host. */
    private static final URI ALLOWED = URI.create("https://push.example/wpush/v2/2f1c8a7e6d5b4a390817");

    /** A refused endpoint carrying a capability-shaped last segment, which is what the leak check searches for. */
    private static final URI REFUSED = URI.create("https://blocked.example/wpush/v2/9f8e7d6c5b4a39281706");

    /** Drives one contract instance over a supplied policy and pair of witnesses. */
    private static final class Contract extends EndpointPolicyContractTest {

        private final EndpointPolicy policy;
        private final URI allowed;
        private final Optional<URI> refused;

        Contract(EndpointPolicy policy, URI allowed, Optional<URI> refused) {
            this.policy = policy;
            this.allowed = allowed;
            this.refused = refused;
        }

        static Contract over(EndpointPolicy policy) {
            return new Contract(policy, ALLOWED, Optional.of(REFUSED));
        }

        static Contract witness(URI refused) {
            return new Contract(conformingPolicy(), ALLOWED, Optional.of(refused));
        }

        @Override
        protected EndpointPolicy policy() {
            return policy;
        }

        @Override
        protected URI allowedEndpoint() {
            return allowed;
        }

        @Override
        protected Optional<URI> refusedEndpoint() {
            return refused;
        }
    }

    @Test
    void conformingPolicySatisfiesEveryCheck() {
        Contract contract = Contract.over(conformingPolicy());

        assertThatCode(contract::permittedEndpointIsAnsweredWithAllowed).doesNotThrowAnyException();
        assertThatCode(contract::refusalIsAValueWhoseReasonKeepsTheCapabilityUrlOut)
                .doesNotThrowAnyException();
        assertThatCode(contract::concurrentAssessmentsAllComeBackWithAnAnswer).doesNotThrowAnyException();
    }

    /**
     * The rendering a conforming policy is entitled to print — the origin plus a sixteen-character fingerprint — must
     * never be read as a leak. This is the false-positive direction, and getting it wrong would teach implementors to
     * distrust the contract rather than their policies.
     */
    @Test
    void printingTheLibrarysOwnRedactionIsNotALeak() {
        Contract contract = Contract.over(conformingPolicy());

        assertThatCode(contract::refusalIsAValueWhoseReasonKeepsTheCapabilityUrlOut)
                .as("origin and fingerprint are what a refusal may name")
                .doesNotThrowAnyException();
    }

    @Test
    void printingTheRawEndpointFailsTheLeakCheck() {
        Contract contract = Contract.over(refusingWith(URI::toString));

        assertThatThrownBy(contract::refusalIsAValueWhoseReasonKeepsTheCapabilityUrlOut)
                .as("the whole capability URL in a refusal is the failure this check exists to catch")
                .isInstanceOf(AssertionError.class);
    }

    /**
     * The granularity a first attempt leaves out. This reason contains neither the full URI nor the whole path, and it
     * has published the entire bearer credential all the same — a check searching only entire components would pass it.
     */
    @Test
    void printingOnlyTheLastPathSegmentFailsTheLeakCheck() {
        Contract contract = Contract.over(refusingWith(EndpointPolicyContractSelfTest::lastSegment));

        assertThatThrownBy(contract::refusalIsAValueWhoseReasonKeepsTheCapabilityUrlOut)
                .as("one path segment is the whole credential; nothing about the URI or the path appears in the "
                        + "message")
                .isInstanceOf(AssertionError.class);
    }

    @Test
    void printingOnlyAQueryValueFailsTheLeakCheck() {
        URI tokenInQuery = URI.create("https://blocked.example/p?token=9f8e7d6c5b4a3928170615");
        Contract contract = new Contract(
                refusingWith(EndpointPolicyContractSelfTest::queryValue), ALLOWED, Optional.of(tokenInQuery));

        assertThatThrownBy(contract::refusalIsAValueWhoseReasonKeepsTheCapabilityUrlOut)
                .as("a token leaked as the bare value of a query parameter is the same credential")
                .isInstanceOf(AssertionError.class);
    }

    /**
     * A policy that percent-decodes before building its message leaks exactly as much as one that does not, and the
     * decoded spelling is the only one that would find it: the raw form of this segment appears nowhere in the reason.
     */
    @Test
    void printingTheDecodedFormFailsTheLeakCheck() {
        URI encoded = URI.create("https://blocked.example/t/token%2D9f8e7d6c5b4a3928");
        Contract contract = new Contract(refusingWith(URI::getPath), ALLOWED, Optional.of(encoded));

        assertThatThrownBy(contract::refusalIsAValueWhoseReasonKeepsTheCapabilityUrlOut)
                .as("URI.getPath() is the decoded spelling, which the raw marker alone would miss")
                .isInstanceOf(AssertionError.class);
    }

    /**
     * The other half of the fitness rule, at the level where it bites. This witness carries a segment whose
     * <em>decoded</em> form is the origin itself, which the redaction prints on purpose — so that spelling is dropped
     * from the search while its raw form is kept. Without the drop a conforming policy would be convicted for printing
     * the one thing it is allowed to print.
     */
    @Test
    void aDecodedPartCollidingWithTheRedactionIsNotSearchedFor() {
        URI originInPath = URI.create("https://blocked.example/https%3A%2F%2Fblocked.example");
        Contract contract = new Contract(conformingPolicy(), ALLOWED, Optional.of(originInPath));

        assertThatCode(contract::refusalIsAValueWhoseReasonKeepsTheCapabilityUrlOut)
                .as("the decoded segment is the origin the redaction already names, so finding it proves nothing")
                .doesNotThrowAnyException();
    }

    /**
     * A hex-shaped component is the trap the length half of the fitness rule closes: the redaction ends in a
     * sixteen-character hexadecimal fingerprint, so a short hex marker could match on the fingerprint and report a leak
     * against a policy that leaked nothing. Below the threshold nothing that short is ever searched for.
     */
    @Test
    void aHexShapedComponentNeverConvictsAConformingPolicy() {
        Contract contract = Contract.witness(URI.create("https://blocked.example/p/a1b2c3d4"));

        assertThatCode(contract::refusalIsAValueWhoseReasonKeepsTheCapabilityUrlOut)
                .as("the fingerprint the redaction prints must not be mistaken for the endpoint")
                .doesNotThrowAnyException();
    }

    /**
     * A witness with nothing distinctive in it: every part of {@code https://blocked.example/} already occurs in the
     * redaction of that same endpoint, so the search would report success for a property it never tested. The contract
     * has to say that about the fixture, and not about the policy.
     */
    @Test
    void aWitnessWithNothingToLeakIsReportedAsUnfitRatherThanAsAPolicyFailure() {
        Contract contract = Contract.witness(URI.create("https://blocked.example/"));

        assertThatThrownBy(contract::refusalIsAValueWhoseReasonKeepsTheCapabilityUrlOut)
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("unfit for this check")
                .hasMessageContaining("problem with the fixture and not with the policy")
                .hasMessageContaining("already occur in the rendering");
    }

    /**
     * The other half of the same rule, and the message has to name which half was failed: here nothing about the
     * endpoint is long enough to tell a leaked credential apart from the ordinary words of a refusal.
     */
    @Test
    void aWitnessWhoseEveryPartIsTooShortIsReportedAsUnfitAndSaysSo() {
        Contract contract = Contract.witness(URI.create("https://a.io/x"));

        assertThatThrownBy(contract::refusalIsAValueWhoseReasonKeepsTheCapabilityUrlOut)
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("unfit for this check")
                .hasMessageContaining("shorter than 16 characters")
                .hasMessageNotContaining("already occur in the rendering");
    }

    /**
     * A refusal that arrives as an exception is the failure the seam was moved off the exception channel to prevent:
     * one hostile row would abort a fan-out over a whole subscription store. It reaches the runner as the policy's own
     * defect rather than as an assertion, which is a failed check either way and names the culprit more precisely than
     * a wrapped message would.
     */
    @Test
    void aPolicyThrowingInsteadOfRefusingFailsTheRefusalCheck() {
        Contract contract = Contract.over(endpoint -> {
            throw new IllegalStateException("endpoint refused");
        });

        assertThatThrownBy(contract::refusalIsAValueWhoseReasonKeepsTheCapabilityUrlOut)
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void aPolicyAnsweringNullFailsBothClassificationChecks() {
        Contract contract = Contract.over(endpoint -> null);

        assertThatThrownBy(contract::permittedEndpointIsAnsweredWithAllowed).isInstanceOf(AssertionError.class);
        assertThatThrownBy(contract::refusalIsAValueWhoseReasonKeepsTheCapabilityUrlOut)
                .isInstanceOf(AssertionError.class);
    }

    @Test
    void aPolicyRefusingTheEndpointItWasToldItPermitsFailsTheAllowedCheck() {
        Contract contract = Contract.over(endpoint -> new EndpointAssessment.Refused("everything is refused"));

        assertThatThrownBy(contract::permittedEndpointIsAnsweredWithAllowed).isInstanceOf(AssertionError.class);
    }

    /**
     * An empty witness is the answer for a policy that refuses nothing. The refusal check is then reported as skipped
     * rather than passed — a green check nothing exercised would misreport the subject's coverage — while the other two
     * still run, which is the whole reason the witness is optional.
     */
    @Test
    void anEmptyWitnessSkipsOnlyTheRefusalCheck() {
        Contract contract = new Contract(endpoint -> new EndpointAssessment.Allowed(), ALLOWED, Optional.empty());

        assertThatThrownBy(contract::refusalIsAValueWhoseReasonKeepsTheCapabilityUrlOut)
                .isInstanceOf(TestAbortedException.class);
        assertThatCode(contract::permittedEndpointIsAnsweredWithAllowed).doesNotThrowAnyException();
        assertThatCode(contract::concurrentAssessmentsAllComeBackWithAnAnswer).doesNotThrowAnyException();
    }

    /**
     * The seam's precondition applies to the fixture too: {@code assess} is only ever handed an absolute {@code https}
     * URL with a host, so measuring a policy against anything else would report on a question nobody asked.
     */
    @Test
    void anEndpointOutsideTheSeamsPreconditionIsReportedAgainstTheFixture() {
        Contract contract = new Contract(conformingPolicy(), URI.create("http://push.example/p"), Optional.of(REFUSED));

        assertThatThrownBy(contract::permittedEndpointIsAnsweredWithAllowed)
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("allowedEndpoint()")
                .hasMessageContaining("absolute https URL with a host");
    }

    /** Admits the one permitted host and renders every refusal the way the seam's contract requires. */
    private static EndpointPolicy conformingPolicy() {
        return refusingWith(
                endpoint -> "push endpoint is not in the allowed set: " + Endpoints.redact(endpoint.toString()));
    }

    /**
     * A policy admitting {@code push.example} and refusing everything else with a reason the caller composes — which is
     * the only thing that differs between a conforming policy and the leaking ones below.
     */
    private static EndpointPolicy refusingWith(Function<URI, String> reason) {
        return endpoint -> "push.example".equals(endpoint.getHost())
                ? new EndpointAssessment.Allowed()
                : new EndpointAssessment.Refused(reason.apply(endpoint));
    }

    private static String lastSegment(URI endpoint) {
        String path = endpoint.getRawPath();
        return path.substring(path.lastIndexOf('/') + 1);
    }

    private static String queryValue(URI endpoint) {
        String query = endpoint.getRawQuery();
        return query.substring(query.indexOf('=') + 1);
    }
}
