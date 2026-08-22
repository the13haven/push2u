/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.net.URI;
import java.util.Optional;

import com.the13haven.push2u.testkit.EndpointPolicyContractTest;

/**
 * {@link EndpointPolicies#unrestricted()} satisfies the shared {@link EndpointPolicyContractTest} with an empty refusal
 * witness, which is the answer for a policy whose declared behaviour is to admit every endpoint the seam's precondition
 * lets through.
 *
 * <p>It is the smallest subject of the four and does the most work: an empty witness is a shape nothing else in this
 * build takes, so it is precisely the path a later change could break without a single other test noticing.
 */
class EndpointPoliciesUnrestrictedContractTest extends EndpointPolicyContractTest {

    @Override
    protected EndpointPolicy policy() {
        return EndpointPolicies.unrestricted();
    }

    @Override
    protected URI allowedEndpoint() {
        return URI.create("https://push.example/wpush/v2/2f1c8a7e6d5b4a390817");
    }

    @Override
    protected Optional<URI> refusedEndpoint() {
        return Optional.empty();
    }
}
