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
 * {@link EndpointPolicies#allowedOrigins} satisfies the shared {@link EndpointPolicyContractTest}. Both witnesses carry
 * a capability-shaped last path segment, which is what the contract's leak check searches a refusal for.
 */
class EndpointPoliciesAllowedOriginsContractTest extends EndpointPolicyContractTest {

    @Override
    protected EndpointPolicy policy() {
        return EndpointPolicies.allowedOrigins("https://push.example");
    }

    @Override
    protected URI allowedEndpoint() {
        return URI.create("https://push.example/wpush/v2/2f1c8a7e6d5b4a390817");
    }

    @Override
    protected Optional<URI> refusedEndpoint() {
        return Optional.of(URI.create("https://blocked.example/wpush/v2/9f8e7d6c5b4a39281706"));
    }
}
