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
 * {@link EndpointPolicies#allowedEndpoints} satisfies the shared {@link EndpointPolicyContractTest}, configured the way
 * a cross-browser deployment actually configures it: an origin rule beside a domain rule in one list.
 */
class EndpointPoliciesAllowedEndpointsContractTest extends EndpointPolicyContractTest {

    @Override
    protected EndpointPolicy policy() {
        return EndpointPolicies.allowedEndpoints(
                EndpointRule.origin("https://push.example"), EndpointRule.domain("zone.example"));
    }

    @Override
    protected URI allowedEndpoint() {
        return URI.create("https://a.b.zone.example/wpush/v2/2f1c8a7e6d5b4a390817");
    }

    @Override
    protected Optional<URI> refusedEndpoint() {
        return Optional.of(URI.create("https://blocked.example/wpush/v2/9f8e7d6c5b4a39281706"));
    }
}
