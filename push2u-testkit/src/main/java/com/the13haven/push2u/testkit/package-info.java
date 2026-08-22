/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/**
 * The published test kit: conformance contracts a {@code push2u} extension point must satisfy, and coherent values of
 * the library's public input contracts for the tests an application writes around its own sending code.
 *
 * <p>This package is the whole of the {@code push2u-testkit} artifact, which belongs on a consumer's <em>test</em>
 * classpath and not in an application's runtime. It is a separate package from {@code com.the13haven.push2u} because
 * the core is an explicit JPMS module: a package split across two artifacts cannot be resolved from the module path, so
 * a consumer holding both jars would get a {@code ResolutionException} rather than a test kit.
 *
 * <p>The contract side holds one executable contract per extension point a deployment writes itself.
 * {@link com.the13haven.push2u.testkit.VapidSignerContractTest} is what every {@link com.the13haven.push2u.VapidSigner}
 * implementation extends — the encodings a push service will otherwise reject silently.
 * {@link com.the13haven.push2u.testkit.EndpointPolicyContractTest} is what a custom
 * {@link com.the13haven.push2u.EndpointPolicy} extends — every one that admits an endpoint, which is every one this
 * library has a use for: it checks that the policy answers with a value rather than an exception, that concurrent calls
 * all come back, and that a refusal's reason does not carry the capability part of the endpoint into the logs the
 * outcome reaches. A policy that permits nothing has no permitted endpoint to hand over and stays outside it. The
 * fixture side serves the application that only sends: {@link com.the13haven.push2u.testkit.VapidKeyPairFixture}
 * generates a VAPID pair the builder and the configuration properties accept,
 * {@link com.the13haven.push2u.testkit.SubscriptionFixture} holds one coherent browser subscription in both the typed
 * and the base64url form, and {@link com.the13haven.push2u.testkit.ScriptedPushHttpClient} answers a declared response
 * sequence while recording each call as a {@link com.the13haven.push2u.testkit.SentPush}. What admits a member here is
 * that the knowledge it carries is the library's own and moves with it — what the current contracts accept, what a
 * transport owes — never that some assembly is tedious; values produced by the library stay valid across an upgrade
 * that tightens validation, where a pasted literal breaks with no warning a release note could give.
 */
@NullMarked
package com.the13haven.push2u.testkit;

import org.jspecify.annotations.NullMarked;
