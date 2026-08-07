/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/**
 * The published test kit: conformance contracts a {@code push2u} extension point must satisfy.
 *
 * <p>This package is the whole of the {@code push2u-testkit} artifact, which belongs on a consumer's <em>test</em>
 * classpath and not in an application's runtime. It is a separate package from {@code com.the13haven.push2u} because
 * the core is an explicit JPMS module: a package split across two artifacts cannot be resolved from the module path, so
 * a consumer holding both jars would get a {@code ResolutionException} rather than a test kit.
 *
 * <p>Its one member today is {@link com.the13haven.push2u.testkit.VapidSignerContractTest}, which every
 * {@link com.the13haven.push2u.VapidSigner} implementation extends.
 */
@NullMarked
package com.the13haven.push2u.testkit;

import org.jspecify.annotations.NullMarked;
