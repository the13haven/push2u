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
 * the core is an explicit JPMS module (ADR-014) and would refuse to share its package with a second artifact on the
 * module path.
 *
 * <p>Its one member today is {@link com.the13haven.push2u.testkit.VapidSignerContractTest}, which every
 * {@link com.the13haven.push2u.VapidSigner} implementation extends.
 */
@NullMarked
package com.the13haven.push2u.testkit;

import org.jspecify.annotations.NullMarked;
