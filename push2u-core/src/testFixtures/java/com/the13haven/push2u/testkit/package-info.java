/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/**
 * The published test kit: conformance contracts a {@code push2u} extension point must satisfy.
 *
 * <p>This package ships in {@code push2u-core}'s test-fixtures artifact, not in the library jar. It is a separate
 * package from {@code com.the13haven.push2u} on purpose — the core is an explicit JPMS module (ADR-014), and a package
 * split across two artifacts cannot be read by a consumer that puts either of them on the module path.
 *
 * <p>Its one member today is {@link com.the13haven.push2u.testkit.VapidSignerContractTest}, which every
 * {@link com.the13haven.push2u.VapidSigner} implementation extends.
 */
@NullMarked
package com.the13haven.push2u.testkit;

import org.jspecify.annotations.NullMarked;
