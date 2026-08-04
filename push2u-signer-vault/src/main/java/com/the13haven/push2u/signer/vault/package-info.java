/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/**
 * A {@link com.the13haven.push2u.VapidSigner} backed by HashiCorp Vault Transit — the private key never leaves Vault.
 * Opt-in module on top of {@code push2u-core}.
 */
@NullMarked
package com.the13haven.push2u.signer.vault;

import org.jspecify.annotations.NullMarked;
