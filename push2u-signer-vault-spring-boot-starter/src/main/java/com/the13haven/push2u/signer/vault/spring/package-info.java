/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/**
 * Spring Boot auto-configuration for push2u-signer-vault — binds {@code push2u.signer.vault.*} to a
 * {@link com.the13haven.push2u.VapidSigner} backed by Vault Transit. Opt-in module; with the core
 * {@code push2u-spring-boot-starter} present it supplies the signer the {@code PushSender} uses.
 */
@NullMarked
package com.the13haven.push2u.signer.vault.spring;

import org.jspecify.annotations.NullMarked;
