/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.spring;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Binds the push2u health indicator's tuning, under the prefix Spring Boot gives a contributor's own settings —
 * {@code management.health.push2u.*}, beside the {@code enabled} switch every other contributor is turned off by.
 *
 * <p>Deliberately not public and deliberately holding one component. It is not public because nothing outside this
 * starter has a reason to inject it, and a published type here would be a permanent accessor for a key whose whole
 * point is that the framework, not this library, decides where it lives. It holds one component because the switch
 * beside it is <em>not</em> bound here: {@code management.health.push2u.enabled} is read by the framework's own
 * condition on the indicator's factory method, and a component of the same name here would make two readers of one key,
 * each able to disagree with the other about what the operator wrote.
 *
 * @param cacheTtl how long a successful probe result is served from cache before the signer is exercised again. A
 *     <em>failed</em> result is cached for at most 5 seconds regardless (the shorter of this value and 5s), so recovery
 *     is noticed quickly even under a long TTL. {@code 0s} disables caching; negative values are rejected at startup
 */
@ConfigurationProperties("management.health.push2u")
record Push2uHealthProperties(@DefaultValue("30s") Duration cacheTtl) {}
