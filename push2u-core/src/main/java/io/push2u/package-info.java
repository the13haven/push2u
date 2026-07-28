/**
 * push2u — a zero-dependency JVM library for the Web Push protocol
 * (RFC 8030 / 8291 / 8292 / 8188): VAPID-authenticated, end-to-end-encrypted delivery of push
 * messages to browser push services from a Java application server.
 *
 * <p>This package is the public surface of {@code push2u-core}. The package name and Maven
 * coordinate ({@code io.push2u}) are provisional and finalised at extraction — see
 * {@code backend/lib/push2u/DESIGN.md} (ADR-008 / ADR-009) and {@code ROADMAP.md}.
 *
 * <p>Phase 0 scaffolding: this file exists so the module compiles in the umbrella Gradle build
 * before the Phase 1 crypto core (domain records, RFC 8291 encryptor, VAPID JWT) lands.
 */
package io.push2u;
