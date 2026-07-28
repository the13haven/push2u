/**
 * Spring Boot auto-configuration for push2u-signer-vault — binds {@code push2u.signer.vault.*} to a
 * {@link io.push2u.VapidSigner} backed by Vault Transit. Opt-in module; with the core
 * {@code push2u-spring-boot-starter} present it supplies the signer the {@code PushSender} uses.
 *
 * <p>Provisional package + Maven coordinate, finalised at extraction (DESIGN.md ADR-008/009).
 */
package io.push2u.signer.vault.spring;
