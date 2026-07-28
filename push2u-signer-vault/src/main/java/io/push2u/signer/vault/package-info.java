/**
 * A {@link io.push2u.VapidSigner} backed by HashiCorp Vault Transit — the private key never
 * leaves Vault (DESIGN.md ADR-010). Opt-in module on top of {@code push2u-core}.
 *
 * <p>Provisional package + Maven coordinate, finalised at extraction (DESIGN.md ADR-008/009).
 */
package io.push2u.signer.vault;
