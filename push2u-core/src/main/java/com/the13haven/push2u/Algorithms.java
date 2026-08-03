package com.the13haven.push2u;

/**
 * JCA standard algorithm names used across the crypto code. Centralised so these identifiers — which fail only at
 * runtime if mistyped — live in one place, and so the ones shared between classes cannot drift apart.
 *
 * <p>Two invariants this enforces by construction:
 *
 * <ul>
 *   <li>the HMAC transformation passed to {@code Mac.getInstance} ({@link Jca}) is the same string as the key algorithm
 *       passed to {@code SecretKeySpec} ({@link Hkdf});
 *   <li>the AES cipher <em>transformation</em> ({@link #AES_GCM_NO_PADDING}) and the AES <em>key algorithm</em>
 *       ({@link #AES}) are related but distinct strings, kept separate.
 * </ul>
 */
final class Algorithms {

    private Algorithms() {}

    /** HMAC-SHA-256 — the {@code Mac} transformation and the {@code SecretKeySpec} key algorithm for HKDF. */
    static final String HMAC_SHA256 = "HmacSHA256";

    /** AES-128-GCM content encryption (RFC 8188) — the {@code Cipher} transformation. */
    static final String AES_GCM_NO_PADDING = "AES/GCM/NoPadding";

    /** The {@code SecretKeySpec} key algorithm for the AES key (base cipher of {@link #AES_GCM_NO_PADDING}). */
    static final String AES = "AES";

    /** Elliptic Curve Diffie-Hellman key agreement (RFC 8291). */
    static final String ECDH = "ECDH";

    /** Elliptic Curve — {@code KeyFactory}, {@code KeyPairGenerator} and {@code AlgorithmParameters}. */
    static final String EC = "EC";

    /** ES256 in P1363 format — raw {@code r||s} signatures for the VAPID JWT (RFC 8292), no DER. */
    static final String ES256_P1363 = "SHA256withECDSAinP1363Format";

    /**
     * ES256 in the standard DER format — the fallback when a provider does not register {@link #ES256_P1363}
     * (BouncyCastle FIPS registers only this name); the DER output is then strictly converted to the raw {@code r||s}
     * JOSE needs.
     */
    static final String ES256_DER = "SHA256withECDSA";

    /** NIST P-256 / {@code secp256r1} — the only curve Web Push uses. */
    static final String SECP256R1 = "secp256r1";
}
