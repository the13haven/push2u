package com.the13haven.push2u;

/**
 * Produces the VAPID (RFC 8292) ES256 signature over a JWT signing input and advertises the corresponding public key.
 *
 * <p>This is the library's primary extension point: the seam is <em>key custody</em>. The default
 * {@link LocalEcVapidSigner} holds the private key in memory; a Vault Transit / KMS / HSM implementation keeps it off
 * the JVM heap entirely — a genuinely different security posture, the articulable reason this is an SPI.
 */
public interface VapidSigner {

    /**
     * Sign the JWT signing input (the ASCII {@code base64url(header) || "." || base64url(claims)}) with ES256,
     * returning the raw {@code r || s} pair (64 bytes for P-256) that JOSE expects — not a DER-encoded signature.
     *
     * @param signingInput the ASCII JWT signing input
     * @return the raw {@code r || s} ES256 signature (64 bytes for P-256)
     */
    byte[] sign(byte[] signingInput);

    /**
     * The application server's VAPID public key as a 65-byte X9.62 uncompressed point.
     *
     * @return the 65-byte uncompressed public key
     */
    byte[] publicKey();
}
