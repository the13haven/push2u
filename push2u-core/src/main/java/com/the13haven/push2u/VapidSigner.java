/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

/**
 * Produces the VAPID (RFC 8292) ES256 signature over a JWT signing input and advertises the corresponding public key.
 *
 * <p>This is the library's primary extension point: the seam is <em>key custody</em>. The default
 * {@link LocalEcVapidSigner} holds the private key in memory; a Vault Transit / KMS / HSM implementation keeps it off
 * the JVM heap entirely — a genuinely different security posture, the articulable reason this is an SPI.
 *
 * <p><b>Both outputs are checked on every send</b>, and a violation raises {@link PushCryptoException} naming what was
 * returned. Neither is checkable by the implementation's own tests in the way that matters: a signature or key of the
 * wrong shape still produces a syntactically valid {@code Authorization} header, so the failure would otherwise reach
 * the caller as an opaque 401/403 from the push service — on every send, with nothing in it pointing at the signer. The
 * shapes are not this library's invention: RFC 7518 §3.4 fixes the ES256 signature at the raw {@code r || s} pair, and
 * RFC 8292 §3.2 fixes the key at the X9.62 uncompressed point.
 *
 * <p>The likely mistake is DER. JCA's {@code SHA256withECDSA} returns a DER-encoded signature, and an implementation
 * that forwards its provider's output unconverted looks correct until a push service rejects it. Ask the provider for
 * {@code SHA256withECDSAinP1363Format}, or convert before returning — the library does exactly that for its own signer
 * but cannot do it here, since these bytes arrive from an implementation whose provider and encoding are unknown.
 */
public interface VapidSigner {

    /**
     * Sign the JWT signing input (the ASCII {@code base64url(header) || "." || base64url(claims)}) with ES256,
     * returning the raw {@code r || s} pair (64 bytes for P-256) that JOSE expects — not a DER-encoded signature.
     *
     * <p>The returned array becomes the caller's: return freshly produced bytes, never a buffer the implementation
     * retains for reuse.
     *
     * @param signingInput the ASCII JWT signing input
     * @return the raw {@code r || s} ES256 signature (64 bytes for P-256), owned by the caller
     */
    byte[] sign(byte[] signingInput);

    /**
     * The application server's VAPID public key as a 65-byte X9.62 uncompressed point.
     *
     * <p>Every call must return a fresh copy, never a reference to the signer's own array: the caller owns the returned
     * bytes, and a signer handing out its internal state is silently corrupted for every later send the moment anything
     * writes into a returned array. Both shipped signers return a {@code clone()}, and the {@code push2u-testkit}
     * conformance kit checks the copy.
     *
     * @return the 65-byte uncompressed public key, a fresh copy owned by the caller
     */
    byte[] publicKey();
}
