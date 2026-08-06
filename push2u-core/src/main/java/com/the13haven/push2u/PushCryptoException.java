/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

/**
 * Thrown when a cryptographic operation cannot be set up or carried out — a required JCE algorithm or provider is
 * missing, a key is invalid, an EC point is malformed, or a {@link VapidSigner} could not produce the VAPID signature.
 * Never a normal protocol outcome: a dead subscription is a {@code PushResult}, not an exception.
 *
 * <p>Unchecked on purpose: the library's contract is that the public surface throws only on genuine errors, and none of
 * these is something the call site can correct by trying differently.
 *
 * <p><b>Not every occurrence is permanent.</b> A missing {@code AES/GCM/NoPadding} or {@code HmacSHA256} is a
 * deployment fault that will fail identically on the next send, and wants an alert rather than a retry. A
 * {@link VapidSigner} backed by a remote key service reports its transport failures as this exception too — the Vault
 * Transit signer does so for a request timeout and for a dropped connection — and those are transient by nature. One
 * type covers both on purpose; the message and the cause chain, not the type, say which happened.
 */
public class PushCryptoException extends RuntimeException {

    /**
     * Creates an exception describing the crypto failure.
     *
     * @param message the detail message
     */
    public PushCryptoException(String message) {
        super(message);
    }

    /**
     * Creates an exception describing the crypto failure, wrapping the underlying cause.
     *
     * @param message the detail message
     * @param cause the underlying cause
     */
    public PushCryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
