package io.push2u;

/**
 * Thrown when a cryptographic primitive cannot be set up or executed — a genuine
 * misconfiguration (a required JCE algorithm/provider is missing, an invalid key, a malformed
 * EC point), never a normal protocol outcome.
 *
 * <p>Unchecked on purpose: per the library contract (DESIGN.md §5.2) the public surface throws
 * only on genuine errors, and a missing {@code AES/GCM/NoPadding} or {@code HmacSHA256} is a
 * deployment fault the caller cannot meaningfully recover from at the call site. A dead
 * subscription, by contrast, is a {@code PushResult}, not an exception (ADR-007).
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
     * @param cause   the underlying cause
     */
    public PushCryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
