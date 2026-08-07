/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Objects;

import org.jspecify.annotations.Nullable;

/**
 * The default {@link VapidSigner}: holds the P-256 private key in memory and signs in-JVM, always producing the raw
 * {@code r || s} pair JOSE wants. When the configured provider registers raw-format ECDSA
 * ({@code SHA256withECDSAinP1363Format}) the signature is used as is; when it registers only the standard DER form
 * ({@code SHA256withECDSA}, e.g. BouncyCastle FIPS), the DER output is strictly re-encoded to {@code r || s} — a
 * representation change only, the signing itself stays inside that provider. Suitable when the key is sourced at rest
 * (e.g. from a secrets manager) and signing in-process is acceptable; for a key that must never touch the heap, use a
 * remote signer instead.
 *
 * <p>The constructor rejects a key pair whose halves do not belong together: the JWT is signed with the private scalar
 * while the public key is advertised verbatim as the {@code k} parameter, so a mismatched pair yields plausible-looking
 * requests that every push service rejects with 401/403. A one-time sign-and-verify self-test catches this at
 * construction — one ECDSA sign plus one verify per signer created, not per send — and throws
 * {@link IllegalArgumentException} on a mismatch.
 */
public final class LocalEcVapidSigner implements VapidSigner {

    /** Fixed probe input for the construction-time key-pair self-test. */
    private static final byte[] SELF_TEST_INPUT = "push2u VAPID key-pair self-test".getBytes(StandardCharsets.US_ASCII);

    private final byte[] publicKey;
    private final ECPrivateKey privateKey;
    private final Jca jca;

    /**
     * Creates a signer over the given VAPID key pair, signing in-JVM with the platform JCE provider.
     *
     * @param keys the VAPID key pair
     */
    public LocalEcVapidSigner(VapidKeys keys) {
        this(keys, Jca.platform());
    }

    LocalEcVapidSigner(VapidKeys keys, Jca jca) {
        Objects.requireNonNull(keys, "keys");
        this.jca = Objects.requireNonNull(jca, "jca");
        this.publicKey = keys.publicKey();
        this.privateKey = EcKeys.decodeP256PrivateKey(keys.privateScalar(), jca);
        requireMatchingKeyPair();
    }

    /**
     * One-time self-test that the advertised public key belongs to the private scalar: sign a fixed probe with the
     * private key, then verify that signature against the decoded public key. Deriving the public point directly
     * ({@code d * G}) is not an option — the JDK exposes no public EC point-arithmetic API and this module deliberately
     * carries no runtime implementation dependencies — and sign+verify additionally proves the configured provider can
     * actually sign with this key. Both {@link Signature} instances come from the same {@link Jca#es256()} resolution,
     * so the probe signature is verified exactly as the provider produced it — do not convert it with
     * {@code EcdsaDer.toP1363} here, even on a DER-only provider.
     *
     * <p>A public key that is well-formed but not a point on P-256 is rejected too, and always as
     * {@link PushCryptoException}: {@code EcKeys.decodeP256PublicKey} checks the curve equation itself, before the
     * provider sees the point, so the outcome no longer depends on whether that provider validates on import. The type
     * is still deliberately not normalised to {@link IllegalArgumentException}, because the same decode raises
     * {@code PushCryptoException} when the provider has no EC {@code KeyFactory} at all, and collapsing the two would
     * relabel a missing provider as bad input.
     */
    private void requireMatchingKeyPair() {
        ECPublicKey advertised = EcKeys.decodeP256PublicKey(publicKey, jca);
        try {
            Signature probeSigner = jca.es256().delegate();
            probeSigner.initSign(privateKey);
            probeSigner.update(SELF_TEST_INPUT);
            byte[] probeSignature = requireSignatureProduced(probeSigner.sign());

            Signature probeVerifier = jca.es256().delegate();
            probeVerifier.initVerify(advertised);
            probeVerifier.update(SELF_TEST_INPUT);
            if (!probeVerifier.verify(probeSignature)) {
                // Deliberately key-free: the message must never carry key bytes, not even the
                // public half.
                throw new IllegalArgumentException(
                        "VAPID public key does not correspond to the private key: a signature"
                                + " produced with the private scalar does not verify against the"
                                + " advertised public key");
            }
        } catch (GeneralSecurityException e) {
            throw new PushCryptoException("VAPID key-pair self-test failed", e);
        }
    }

    @Override
    public byte[] sign(byte[] signingInput) {
        Jca.EcdsaSignature es256 = jca.es256();
        try {
            Signature signature = es256.delegate();
            signature.initSign(privateKey);
            signature.update(signingInput);
            byte[] raw = requireSignatureProduced(signature.sign());
            return es256.encoding() == Jca.EcdsaSignature.Encoding.DER ? EcdsaDer.toP1363(raw) : raw;
        } catch (GeneralSecurityException e) {
            throw new PushCryptoException("VAPID ES256 signing failed", e);
        }
    }

    /**
     * Refuse a {@link Signature#sign()} answer of {@code null}. The provider's own signature implementation is what
     * answers, nothing in the JDK obliges a defective one to answer bytes at all, and this answer travels: on a
     * raw-format provider it would leave {@code sign(byte[])} — a public method that promises never to return
     * {@code null} — as this library's own answer, ending up wherever the caller puts it. A provider answer of that
     * kind is refused wherever it is obtained, so the construction-time self-test applies the same refusal rather than
     * handing the missing bytes back to the provider's verify, whose {@link NullPointerException} would escape a public
     * constructor. Refused by name as the library's crypto failure; the DER conversion's own {@code null} rejection
     * stays as defence in depth behind this.
     */
    private static byte[] requireSignatureProduced(byte @Nullable [] signature) {
        if (signature == null) {
            throw new PushCryptoException("VAPID ES256 signing returned no signature at all");
        }
        return signature;
    }

    @Override
    public byte[] publicKey() {
        return publicKey.clone();
    }
}
