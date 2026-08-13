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
 * <p><b>Both outputs are checked wherever a new value enters a send</b> — on every signature taken, which under the
 * default token reuse ({@link PushSender.Builder#jwtReuse(boolean)}) is every cache miss rather than literally every
 * send: a reused {@code Authorization} value was checked when it was signed, and {@link #sign} is not called again for
 * it. A violation raises {@link PushCryptoException} naming what was returned. Neither output is checkable by the
 * implementation's own tests in the way that matters: a signature or key of the wrong shape still produces a
 * syntactically valid {@code Authorization} header, so the failure would otherwise reach the caller as an opaque
 * 401/403 from the push service — on every send, with nothing in it pointing at the signer. The shapes are not this
 * library's invention: RFC 7518 §3.4 fixes the ES256 signature at the raw {@code r || s} pair, and RFC 8292 §3.2 fixes
 * the key at the X9.62 uncompressed point.
 *
 * <p>The likely mistake is DER. JCA's {@code SHA256withECDSA} returns a DER-encoded signature, and an implementation
 * that forwards its provider's output unconverted looks correct until a push service rejects it. Ask the provider for
 * {@code SHA256withECDSAinP1363Format}, or convert before returning — the library does exactly that for its own signer
 * but cannot do it here, since these bytes arrive from an implementation whose provider and encoding are unknown.
 *
 * <p><b>A failure leaves in one of two types, and this is the split an implementation is most likely to get wrong.</b>
 * A key custodian that cannot sign <em>now</em> — unreachable, timed out, sealed, not yet initialized, still catching
 * up, rate-limiting — raises {@link VapidSignerUnavailableException}, from {@link #sign} and {@link #publicKey} alike.
 * Everything else raises {@link PushCryptoException}: a defect, a substrate that cannot perform the cryptography, an
 * answer no custodian could have meant, and a misconfiguration that answers the same way until a person edits it. The
 * two are not interchangeable, and the difference is what a caller does — wait and repeat, against stop and fetch a
 * human.
 *
 * <p><b>Nothing checks which of the two an implementation chose.</b> The conformance kit asserts no exception types, on
 * purpose, so a signer that reports its custodian's outages as a cryptographic failure passes every test it has while
 * turning each of those outages into a permanent failure for its callers — a wait reported as a defect, and no way for
 * anything above to tell otherwise. That is worth a deliberate look at every {@code throw} in an implementation over a
 * network, an HSM or a KMS, because a signer written against an older reading of this contract keeps compiling
 * unchanged.
 *
 * <p><b>Implementations must be thread-safe.</b> One {@link PushSender} is shared across threads and
 * {@link PushSender#sendAsync} makes concurrent calls the normal case. This is not checkable by the conformance kit,
 * and the natural mistake is silent: {@code java.security.Signature} is not thread-safe, so one held in a field
 * corrupts signatures under concurrency instead of failing. Obtain per-call instances, or confine them to a thread.
 *
 * <p><b>The advertised public key is stable for a signer's lifetime.</b> VAPID's public key is the application server's
 * published identity: a browser subscription is bound to the {@code applicationServerKey} it was created with, and RFC
 * 8292 §4.2 entitles a push service to refuse a JWT whose key is not the one the subscription was created under. A
 * signer that swaps its advertised key under a live sender has therefore already broken every restricted subscription
 * taken out before the swap — whatever the library does with the values {@link #sign} and {@link #publicKey} return.
 * Rotation is a re-subscription event that produces a <em>new</em> signer, never a new answer from an existing one; the
 * shipped Vault signer says the same of itself. Like thread-safety, this cannot be checked from outside — the library
 * sees only what each call returns, and two equal answers say nothing about the next one — so it is stated as contract,
 * and the conformance kit pins only its two checkable moments: consecutive calls answering the same key, and one
 * signature verifying against the key advertised beside it.
 */
public interface VapidSigner {

    /**
     * Sign the JWT signing input (the ASCII {@code base64url(header) || "." || base64url(claims)}) with ES256,
     * returning the raw {@code r || s} pair (64 bytes for P-256) that JOSE expects — not a DER-encoded signature.
     *
     * <p>The returned array becomes the caller's: return freshly produced bytes, never a buffer the implementation
     * retains for reuse.
     *
     * <p>Failing is the contract, whichever of the two types carries it: returning a placeholder or a zero-filled array
     * would reach the push service as an opaque 401.
     *
     * @param signingInput the ASCII JWT signing input
     * @return the raw {@code r || s} ES256 signature (64 bytes for P-256), owned by the caller
     * @throws VapidSignerUnavailableException if the key custodian cannot sign now — nothing answered (a refused
     *     connection, a failed handshake, a timeout, an interrupted exchange), or it answered that it cannot serve this
     *     request at the moment (sealed, not initialized, still catching up, rate-limited). Carry the custodian's
     *     status and any moment it declared for coming back, where it declared either
     * @throws PushCryptoException if no signature can be produced for a reason that recurs — the key is unusable, the
     *     provider cannot do ES256, or the custodian answered about the request or about what this deployment
     *     configured: a key of a type VAPID cannot use, a token without the capability, a mount or key that is not
     *     there
     */
    byte[] sign(byte[] signingInput);

    /**
     * The application server's VAPID public key as a 65-byte X9.62 uncompressed point.
     *
     * <p>Every call must return a fresh array, never a reference to one the signer keeps — not even a shared buffer
     * refilled per call. The caller owns the returned bytes, and a signer handing out its internal state is silently
     * corrupted for every later send the moment anything writes into a returned array. Both shipped signers return a
     * {@code clone()}, and the {@code push2u-testkit} conformance kit checks it by array identity.
     *
     * @return the 65-byte uncompressed public key, a fresh copy owned by the caller
     * @throws VapidSignerUnavailableException if a custodian holding the key cannot serve it now — nothing answered, or
     *     it answered that it cannot serve this request at the moment
     * @throws PushCryptoException if the key cannot be produced for a reason that recurs — it is unusable, or the
     *     custodian answered about the request or about what this deployment configured: a token without the capability
     *     to read it, a mount or key that is not there, a key of a type VAPID cannot use
     */
    byte[] publicKey();

    /**
     * This signer's public key as the string a browser takes as the {@code applicationServerKey} option of
     * {@code pushManager.subscribe(...)} — the encoding of {@link #publicKey()}, and the same value this library puts
     * in the {@code k} parameter of every {@code Authorization} header it signs.
     *
     * <p>The encoding is base64 in the URL-safe alphabet of <a
     * href="https://datatracker.ietf.org/doc/html/rfc4648#section-5">RFC 4648 §5</a> — {@code '-'} and {@code '_'}
     * rather than {@code '+'} and {@code '/'} — and without padding, so no trailing {@code '='}. What is encoded is the
     * raw 65-byte X9.62 uncompressed point of <a href="https://datatracker.ietf.org/doc/html/rfc8292#section-3.2">RFC
     * 8292 §3.2</a>, which is what {@link #publicKey()} already returns — not a {@code SubjectPublicKeyInfo}, the
     * 91-byte wrapper {@code java.security.interfaces.ECPublicKey.getEncoded()} produces and the browser cannot read.
     * All three are contract rather than taste, and the same contract on both sides: {@code subscribe(...)} reads a
     * string {@code applicationServerKey} as the base64url of <a
     * href="https://datatracker.ietf.org/doc/html/rfc7515#section-2">RFC 7515 §2</a> — that alphabet with every
     * trailing {@code '='} omitted — and RFC 8292 §3.2 spells the {@code k} parameter the same way, so the standard
     * alphabet and the padding each break the browser's contract and the header's alike. What differs is how the
     * browser reports them: a string it will not decode rejects with an {@code InvalidCharacterError}, while a
     * {@code SubjectPublicKeyInfo} decodes cleanly and is then refused for not describing a valid point on P-256, with
     * an {@code InvalidAccessError} (steps 10.2 and 10.3 of <a
     * href="https://www.w3.org/TR/push-api/#subscribe-method">the Push API's {@code subscribe()}</a>) — either in a
     * browser console far from the code that made the string.
     *
     * <p>This is the value an application publishes to its frontend, and for a signer whose key lives in a remote
     * custodian it is the only place the string exists at all: nothing configured it, the signer read it from the
     * custodian, and asking the signer is the one way to be sure the advertised key is the key the next send will
     * carry.
     *
     * <p><b>What an override owes.</b> The default implementation is correct for every signer and exists so that
     * implementing this interface stays a matter of signing and naming a key. Overriding it is nevertheless legitimate
     * — a custodian whose API hands the key out already encoded need not decode it only to encode it again — and an
     * override must return <em>exactly</em> the unpadded URL-safe base64 of what {@link #publicKey()} returns, byte for
     * byte and character for character. A signer whose two answers drift publishes an {@code applicationServerKey} that
     * does not match the key it signs with, and every subscription taken against the published one is unusable from the
     * moment it is created, with nothing but a push service's rejection of the JWT to say so. The conformance kit
     * checks the two against each other; an implementation that does not run it is bound by this sentence alone. An
     * override signals a failure exactly as {@link #publicKey()} does — a custodian that cannot serve the key now with
     * {@link VapidSignerUnavailableException}, and everything that recurs with {@link PushCryptoException} — so that
     * one signer's two answers about one value do not disagree about what kind of failure it was.
     *
     * <p>That is what an override may throw, not a promise that nothing else leaves this method. A signer returning
     * {@code null} from {@link #publicKey()} gets a {@link NullPointerException}: the method is declared to return
     * bytes, so {@code null} is a broken type contract rather than a failed cryptographic operation, and it is reported
     * as the same defect a send reports it as.
     *
     * @return this signer's public key as unpadded URL-safe base64
     * @throws VapidSignerUnavailableException if a custodian holding the key cannot serve it now, exactly as
     *     {@link #publicKey()} raises it
     * @throws PushCryptoException if the key cannot be produced, exactly as {@link #publicKey()} raises it, or if what
     *     it returned is not the 65-byte uncompressed point the contract requires — the same check, the same type and
     *     the same wording a send applies to the same value, so this method's verdict on the key's <em>shape</em> is
     *     the send path's verdict on it: no key is published here that a send would refuse for its shape, and none is
     *     refused here that a send would carry. That agreement is about the key and nothing else — the signature, the
     *     endpoint policy and the transport are a send's own business, and a send can still fail on any of them
     * @throws NullPointerException if {@link #publicKey()} returns {@code null}
     */
    default String publicKeyBase64Url() {
        return Base64Url.encode(Vapid.requireUncompressedPoint(publicKey()));
    }
}
