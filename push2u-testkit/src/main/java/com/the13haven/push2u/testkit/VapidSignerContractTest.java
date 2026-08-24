/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import com.the13haven.push2u.VapidKeys;
import com.the13haven.push2u.VapidSigner;

/**
 * The conformance contract every {@link VapidSigner} must satisfy: the advertised public key is a 65-byte uncompressed
 * point that actually lies on NIST P-256 and arrives as a fresh copy on every call, its published base64url spelling is
 * the encoding of those same bytes, and signing produces a raw {@code r || s} ES256 signature (64 bytes) that verifies
 * against it. Each implementation extends this and supplies a configured signer via {@link #signer()} — the local
 * signer's unit test and every remote signer's integration test.
 *
 * <p>A last check has several threads signing at once, each over an input of its own, and requires every signature to
 * verify against the input its own call handed in. That one is a smoke check and is named one: it can catch a signer
 * sharing one signing object between callers, and a green run establishes nothing, since no schedule is forced.
 * Thread-safety remains a requirement {@link VapidSigner} states and this kit cannot prove.
 *
 * <p>Verification uses the JDK and the public {@link VapidSigner} surface, and beyond them one published call —
 * {@link VapidKeys#encodePublicKey} — which the encoding check below compares against because "must agree with the
 * library's own encoder" is the whole of what that check claims. Nothing package-private or otherwise internal is
 * reached, and the module carrying that call is one the kit already depends on. The rest of the contract is
 * self-contained. It also runs wherever the library itself runs: signature verification prefers the provider's native
 * {@code SHA256withECDSAinP1363Format} and, on a JVM whose providers register only the DER form {@code SHA256withECDSA}
 * (a FIPS-only platform — BouncyCastle FIPS registers no raw-format name), re-encodes the raw signature to minimal DER
 * and verifies through that name instead, the same resolution the library makes for its own signing. A kit that failed
 * with {@code NoSuchAlgorithmException} there would condemn a perfectly conforming signer for a platform reason.
 *
 * <p>Put {@code com.the13haven:push2u-testkit} on the test classpath and extend this class:
 *
 * <pre>{@code
 * class MySignerContractTest extends VapidSignerContractTest {
 *     @Override
 *     protected VapidSigner signer() {
 *         return new MySigner(...);
 *     }
 * }
 * }</pre>
 */
public abstract class VapidSignerContractTest {

    /** How many threads the concurrency check has inside {@code sign} at the same moment. */
    private static final int CONCURRENT_SIGNATURES = 8;

    /**
     * How long the concurrency check as a whole may wait for its signatures. One budget for the check rather than one
     * timeout per call: the calls are collected in a loop, so a per-call timeout would multiply by the number of
     * threads and a signer that never answers would hold the suite for that product instead of for this.
     */
    private static final int SIGNATURE_BUDGET_SECONDS = 30;

    /** For subclasses: the kit is extended, never instantiated on its own. */
    protected VapidSignerContractTest() {}

    /**
     * The signer under test.
     *
     * @return a fully configured {@link VapidSigner}
     */
    protected abstract VapidSigner signer();

    // UnitTestContainsTooManyAsserts: PMD analyses this module's main sources, and this is main
    // source that happens to be a test. Length and prefix are the two halves of one claim — "this
    // is an X9.62 uncompressed point" — and neither half means anything alone.
    @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
    @Test
    void publicKeyIsA65ByteUncompressedPoint() {
        byte[] publicKey = signer().publicKey();
        assertThat(publicKey).hasSize(65);
        assertThat(publicKey[0]).as("X9.62 uncompressed point prefix").isEqualTo((byte) 0x04);
    }

    /**
     * Length and prefix say nothing about the coordinates: the JCA imports a well-framed off-curve point without
     * complaint, and a signer advertising one would publish a VAPID key no push service can verify. So the contract
     * checks the point against P-256 itself — coordinates inside the prime field, then the curve equation {@code y² ≡
     * x³ + ax + b (mod p)}.
     */
    // UnitTestContainsTooManyAsserts: "the point is on P-256" is one claim, and its assertions are
    // a chain rather than a list — the length guard is what makes the coordinate split meaningful,
    // the field bounds are what make the curve equation meaningful. Split across methods they would
    // re-derive the same key and report one broken signer as several unrelated failures.
    @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
    @Test
    void publicKeyIsAPointOnTheP256Curve() throws GeneralSecurityException {
        byte[] publicKey = signer().publicKey();
        assertThat(publicKey).hasSize(65);

        BigInteger x = new BigInteger(1, Arrays.copyOfRange(publicKey, 1, 33));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(publicKey, 33, 65));
        EllipticCurve curve = p256Parameters().getCurve();
        BigInteger p = ((ECFieldFp) curve.getField()).getP();
        assertThat(x).as("x is inside the prime field (x < p)").isLessThan(p);
        assertThat(y).as("y is inside the prime field (y < p)").isLessThan(p);

        BigInteger left = y.multiply(y).mod(p);
        BigInteger right = x.multiply(x)
                .multiply(x)
                .add(curve.getA().multiply(x))
                .add(curve.getB())
                .mod(p);
        assertThat(left)
                .as("the advertised point satisfies the P-256 curve equation (y² = x³ + ax + b mod p)")
                .isEqualTo(right);
    }

    /**
     * {@link VapidSigner#publicKeyBase64Url()} is a {@code default} method, so it cannot be {@code final} and an
     * implementation may override it — legitimately, for a custodian that hands the key out already encoded. The one
     * behaviour it must never have is disagreeing with {@link VapidSigner#publicKey()}: a signer whose two answers
     * drift publishes an {@code applicationServerKey} that does not match the key it signs with, and every subscription
     * taken against the published one is unusable from the moment it is created — invisible until a push service starts
     * rejecting the JWT.
     *
     * <p>An equality against the library's encoder rather than a round trip back through a decoder: one comparison pins
     * the URL-safe alphabet, the absent padding and the canonical final character at once, and it leaves this kit no
     * decoder of its own to pick. Decoding and comparing bytes would admit a standard-alphabet override whenever its
     * characters happened to avoid {@code '+'} and {@code '/'}.
     */
    @Test
    void publicKeyBase64UrlIsTheEncodingOfTheAdvertisedPublicKey() {
        VapidSigner signer = signer();

        assertThat(signer.publicKeyBase64Url())
                .as("the published base64url must be the encoding of publicKey(), or the advertised key and the "
                        + "signing key have drifted apart")
                .isEqualTo(VapidKeys.encodePublicKey(signer.publicKey()));
    }

    /**
     * The signature is the raw {@code r || s} pair and it verifies against the key the signer advertises beside it.
     * That second half carries a contract obligation of its own: {@link VapidSigner} requires the advertised key to be
     * stable for the signer's lifetime — the key is the application server's published identity, and a subscription is
     * bound to the {@code applicationServerKey} it was created under — and pinning one signature against the key
     * advertised in the same breath is one of the two moments that sentence can be enforced at, the other being two
     * consecutive calls answering the same key, which {@link #publicKeyIsAFreshCopyOnEveryCall} carries. It is a
     * moment's agreement, not the lifetime's: a signer whose key drifts between test time and production, or hours into
     * a run, passes both and is bound by the contract sentence alone, because stability across a lifetime cannot be
     * checked from outside.
     */
    // UnitTestContainsTooManyAsserts: the signature's length and its verification are one claim —
    // raw r||s that verifies — and asserting the length first is what turns a DER signature into
    // "expected 64 bytes" instead of an opaque `verify() == false`.
    @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
    @Test
    void signatureIsRawRsThatVerifiesAgainstTheAdvertisedPublicKey() throws GeneralSecurityException {
        VapidSigner signer = signer();
        byte[] signingInput = "push2u VapidSigner conformance".getBytes(StandardCharsets.US_ASCII);

        byte[] signature = signer.sign(signingInput);
        assertThat(signature).as("raw r||s, not DER").hasSize(64);

        assertThat(verifyEs256(signer.publicKey(), signingInput, signature))
                .as("verifies against the advertised public key")
                .isTrue();
    }

    /**
     * A 65-byte array of the right shape can still be the signer's own state: {@link VapidSigner#publicKey()} requires
     * a fresh copy on every call, because a signer handing out one shared array is corrupted for every later signature
     * by the first caller that writes into the returned bytes — and nothing else would notice, the mutated key still
     * being a well-framed point.
     *
     * <p>Checked by identity rather than by mutating and looking: two distinct arrays cannot alias, so this catches
     * every single-buffer signer including one that refills its buffer per call, which a mutation probe would miss
     * because the refill overwrites the probe before the second call is compared. It also leaves a non-conforming
     * signer's key intact — a mutation probe would zero it, and the three checks above would then fail as well, for a
     * reason that has nothing to do with what they test. A signer rotating a pool of buffers defeats this and any other
     * check made from outside; the contract is what binds there.
     *
     * <p>The equality half of the assertion has grown a second job. {@link VapidSigner} requires the advertised key to
     * be stable for the signer's lifetime — the key is the application server's published identity, and every
     * subscription is bound to the {@code applicationServerKey} it was created under — and two consecutive calls
     * answering the same key is the checkable half of that requirement, enforced nowhere but here. The other half,
     * stability across a <em>lifetime</em>, stays uncheckable from outside — this method observes two adjacent calls,
     * not the hours between two sends — so the kit does not claim it: a signer whose key moves later is bound by the
     * contract sentence alone.
     */
    @Test
    void publicKeyIsAFreshCopyOnEveryCall() {
        VapidSigner signer = signer();

        byte[] first = signer.publicKey();
        byte[] second = signer.publicKey();

        assertThat(second)
                .as("publicKey() must hand out a fresh array, not a reference to the signer's own")
                .isNotSameAs(first)
                .as("and every call must still describe the same key")
                .isEqualTo(first);
    }

    /**
     * The same ownership rule on the other half of the SPI: {@link VapidSigner#sign(byte[])}'s bytes become the
     * caller's. Identity is all that can be checked here — ES256 is randomized, so two signatures over the same input
     * differ in content by design, and comparing them would pin nothing.
     */
    @Test
    void signHandsOutAFreshArrayOnEveryCall() {
        VapidSigner signer = signer();
        byte[] signingInput = "push2u VapidSigner conformance".getBytes(StandardCharsets.US_ASCII);

        byte[] first = signer.sign(signingInput);
        byte[] second = signer.sign(signingInput);

        assertThat(second)
                .as("sign() must hand out a fresh array, not a buffer the signer keeps reusing")
                .isNotSameAs(first);
    }

    /**
     * A smoke check, and named one. Several threads are inside {@code sign} at the same moment, each signing an input
     * of its own, and every signature that comes back must be the raw 64-byte {@code r || s} that verifies against that
     * call's own input, under the key read before any of them started. One {@link com.the13haven.push2u.PushSender} is
     * shared across threads and {@code sendAsync} makes concurrent signing ordinary, so a signer weaving one
     * {@code java.security.Signature} through several callers fails here rather than in production, where the same
     * defect arrives as an opaque 401 from a push service.
     *
     * <p><b>The inputs differ from one another, and that is the whole of what makes the defect catchable.</b> Under one
     * shared input, two interleaved {@code update} calls feed the same bytes twice and the signature that comes out can
     * still verify, so the check would pass over the very signer it is for. Under inputs that differ, an interleaving
     * signs something no caller asked for, and the result verifies against none of them. The signatures are never
     * compared with each other: ES256 is randomized, two signatures over one input differ by design, and
     * {@link #signHandsOutAFreshArrayOnEveryCall} says so already.
     *
     * <p>The key is read once, before the threads start, and read on one thread. This check is about signing; a
     * concurrent read of the key folded into it would leave a failure unable to say which of the two it was about, and
     * what the key owes is pinned by the checks above.
     *
     * <p><b>What it is worth is asymmetric, and saying so is part of the check.</b> Passing establishes nothing: no
     * schedule is forced, and a signer sharing one signing object can go a thousand runs without two threads colliding
     * inside it, so a green run is not a statement that this signer is thread-safe. Failing what it asserts is a real
     * defect every time — a thread-safe signer cannot hand back bytes that verify against nothing it was asked to sign,
     * however the threads interleave. Having no false positives is what earns the check its place; being no proof is
     * why it is not called one, and why the thread-safety requirement in {@link VapidSigner} stays a contract sentence
     * rather than something a suite can hold an implementation to.
     *
     * <p>A call answering {@link com.the13haven.push2u.VapidSignerUnavailableException} is counted as neither a pass
     * nor a failure. A custodian rate-limiting a burst is that type's own example of a signer that cannot sign
     * <em>now</em>, and a burst of concurrent calls is exactly what provokes it, so such a call carries no evidence
     * about interleaving. When fewer than two calls come back with a signature the check aborts rather than passing
     * green, since a result nothing exercised would misreport what this signer has been held to — and the threshold is
     * two rather than one because what this check reads is what overlapping calls do to each other, so a single
     * signature is as empty as none. A custodian with a quota admitting one call of the burst is what makes the
     * difference, and it is the ordinary shape of the remote custodian this contract is written for. The abort stands
     * down for a signature that came back and did not verify: bytes verifying against nothing the signer was asked to
     * sign are a verdict however few signatures there were — no quota explains them — and a check aborting over that
     * would turn its own strongest finding into a skip. No other kind of failure is read that way: the contract's other
     * checks sign one call at a time and require that to succeed, so anything else thrown out of a concurrent call is
     * reported as a failure. Which type it was is not part of the report — this contract asserts no exception types
     * anywhere.
     *
     * <p>The check stops waiting after a fixed budget, and what it does then is <em>abort</em> rather than fail. A
     * signer that never answers would otherwise hang the suite it was added to, which is how a contract gets deleted
     * from a build; but this seam promises nothing about how fast a custodian signs, so a call still running when the
     * budget runs out may equally be a correct signer being slow. Nothing here can tell those apart, and a failure
     * would be a verdict this check has not reached.
     */
    // UnitTestContainsTooManyAsserts: PMD counts the assumption beside the assertion, and the two
    // are not two claims but one claim and the case where the check has no claim to make — the
    // abort fires instead of the assertion rather than beside it, and only where the assertion had
    // nothing to say: a signature that came back and did not verify is a verdict however few of
    // them there were, so it is read first and the abort stands down for it.
    @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
    @Test
    void concurrentSignaturesEachVerifyAgainstTheirOwnInput() throws GeneralSecurityException, InterruptedException {
        VapidSigner signer = signer();
        byte[] advertisedKey = signer.publicKey();
        List<byte[]> inputs = new ArrayList<>(CONCURRENT_SIGNATURES);
        for (int call = 0; call < CONCURRENT_SIGNATURES; call++) {
            inputs.add(("push2u VapidSigner concurrent conformance " + call).getBytes(StandardCharsets.US_ASCII));
        }

        List<SignAttempt> attempts = SignAttempt.concurrently(signer, inputs, SIGNATURE_BUDGET_SECONDS);

        int unavailable = 0;
        int unverifiable = 0;
        for (int call = 0; call < CONCURRENT_SIGNATURES; call++) {
            Optional<byte[]> signature = attempts.get(call).signature();
            if (signature.isPresent()) {
                byte[] bytes = signature.get();
                if (bytes.length != 64 || !verifyEs256(advertisedKey, inputs.get(call), bytes)) {
                    unverifiable++;
                }
            } else {
                unavailable++;
            }
        }
        if (unverifiable == 0 && CONCURRENT_SIGNATURES - unavailable < 2) {
            Assumptions.abort(
                    "of the " + CONCURRENT_SIGNATURES + " concurrent calls, " + unavailable + " reported that "
                            + "the key custodian cannot sign now, which leaves fewer than two signatures for this check "
                            + "to have read anything from — so it reached no verdict. That answer is legitimate — a "
                            + "custodian rate-limiting a burst is what it is for — but a green result here would say "
                            + "this signer had been held to something it never was. One signature is no less empty "
                            + "than none: what this check reads is what callers overlapping each other do, and a lone "
                            + "call overlaps nothing. If the burst is what provoked the refusals, the contract's "
                            + "one-call-at-a-time checks still stand on their own.");
        }

        assertThat(unverifiable)
                .as("every concurrent signature must be the raw 64-byte r||s that verifies against the input its own "
                        + "call handed in, under the key read before the threads started. The signatures are not "
                        + "compared with one another — ES256 is randomized — so each is checked against its own input "
                        + "alone, and a signer weaving one signing object through several callers produces bytes that "
                        + "verify against none of them. Of " + CONCURRENT_SIGNATURES + " calls, " + unverifiable
                        + " came back with such bytes and " + unavailable + " reported the custodian unable to sign "
                        + "now, which is counted as no evidence either way.")
                .isZero();
    }

    /**
     * ES256 verification with the same provider resolution the library makes for its own signing: prefer the native
     * raw-signature form {@code SHA256withECDSAinP1363Format}; where a provider registers only DER-form ECDSA
     * (BouncyCastle FIPS), fall back to {@code SHA256withECDSA} over the raw {@code r || s} re-encoded to minimal DER.
     */
    private static boolean verifyEs256(byte[] uncompressedPublicKey, byte[] signingInput, byte[] rawSignature)
            throws GeneralSecurityException {
        Signature p1363Verifier;
        try {
            p1363Verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
        } catch (NoSuchAlgorithmException p1363NotRegistered) {
            return verifyEs256ViaDerFallback(uncompressedPublicKey, signingInput, rawSignature);
        }
        return verify(p1363Verifier, uncompressedPublicKey, signingInput, rawSignature);
    }

    /**
     * The DER-only branch of {@link #verifyEs256(byte[], byte[], byte[])}, callable on its own: CI has no JVM whose
     * providers lack the P1363 name, so {@code VapidSignerContractSelfTest} drives this path directly instead of hoping
     * some platform reaches it.
     */
    static boolean verifyEs256ViaDerFallback(byte[] uncompressedPublicKey, byte[] signingInput, byte[] rawSignature)
            throws GeneralSecurityException {
        return verify(
                Signature.getInstance("SHA256withECDSA"),
                uncompressedPublicKey,
                signingInput,
                toMinimalDer(rawSignature));
    }

    private static boolean verify(
            Signature verifier, byte[] uncompressedPublicKey, byte[] signingInput, byte[] wireSignature)
            throws GeneralSecurityException {
        verifier.initVerify(decodeP256PublicKey(uncompressedPublicKey));
        verifier.update(signingInput);
        try {
            return verifier.verify(wireSignature);
        } catch (SignatureException invalidSignature) {
            // Some providers report an unparseable or out-of-range signature by throwing rather
            // than returning false. For a conformance check both are the same answer: this byte
            // string is not a valid signature for this key and input.
            return false;
        }
    }

    /**
     * Re-encodes a raw 64-byte {@code r || s} signature as the minimal DER {@code ECDSA-Sig-Value} — {@code SEQUENCE {
     * INTEGER r, INTEGER s }} — that the DER-form verifier consumes. A representation change only: the ECDSA math stays
     * inside the provider. Each INTEGER's content octets are the value's minimal two's-complement encoding, which for a
     * non-negative value is exactly what {@link BigInteger#toByteArray()} produces: leading zero bytes stripped, one
     * {@code 0x00} sign byte exactly when the first magnitude byte has its high bit set, a single {@code 0x00} for
     * zero. A zero {@code r} or {@code s} is not a valid ECDSA signature, but rejecting it is the verifier's job — it
     * can never verify — not the re-encoder's, whose output must simply stay well-formed DER.
     */
    static byte[] toMinimalDer(byte[] rawRs) {
        byte[] r = new BigInteger(1, Arrays.copyOfRange(rawRs, 0, 32)).toByteArray();
        byte[] s = new BigInteger(1, Arrays.copyOfRange(rawRs, 32, 64)).toByteArray();
        // Worst case 2 + 35 + 35 = 72 bytes: the SEQUENCE body always fits a short-form length.
        byte[] der = new byte[2 + 2 + r.length + 2 + s.length];
        der[0] = 0x30; // SEQUENCE
        der[1] = (byte) (der.length - 2);
        der[2] = 0x02; // INTEGER r
        der[3] = (byte) r.length;
        System.arraycopy(r, 0, der, 4, r.length);
        int sTag = 4 + r.length;
        der[sTag] = 0x02; // INTEGER s
        der[sTag + 1] = (byte) s.length;
        System.arraycopy(s, 0, der, sTag + 2, s.length);
        return der;
    }

    private static ECPublicKey decodeP256PublicKey(byte[] uncompressed) throws GeneralSecurityException {
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(uncompressed, 1, 33));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(uncompressed, 33, 65));
        return (ECPublicKey)
                KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), p256Parameters()));
    }

    /**
     * The canonical {@code secp256r1} (NIST P-256) domain parameters, from the platform JCE providers.
     *
     * <p>{@code "EC"} here and in {@link #decodeP256PublicKey(byte[])} needs no FIPS fallback, unlike the signature
     * name: the P1363/DER split is a signature-format concern with no {@code KeyFactory} or {@code AlgorithmParameters}
     * counterpart, {@code "EC"} is the single standard JCA name for both services, and BouncyCastle FIPS registers both
     * — the core's BC-FIPS suite resolves keys and domain parameters through these very names against that provider.
     */
    private static ECParameterSpec p256Parameters() throws GeneralSecurityException {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        return parameters.getParameterSpec(ECParameterSpec.class);
    }
}
