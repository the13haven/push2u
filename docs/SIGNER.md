# Writing a VapidSigner

`VapidSigner` is the key-custody seam: an implementation over an HSM, a KMS or a remote custodian
answers with a raw 64-byte `r || s` ES256 signature and the 65-byte uncompressed P-256 point, and
the private key itself never reaches the library. This is the reference for writing one —
[`README.md` → Writing a VapidSigner](../README.md#writing-a-vapidsigner) carries the conformance
kit's dependency coordinate, and [`README.md` → JCE provider
selection](../README.md#jce-provider-selection) the provider question a signer that signs locally
answers instead.

The document is what the contract requires and how a violation of it surfaces: the two checks every
signature and key passes on its way into a send, the split between the two failure types an
implementation is most likely to get wrong, the thread safety a shared sender takes for granted,
the one thing that may never change about a signer, and the kit that holds what can be held in your
own test suite.

## The two shape checks

Whatever the signer, its two outputs are checked wherever a new one enters a send: the signature
must be the raw 64-byte `r || s` pair (RFC 7518 §3.4) and the key the 65-byte uncompressed point
(RFC 8292 §3.2). Under the default token reuse that is every send that signs — a reused
`Authorization` value was checked when it was signed, and `sign` is not called for it again — so a
misencoded signer is still caught the first time it is asked, on the send that asks. A violation
raises `PushCryptoException` saying what was returned; otherwise it would surface as an opaque
`401`/`403`, with nothing pointing at the signer. If your implementation signs through JCA, note
that `SHA256withECDSA` produces DER: ask for `SHA256withECDSAinP1363Format` or convert before
returning, and the rejection message will say so if you forget.

## The two failure types

**A signer failure leaves in one of two types, and this is the split an implementation is most
likely to get wrong.** A key custodian that cannot sign *now* — unreachable, timed out, sealed, not
yet initialized, still catching up, rate-limiting — raises `VapidSignerUnavailableException`, from
`sign` and `publicKey` alike, carrying the status the custodian answered with and any moment it
declared for coming back where it declared either. That is what the sender converts into the
`SignerUnavailable` outcome. Everything else raises `PushCryptoException`: a defect, a substrate
that cannot perform the cryptography, an answer no custodian could have meant, and a
misconfiguration that answers the same way until a person edits it. Nothing checks which one an
implementation chose — the conformance kit asserts no exception types on purpose — so a signer that
reports its custodian's outages as a cryptographic failure passes every test it has while turning
each of those outages into a permanent failure for its callers. **If you wrote a signer over a
network, an HSM or a KMS against an older reading of this contract, it keeps compiling unchanged**;
every `throw` in it is worth a look.

## The signer must be thread-safe

**Implementations must be thread-safe.** One `PushSender` is shared across threads and
`sendAsync` makes concurrent calls the normal case. This is not checkable by the conformance kit,
and the natural mistake is silent: `java.security.Signature` is not thread-safe, so one held in a
field corrupts signatures under concurrency instead of failing. Obtain per-call instances, or
confine them to a thread.

## The advertised key never changes

**The key a signer advertises must stay the same for that signer's lifetime.** VAPID's public key
is your application server's published identity: a browser subscription is bound to the
`applicationServerKey` it was created with, and RFC 8292 §4.2 lets a push service refuse a JWT
whose key is not the one that subscription was created under. So a signer that starts answering
`publicKey()` differently has already broken every restricted subscription taken out before the
change — rotation is a re-subscription event that produces a *new* signer, not a new answer from
the existing one. The library cannot check this from outside, since two equal answers say nothing
about the next one, and states it as contract instead.

## The conformance kit

The two shape checks above are what your signer meets on the sends that reach it; `push2u-testkit`
is how it finds out in its own test suite instead. It is a test-scoped artifact holding one
abstract JUnit Jupiter class — [`README.md` → Writing a
VapidSigner](../README.md#writing-a-vapidsigner) carries its coordinate:

```java
class MySignerContractTest extends VapidSignerContractTest {

    @Override
    protected VapidSigner signer() {
        return new MySigner(...);
    }
}
```

Six checks run: the advertised public key is 65 bytes with the X9.62 uncompressed prefix, its
coordinates really do satisfy the P-256 curve equation (a well-framed off-curve point is imported
by the JCA without complaint), `publicKeyBase64Url()` is exactly the unpadded URL-safe base64 of
those same bytes, `publicKey()` and `sign()` each hand out a fresh array rather than
one the signer keeps — two successive calls must not return the same object — and a signature is
the raw 64-byte `r || s` that verifies against that key. Verification uses the JDK alone and runs
on a FIPS-only JVM: the kit prefers
`SHA256withECDSAinP1363Format` and, where a provider registers only DER-form `SHA256withECDSA`
(BC-FIPS), re-encodes the raw signature to minimal DER and verifies through that name — [the same
fallback the library itself makes](../README.md#jce-provider-selection). It is the same contract
`LocalEcVapidSigner` and the Vault Transit signer are held to. The kit brings JUnit Jupiter and
AssertJ with it, which is why it is a separate artifact and never a dependency of `push2u-core`.
