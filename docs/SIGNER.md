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
`sendAsync` makes concurrent calls the normal case. The natural mistake is silent:
`java.security.Signature` is not thread-safe, so one held in a field corrupts signatures under
concurrency instead of failing. Obtain per-call instances, or confine them to a thread.

The conformance kit puts several threads inside `sign` at once and requires each signature to verify
against the input its own call handed in. That is a smoke check and the kit calls it one: it catches
a shared signing object when the threads happen to collide inside it, and establishes nothing when
they do not, because no schedule is forced. A green run says your signer was not caught — never that
it is safe. The requirement is the sentence above; the check is what a suite can do under it.

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
is how it finds out in its own test suite instead. The contract is one abstract JUnit Jupiter class
in that test-scoped artifact — [`README.md` → Writing a
VapidSigner](../README.md#writing-a-vapidsigner) carries its coordinate:

```java
class MySignerContractTest extends VapidSignerContractTest {

    @Override
    protected VapidSigner signer() {
        return new MySigner(...);
    }
}
```

Seven checks run: the advertised public key is 65 bytes with the X9.62 uncompressed prefix, its
coordinates really do satisfy the P-256 curve equation (a well-framed off-curve point is imported
by the JCA without complaint), `publicKeyBase64Url()` is exactly the unpadded URL-safe base64 of
those same bytes, `publicKey()` and `sign()` each hand out a fresh array rather than
one the signer keeps — two successive calls must not return the same object — a signature is
the raw 64-byte `r || s` that verifies against that key, and several threads signing at once each
come back with a signature that verifies against the input that call handed in.

That last one is the concurrency smoke check described above, and three of its choices are worth
knowing before you read a failure. Every caller signs a *different* input, which is what makes the
defect catchable at all: under one shared input, two interleaved `update` calls feed the same bytes
twice and the signature can still verify. The signatures are never compared with one another — ES256
is randomized. And the key is read once, on one thread, before the threads start, so a failure is
about signing and not about a race on the key. A call answering `VapidSignerUnavailableException`
is counted as neither pass nor failure — a custodian rate-limiting a burst is exactly what that type
is for, and a concurrent burst is what provokes it — and if fewer than two calls come back with a
signature, the check aborts rather than reporting a green it did not earn. Two rather than one,
because what the check reads is what overlapping calls do to each other and a lone signature
overlaps nothing: a quota admitting a single call of the burst would otherwise pass having observed
no concurrency at all, which is the shape a remote custodian takes and not a corner case. One thing
outranks that abort — a signature that came back and does not verify, which is a verdict however few
of them there were, since no quota explains bytes that verify against nothing the signer was asked
to sign. So a metered custodian may report this check as skipped, and that is the honest answer
rather than a green one. It also stops waiting after a budget and aborts then too: the seam promises
nothing about how fast a custodian signs, so a slow call is not a verdict.

Verification uses the JDK alone and runs
on a FIPS-only JVM: the kit prefers
`SHA256withECDSAinP1363Format` and, where a provider registers only DER-form `SHA256withECDSA`
(BC-FIPS), re-encodes the raw signature to minimal DER and verifies through that name — [the same
fallback the library itself makes](../README.md#jce-provider-selection). It is the same contract
`LocalEcVapidSigner` and the Vault Transit signer are held to. The kit brings JUnit Jupiter and
AssertJ with it, which is why it is a separate artifact and never a dependency of `push2u-core`.

The same artifact carries a second half, for the other audience: fixtures producing a VAPID pair
and a browser subscription valid against the library's current input contracts, and a scripted,
recording `PushHttpClient` for the tests an application writes around its own sending code.
[`TESTKIT.md`](TESTKIT.md) is its reference; nothing there is needed to write a signer, and a
signer's own test suite may still find the pair fixture useful for the sends it drives end to end.
