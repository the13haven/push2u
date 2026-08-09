# ADR-018 — The encoded VAPID public key is part of the signer contract

**Status:** Proposed

Every Web Push deployment hands its VAPID public key to the browser as the `applicationServerKey`
option of `pushManager.subscribe(...)`: the 65-byte X9.62 uncompressed P-256 point
([RFC 8292 §3.2](https://datatracker.ietf.org/doc/html/rfc8292#section-3.2)) spelled as base64url
with the URL-safe alphabet and no padding
([RFC 4648 §5](https://datatracker.ietf.org/doc/html/rfc4648#section-5), the JOSE form of
[RFC 7515 §2](https://datatracker.ietf.org/doc/html/rfc7515#section-2)). The library consumes that
spelling — `VapidKeys.fromBase64`, `Subscription.fromBase64` — and produces it on every send: the
key itself as the `k` parameter of the `Authorization` header, and the same alphabet as the JOSE
encoding of all three JWT segments. It has never published it: the encoder is a package-private
`Base64Url`, and `VapidSigner.publicKey()` hands back bytes. Reported as
https://github.com/the13haven/push2u/issues/95, from a deployment signing through Vault Transit that
needs a `GET …/web-push/public-key` for its frontend.

Where the string exists, by mode:

| Mode | Where the base64url string lives |
|---|---|
| Local keys (`push2u.vapid.public-key`) | in configuration — the operator typed it |
| Vault, explicit key (`push2u.signer.vault.public-key` set) | in configuration |
| Vault, fetched key (that property unset — the mode the Vault guide calls the recommended one) | **only as runtime bytes** |
| Any future signer with remote key custody | **only as runtime bytes** |

There is no fifth row: `LocalEcVapidSigner` takes a ready `VapidKeys`, and the core has no runtime
VAPID key generation at all — `EcKeys.generateP256` serves the per-send ephemeral ECDH key, not
VAPID. The fourth row is not hypothetical either. ADR-010 exists so that key custody can move to a
KMS, an HSM or anything else that will not hand a scalar to a library, and a custodian that owns the
key owns its public half too, so every one of them arrives with this same hole. Vault is the first
case, not a special one.

The library returns the string in *no* mode. `fromBase64` decodes and does not retain what it was
given; `publicKey()` returns bytes on both shipped signers. In the top two rows the value is
recoverable only from configuration, which under Spring means reading `push2u.vapid.public-key` or
`push2u.signer.vault.public-key` back out of a namespace the application does not own — both
`Push2uProperties` and `VaultSignerProperties` are registered beans, so the route exists — and
branching on which of the two starters won, which is knowledge duplicated out of the starters' own
ordering rules. In the bottom two rows that route has nothing to read: the fetched mode deliberately
has no `public-key` property, because the Transit key is the single source of truth and the signer
reads its own key at startup. That is what keeps the advertised key from drifting away from the
signing key, and it is why the deployment following the strongest recommendation in the
documentation is the one with no string anywhere.

So what a consumer writes today is `Base64.getUrlEncoder().withoutPadding().encodeToString(...)`
over `publicKey()`, and three details in it are load-bearing while none of them is stated where that
consumer is looking: the URL-safe alphabet, the absence of padding, and the fact that these bytes
are already the raw point the browser wants rather than a `SubjectPublicKeyInfo` — the encoding
`ECPublicKey.getEncoded()` returns and the one the send path's own rejection message already
anticipates by name. Each mistake fails at `subscribe()` in the browser, far from the code that
produced the string, and the library applies all three correctly to the same value a few lines
inside itself.

**Decision.** Two public members and one conformance assertion.

```java
// VapidKeys — beside fromBase64, where the consumer looking for this value already is
public static String encodePublicKey(byte[] uncompressedPublicKey);

// VapidSigner — the half that carries the feature
default String publicKeyBase64Url();
```

- **The `default` method is the load-bearing half, and not because the static cannot produce the
  value.** `VapidKeys.encodePublicKey(signer.publicKey())` is one call in every mode too, so the
  claim is not about capability. What the static alone cannot do is own the operation: the value a
  consumer needs is *this signer's published key*, and only a member of the SPI can carry that
  contract — including its failure mode (below), the sentence saying what the value is for, and the
  fact of being findable on the type the consumer holds. With the static alone, the composition of
  "ask the signer" and "encode correctly" stays the consumer's to assemble, which is the assembly
  the report is about.
- **It is a `default` method and never a new abstract one.** ADR-010's premise is that implementing
  this SPI stays cheap — a custodian that can sign and name its key should not have to learn an
  encoding to satisfy the interface — and a `default` adds nothing for an implementor to write. The
  compatibility facts point the same way and are not what decides it: `VapidSigner` shipped in
  `0.1.0`, so an abstract addition is a compile error for every implementation outside this
  repository and an `AbstractMethodError` for every one already compiled. That is a cost worth
  paying for something, and this is not it; `0.x` is the declared window for revising shapes, so the
  argument rests on ADR-010 rather than on compatibility being absolute. A `default` is not free
  either, and the residue is named rather than glossed: an implementation outside this repository
  that already carries a `publicKeyBase64Url()` of its own keeps compiling only where the signature
  agrees — a different return type clashes, and so does a second interface contributing a competing
  `default` — but that is a name collision resolved at the implementor's keyboard, not a contract
  every implementor has to satisfy.
- **Each of the two members applies the check that already belongs to its own position, and the two
  positions are not the same one.** The static's argument arrives from outside with nothing behind
  it: no constructor has seen those bytes, no signer vouched for them, and this call is the first
  and only boundary they cross. That is exactly where `VapidKeys`' constructor already stands, and
  what it applies to this very value is `P256PublicKeys.requireOnCurve` — so the full check is what
  the static runs too. A static on `VapidKeys` accepting what a `VapidKeys` refuses would be one
  class holding one kind of value to two standards, and the value it would let through is one the
  browser rejects anyway: `subscribe()` ensures the `applicationServerKey` "describes a valid point
  on the P-256 curve" and rejects with `InvalidAccessError` when it does not
  ([Push API §7.1](https://www.w3.org/TR/push-api/#subscribe-method)). So the choice is not whether
  an off-curve key is refused but where — here, at the call that produced the string, or in a
  browser console at the far end of the loop this decision exists to shorten.
- **The `default` method applies the structural check instead, and that is not a weaker version of
  the same decision.** Its value is not entering the library — it is the signer's own output, and
  the SPI already requires that output to be a point on P-256: both shipped signers refuse an
  off-curve key in their constructors, and `push2u-testkit` fails any signer whose key is off the
  curve before it is ever asked to publish one. What is left for runtime is the agreement with
  delivery: **the publication path is as strict as the send it precedes, and no stricter.** What the
  send path applies to the *VAPID* key is the structural check alone (the full curve check it runs
  per send is on the subscription's `p256dh`), so a signer whose key this method publishes is a
  signer whose key the next send carries. An encoder refusing what delivery would carry is a second,
  later opinion about a key the library was already handed.
- **So the two members also fail with different exception types, for the same reason.** The static's
  argument is the caller's own byte array, so a malformed one is an ordinary argument failure:
  `IllegalArgumentException`, from `requireOnCurve`, which is already public, already exported and
  already the library's answer for a caller-supplied key that is not a P-256 point. The `default`
  method's value is the *signer's* output, which the SPI holds to a different standard: a signer
  returning the wrong shape raises `PushCryptoException` naming
  what it returned, and the message the send path produces for it names the `SubjectPublicKeyInfo`
  case specifically, which is the realistic mistake in exactly this call. So the `default` method
  applies **the send path's own check**, not the static's — that check becomes package-private and
  shared instead of staying private to the JWT builder — and a consumer meeting a broken signer
  through its `/public-key` endpoint gets the same type *and* the same wording delivery would give
  them. This is a decision about where the second structural check lives rather than a new one being
  introduced: `main` already carries both spellings, and what changes is that the send path's stops
  having a single caller. A `PushCryptoException` raised by `publicKey()` itself — a remote
  custodian that is unreachable or refuses to publish the key — propagates untouched; it is already
  the right type and the right message.
- **The name says the encoding, not the caller.** `publicKeyBase64Url()` sits beside `publicKey()`
  as a second representation of one value. `applicationServerKey()` was the alternative and is
  rejected: the same string is the VAPID `k` parameter of the `Authorization` header — a server-side
  protocol element RFC 8292 §3.2 keeps beside the JWT `t` carries rather than inside it — as much as
  it is the browser's `applicationServerKey`, and naming a member of a server-side SPI after one
  browser API's option ties the library's vocabulary to a name it does not own.
- **The static lives on `VapidKeys`.** Not on `P256PublicKeys`, whose subject is validation of the
  wire form for both the VAPID key and a subscription's `p256dh`, and where an encoder would invite
  encoding the latter, which nothing needs. Not as a published `Base64Url`, which answers "how do I
  base64url" — a question `java.util.Base64` already answers — rather than "what do I give the
  browser", and which would freeze a general codec the library currently keeps free to move.
  `VapidKeys` is where `fromBase64` is, and that is where a consumer looks.
- **There is no inverse of `fromBase64` at the pair level, and there will not be.** The private
  scalar gets no encoder: handing the secret back as a string is the one direction this library does
  not provide, and a pair-level `toBase64()` would have to either include it or explain its absence.
  Only the public half is published, because only the public half is meant to be.
- **The Javadoc is half the value, and it carries the override contract as well as the recipe.** The
  first sentence of both members says that this is what goes into `applicationServerKey`, and the
  prose names the URL-safe alphabet without padding (RFC 4648 §5) and the fact that the bytes are
  the raw X9.62 point rather than an SPKI encoding. `VapidSigner`'s own Javadoc additionally states
  what an override owes: exactly the unpadded URL-safe base64 of what `publicKey()` returns, and
  `PushCryptoException` as the type it signals a failure with — the one `publicKey()` is already
  documented to raise, so an override inventing a second type is what the sentence forbids. That is
  what an override may throw, not a promise that nothing else can leave the method: `publicKey()` is
  declared under JSpecify's `@NullMarked`, so a signer answering `null` has broken the type contract
  rather than failed at a cryptographic operation, and it gets the `NullPointerException` the send
  path gives it today. The Javadoc states that rather than converting it, because converting would
  hand one broken signer two different failures depending on which caller reached it first — the
  split the exception-type point above exists to prevent. Both are pinned by a test: the
  `PushCryptoException` for a key of the wrong shape, the `NullPointerException` for a `null` one.
  The kit below enforces the agreement with `publicKey()`, but an implementor outside this
  repository may never extend the kit, and the interface is the only normative text they read.
  Published sources may not point at a Markdown file or an ADR, so all of it is stated in the text
  itself — which is what the report asked for in the first place.
- **`push2u-testkit`'s `VapidSignerContractTest` gains one assertion**, and shipping without it is
  not an option. A `default` method cannot be `final`, so `publicKeyBase64Url()` is overridable —
  legitimately so, for a custodian whose API hands out the key already encoded — and the one
  behaviour it must never have is disagreeing with `publicKey()`. A signer that drifts publishes an
  `applicationServerKey` that does not match the key it signs with: exactly the failure the fetched
  mode's atomic (version, public key) read exists to prevent, reintroduced one method along, and
  invisible until a push service rejects the JWT for every subscription taken since. The assertion
  is an equality against `VapidKeys.encodePublicKey(signer.publicKey())` rather than a round trip
  back through a decoder: one comparison pins the alphabet, the padding and the canonical final
  character at once, and it leaves the kit no decoder of its own to choose — decoding and comparing
  admits a standard-alphabet override whenever its characters happen to avoid `+` and `/`. That
  makes the kit call `VapidKeys` for the first time, and its class Javadoc — which promises
  verification through the JDK and the public `VapidSigner` surface alone, self-contained and with
  no push2u-internal dependency — is amended to say so rather than left standing as a sentence the
  new assertion falsifies in published Javadoc. Nothing the promise was protecting is given up:
  `VapidKeys` is published API of a module the kit already depends on, nothing package-private is
  reached, and the platform portability the surrounding sentences are about belongs to the signature
  verification, which is untouched. The comparison has to be against the library's own encoder,
  because "must not disagree with the library" is the whole claim. It can only fail for a signer
  that overrode the method, which is precisely the case it exists for.
- **`README.md` and `docs/VAULT.md` are part of the change, not a follow-up.** This report is a
  discoverability complaint before it is an API complaint: the three details cost the reporter time
  because nothing said them where they were looking, and a method nobody finds closes the mechanism
  while leaving the report standing. README's VAPID section states that the public half is what the
  browser needs as `applicationServerKey` and then stops; that sentence is where the two new members
  belong, for the local mode as much as any other. `docs/VAULT.md`'s fetched-key section is the
  second place, because that is the mode with no configured string to serve and the one the report
  came from. Shipping the members without both is not a smaller version of this decision — it is the
  half that does not answer the issue.
- **`docs/VAPID.md` keeps hand-rolling the encoder**, and this is recorded because it looks like a
  cleanup somebody will attempt once the method exists. That block runs in a bare `jshell` with no
  push2u on the classpath, for someone who has not wired the library up yet, and the test suite
  executes it out of the file. What must hold is that the recipe's encoder and the new members agree
  — URL-safe alphabet, no padding — or the guide emits a value the library will refuse.

**What this decision does not settle.** Whether a starter should *serve* the encoded value — as a
bean, or as an endpoint — is a separate question with its own surface, and it is deliberately left
open rather than folded in here: this decision makes the value reachable in one call from the type
every consumer already holds, and publishing it over HTTP is the application's route, its
authentication and its caching. Nothing here forecloses a later decision to add one.

Rejected alternatives:

- **The static alone**, which is what the report proposed first. It produces the right string, and
  it leaves the SPI silent about the one value every consumer of it has to publish: no failure
  contract for a signer's own bytes, no sentence on the type the consumer holds saying what the
  value is for, and a two-type composition where the need is one call.
- **An abstract `publicKeyBase64Url()` on `VapidSigner`**, above: work handed to every implementor
  for a value the interface can derive itself, and a break of every implementation compiled against
  `0.1.0` on top of it.
- **An instance `VapidKeys.publicKeyBase64Url()`.** A third spelling of one value, for the mode that
  is least short of it — a local-keys deployment holds a signer like every other, and the static
  covers the case where it holds only the pair.
- **A padding switch, or any configurability of the alphabet.** RFC 7515's base64url is unpadded and
  the browser side agrees; a knob here would exist only to produce values that fail in the field.
- **An on-curve check inside the `default` method** — the full check on the *signer's* answer,
  applied at publication time to a key the very next send would carry on its structural check alone.
  It would refuse in a different exception type from the one delivery raises for the same signer,
  and the case it would catch is a signer whose key is off the curve: unbuildable in both shipped
  signers and a conformance-kit failure for any other, so it is a defect found at construction and
  in the test suite rather than one discovered by an encoder. The static is the opposite position
  and gets the full check, above.
- **A structural-only check inside the static.** It would let `VapidKeys` encode a value
  `VapidKeys`' own constructor refuses, and hand the browser a string `subscribe()` rejects for
  being off the curve — the failure at the far end of the loop this decision exists to shorten.
- **Publishing the configured string from the starters** — a bean carrying whichever of
  `push2u.vapid.public-key` and `push2u.signer.vault.public-key` was set. It re-creates in the
  library the two-branch knowledge the consumer was rejected for having, and it has nothing to
  return in the fetched mode, which is the mode the report is about.

This rules out an abstract addition to `VapidSigner`; a general-purpose base64url codec published
from the core; any encoder for the private scalar; a padded or configurable encoding; an on-curve
check inside the `default` method and a merely structural one inside the static; and a
`docs/VAPID.md` recipe that depends on the library it generates keys for. ADR-002 is untouched —
`java.util.Base64` is `java.base`, and the core gains no dependency; ADR-005 and ADR-010 are
untouched and not superseded — no seam is added, and the three SPIs stay three. No new package, so
no `exports` line moves, and no provider is involved, so the BC-FIPS source set is not affected.
