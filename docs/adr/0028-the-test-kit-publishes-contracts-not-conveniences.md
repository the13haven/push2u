# ADR-028 — The test kit publishes contracts, not conveniences

**Status:** Proposed

Reported as https://github.com/the13haven/push2u/issues/92, by a consumer whose controller tests
broke on an upgrade that tightened the library's own validation.

`push2u-testkit` exists because one source set cannot be half published:
[ADR-014](0014-jpms-explicit-and-automatic-modules.md) put the conformance kit in its own artifact
and its own package so that the core's fixtures — the mock push receiver, the self-signed loopback
certificate, the RFC vectors — could stay in this build while the signer contract went out whole.
That split was right, and it left the kit holding exactly one thing: `VapidSignerContractTest`, the
executable statement of what a `VapidSigner` owes. It serves the smallest audience this library has.

The audience that writes tests against push2u every week is the one that only sends. It gets
nothing, and the report names what that costs. A consumer assembling a `PushSender` needs a VAPID
pair the builder will accept, a `Subscription` whose three components all pass, and a stub
transport; all three were hand-rolled, the pair as a base64 literal duplicated across four test
classes on both sides of a module boundary. When the library tightened the endpoint to strict
`https` and enforced the key lengths at the API boundary, placeholder key material that had been
fine — nothing decoded it before — stopped being fine, and five of six tests in one class broke on
an upgrade whose release notes could not have warned about them. The values were never wrong on
purpose. They were written against a contract, and the contract moved.

The same duplication is in this repository, and counting it precisely is what makes it evidence
rather than a slogan. A fixed-width writer for a 32-byte value is copied into eleven test sources,
but most of those encode the coordinates of a public point; **five encode a private scalar, and all
five are in the two Spring starter modules**, where a valid pair exists only so that
`push2u.vapid.public-key` and `.private-key` have something to bind and the context can come up.
That is incidental setup, and it is what the fixture below replaces. The other six are a different thing
and stay: in `P256PublicKeysTest` and the Vault module's key-validation tests the hand-assembly *is*
the subject, and a fixture there would test the fixture.

Those two starter modules do not depend on `push2u-testkit` today, so putting the fixture to work
inside this build is a step of the implementation rather than a consequence of it — the dependency
is added where the setup is replaced, and nowhere else.

**The question this record answers is not which helpers are convenient.** It is which knowledge
belongs to the library and therefore has to travel with it. A consumer can write a stub transport
answering one constant status in five lines and will get it right. A consumer cannot know what the
current `Subscription` contract accepts, and cannot find out except by upgrading and watching what
breaks.

## The decision

**The kit publishes executable contracts and coherent values of the library's public input
contracts, plus correct fakes of seams that already exist. It creates no seam, hides no decision the
application owns, and publishes none of the library's own test infrastructure.**

The first version adds four types beside the existing contract, and nothing else:

```java
public final class VapidKeyPairFixture {
    public static VapidKeyPairFixture generate();
    public VapidKeys vapidKeys();
    public String publicKeyBase64Url();
    public String privateKeyBase64Url();
}

public final class SubscriptionFixture {
    public static SubscriptionFixture at(URI endpoint);
    public Subscription subscription();
    public String endpoint();
    public String p256dhBase64Url();
    public String authBase64Url();
}

public final class ScriptedPushHttpClient implements PushHttpClient {
    public static ScriptedPushHttpClient respondingWith(int firstStatus, int... followingStatuses);
    public static ScriptedPushHttpClient respondingWith(PushResponse first, PushResponse... following);
    public static ScriptedPushHttpClient failingWith(PushDeliveryException failure);
    public List<SentPush> sent();
}

public record SentPush(URI endpoint, Map<String, String> headers, int bodyBytes) { /* written toString */ }
```

`VapidSignerContractTest` is untouched. The package stays `com.the13haven.push2u.testkit`, so no
`exports` line moves and the automatic module keeps its fixed name. The kit is a module's `main`
source set, so every analyser, the licence header, the Javadoc requirement and the ban on citing
this record from published sources apply to all four types.

[ADR-002](0002-zero-dependency-core.md) is untouched: the core gains nothing, and the kit already
carries JUnit and AssertJ through `api`. [ADR-005](0005-public-spis-in-the-core.md) is untouched and
not superseded: `ScriptedPushHttpClient` implements a seam that exists, and the three SPIs stay
three.

## The values are published because validity moves, not because assembly is tedious

A fixture produced by the library satisfies whatever the library currently requires, by
construction. A literal in a consumer's test satisfies whatever it required on the day it was
pasted. The report is the proof that the difference is not theoretical: the placeholders were
accepted for as long as nothing decoded them, and the release that started decoding them was a
release the consumer had every reason to take.

This is the whole admission test for anything in the kit. `PushSender.builder(...)` assembly does
not pass it — the builder's shape is compiled against and a change to it breaks loudly. A valid
`p256dh` does pass it: its length, its encoding and its being a point on the curve are the library's
rules, they are checked at construction, and nothing tells a consumer when they change.

## Generated per call, and no fixed pair at all

`generate()` makes new material each time. There is no `fixedPair()` and no key-shaped constant
anywhere in the artifact.

A published private scalar would be copied into a real `application.yml`, whatever the Javadoc says
about it, and the copy would outlive every warning attached to the original. The stability such a
constant offers is also mostly imagined: a send's ciphertext and its ES256 signature are
non-deterministic regardless, so the assertions that would rest on a fixed pair are few. Where a
test genuinely needs the same public key twice, it needs it within one run, and a field holding one
`generate()` gives it that without publishing anything. A deployment that asserts on its own
configured public key is asserting about its own configuration, which belongs to its own tests.

**The kit re-derives two encodings the core keeps package-private, and how far that is caught is
part of the decision.** `EcKeys` is package-private in the core's single exported package, so no
`exports` line could ever reach it from the kit's own package: the fixture cannot use the library's
X9.62 uncompressed-point writer, nor the fixed-width scalar writer this build keeps beside its
vectors, and must produce both encodings itself — the operation this repository's rules single out,
because a coordinate quietly padded or truncated to reach 32 bytes yields a pair that looks right
and is not. Handing the two strings to
`VapidKeys.fromBase64` catches half of it and no more: the constructor applies the on-curve check to
the public half and a length check to the scalar, and **nothing anywhere verifies that the scalar is
the one belonging to that point**. A mis-encoded public key therefore fails at `generate()`, loudly,
in the consumer's own build; a mis-padded scalar produces a fixture that looks coherent and whose
JWTs a push service rejects, which is the failure this record exists to keep out of consumers'
tests.

**The fixture reaches for no provider at all, and two separate things make that so.** The first is a
fact of this build: `push2u-core` already puts the kit on both its `test` and its `fipsTest`
classpath, and those two carry deliberately incompatible BouncyCastle flavours that can never meet,
so a fixture *referring to either* breaks whichever source set it is not on — in the library's own
build rather than in a consumer's. That is the invariant the core's shared send-pipeline helper
states for itself, and it reaches BouncyCastle only.

The second is wider and is the one that governs a published artifact. Naming any provider — `SunEC`
as much as another — would compile everywhere and still be wrong: a consumer's JVM may not have the
one the kit named, or may deliberately run with a different one, and a fixture that pins its own
would then produce keys through a provider the library under test is not using. So the contract is
standard JCA types and algorithm names, no provider argument and no provider lookup; the environment
chooses, exactly as it does for the code the fixture is used to test.

So the correspondence is pinned where it can be: a test in the kit signs with a generated pair and
verifies the signature against its public half through `Es256Verifier`, which the core publishes for
exactly this kind of check. That test is part of the fixture, not an extra — without it the fixture
carries a defect class the library's own key handling does not have.

This also makes the repository's second key generator, after `docs/VAPID.md`'s recipe, and the two
are deliberately not consolidated: ADR-018 ruled out a recipe depending on the library it generates
keys for, and the fixture is the opposite case and lives inside the library on purpose. A later
reader finding both should not read the duplication as an oversight.

## The private scalar's string form, and what ADR-018's clause reaches

[ADR-018](0018-encoded-vapid-public-key-on-the-signer.md) rules out any encoder for the private
scalar, in plain words: handing the secret back as a string is the one direction this library does
not provide, and only the public half is published because only the public half is meant to be.
`VapidKeys` has no accessor for the scalar, and this record does not give it one.

`VapidKeyPairFixture` is not an encoder. An encoder takes key material someone holds and returns its
secret as text; the fixture takes nothing. It generates a pair and reports both halves of what it
has just made, and the direction inside it runs the other way — the strings are the primary form and
`vapidKeys()` is `VapidKeys.fromBase64` applied to them. After this change, as before it, there is
no path anywhere in this repository from a `VapidKeys` a consumer is holding to its private scalar
as a string. The one secret the fixture can name is one that did not exist until the caller asked
for it.

What makes the accessor necessary rather than merely defensible is the Spring starter.
`push2u.vapid.private-key` binds a base64url string, so a deployment testing its own property
binding — the most ordinary Spring test there is — needs the pair in exactly that form. Without the
accessor it writes a literal, which is the defect this record exists to remove, and it writes it for
the largest audience the library has.

The Javadoc states the consequence rather than a prohibition, because a prohibition is what readers
skip: a pair generated at deployment start is replaced by a different pair at the next restart, and
every browser subscription taken under the old application server key becomes unusable. That is the
sentence someone tempted to shortcut the key-generation recipe needs to have read.

**One clause of ADR-018 is superseded by this record, and calling it anything softer would be
bookkeeping in the library's favour.** Its closing sentence rules out *any* encoder for the private
scalar, unqualified; the index row compressing it says the same; `VapidKeys`' own Javadoc says it to
consumers. After this change a published push2u artifact hands a caller a private scalar as a
base64url string. The distinction drawn above is real and it is what survives — the secret is one
the caller's own call brought into existence, and nothing can be handed material and asked for its
secret — but it is a *narrowing* of the rule ADR-018 wrote, not an application of it. Someone
reading ADR-018 alone, afterwards, would hold a false picture of the tree, and the status line
exists for exactly that reader.

The argument for calling it an extension rather than a supersession was that the ruled-out list
below re-imposes the clause and reaches one artifact further. That is true of the property and not
of the rule: the list states the property in narrower words than ADR-018 used, which is the
narrowing itself rather than a reason to deny it.

**The spelling, and the procedure it needs.** ADR-018 already carries a partial supersession from
[ADR-021](0021-retry-belongs-to-the-caller.md), so the status line becomes
`Accepted; one clause superseded by ADR-021, another by ADR-028`. The procedure as it stands offers
two forms and says a third is not legal, and this is a third; a record that needs a form the
procedure lacks either extends the procedure openly or invents one and hopes nobody checks. **This
one extends it**: `docs/adr/README.md`, `CLAUDE.md` and `CONTRIBUTING.md` each carry the two-form
rule and each gains the accumulating form, which is the general case they were always one clause
away from. The clause that moves is the private-scalar encoder and nothing else — the public-key
members, the alphabet, the absence of a pair-level inverse and every other item ADR-018 rules out
stand exactly as they are, and `VapidKeys` gains no accessor for the scalar in this record or after
it.

**The edits belong to the implementation, not to this proposal.** While this record is `Proposed`
nothing is superseded and no fixture exists, so ADR-018's status line, its index row and the
procedure documents are all still accurate today; they move when the code lands.

## The subscription fixture is one coherent set, published in the two forms it is read in

A subscription's endpoint, `p256dh` and `auth` are one set. Static factories returning them
separately would let a test combine the `p256dh` of one subscription with the `auth` of another and
spend an afternoon on the result. One instance holding one coherent set cannot be misused that way,
and it serves both callers at once: a send test takes `subscription()`, a registration or controller
test takes the browser-form strings and posts them as JSON, and they describe the same subscription.

`at(URI)` has no argument-free form. The endpoint has to agree with the `EndpointPolicy` the test
configures beside it, and keeping both visible in the same block is the same argument
[ADR-016](0016-endpoint-policy-is-a-required-decision.md) makes about egress decisions generally: a
required value belongs in the factory method, not in a default.

**The browser-form accessors carry a rule too.** The part of it that is the library's own to move
is what the bytes are: a raw X9.62 uncompressed point rather than an SPKI encoding, 65 bytes opening
`0x04`, with the `auth` secret beside it at exactly 16 — the composition ADR-018 spent a bullet on
as load-bearing and unstated where consumers look, and the composition whose tightening is what
broke the tests in the report. The spelling is fixed rather than moving, and it is where a consumer
goes wrong on the first attempt: the core tolerates *padding*, because browsers vary on it, and does
not tolerate a second alphabet, so `java.util.Base64.getEncoder()` in place of `getUrlEncoder()`
yields a string `Subscription.fromBase64` refuses.

**How that mistake presents is itself an argument for publishing the values.** For a 65-byte
`p256dh` the two alphabets differ almost always — around 93 % of keys — so the bug surfaces on the
first run. For the 16-byte `auth` they agree about half the time, so it surfaces on some runs and
not others, in a value whose only symptom downstream is a subscription the browser cannot decrypt
for. A fixture removes both, and the coherent set is why the two accessors sit on one fixture rather
than on two.

## The transport fake is scripted, because retry belongs to the caller

[ADR-021](0021-retry-belongs-to-the-caller.md) gave the caller the schedule and the library exactly
one POST. That decision handed every consumer a new obligation — decide, per outcome, whether to
repeat and when — and gave them nothing to exercise it with. A fake answering one constant status
cannot express the sequence the obligation is about: `429`, `429`, `201` is the shape of the loop a
consumer must now write, and a single canned answer cannot produce it.

A sequence is a vararg, not a framework. The first response is a separate parameter so that an empty
script cannot be written — the compiler refuses it rather than `build()`-style runtime validation,
which is the same rule the builders here follow. `respondingWith(PushResponse...)` exists beside the
status form because a `Retry-After` belongs to one particular response, and the retry test is
precisely the one that needs the second response to carry a different hint from the first; a global
header setter would put it on all of them.

An exhausted script raises `IllegalStateException`. That is a defect from a consumer seam, and the
facade converts only `VapidSignerUnavailableException` and `PushDeliveryException`
([ADR-022](0022-one-type-per-programmatic-action.md)'s taxonomy under ADR-021's sorting), so it
propagates out of `send` unchanged instead of arriving as an outcome. That is the behaviour a test
wants — one POST too many is a failure, not a scenario — and the Javadoc says where it surfaces, so
that nobody waits for an `Indeterminate` that will not come.

**`reset` and mutable configuration are refused, each for its own reason.** A `reset` makes one fake
serve several tests, and the first symptom of a test that forgot it is a neighbour's request in
`sent()`; a fresh fake per test costs one line and cannot do that. Mutable configuration means the
script a test declared is not the script that ran.

**Per-endpoint routing is left out of the first version and deliberately not ruled out.** A sender
holds exactly one `PushHttpClient`, so "a fake per subscription" is not available to a fan-out test
— it would need a sender per subscription, which is no longer the fan-out being tested. The honest
position is therefore that a test wanting a different answer per subscription has no shape here yet:
routing is a second addressing model over a seam whose method already carries the endpoint, which is
reason enough not to add it before the need is demonstrated, and no reason at all to forbid it once
it is.

**A transport failure cannot sit inside a script, and that is a deliberate omission rather than an
oversight.** `failingWith` is a mode of the whole fake, so `429`, then nothing answering, then `201`
— a shape ADR-021's obligation genuinely reaches — is not expressible here. Expressing it needs a
script element that is either a response or a failure, which is the sealed answer type this record
otherwise refuses as the start of a scripting language; a consumer needing that composes a
five-line `PushHttpClient` of its own, which is exactly the case where writing the stub is the
right answer. If the shape turns out to be ordinary rather than rare, it is an addition a later
record can make on evidence, and this one does not rule it out.

**The Javadoc also states what a shared script does under a fan-out.** `sendAsync` makes concurrent
`post` calls the normal case; responses are handed out in the order calls enter the fake, which for
concurrent sends is not the order of the subscriptions. Scripted sequences are for the sequential
loop over one subscription; a fan-out test uses one constant response, and asserts over `sent()`
rather than over which subscription got which status. Left unsaid, this produces flaky consumer
tests that read as a library defect.

## No fake for the third seam

The charter admits correct fakes of seams that already exist, and there are three seams. A signer
that raises `VapidSignerUnavailableException` is the only way to reach `SignerUnavailable` through
the real pipeline, and that variant is one of the eight a consumer must now decide about — so the
question has to be answered rather than left to the charter's wording.

It is not published. `VapidSigner` declares two abstract methods, so the fake is an anonymous class
rather than a lambda, and the correct form is the short one: both methods raise
`VapidSignerUnavailableException`, which is what an unreachable custodian does anyway, and the send
converts the first of them it reaches. Nothing about that moves when the library moves — a
consumer's own custodian is the thing being simulated, and the seam has one failure type. The
admission test fails, and the fact that a fake *could* live here is not a reason for one.

Raising from both is also the form with nothing left to get wrong, and the trap it avoids is worth
naming because it sits the other way round from where one would look for it. The send asks for the
signature first and validates the advertised key **after** it, so a fake that *returns* from both
methods has to return a structurally valid 65-byte point: a placeholder there ends the send as a
`PushCryptoException`, with the signature already produced, and the test never reaches the outcome
it was written for. A fake that raises has no returned value read at all. The transport fake is
published on the other side of that test — not because a stub transport is harder to write, but
because what the fake records is subject to rules about capability URLs and tokens that this library
owns and that move with it — and, beside that, because the sequence of answers a retry loop needs is
a shape a consumer cannot get from a lambda without writing the counter and the thread safety
themselves.

## What the recording keeps, and what it refuses to keep

`SentPush` carries the endpoint, a copy of the headers, and the body's length. It does not keep the
body. A test that holds the ciphertext will eventually decrypt it, and a consumer decrypting a
record this library produced is testing the library through its own test double — the assertion is
either a re-implementation of RFC 8291 or a comparison against whatever the code currently emits,
and neither is the consumer's business.

`toString()` renders the endpoint through `Endpoints.redact` and prints header names without their
values. The endpoint is a capability URL and the `Authorization` header carries a VAPID token; a
consumer's integration test may well be pointed at a real subscription, and an assertion failure
printed into a CI log is exactly how such a value leaves the machine. Redaction here is the
library's own function rather than a second scheme invented for the kit, which is also why the
rendering stays useful — `redact` keeps the origin and replaces the capability part, so a failure
message still says which service was called.

**What the fake owes a concurrent caller is part of this decision, not an implementation detail.**
`post` and `sent()` are safe to call from several threads, because `sendAsync` makes that ordinary.
Taking the next scripted answer and recording the call are one atomic step, so the recorded order is
the order answers were handed out and no call is answered without being recorded. A call that ends
in `PushDeliveryException` is recorded before the throw — the POST was attempted, and a fake that
forgot it would make `Indeterminate` look like a send that never happened. `sent()` answers an
immutable point-in-time snapshot, and `SentPush.headers()` an immutable copy, so an assertion made
while a fan-out is still running reads a list that cannot change under it.

`sent()` answers a plain `List<SentPush>` and the fake asserts nothing itself. A consumer already
has an assertion library and knows it better than this kit would; a `hasSentTo(...)` here would be a
second one, worse, in the artifact that is meant to remove work rather than add vocabulary.

`bodyBytes()` and not `bodyLength()`: `PushOutcome.PayloadRejected` already says `payloadBytes`.

## No `PushSender` fixture, in any spelling

A factory returning a ready sender must choose a contact, an endpoint policy and some part of the
builder's configuration. The policy is the one it cannot choose: ADR-016 makes the egress decision
required precisely so that no sender exists without one, and a fixture defaulting to
`EndpointPolicies.unrestricted()` reintroduces the invisible default in the source set where
security assumptions are least examined. A preconfigured sender also freezes a builder configuration
into a published artifact, so every option added later arrives with the question of whether the
fixture sets it.

None of that buys anything once the values exist. With a pair, a subscription and a fake in hand,
the sender is one statement — and it is the statement the consumer's production code also writes,
which is the one worth having in the test.

## No outcome factory, and no catalogue of the eight

All eight `PushOutcome` variants have public constructors, `SignerUnavailable` and `Indeterminate`
included. A consumer's decision table is a unit test over values, and `new
PushOutcome.RetryableFailure(503, Optional.empty())` is a real value of the public contract, not a
mock of it. A kit factory wrapping that constructor would hide the status and the hint, which are
the components the decision is about.

A catalogue produced by driving the real pipeline was considered and refused. It is either a second
classifier — the mapping from status to outcome restated in the kit, where it can disagree with the
sender — or an expensive detour that builds a sender and runs the crypto to obtain objects a
constructor already offers, and in both forms the value arrives stripped of the scenario that
produced it. The mapping itself is the library's to pin, and this library pins it in its own suite;
a consumer needs to handle a `RetryableFailure`, not to re-derive that `429` is one. Where the real
classification genuinely matters, the scripted transport and a real sender give it, in the
consumer's own wiring.

Public constructors do admit combinations the sender never produces — `Accepted(500)` is
constructible, since the compact constructor only refuses a negative status. That is a note for
`docs/TESTKIT.md`, which can say which combinations are reachable, and not a reason for an API that
would have to be kept in step with the classifier forever.

## The rejected-input catalogue is deferred, not refused

A published list of inputs `Subscription.fromBase64` rejects — string-shaped, since an invalid
`Subscription` cannot exist — would let a registration test inherit a new case whenever the library
adds an invariant. It is not in the first version for a reason that is about the consumer's design
rather than about API size: an application should delegate this validation rather than reproduce it,
and its boundary test needs to prove one thing, that an `IllegalArgumentException` out of
`fromBase64` becomes a `400` with no row stored. The full matrix of invariants is already covered by
this library's own tests.

If a consumer is ever found checking each invariant at its own boundary, two constraints hold
whatever shape it takes, and the shape itself is for the record that adds it rather than for this
one: the catalogue is string-shaped, since an invalid `Subscription` cannot exist to be published,
and it carries **a test inside the kit asserting that every entry is still rejected**. Without that
test the promise the catalogue exists for is a wish: a relaxed rule leaves a stale entry behind, and
the consumer's test goes on reporting success for an invariant that no longer exists.

## The library's own fixtures stay in this build

`MockPushReceiver`, `LoopbackTls`, `TestVectors`, `PushTestSupport`, and the Vault module's
`FakeTransitVault` and `RecordingHttpClient` are not published. The vectors are conformance material
for the library's crypto, which a consumer does not re-run; the receiver and the certificate are
this build's plumbing; and the Vault pair belongs to the other trust domain entirely — the one where
responses must be read. `PushTestSupport` is named explicitly because it is the one most likely to
be offered for promotion: it already holds this build's valid-pair and valid-subscription helpers.
It stays because the class as a whole is wired to the in-process receiver and bound by an invariant
of the two BouncyCastle classpaths that no consumer has — and its key-pair helper stays with it
rather than being promoted alone, because it reaches `EcKeys` and the vectors' scalar writer, which
is exactly the reach the kit does not have and the reason the fixture encodes its own. This is the
split ADR-014 already made, and the addition here does not narrow it.

## One artifact

`push2u-testkit` keeps its single coordinate. Splitting a leaner fixtures artifact off would buy a
consumer freedom from a transitive JUnit on a test classpath that has JUnit on it already, and would
cost a coordinate, a JPMS identity, a publication surface and a second thing to keep in step. The
fixtures themselves use neither JUnit nor AssertJ, so a consumer on another runner can use them; the
existing contract needs both and keeps them on `api`.

## What this record does not decide

The kit describes itself as the conformance kit for this library's extension points, and there are
three. `VapidSigner` has its contract; `PushHttpClient` and `EndpointPolicy` do not, and the charter
above plainly admits both. Neither is decided here.

`PushHttpClientContractTest` has real obligations to state — no redirects followed, an HTTP error
status is not a transport failure, `PushDeliveryException` when nothing answered, the response body
never materialised, thread safety — and one unsolved cost: verifying them needs a server, over TLS,
inside a published artifact. This build's `LoopbackTls` assembles a self-signed certificate by hand
because bcpkix is not a dependency here and `sun.security.*` would need `--add-exports`. Publishing
that machinery, or choosing something else, is a decision of its own, and settling the values above
must not wait behind it.

`EndpointPolicyContractTest` has a narrower subject than it first appears, and the narrowing is
worth recording so that the next attempt does not overreach. The seam's written obligations are that
the answer is never `null`, that a refusal is a `Refused` rather than an exception, that
implementations are thread-safe, and that a refusal's reason must not carry the raw URI — that last
one is the one that matters, since the reason travels into `PushOutcome.EndpointRejected` and from
there into a consumer's logs. It is checkable only if the kit asks the implementor for an endpoint
their own policy refuses: a contract test handed an arbitrary `EndpointPolicy` has no other way to
obtain a `Refused` to inspect. That is a shape for the record which decides this, named here so the
next attempt does not assume the check comes free. Determinism is **not** part of
the contract: the seam's own Javadoc names a resolution cache and a counter as legitimate state, so
a contract test asserting that one URI always gets one answer would refuse an implementation the
library permits.

## Documents

`docs/TESTKIT.md` is new and is the kit's reference for the consumer side, in the shape
`docs/SIGNER.md` has for the implementor side, with README's *Documentation* table gaining its row
and the Maven coordinate staying in README alone. It is named for the artifact and not for the
activity: a `docs/TESTING.md` would read as a contributor's guide to testing this repository, which
is `CONTRIBUTING.md`'s subject, and this repository has already paid once for a document whose name
did not say which of two journeys it described. `docs/SIGNER.md` keeps the contract material and
links across.

Five texts state that the kit holds one thing, and each is part of the change rather than a
follow-up. `CLAUDE.md` calls it the conformance kit "and nothing else", and its module table is the
other place the artifact is described there. `CONTRIBUTING.md` calls the contract "the whole of the
`push2u-testkit` module". README's module table describes the artifact as the `VapidSigner`
conformance contract, and the prose above it introduces the kit in the same terms. The kit's
`package-info.java` says its one member today is `VapidSignerContractTest`. Its `build.gradle.kts`
`description` becomes the published POM description and names only the signer contract.

A sixth text is listed for a different reason, and it is the one that moves rather than merely being
counted. `VapidKeys`' own Javadoc carries ADR-018's clause in the words a consumer actually reads —
that the private scalar gets no encoder, because handing a secret back as a string is the one
direction this library does not provide. It stays true of `VapidKeys`, and reads as a claim about
the library that the kit's fixture contradicts, so it takes the same narrowing the clause does: the
sentence becomes one about this type and the material a caller hands it.

`docs/DESIGN.md` describes the module layout and gains the kit's second half. `docs/adr/README.md`
gains the row; ADR-018's status line and its row take the change named above; and the three
documents carrying the supersession procedure — `docs/adr/README.md`, `CLAUDE.md` and
`CONTRIBUTING.md` — gain the accumulating form, all of it at implementation rather than now. The
kit's own Javadoc carries every reason above in its own words, since it ships in a `sources.jar` to
readers who have neither this record nor those documents.

## What this rules out

- A helper in the kit that exists because assembly is tedious rather than because the library owns
  the knowledge it carries.
- A `PushSender` fixture or factory, in any spelling, and an `EndpointPolicies.unrestricted()`
  reached through one.
- A fixed VAPID pair, or any key-shaped constant, in a published artifact.
- A fixture selecting or naming a JCE provider, rather than taking whichever one the environment
  offers for a standard algorithm name — and, narrower and harder, any reference from the kit to
  either BouncyCastle flavour, which the core's two disjoint test classpaths make unbuildable rather
  than merely unwise.
- An encoder taking key material a caller already holds and returning its private scalar as a string
  — in the kit, the core or a starter. That is the property ADR-018's clause protects, which
  survives the one-clause supersession named above and reaches one artifact further than ADR-018
  had occasion to take it.
- An accessor for the private scalar on `VapidKeys`, in this record or after it.
- A published fake for `VapidSigner`, whose failure mode is a short anonymous class whose two
  methods both raise, and nothing about which moves when the library moves.
- A second model of a browser subscription, or a fixture returning subscription components
  separately, so that an incoherent set can be assembled from them.
- A fixture that hands over the encrypted body, or a `toString()` rendering a capability URL, a
  header value or a token.
- A canned `PushOutcome` factory, a catalogue of the eight variants, and any second statement in the
  kit of the mapping from status to outcome.
- A rejected-input catalogue published without a kit test that keeps it true.
- The library's own fixtures — the receiver, the loopback certificate, the RFC vectors, the shared
  send-pipeline helper, the Vault fakes — published from any artifact.
- A second published artifact carrying the fixtures apart from the contract.
- A retry DSL, an assertion DSL, mutable configuration or a `reset` on the transport fake — each
  refused for its own reason above, not as a group. Per-endpoint routing is left out of the first
  version and is deliberately absent from this list.
- A mock push service listening on a socket, shipped as part of this decision.
- A contract test asserting that an `EndpointPolicy` answers deterministically.
