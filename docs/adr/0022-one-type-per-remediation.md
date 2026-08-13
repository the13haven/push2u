# ADR-022 — One exception type per remediation

**Status:** Proposed

Reported as https://github.com/the13haven/push2u/issues/128, which is the wider review promised in
https://github.com/the13haven/push2u/issues/87 rather than a new complaint. Counted over every
`main` source set, and counting the sites that throw through a factory helper as well as the ones
that write `throw new`: 89 `PushCryptoException`, 88 `IllegalArgumentException`, six
`IllegalStateException`, three `PushDeliveryException`, three `EndpointRejectedException`, and one
`AssertionError` that dies with the retry loop. Three of those types are ours and all three already
extend `RuntimeException` directly.

The first number is the one that matters. `PushCryptoException` covers, indistinguishably from
outside and by its own Javadoc's admission — *"One type covers both on purpose; the message and the
cause chain, not the type, say which happened"* — a Vault that cannot be reached, a Vault that
answered an error status of any kind, a Vault that answered something it could not have meant, a
Transit key created with a type VAPID cannot use, a platform missing an algorithm, a request URI a
configured address made unusable, a header a trailing newline in a YAML block scalar made illegal,
and a thread that was interrupted. `PushSender.send`'s published Javadoc then tells a caller that
this type means a key service *"unreachable or refuses the operation, which may be transient"*, so a
durable retrier that believes the contract retries a wrong-typed Transit key forever.

## The decision

**A site earns its own type only if a consumer would take a materially different action on it, and
that action cannot be derived from what the consumer already holds.** That is issue #87's criterion,
quoted as it was written, and the shape of it is load-bearing: it is a *necessary* condition and not
a sufficient one. A different log line is not a different action, and a taxonomy that minted a type
per condition would answer the count without answering the complaint.

**One refinement, because ADR-021 changes who is reading.** After it, most of these failures never
reach a `catch` block in an application at all — the facade catches them and reports an outcome. The
audiences that remain are three: the facade, which switches on the type; a startup supervisor, for a
signer that reads its key inside `build()`; and whoever reads a stack trace at three in the morning.
The criterion is judged against those. It is not weakened by that: the facade's `catch` clauses are
an enumeration, so a distinction the facade does not act on still does not earn a type.

**And the axis is remediation, not aetiology.** Two failures with different causes and one remedy
are one type. The question every site is put to is *who fixes this, and with what*.

## What the axis produces

**ADR-021 has already drawn the sharpest line, and this review's remaining job is smaller than 89
suggests.** Its outcome-versus-exception decision moves every operational failure out of the
exception channel, and that is the transient-versus-permanent distinction issue #87 was filed about —
the one whose absence lets a durable retrier repeat a wrong key type forever. What is left on the
exception channel afterwards is a defect, a misconfiguration that recurs, a misuse, or a
cancellation.

**No configuration type is added, and the reason is the criterion rather than a shortage of cases.**
Half of the obvious candidates never reach a send, because the boundary that takes a required value
refuses it there: the Vault token carrying a YAML block scalar's newline is refused by `VaultToken`'s
own constructor, whose message names that exact case; an address that would yield an unusable request
URI is refused at the builder factory; a supplied public key that is not on P-256 is refused by the
factory that takes it. That is `CONTRIBUTING.md`'s builder convention working — a required value is
validated where it is supplied, and `build()` cannot refuse over one — and it makes those an
`IllegalArgumentException` at the boundary rather than anything a send reports.

The other half does reach a send, and saying otherwise would be false. Those checks are checks of
*form*: a mount that names no engine, a key name Vault does not hold, a token whose character set is
legal but whose capability or lifetime is not, a pinned key version Vault has trimmed — every one of
them is well-formed, passes every boundary, and comes back as a Vault error status. They are a
deployment's own to fix, and they are exactly what ADR-021's recurring list already names.

They still earn no type, and the criterion is what decides it. A consumer takes no different
programmatic action on "your token cannot read that key" than on "your platform has no `AES/GCM`":
both stop the sender until a human intervenes, and neither is retried. The difference is the sentence
in the log — and a different log line is not a different action, which is the same answer this record
gives the signer split below. A type would be minted for a distinction only a human reads, and the
message and the cause chain already carry it.

**`PushCryptoException` therefore covers what recurs until a human acts**, whether the human edits a
property or files a bug, and it keeps its name because the cryptography is what could not be
performed in every case. A platform without `AES/GCM/NoPadding`, `HmacSHA256` or the `secp256r1`
parameters; a custodian or a `VapidSigner` implementation that answered something that is not a
signature or not a key; a Transit key whose type VAPID cannot use, a mount or key name that is not
there, a token without the capability, a pinned key version Vault no longer holds. `Endpoints`'s
unavailable `SHA-256 MessageDigest` is an `IllegalStateException` today and joins them, on a stated
ground rather than on a claim of sameness. It is not the same condition: the fingerprint hashes with
the platform's own SHA-256 whatever provider is configured, deliberately, because it is diagnostics
and not protocol — so its failure means a runtime that is not a Java SE implementation, where a
missing `secp256r1` from a configured FIPS provider is an ordinary misconfiguration of a supported
kind. It joins them because an unusable cryptographic substrate is worth one channel rather than two,
and because the site is unreachable on a conforming JVM, so the choice costs nothing either way.

So the type loses two things and no more: the operational half
ADR-021 moves to outcomes, and the cancellation the section below gives a type of its own — the
interrupted custodian wait, which is `PushCryptoException` today and is neither cryptographic nor a
defect. The misconfigurations ADR-021 names beside the defects stay where that record puts them.

**The starters keep `IllegalStateException`**, and this is stated so the inventory is complete rather
than silently exempt. Their five conditions are a missing `push2u.vapid.subject`; a
`push2u.signer.vault.key-version` without a `push2u.signer.vault.public-key`; the allowlist
properties and an `EndpointPolicy` bean both present; no egress decision expressed at all; and every
configured allowlist present but empty. All five are startup failures of a Spring context, where a
failed context is what an `IllegalStateException` idiomatically means, where nothing catches by type,
and where the library's own rule is already that the message names the YAML property rather than the
builder's camelCase parameter. A library type would say less than the message does and would be
caught by nothing.

**Cancellation gets its own type**, `PushInterruptedException`, raised by the facade. It rides
`PushDeliveryException` in two places and `PushCryptoException` in a third today, and it is none of
them: nothing failed, the caller asked to stop, and the action — clear nothing, retry nothing, let
the interrupt propagate — is shared with no other failure here. **The seams are not obliged to raise
it.** ADR-021 put the recognition test on the facade, written as a disjunction over the cause chain
and the thread's interrupt status, *"precisely so that no transport has to be obliged to anything"*,
and that stands: `PushHttpClient`'s contract does not change, and the type is what `send` reports
rather than what a seam must throw. The residue is named rather than papered over: a signer that reads
its key inside `build()` is not inside a send, so an interruption during that read leaves as the
seam's own type — `VapidSignerUnavailableException`, since an interrupted exchange is an incomplete
one and the transport does not sort them — and the startup supervisor sees that type rather than this
one. Obliging the seams to tell an interruption apart would close it at a price ADR-021 declined to
pay for the send path, and it is not worth paying for one call that happens once. What it costs
instead is a sentence in the supervisor's contract, which the section below owes it anyway.

**`IllegalArgumentException` stays exactly what the JDK made it**: a value that is not a legal value
of its parameter, carrying no library semantics, handled in a generic pool. `Subscription`'s 16-byte
`auth`, a negative `ttl`, a `p256dh` that is not 65 bytes, every builder bound, and — per the
finding above — every configured value refused at the boundary that took it. It is the larger half
of #87's rule and the half that keeps the taxonomy from growing: we do not mint a type for what is
genuinely an argument defect. The two sites that were not argument defects, the size preconditions,
are already leaving as ADR-021's `PayloadRejected`.

## The signer's operational failure stays one type

A custodian reached over a network fails in two ways that are not the same event: nothing answers —
a refused connection, a failed handshake, a timeout — or the custodian answers that it cannot serve
this request now, sealed or not caught up or rate-limited. Only the second can carry a retry hint,
because only the second declared anything. That asymmetry is the case for two types, and it was
argued at length in a draft of this record. It does not survive the criterion this document adopts,
and the reasoning is set out because the question will be asked again.

The remedy is the same on both sides — wait, and look at the custodian — and it is the same human.
The facade's action is the same: one `SignerUnavailable`, with a hint copied across if one arrived.
Whether an answer arrived is a fact about how the failure happened, which is the aetiology this
document's axis exists to stop ranking. And the shape argument proves too much: a field that is
always absent on one side would equally justify splitting a timeout from a refused connection, and
nothing in the criterion stops that regress once it is admitted.

The precedent runs the same way. ADR-021 weighed *these two types* and rejected them, and it
accepted `RetryableFailure(413, empty)` — a representable pair that cannot occur — rather than pay a
type for one dead combination. A record that reversed both while claiming to apply the same rule
would be applying a different one.

What the two halves do differ in is the sentence an operator reads, and the criterion answers that
directly: a different log line is not a different action. The message and the cause chain carry it,
which is the half of `PushCryptoException`'s own reasoning that survives its narrowing.

**`SignerUnavailable` carries the cause**, which ADR-021 leaves unanswered. The facade catches the
signer's exception and reports a value; with nothing carried, the `IOException` under an unreachable
custodian is destroyed and no one can say why a send was not attempted — and that loss falls hardest
on exactly the distinction the paragraph above leaves to the message. It carries it under
`Indeterminate`'s discipline and for `Indeterminate`'s reason, which means the same consequence:
a variant carrying a cause is a class with a written `toString()` rather than a record, because a
record's generated one prints its components.

**And the exception that feeds it is pinned here too**, because a shape fixed on the outcome and left
open on the seam that produces it is half a decision — the hint cannot reach a caller unless the
exception carries it first. `VapidSignerUnavailableException` carries an `Optional<Duration>` retry
hint and the cause; an interrupted custodian call carries the `InterruptedException` in its chain
with the interrupt flag re-set, which is what lets the facade's disjunction recognise one; and a
signer that reads its key inside `build()` raises the same type when its custodian is down at
startup. That last clause is the whole of what the startup supervisor named above acts on: catching
this type, it retries the boot with backoff, where catching `PushCryptoException` it should fail the
deployment and stop. A record that names an audience owes that audience a contract.

**And the contract begins with the interrupt, not with the type.** A boot interrupted while the key
is being read raises the unavailable type as well, because the transport does not sort an incomplete
exchange by what made it incomplete — so a supervisor that reads the type first answers a shutdown by
looping the boot, and every backoff it sleeps fails instantly on a flag nobody cleared. That is the
spin ADR-021 refuses on the send path, arriving at the one place there is no facade to refuse it. The
order is therefore fixed here: test the interruption first — the flag, or an `InterruptedException`
in the chain, the same disjunction and for the same reason — and only then read the type. A
supervisor of anything that blocks owes that test in any case; what this record adds is that it comes
first.

**`PushInterruptedException` promises the interrupt flag.** The action it exists for — let the
cancellation propagate — only works if a caller catching it finds the flag set or the
`InterruptedException` in the chain, and every site that raises one today re-sets it. That is a habit
inherited from three separate implementations rather than a contract, and an interruption swallowed
without the flag is the oldest defect in the genre. It becomes the type's written promise.

## What ADR-021 takes, and what this costs

ADR-021 is unimplemented, so it is edited rather than superseded, and the edits are narrower than an
earlier draft of this record claimed. Its *"a defect and a misconfiguration"*, in the two places it
says that, **stands**: the misconfigurations it names beside the defects are the ones that reach a
send, and this record keeps them in the same type for the reason set out above rather than moving
them anywhere. Its signer decision **stands** too, and is confirmed rather than edited. What it takes
is three edits, and they are made in that record rather than described here: `SignerUnavailable`
becomes a cause-carrying class where its sketch had a record; the interrupted send, whose seam
exception it deliberately does not convert to an outcome, leaves as a type of its own instead, for a
send and not for a `build()`; and its enumeration of the types the facade converts, written before
the signer had one, is completed — which matters more than it looks, because everything above turns
on a type outside that list never reaching the facade at all.

Every one of these is a breaking change for a consumer that catches by type. `0.x` was declared the
window for revising names and constructor shapes once real integrations exist, and each transition
is named in the release notes rather than described in the abstract. The one that bites hardest is
the narrowing of `PushCryptoException`: a `catch` clause that today swallows an unreachable Vault
compiles unchanged and silently stops catching it.

**It breaks signer implementers the same way, one seam deeper, and that half is the one nobody
would look for.** `VapidSigner`'s published contract instructs an implementation to raise
`PushCryptoException` when a remote key service is unreachable, timed out or refused the operation.
A KMS or HSM signer written against that sentence keeps compiling afterwards, and its outages then
leave `send` as permanent defects instead of becoming `SignerUnavailable` — because the facade
rightly refuses to sniff a cause chain to guess otherwise. Nothing catches this: the conformance kit
asserts no exception types on purpose, so a stale implementation passes it. The release note
therefore addresses signer implementers in their own paragraph rather than leaving them to read a
consumer's.

The name `PushCryptoException` is kept through that narrowing, and the asymmetry is worth one
sentence because ADR-021 paid the opposite price next door: it renamed `PushResult` to `PushOutcome`
for a smaller shift in meaning, arguing that the old name described something the type no longer
meant. A rename here would turn the silent break above into a compile error at every affected site,
which is a real gain. It is declined because the name is still accurate for what the type keeps — the
cryptography is what could not be performed in every remaining case — and because the candidates that
would describe the narrowing better describe the type worse. A name that has stopped being true is
worth changing; a name that is true and merely covers less is not.

**ADR-005's seams are untouched** — none added, none removed, and `PushHttpClient`'s contract in
particular is left exactly where ADR-021 left it. **ADR-002 is untouched**: an exception class is
core code, not a dependency, and every type named here lives in `push2u-core` beside the three that
are there now, because the facade must catch them and a type the core cannot see cannot be caught
there.

## What this rules out

A type per throw site, which answers the count and not the complaint. A type whose only consumer
difference is the sentence it puts in a log. A type for a configured value that the boundary
accepting it should have refused. `IllegalArgumentException` as a base class for anything the
library owns, which lets an existing `catch` keep swallowing both cases and so cancels the
disambiguation it was minted for. A library exception that does not extend `RuntimeException`
directly. Message-text matching as the supported way to tell two conditions apart — anywhere a
consumer must do that, a type is missing. A cancellation reported by `send` as the type of whatever
it interrupted, and equally a seam obliged to recognise one. And a taxonomy settled one exception at
a time, in whichever ADR happens to touch a failure next.
