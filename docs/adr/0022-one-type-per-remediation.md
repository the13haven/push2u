# ADR-022 — One exception type per remediation

**Status:** Proposed

Reported as https://github.com/the13haven/push2u/issues/128, which is the wider review promised in
https://github.com/the13haven/push2u/issues/87 rather than a new complaint. The count that opened it:
88 `IllegalArgumentException`, 66 `PushCryptoException`, three each of `PushDeliveryException`,
`EndpointRejectedException` and `IllegalStateException`, across every `main` source set. Three of
those types are ours and all three already extend `RuntimeException` directly.

The number that matters is the second one. `PushCryptoException` covers, indistinguishably from
outside and by its own Javadoc's admission — *"One type covers both on purpose; the message and the
cause chain, not the type, say which happened"* — a Vault that cannot be reached, a Vault that
answered an error status of any kind, a Vault that answered something it could not have meant, a
Transit key created with the wrong type, a platform missing an algorithm, a request URI the
configuration made unusable, a header a trailing newline in a YAML block scalar made illegal, and a
thread that was interrupted. `PushSender.send`'s published Javadoc then tells a caller that this
type means a key service *"unreachable or refuses the operation, which may be transient"*, so a
durable retrier that believes the contract retries a wrong-typed Transit key forever.

## The decision

**A failure earns its own type when a consumer would take a materially different action on it, and
that action cannot be derived from what the consumer already holds.** That is issue #87's criterion,
unchanged, and it is deliberately not "one type per condition": a different log line is not a
different action, and a taxonomy that mints a type per throw site would answer the count without
answering the complaint.

**One refinement, because ADR-021 changes who is reading.** After it, most of these failures never
reach a `catch` block in an application at all — the facade catches them and reports an outcome. The
audiences that remain are three: the facade, which switches on the type; a startup supervisor, for a
signer that reads its key inside `build()`; and whoever reads a stack trace at three in the morning.
"Materially different action" is judged against those, and the first of them is the strict one — the
facade's `catch` clauses are the enumeration, so a distinction the facade cannot see does not exist.

**And the axis is remediation, not aetiology.** Two failures with different causes and one remedy
are one type. The question every site is put to is *who fixes this, and with what*.

## What the axis produces

**ADR-021 has already drawn the sharpest line and it is not on this axis.** Its outcome-versus-
exception decision moves every operational failure out of the exception channel entirely, and that
is the transient-versus-permanent distinction whose absence issue #87 was filed about. Once it is
implemented, what remains on the exception channel is uniformly *permanent until a human acts*, and
this review's job is smaller than 66 suggests: it is to split "which human, with what" and to stop
three conditions from riding types that describe something else.

**Two permanent types, split by whether the deployment can fix it alone.**

- **A value the deployment supplied cannot be used** is `PushConfigurationException`. A Vault token
  carrying the newline a YAML block scalar left on it, so the request header is illegal; an address
  that yields an unusable request URI; a Transit key created as anything other than `ecdsa-p256`; a
  configured public key that is not on P-256. The remedy is a property, and the deployment owns it.
- **Everything else permanent is a defect** and keeps `PushCryptoException`, narrowed to what its
  name says: the cryptography could not be performed. A platform without `AES/GCM/NoPadding`,
  `HmacSHA256` or the `secp256r1` parameters; a custodian or a `VapidSigner` implementation that
  answered something that is not a signature or not a key. The remedy is a bug report or an
  infrastructure change, and the deployment cannot write it as configuration.

The line between them is the one a deployment can act on without anyone else, which is why it is
worth a type where "a wrong key type" versus "a malformed JSON body" is not: both of the latter end
in the same place, with a human reading a stack trace, and the message says which.

`Endpoints`'s unavailable `SHA-256 MessageDigest` is an `IllegalStateException` today and is the
same condition as the platform cases above. It joins them.

**Cancellation gets its own type**, `PushInterruptedException`. It rides `PushDeliveryException` in
one place and `PushCryptoException` in another today, and it is neither: nothing failed, the caller
asked to stop, and the action — clear nothing, retry nothing, let the interrupt propagate — is
shared with no other failure here. ADR-021 already decided that an interrupted send stays an
exception and wrote the test for recognising one; this gives that decision a type instead of
borrowing the type of whatever was being done at the time.

**`IllegalArgumentException` stays exactly what the JDK made it**: a value that is not a legal value
of its parameter, carrying no library semantics, handled in a generic pool. `Subscription`'s
16-byte `auth`, a negative `ttl`, a `p256dh` that is not 65 bytes, every builder bound. It is the
larger half of #87's rule and the half that keeps the taxonomy from growing: we do not mint a type
for what is genuinely an argument defect. The two sites that were not argument defects — the size
preconditions — are already leaving, as ADR-021's `PayloadRejected`.

## The signer's operational failure takes two types, not one

This is the one place the criterion is applied against a reading of it, so the reasoning is set out
rather than asserted.

A custodian reached over a network fails in two ways that are not the same event. **Nothing
answered** — a refused connection, a handshake that failed, a timeout. Or **the custodian answered
that it cannot serve this request now** — Vault sealed, a node that has not caught up, a rate-limit
quota. So: `VapidSignerUnreachableException` for the first, `VapidSignerUnavailableException` for
the second, and only the second can carry the retry hint, because only the second declared anything.

The one-type alternative is not weak and it is what ADR-021 currently records: both produce one
outcome, `SignerUnavailable`, and one caller decision — do not send now, come back later — so by the
criterion's letter the split buys nothing. It is rejected on two grounds.

The first is that the criterion's letter is about a *consumer*, and this exception has no consumer.
It is caught by the facade, which is one of the three audiences above and the one that enumerates by
type. A hint that can arrive on one half and by construction never on the other is a fact about the
event, and modelling it as one type with an optional field states that the field is *sometimes*
absent where the truth is that it is *always* absent on one side. This repository has refused that
shape twice in the last two decisions — a retry advice enum that was a policy renamed, a nested
failure object forcing two dispatches — for the same reason.

The second is that the strain shows. ADR-021 needed a paragraph to explain that its own axis —
whether the failure recurs — settles neither half of this one type, because with no answer there is
no statement of recurrence to read. A type covering two things that its governing rule cannot rank
together is two types wearing one name.

What does *not* split is the outcome. Both arrive as `SignerUnavailable`, because there the
criterion applies with its full force: the caller's action is identical, and it is holding the hint
either way. The seam distinguishes because the facade and the operator can act on the distinction;
the outcome unifies because the application cannot.

**`SignerUnavailable` carries the cause.** The facade catches the signer's exception and reports a
value; with nothing carried, the `IOException` under an unreachable custodian is destroyed and no
one can say why a send was not attempted. `Indeterminate` keeps a `cause()` for exactly this reason
and under exactly this discipline — reachable only by an explicit call, absent from `toString()` and
from anything a bean serializer walks.

## What this costs, and what it does not

Every one of these is a breaking change for a consumer that catches by type. `0.x` was declared the
window for revising names and constructor shapes once real integrations exist, and each transition
is named in the release notes rather than described in the abstract. The one that bites hardest is
the narrowing of `PushCryptoException`: a `catch` clause that today swallows an unreachable Vault
compiles unchanged and silently stops catching it.

**ADR-021 takes a narrow edit rather than a supersedence**, because it is unimplemented and can
still be aligned. It names one signer exception where this names two, and it does not say whether
`SignerUnavailable` carries a cause. Both are edits to a `Proposed` record, which is the reason this
review is being settled before that one is implemented rather than after: an implemented ADR is
immutable, and the piecemeal choices would freeze exactly where issue #87 asked them not to be made.

**ADR-005's seams are untouched** — none added, none removed. Two of the four contracts change what
they may raise, which is a change within a seam rather than to which seams exist, and ADR-021 has
already recorded both. **ADR-002 is untouched**: an exception class is core code, not a dependency,
and every type named here lives in `push2u-core` beside the three that are there now, because the
facade must catch them all and a type the core cannot see cannot be caught there.

## What this rules out

A type per throw site, which answers the count and not the complaint. A type whose only consumer
difference is the sentence it puts in a log. `IllegalArgumentException` as a base class for anything
the library owns, which lets an existing `catch` keep swallowing both cases and so cancels the
disambiguation it was minted for. A library exception that does not extend `RuntimeException`
directly. Message-text matching as the supported way to tell two conditions apart — anywhere a
consumer must do that, a type is missing. And a taxonomy settled one exception at a time, in
whichever ADR happens to touch a failure next.
