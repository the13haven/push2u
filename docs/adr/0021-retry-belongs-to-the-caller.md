# ADR-021 — Retry belongs to the caller

**Status:** Proposed

`PushSender.send` retries. Three separable things are welded into one `for` loop: **which** responses
may be retried at all, which is a private static naming 429 and the whole 5xx class; **how long** to
wait and **when to stop**, which is `RetryPolicy`, a record of three numbers whose backoff doubles
until a ceiling stops it and which the sender overrides with a parseable `Retry-After`, clamped at
that same ceiling; and **who executes** the schedule, which is the loop itself — one thread, inside
one call, sleeping through every wait. Only the middle one is configurable, and only in the three
numbers the record holds.

Reported as https://github.com/the13haven/push2u/issues/86, from the deployment where that bites
hardest: a sender whose retries are *durable*. There the next attempt is a job the engine reschedules
minutes or hours later, across a process restart or a deploy, and a `Thread.sleep` inside `send`
cannot participate in it — it holds a worker for the wait and its state dies with the process. So the
sender is configured for one attempt per call and the application owns backoff, expiry and the
404/410 delete. The report's complaint is precise: the consumer that most needs the push service's
`Retry-After` is the one configuration that cannot see it, and it reschedules on a blind exponential
backoff that may POST again well before the service said it would accept anything — the exact harm
the header exists to prevent.

The first reading of that report is that the library's retry should become pluggable: a policy behind
a seam, a driver the caller can supply, a resumable state the caller can persist. This ADR was
drafted in that shape and the shape was wrong. Every clause it needed was a question about
retrying — what a policy that throws does to a send, which of the two clocks measures elapsed time,
who bounds a policy that never gives up, whether a held thread is acceptable, what a driver would
have to be handed across a restart — and not one of them was a question about Web Push. When a
feature's design cost is six open questions in a neighbouring domain, the feature is in the wrong
library.

## The decision

**The library does not retry.** `PushSender.send` performs exactly one POST and returns what happened.
`RetryPolicy`, the `Sleeper` seam, the loop and the `push2u.retry.*` properties are removed, and
nothing replaces them: no retry SPI, no shipped retrying wrapper, no separate retry module.

Three things make that the right boundary rather than an abdication.

**Every deployment that sends push at volume already owns a retrier** — Spring Retry, Resilience4j, a
job engine, a queue with redelivery — and the library's loop integrates with none of them. It
competes, and it competes from ignorance: it cannot see the deployment's retry budget, its
dead-letter path, its concurrency limit, or what survives a restart. The reporter's situation is that
competition in its plainest form, two retriers in one call path, discovered by symptom.

**It is on by default, so it wins that competition by accident.** On the shipped defaults `send` — a
method that looks like one POST — blocks for up to 93 seconds: three attempts at the transport's
30-second per-request timeout, plus one and two seconds of computed backoff. A push service
answering `429` with a large `Retry-After` raises that to three and a half minutes, because the
honoured hint is capped only at the 60-second ceiling and the computed schedule never reaches it.
A consumer who never read the retry section gets that budget, and a consumer who has their own
retrier gets it *underneath* theirs.

**And it can never be the better of the two.** Everything the loop does — count, wait, give up — the
caller's retrier does knowing things the library cannot know. There is no configuration of a
three-number record that beats a scheduler with a persistent store.

What the library does know, and a caller cannot re-derive without repeating work that has already
been done here twice over, is two facts about a *response*:

- which statuses the RFCs treat as worth another attempt (429 and 5xx), which are a permanent
  rejection, and which mean the subscription is gone;
- what the push service's `Retry-After` actually said — delta-seconds, or any of the three HTTP-date
  forms a recipient must accept, with RFC 9110's two-digit-year rule and the leap-second case.

Neither is a loop. Both become values on the result, and the loop goes. That the parsed `Retry-After`
is today reachable *only* from inside the loop is the sharpest argument for doing both at once:
deleting the loop without surfacing the value would throw away the most careful code in the module.

**The result becomes a sealed hierarchy**, because with the loop gone the outcomes stop having the
same shape:

```java
public sealed interface PushResult {

    record Delivered(int statusCode) implements PushResult {}

    record SubscriptionExpired(int statusCode) implements PushResult {}

    record RetryableFailure(int statusCode, Optional<Duration> retryAfter, Optional<Throwable> cause)
            implements PushResult {}

    record NonRetryableFailure(int statusCode) implements PushResult {}
}
```

A `Retry-After` is meaningful on exactly one of the four; a cause exists on exactly one; a status code
of zero — which this record already documents as "no response was obtained" — is possible on exactly
one. Flattened into a single record, three of the four outcomes would carry two permanently empty
`Optional`s and the Javadoc would have to explain, in prose, which fields are populated when. This
repository's habit is to put that in the type system instead: `EndpointRule` is sealed so a rule kind
cannot be invented from outside, required values go into factory parameters so `build()` cannot
refuse over a missing one, and value types make transposable arguments inexpressible. An exhaustive
`switch` over four variants is the same move, and Java 21 is already the baseline that makes it free.

`attempts` is removed. The sender makes one POST and no longer has an attempt count to report; the
caller's retrier has one, and it is the only correct one. `isDelivered()` and `isSubscriptionExpired()`
go with it, and not because the convention stops blessing them — it blesses them explicitly, and
`isDelivered()` is the worked example it blesses them with. They go because an exhaustive `switch`
says the same thing and says it about all four outcomes at once, where a predicate is a question a
caller can decline to ask. That is ADR-007's own cost paragraph — a caller who ignores the result
keeps a dead subscription — answered better than a predicate answered it. The validation each variant
needs stays where the
current compact constructor put it — a negative status code still describes a send that cannot have
happened, and the record that would carry it still refuses it.

**The two failures are named for retryability, not for durability.** `RetryableFailure` and
`NonRetryableFailure` say what the RFC permits, which is a fact about the response the library can
actually establish. `TRANSIENT` and `PERMANENT` were considered and rejected as overclaiming: a 500
may well be permanent and the library has no way to know, so a name promising transience would be a
prediction dressed as a classification. The Javadoc says the same thing in its own words — a
retryable failure is one where another attempt is *legitimate*, never one where it will succeed.

The taxonomy is an action taxonomy rather than a cause taxonomy, which is why `SubscriptionExpired`
keeps its own variant beside two that are named for retryability: ADR-007 made a dead subscription a
result rather than an exception because pruning a store is expected control flow, and the caller's
four actions — nothing, delete the row, schedule another attempt, stop and record — are exactly what
the four variants select.

**The line between a result and an exception is redrawn to match**: what could differ on another
attempt is a result; what will fail identically until someone changes something is an exception.

- A transport failure becomes `RetryableFailure` with a status code of zero and the exception as its
  cause. The seam is unaffected — a `PushHttpClient` still signals transport failure by throwing
  `PushDeliveryException`, exactly as its contract says; it is the facade that stops rethrowing. Only
  that type converts: any other `RuntimeException` out of a transport propagates unchanged as a
  defect in the implementation, which is the rule `EndpointPolicy` already states for its own seam.
  Note the position this reverses: today the library retries statuses and declines to retry a
  transport failure at all, so calling one retryable is a new claim. It is the right one — a
  connection that timed out may well connect next time — and it was never the library's call to make.
- **An interrupted send is not a delivery outcome and stays an exception.** The transport converts an
  `InterruptedException` into a `PushDeliveryException`, so under the bullet above an interrupt would
  arrive labelled "another attempt is legitimate" and the caller's loop would spin — every retry
  failing instantly on an interrupt status nobody cleared. The carve-out is therefore a disjunction,
  and it is one because neither test alone is sound. A cause chain carrying an `InterruptedException`
  misses an interruption that surfaces as `ClosedByInterruptException` or `InterruptedIOException`,
  both of which are `IOException`s a transport will wrap without an `InterruptedException` anywhere
  beneath — the spin, exactly. The calling thread's interrupt status misses nothing but catches more
  than interruption: an ordinary connect timeout that merely raced a shutdown propagates too, which
  is not a false positive worth avoiding, since a caller whose thread is being shut down is better
  served by an exception than by an invitation to schedule another attempt. So: a
  `PushDeliveryException` propagates unconverted when its cause chain carries an `InterruptedException`
  **or** the current thread's interrupt status is set. Neither limb is free of the seam — a cause
  chain is a property of how a transport chose to report the failure, not of the failure — so the
  transport contract gains the requirement the shipped one already meets: a transport that meets an
  interruption re-sets the flag and attaches the cause. The disjunction is what keeps a transport
  that honours only one of the two from producing the spin.
- `EndpointRejectedException` and `IllegalArgumentException` keep propagating. A payload that does
  not fit will not fit next time either. A refused endpoint is treated as permanent **by decision**
  rather than by observation: `EndpointPolicy` is a consumer-implemented seam whose own contract
  contemplates a policy with mutable state or a name-resolution step, so a later attempt genuinely
  may be judged differently — and the library will not re-run a deployment's egress verdict on the
  caller's behalf, nor invite a caller to retry past one.
- A remote signer that cannot be reached gets its own type. `PushCryptoException` today covers both
  "this JVM has no `AES/GCM/NoPadding`" and "Vault did not answer", and says so deliberately in its
  own Javadoc — one type, with the message and the cause chain left to say which happened. Under the
  rule above that is no longer tenable, because those two sit on opposite sides of it. So a signer
  whose key service is unreachable throws `VapidSignerUnavailableException`, which the core maps to
  `RetryableFailure`, and `PushCryptoException` returns to meaning a cryptographic defect that will
  recur. It extends `RuntimeException` directly rather than the type it splits from: a subtype would
  let the old catch clause keep swallowing both, which is the ambiguity being removed.

The new type lives in the core, since both the core and the Vault module name it, and the package it
goes in is already exported. Its reach is wider than the send path and that is accepted rather than
scoped away: a signer may be unreachable at construction too — the Vault signer that fetches its
public key reads Vault inside `build()` — and there is no result for it to land in there, so it
simply propagates. The cost is precise and worth stating: a consumer catching `PushCryptoException`
around signer construction, or around a direct `sign` call, must add the new type to that clause or
the failure will fly past. That is the intended consequence of not subtyping, arriving in the one
place where no result exists to soften it.

What moves with it is the `VapidSigner` contract itself, which is the larger half and is dealt with
in the roll-call below rather than here: the SPI's published Javadoc names `PushCryptoException` for
a remote key service that cannot be reached, and ADR-018 decided that wording deliberately.

Apart from that type, this ADR decides only *which side of the line* each failure falls on. It does
change the surface in doing so: `PushDeliveryException` stops escaping `send` for every reason but
one, so the status-mapping row narrows to the interrupted send rather than disappearing — which is
the form the table takes wherever it is written down, and a narrower repair than deletion in the one
published argument that uses a *retryable* transport failure as its foil. What it does not touch is the
shape of the hierarchy: the `IllegalArgumentException` ambiguity reported as
https://github.com/the13haven/push2u/issues/87, and whatever the exception types settle into, are
that work's to decide.

**The documentation is the deliverable that replaces the removed code.** A library that hands the
retry decision to its caller owes that caller the material to decide with, and this is not a
paragraph added to a README section — it is the feature. Each variant's Javadoc states what it means
and what a caller does about it. `docs/DESIGN.md` carries the taxonomy, the status-mapping table with
its transport row narrowed to the interrupted send, and the two facts a caller must not get wrong on
its own: that
`Retry-After` is reported exactly as the service stated it, unclamped, so the caller's own ceiling is
the only one applied; and that RFC 8030's `TTL` counts from receipt, so a retry sent hours later
re-bases the message's lifetime unless the caller decrements the value it passes.

Four consumer-facing documents describe retry as a feature and all four move — `README.md`,
`docs/SPRING.md`, `docs/MIGRATION.md` and `docs/DESIGN.md` above — and two more move for a reason
other than retry. `README.md` loses its retry section, its feature bullet and its worst-case blocking
budget, and gains the worked `switch`; one of its arguments is collateral, since it justifies an
exception type by contrast with a *retryable* transport failure, and what escapes `send` afterwards
is the one transport failure that is not. `docs/SPRING.md` loses the `retry.*` property block and the
prose attributing a rejected bound to its key. `docs/MIGRATION.md` is the one that **inverts** and is
therefore the one to get wrong: it warns that
an application retry loop on top of push2u multiplies, and instructs the reader to delete theirs or
configure it away. After this decision the two libraries behave the same here, so that warning is
false and the instruction silently costs a reader their retry entirely. Its neighbouring promise —
that push2u does not retry a transport failure, so each outer attempt costs one POST rather than
three — survives, and becomes trivially true of every failure kind. Three more places in that file
carry retry outside the section: a comparison-table row, the builder-option list and two uses of the
attempt count. `docs/PERFORMANCE.md` needs nothing — checked, it measures the pipeline and never the
loop. The status mapping also appears in this repository's own instructions, which follow the same
edit. And `CONTRIBUTING.md` moves for a different reason than the rest: it uses `isDelivered()` three
times as the worked example of the boolean convention, on the one type this decision reshapes, so it
needs a different example rather than a smaller one.

The published sentences the change falsifies are its own category, because they ship in a
`sources.jar` to readers with no repository to check them against, and there are more of them than
the retry documentation suggests. Beyond the renewal margin's Javadoc and the comment beside the
token cache, which reason from the retry window directly: the threat model stated in two places on
the endpoint policy and its factories names the caller-visible pair — a status code *versus* a
`PushDeliveryException` — as what makes an unrestricted sender an SSRF oracle, and that pair becomes
a variant carrying a zero status code; the delivery exception's own class Javadoc enumerates "a
connection failure, a timeout, an interrupted send" and only the third survives it; the transport
seam's Javadoc says the sender "owns retry and status interpretation", of which half remains; and the
sender's class Javadoc says it interprets the status into a result "with retries". None of these is a
comment to be deleted — each states a reason a consumer needs, and each needs the reason restated for
what the code now does.

## What this rules out

A retry loop inside the sender, in any configuration. A retry SPI, a policy interface, or any other
seam whose subject is retrying — ADR-005's enumeration of three seams is untouched, and this is the
rare change that removes the question rather than answering it. A retrying wrapper shipped from this
repository, in the core or in a module of its own: the loop a caller writes over `send` is a dozen
lines with everything it needs on the result, and shipping one would put the library back into
competition with the retrier the deployment already has, on the losing side. A library-defined
resumable state or a serialization format for one, since there is no state to resume: a send holds
nothing across attempts that a second call would not rebuild — the endpoint policy re-runs, the VAPID
token is re-minted or served from its cache (ADR-019), and the body is re-encrypted under a fresh
ephemeral key and salt, which RFC 8291 requires per message and permits, without requiring, for a
retransmission of one. `RetryAfter.parse` as public API, which the report also asks for: it is needed
only by the workaround the report describes, and once the parsed value is on the result there is no
caller left for it. A `PushResult` that reports an attempt count it no longer controls, or a field
whose meaning depends on which outcome it was attached to.

The report's own primary proposal is ruled out with the rest, and it deserves naming because it is
the first thing a later reader will reach for: keep the loop, add a `Retry-After` component to
`PushResult`, change nothing else. It is minimal, it is very nearly non-breaking, and it would have
worked. It is rejected because it fixes the symptom the reporter could see and leaves the cause they
described — a scheduler in the library, competing with theirs, that they had already switched off.
The result would be a library that owns a retry loop nobody in a durable deployment can use, and a
result type that exists to make opting out of that loop survivable.

## What it costs, and what it does not

There is no migration for the reporter: they already configure one POST per call, so nothing they run
today changes shape. They gain the parsed `Retry-After` — their actual request — and the
classification they currently re-derive from the status code, and they stop having to remember to
disable a loop. `0.1.0` shipped and its release note declared `0.x` the window for revising names and
constructor forms once real integrations exist; this is that revision, and the next release note
carries it. The other consumers a compatibility argument would be made for do not exist, and this
decision is taken on what the library needs to be rather than on their behalf.

`Optional<Throwable>` on a record is the one shape here worth flagging: a `Throwable` compares by
identity, so two `RetryableFailure` values describing the same timeout are unequal. That is
acceptable — results are switched on, not compared — but it is the same class of trap ADR-019
recorded for a `byte[]` cache key, and it is written down for the same reason. The alternative is to
split `RetryableFailure` into a service failure and a transport failure, at which point every field
is populated on every variant and the coarse "should I retry" question needs a sealed marker over
both. Five types and a marker for one conditional field is the worse trade today; it is where to go
if the conditional cause proves awkward in practice.

The suites go with the code: `RetryPolicyTest` and `SleeperTest` cease to have a subject, as does the
recording sleeper in the shared test fixtures, and the RFC vectors in `RetryAfterTest` keep theirs —
they simply reach it through the result instead of through the loop. The parser stays
package-private; what becomes public is what it produced.

Two defaults elsewhere were derived partly from the retry window and are deliberately left where they
are. The async executor's rationale gives two reasons its tasks block for a long time — the
synchronous HTTP call and the backoff sleeps between retries — and loses the second; the worst case
shrinks to one request timeout, and the library-owned virtual-thread executor stays the default
anyway, because a blocking synchronous HTTP call still has no business on the common pool. Only the
size of the claim changes.

The VAPID renewal margin is the sharper case, and the honest word for what happens to it is that it
stops being *derived*. ADR-019 sized the five minutes against the send: a token picked up just before
the boundary had to still be valid at that send's last retry, and with a `Retry-After` honoured up to
the backoff ceiling the reachable worst case was around two minutes, with the clocks as the room on
top. Delete the retries and the sized quantity is gone — the worst case becomes a single POST. The
default nonetheless does not move, for a reason ADR-019 states in the same breath and which now has
to carry it alone: skew against a push service checking `exp` on its own clock is minutes whatever
the token's lifetime is, and the margin costs 0.7 % of a twelve-hour token's life. Five minutes is
retained rather than recomputed, and that distinction is the whole content of this paragraph. ADR-019
is immutable and cannot say it, which is why it is said here; the published sentences that reason
from the retry window, in the margin's own documentation and in the comment beside the cache, are
among the ones this change falsifies and rewrites.

## What else moves, and what does not

ADR-007 is superseded in one clause. Its decision — that `404` and `410` are an ordinary result the
caller inspects rather than exception-driven control flow — is not merely kept but extended, and the
argument it made for making the state visible is what an exhaustive `switch` over a sealed hierarchy
serves better than a predicate did. What does not survive is its next sentence: *"Exceptions stay for
what they are for — a transport failure (`PushDeliveryException`), a cryptographic failure
(`PushCryptoException`), an endpoint the deployment's policy refuses (`EndpointRejectedException`)."*
Two of those three move, one of them with a carve-out. A transport failure becomes a result except
where the send was interrupted; the cryptographic failure splits, and the half that names an
unreachable key service becomes a result too. The spelling ADR-007 uses for its own decision — a
`Status` enum constant and an `isSubscriptionExpired()` predicate — changes with it, but that is a
spelling and not a clause: the decision is that the expiry is a value the caller inspects, and a
`SubscriptionExpired` variant is that value.

**ADR-018 is superseded in one clause too**, and it is the clause that took the most care to write.
Deciding where the second structural check on the encoded public key lives, ADR-018 settled that a
`PushCryptoException` raised by `publicKey()` itself — naming, in its own words, *"a remote custodian
that is unreachable"* — propagates untouched because it is already the right type, and that an
override may signal failure with that type and no other. The sentence that rule produced is published
on the `VapidSigner` contract, and it is where the cost really falls: an override uses that type
*"so that one signer does not answer for one value in two exception types"*. After this decision a
Vault-backed signer does answer for one value in two types —
the new one when the custodian cannot be reached, `PushCryptoException` when what it returned is the
wrong shape. ADR-018's reason is understood and overridden rather than overlooked. It optimised for
one signer speaking one language about one value; this decision splits on a different axis — whether
the failure will recur — and that axis is the one a caller who now owns the retry has to read. The
rest of ADR-018 stands untouched: the encoding, the name, the placement of the shape check, the
`NullPointerException` for a `null` key, and the conformance kit's agreement, which asserts no
exception types and so needs nothing.

ADR-007 and ADR-018 are the only two that move, and each in a single clause; both keep their status
lines until the decision is implemented, as ADR-004's did until ADR-019 was. ADR-004 is untouched and
reinforced: the library holds no per-send state, and this decision removes the one loop that came
closest to holding some. ADR-005 is untouched and not superseded — no seam is added, and the one this
ADR nearly added is ruled out above. ADR-010's pluggable key custody is untouched: which signer a
deployment uses is unchanged, and only what one of them throws moves. ADR-019 is untouched in its
decision; one derivation loses the quantity it was sized against, as recorded in the paragraph above.
ADR-011's size limit is unaffected — nothing here reaches the request-shaping path. ADR-016 and
ADR-017 keep their decisions, but not because this change stays away from them: it decides something
about the endpoint policy above, that a refusal is permanent by decision, and ADR-016 illustrates its
own threat model with the very pair this ADR reshapes — a status code against a
`PushDeliveryException`, plus timing, as the blind SSRF oracle an unrestricted sender offers. The
security property survives for a reason that has nothing to do with how a failure is reported: the
policy still runs first and unconditionally, before the encryption, the signature and any I/O, so
what a rejection *is* has not moved. Only the shape of what a later failure is reported as, which the
oracle argument used as an illustration rather than as its mechanism.
