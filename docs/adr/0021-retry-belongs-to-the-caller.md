# ADR-021 — Retry belongs to the caller

**Status:** Proposed

`PushSender.send` retries. Three separable things are welded into one `for` loop: **which** responses
may be retried at all, which is a private static naming 429 and the whole 5xx class; **how long** to
wait and **when to stop**, which is `RetryPolicy`, a record of three numbers whose backoff doubles
until a ceiling stops it; and **who executes** the schedule, which is the loop itself — one thread,
inside one call, sleeping through every wait. A parseable `Retry-After` overrides the computed
schedule, clamped at the same ceiling, from code in `PushSender` rather than in the record. Only the
middle of the three is configurable, and only in the numbers the record holds.

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
drafted in that shape and the shape was wrong. The questions it needed answering were what a policy
that throws does to a send, which of the two clocks measures elapsed time, who bounds a policy that
never gives up, whether a held thread is acceptable, and what a driver would have to be handed across
a restart. Not one of them is a question about Web Push. When a feature's design cost is five open
questions in a neighbouring domain, the feature is in the wrong library.

## The decision

**The library does not retry.** `PushSender.send` performs exactly one POST and returns what happened.
`RetryPolicy`, the internal sleep indirection, the loop and the `push2u.retry.*` properties are
removed, and no retry mechanism replaces them: no SPI, no shipped retrying wrapper, no separate
retry module.

Three things make that a boundary rather than an abdication.

**Every deployment that sends push at volume already owns a retrier** — Spring Retry, Resilience4j, a
job engine, a queue with redelivery — and the library's loop integrates with none of them. It
competes, and it competes from ignorance: it cannot see the deployment's retry budget, its
dead-letter path, its concurrency limit, or what survives a restart. The reporter's situation is that
competition in its plainest form, two retriers in one call path, discovered by symptom.

**It is on by default, so it wins that competition by accident.** On the shipped defaults `send` — a
method that looks like one POST — has a blocking budget approaching 93 seconds: three attempts, each
bounded by the transport's 30-second per-request timeout, plus one and two seconds of computed
backoff. A push service answering `429` with a large `Retry-After` raises the bound to three and a
half minutes, since an honoured hint is capped only at the 60-second ceiling the computed schedule
never reaches. Both are bounds rather than reachable durations: each attempt has to *answer* just
short of its timeout, because a timeout is not retried today at all. That a caller cannot easily tell
which of the two bounds applies to them is part of the same problem.

**And it can never be the better of the two.** Everything the loop does — count, wait, give up — the
caller's retrier does knowing things the library cannot know. No configuration of three numbers beats
a scheduler with a persistent store.

Three alternatives were considered and rejected.

*Surface `Retry-After` on the result and keep the loop*, which is what the report itself proposes, is
the one a later reader will reach for first: minimal, very nearly non-breaking, and it would have
worked. It fixes the symptom the reporter could see and leaves the cause they described — a scheduler
in the library, competing with theirs, which they had already switched off. What it produces is a
library owning a retry loop nobody in a durable deployment can use, and a result type whose reason to
exist is making the opt-out survivable.

*Keep the loop, default it off, and surface `Retry-After` anyway* is the strongest form of the middle
option, and the one that has to be answered rather than the weak form. It disarms the second reason
outright: a loop nobody gets without asking cannot win by accident, and the competition becomes one a
deployment opts into. It also has the one benefit removal does not — no existing caller is broken by
it. Both are conceded. What it does not answer is that the loop still has to be *carried*: its tests,
its Spring properties, its coupling to the VAPID renewal margin, and — the clause that decides it —
an exception surface where every failure has to be classified twice, once for the loop and once for
the caller, in two vocabularies that this decision is about unifying. The third reason survives too,
in the form the alternative leaves it: offering a mechanism that no deployment sending at volume
should use is a commitment to maintaining it for the deployments that use it by not knowing better.
The compatibility benefit is real and is outweighed by what the next section says about who is being
weighed here.

*Split the retryable failure into a service failure and a transport failure*, five variants under a
sealed marker, is an alternative to one field layout inside the decision rather than to the decision.
It removes the conditional fields the adopted shape keeps (below), and is rejected as the worse trade
today rather than as wrong; it is where to go if those fields prove awkward.

*Hand the caller a resumable send*, the third shape the pluggable reading took, needs no mechanism
and so gets none: a send holds nothing across attempts that a second call would not rebuild. The
endpoint policy re-runs, the VAPID token is re-minted or served from its cache (ADR-019), and the
body is re-encrypted under a fresh ephemeral key and salt — which is what this library does for every
message in any case, RFC 8291 §2 having the application server generate both per message and being
silent on what a retransmission may reuse. There is no state to serialize, so there is no schema for
the library to publish and then have to version.

## What the library keeps, and in what shape

Two things about a *response* would otherwise be re-derived by every caller, and neither is a loop:

- the classification of a status — worth another attempt, a permanent rejection, or a dead
  subscription. Parts of it have a specification behind them and the whole does not, which is exactly
  why it is worth publishing. RFC 8030 §8.4 has a push service answer a rate-limited delivery with
  `429` and says it SHOULD carry a `Retry-After` saying how long to wait before the next request to
  that resource; RFC 9110 §15.6.4 says a `503`'s condition is temporary and that the server MAY send
  a `Retry-After` suggesting how long to wait before retrying. Those two clauses are the warrant for
  honouring the header at all. Nothing says the same for the rest of the 5xx class, which the library
  treats as retryable anyway, so the *set* is its own judgement stitched from two specified cases and
  a generalisation. A caller reproducing it is reproducing a judgement, not reading a specification.
- what the push service's `Retry-After` said — delta-seconds, or any of the three HTTP-date forms a
  recipient must accept, with RFC 9110's two-digit-year rule and the leap-second case.

Both become values on the result. That the parsed `Retry-After` is today reachable *only* from inside
the loop is why the two changes are one: deleting the loop without surfacing the value would discard
the parser's whole output.

The result becomes a sealed hierarchy, because with the loop gone the outcomes stop sharing a shape:

```java
public sealed interface PushResult {

    record Delivered(int statusCode) implements PushResult {}

    record SubscriptionExpired(int statusCode) implements PushResult {}

    record RetryableFailure(int statusCode, Optional<Duration> retryAfter, Optional<Throwable> cause)
            implements PushResult {}

    record NonRetryableFailure(int statusCode) implements PushResult {}
}
```

A `Retry-After` is meaningful on one of the four; a cause exists on one; a status code of zero — which
the current record already documents as meaning none was obtained — is possible on one. Flattened
into a single record, three of the four outcomes carry two permanently empty `Optional`s and the
Javadoc has to explain in prose which fields are populated when. The sealed form does not remove that
problem so much as confine it: `RetryableFailure` still carries two fields of which one is empty
whenever the other is not, which is the trade the five-variant alternative above would close.

The two failure variants are named for the library's own verdict, not for a property of the world.
`TRANSIENT` and `PERMANENT` were the alternative and claim knowledge nobody here has — a 500 may well
be permanent. `RetryableFailure` claims only that this library judges another attempt legitimate, and
the Javadoc says it in those terms: legitimate rather than likely to succeed. The verdict is about
the attempt and not about a response, which is what lets the same variant carry the two failures
where no response exists at all — a transport that never connected and a key service that could not
be reached.

The taxonomy is one of actions rather than of causes, which is why `SubscriptionExpired` keeps a
variant beside two named for retryability: ADR-007 made a dead subscription a result because pruning
a store is expected control flow, and the caller's four actions — nothing, delete the row, schedule
another attempt, stop and record — are what the four variants select.

`attempts` is removed: the sender makes one POST and has no count to report, while the caller's
retrier has one and it is the only correct one. `isDelivered()` and `isSubscriptionExpired()` go too,
and not because the convention stops blessing them — it blesses the form, and uses `isDelivered()`
itself as its worked example, so this decision also costs that document the example it teaches with.
They go because an exhaustive `switch` puts all four outcomes in front of a caller who has decided to
read the result, where a predicate lets that caller read one and forget the rest. Each variant keeps
the validation the current compact constructor carries: a negative status code still describes a send
that cannot have happened.

## The line between a result and an exception

**What could differ on another attempt is a result; what will fail identically until someone changes
something is an exception.** Applying it:

- **A transport failure becomes `RetryableFailure`** with a status code of zero and the exception as
  its cause. A `PushHttpClient` still signals transport failure by throwing `PushDeliveryException`,
  so what it throws does not change; it is the facade that stops rethrowing. Only that type converts:
  any other `RuntimeException` out of a transport propagates as a defect in the implementation, which
  is the rule `EndpointPolicy` already states for its own seam. This reverses the library's current
  position, which retries statuses and declines to retry a transport failure at all, and the reversal
  is right: a connection that timed out may well connect next time.
- **A signer whose key service cannot be reached becomes `RetryableFailure` too.**
  `PushCryptoException` today covers both "this JVM has no `AES/GCM/NoPadding`" and "Vault did not
  answer", deliberately and in its own words. Those sit on opposite sides of the line, so
  unreachability gets `VapidSignerUnavailableException` and `PushCryptoException` returns to meaning
  a cryptographic defect that recurs — everywhere, including inside the Vault module. The new type
  extends `RuntimeException` directly rather than the type it splits from: a subtype would let the
  existing catch clause keep swallowing both, which is the ambiguity being removed. It lives in the
  core, whose package is already exported, because the core reads it and the Vault module raises it.
- **`EndpointRejectedException` and `IllegalArgumentException` keep propagating.** A payload that does
  not fit will not fit next time. A refused endpoint is the rule's first override: `EndpointPolicy` is
  consumer-implemented and its contract contemplates mutable state and name resolution, so a later
  attempt genuinely may be judged differently — it is an exception by decision rather than by
  observation, because the library will not invite a caller to retry past a deployment's egress
  verdict.
- **An interrupted send is an exception**, and this is the rule's second override rather than an
  instance of it: an attempt after the flag is cleared might well succeed. It is not a delivery
  outcome, and reporting it as a retryable one makes the caller's loop spin — every retry failing
  instantly on an interrupt status nobody cleared. The conversion is therefore skipped, on both the
  push and the signer paths, when the cause chain carries an `InterruptedException` **or** the current
  thread's interrupt status is set. Neither test alone is sound: an interruption surfacing as
  `ClosedByInterruptException` or `InterruptedIOException` carries no `InterruptedException` beneath
  it, and a transport may attach a cause without re-setting the flag or the reverse.

Both transport seams therefore take the same two obligations, and `VaultHttpTransport` — the fourth
seam ADR-005 names — takes them as a change to its published contract rather than as nothing. It
must signal an unreachable Vault distinguishably from a failure that will recur, and it must meet the
interruption requirement above. Today it throws `PushCryptoException` for both sides at once: its
contract spans no connection, a timeout **and** an oversized response, and its shipped implementation
adds an unusable request URI and an illegal request header — the documented instance being a token
from a YAML block scalar that ends with a newline. A signer translating that on the way out would
have to discriminate on a message or a cause chain, which is the ambiguity this decision exists to
remove, and would hand a caller a `RetryableFailure` for a trailing newline in a token. So the split
belongs at the seam, where the transport knows which of its own failures it raised, and
`VaultTransitVapidSigner` translates nothing.

This is not the seam's vocabulary changing on ADR-005's account: the Vault transport already speaks a
core exception type, and ADR-005 kept the two transports apart for a different reason — opposite
trust domains, one of which must read a response body and the other must never. That reason is
untouched, and it is why the split is stated for each seam separately rather than once for a shared
one.

Everything else about the exception surface — the `IllegalArgumentException` ambiguity reported as
https://github.com/the13haven/push2u/issues/87, and what shape the hierarchy settles into — belongs
to that work. This ADR decides which side of the line each failure falls on, and needs one new type
to be able to say it.

## What replaces the removed code

**The documentation is the deliverable**, and not as a paragraph appended to a README section. A
library that hands the retry decision to its caller owes that caller the material to decide with.
Four rules govern the rewrite; the file-by-file inventory belongs to the implementation task, not to
a record that cannot be corrected once it is settled.

*The status mapping is rewritten rather than amended*, wherever it appears. Its result column becomes
variants instead of enum constants, so every row is touched; the failure row splits in two; and both
the transport and the crypto rows split, though not alike. The transport row keeps an exception only
for the interrupted send, everything else about it having become a result. The crypto row keeps one
for every cryptographic failure that recurs — a missing algorithm, a key of the wrong shape, a
custodian that answers and refuses — and loses only unreachability to the new type, which is then
itself an exception when the send was interrupted. The one row that survives unchanged is the policy
rejection, which stays an exception outright.

*Two facts a caller must not get wrong on its own are stated where a caller will meet them*: that
`Retry-After` is reported with no ceiling applied, so the caller's own is the only one; and that
RFC 8030's `TTL` counts from receipt, so an attempt sent hours later re-bases the message's lifetime
unless the caller decrements what it passes.

*The migration guide inverts and is the one document that is dangerous rather than merely stale.* It
warns that an application retry loop on top of push2u multiplies, and instructs the reader — in prose
and again as a numbered step — to delete theirs. After this decision push2u behaves as the library
being migrated from does, so the warning is false and the instruction silently costs a reader their
retry. Its neighbouring promise, that an outer attempt costs one POST rather than three, survives and
becomes trivially true.

*Sentences that reason from the removed behaviour are restated rather than deleted*, and a rule
rather than a list is what finds them, because a list in a record that cannot be corrected is worse
than none. Three shapes qualify, wherever they appear — in Javadoc, in a comment, in a reference
document. A sentence that **names what a send throws**, whether as a contract, an enumeration of what
an exception covers, or a contrast that borrows one to explain another type's existence. A sentence
that **reasons from the retry window** — a duration, a margin, a budget, or an indirection justified
by the sleeps. And a sentence that **uses the observable difference between a status and an exception
as an argument**, which is how the SSRF threat model states its oracle in every place it is stated,
and which after this decision is a variant carrying a zero status code rather than an exception.

Two things make that rule load-bearing rather than tidy. The first is that these ship in a
`sources.jar` to readers with no repository to check them against — which is true of the Javadoc and
the comments, while the reference documents are caught by the same rule for the same reason a
consumer reads them. The second is that the most on-point sentences of all are `send`'s own `@throws`
clauses and their twin on `sendAsync`: they state this decision's subject directly, and a rewrite
that started from a list would be a rewrite that could omit them.

The suites follow the same rule as the sentences: those whose subject is the loop, the attempt count,
the removed properties or the replaced enum are rewritten rather than adjusted, and the shared
fixtures that exist to feed a loop several answers go with them. The `Retry-After` parser's own
vectors are the exception worth naming, because they look like they should move and do not: they call
the parser directly, and the parser is unchanged and stays package-private. What becomes public is
what it produced.

## What it costs

The reporter's channel already makes one POST per call, so its retry logic is unaffected — but its
result handling is not, and neither is anyone's: the result type changes shape and a transport
failure stops arriving as an exception. `0.1.0` shipped and its release note declared `0.x` the
window for revising names and constructor forms once real integrations exist; this is that revision,
and the next release note carries it. There is no second consumer whose upgrade path is being weighed
here, and the decision is taken on what the library should be. The one consumer-visible cost worth
stating precisely is the new exception type outside the send path: a signer may be unreachable at
construction, where no result exists to land in, so a `catch (PushCryptoException)` around signer
construction or a direct `sign` call must add the new type or the failure flies past. That is the
intended consequence of not subtyping, arriving in the one place where nothing softens it.

`Optional<Throwable>` on a record compares by identity, so two `RetryableFailure` values describing
the same timeout are unequal. Results are switched on rather than compared, so this is accepted — and
written down, because it is the class of trap ADR-019 recorded for a `byte[]` cache key.

Two defaults elsewhere were derived partly from the retry window and deliberately do not move. The
async executor's rationale gives two reasons its tasks block for a long time, the synchronous HTTP
call and the backoff sleeps, and loses the second; the library-owned virtual-thread executor stays,
because a blocking HTTP call still has no business on the common pool. The VAPID renewal margin is
the sharper case, and the honest word is that it stops being *derived*: ADR-019 sized five minutes
against a worst-case send of about two minutes, with clock skew as the room on top. Delete the
retries and the sized quantity is gone. The default is retained rather than recomputed, because skew
against a push service checking `exp` on its own clock is minutes whatever the token's lifetime is,
and the margin costs 0.7 % of a twelve-hour token's life. ADR-019 is immutable and cannot say this,
which is why it is said here.

## What else moves, and what does not

**ADR-007 is superseded in one clause.** Its decision — that `404` and `410` are an ordinary result
the caller inspects rather than exception-driven control flow — is kept and extended. What does not
survive is its next sentence: *"Exceptions stay for what they are for — a transport failure
(`PushDeliveryException`), a cryptographic failure (`PushCryptoException`), an endpoint the
deployment's policy refuses (`EndpointRejectedException`)."* Two of those three move. The spelling
ADR-007 uses for its own decision — an enum constant and a predicate — changes with it, but that is a
spelling and not a clause: the decision is that the expiry is a value the caller inspects, and a
variant is that value.

**ADR-018 is superseded in half of one clause.** Settling where the second structural check on the
encoded public key lives, it decided that a `PushCryptoException` raised by `publicKey()` itself —
naming *"a remote custodian that is unreachable or refuses to publish the key"* — propagates
untouched because it is already the right type, and that an override signals failure with that type
and no other. Of the two cases that clause names, only the unreachable one moves; a custodian that
answers and refuses is a decision that will be repeated, and keeps `PushCryptoException`. The rule
ADR-018 set produced a sentence now published on the `VapidSigner` contract, and that is where the
cost lands: an override uses that type *"so that one signer does not answer for one value in two
exception types."* After this decision a Vault-backed signer does. ADR-018's reason is understood and
overridden, not overlooked: it refused to split at all, holding one value to one type, and this
splits by whether the failure recurs — the axis a caller who now owns the retry has to read, and one
ADR-018 had no reason to consider. The rest of it stands: the encoding, the name, the placement of
the shape check, the `NullPointerException` for a `null` key, and the conformance kit's agreement,
which asserts no exception types.

Those two are the only ADRs whose decisions move, and each keeps its status line until this one is
implemented, as ADR-004's did until ADR-019 was. ADR-004 is untouched and reinforced: the library
holds no per-send state, and this removes the loop that came closest to holding some. **ADR-005's
enumeration of seams is untouched — none is added and none removed** — but three of the four
contracts it names do change: both transports take the interruption obligation and the
unreachable-versus-recurring split, and `VapidSigner` takes the exception vocabulary above. Those are
changes *within* seams rather than to which seams exist, which is what ADR-005 decides. Its reasoning
survives untouched too, and is quoted above for what it does and does not say. ADR-010's pluggable
key custody is untouched: which signer a deployment uses does not change, only what one of them
throws. ADR-019 keeps its decision; one derivation loses the quantity it was sized against, as
recorded above. ADR-011's size limit is unaffected. ADR-016 and ADR-017 keep theirs, and not because
this change stays away from the egress path — it decides something there, recorded above as the
rule's first override. ADR-016's threat model rests on what a caller can observe being an oracle, and
that mechanism survives in the new shape the documentation rules describe. It is closed by the same
thing it always was — the policy runs first and unconditionally, before the encryption, the signature
and any I/O, so neither what a rejection is nor when it is reached has moved.
