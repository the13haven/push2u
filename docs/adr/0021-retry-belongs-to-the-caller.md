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
`RetryPolicy`, the `Sleeper` seam, the loop and the `push2u.retry.*` properties are removed, and no
retry mechanism replaces them: no SPI, no shipped retrying wrapper, no separate retry module.

Three things make that a boundary rather than an abdication.

**Every deployment that sends push at volume already owns a retrier** — Spring Retry, Resilience4j, a
job engine, a queue with redelivery — and the library's loop integrates with none of them. It
competes, and it competes from ignorance: it cannot see the deployment's retry budget, its
dead-letter path, its concurrency limit, or what survives a restart. The reporter's situation is that
competition in its plainest form, two retriers in one call path, discovered by symptom.

**It is on by default, so it wins that competition by accident.** On the shipped defaults `send` — a
method that looks like one POST — can block for 93 seconds: three attempts at the transport's
30-second per-request timeout, plus one and two seconds of computed backoff. A push service answering
`429` with a large `Retry-After` raises that to three and a half minutes, since an honoured hint is
capped only at the 60-second ceiling the computed schedule never reaches. Both figures need the
service to *answer* slowly rather than to time out, because a timeout is not retried today at all —
which is itself part of what makes the budget hard to predict from the outside.

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

*Keep the loop but default it to one attempt* answers the second reason above and neither of the
others. The loop still cannot see what the deployment's retrier sees, and it still has to be carried:
its tests, its Spring properties, its coupling to the VAPID renewal margin, and an exception surface
where every failure has to be decided twice — once for the loop and once for the caller. It also
leaves `Retry-After` needing to be surfaced anyway, so it buys nothing that removal does not.

*Split the retryable failure into a service failure and a transport failure*, five variants under a
sealed marker, removes the conditional fields the adopted shape keeps (below). It is rejected as the
worse trade today, not as wrong; it is where to go if those fields prove awkward.

## What the library keeps, and in what shape

Two things about a *response* would otherwise be re-derived by every caller, and neither is a loop:

- the classification of a status — worth another attempt, a permanent rejection, or a dead
  subscription. This is the library's own convention rather than an RFC's clause: RFC 8030 mentions
  `429` once, in passing, and RFC 9110 defines the 5xx class without ruling on retrying it. Being a
  convention is why it is worth publishing — a caller reproducing it is reproducing a judgement, not
  reading a specification.
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
the current record already documents as "no response was obtained" — is possible on one. Flattened
into a single record, three of the four outcomes carry two permanently empty `Optional`s and the
Javadoc has to explain in prose which fields are populated when. The sealed form does not remove that
problem so much as confine it: `RetryableFailure` still carries two fields of which one is empty
whenever the other is not, which is the trade the five-variant alternative above would close.

The two failure variants are named for what the library decided about them, not for what it predicts
about the world. `TRANSIENT` and `PERMANENT` were the alternative and claim knowledge the library
does not have — a 500 may well be permanent. `RetryableFailure` claims only that this library
classifies the response as worth another attempt; the Javadoc says so in those terms, and says that
another attempt is *legitimate* rather than likely to succeed.

The taxonomy is one of actions rather than of causes, which is why `SubscriptionExpired` keeps a
variant beside two named for retryability: ADR-007 made a dead subscription a result because pruning
a store is expected control flow, and the caller's four actions — nothing, delete the row, schedule
another attempt, stop and record — are what the four variants select.

`attempts` is removed: the sender makes one POST and has no count to report, while the caller's
retrier has one and it is the only correct one. `isDelivered()` and `isSubscriptionExpired()` go too,
and not because the convention stops blessing them — it blesses them by name. They go because an
exhaustive `switch` puts all four outcomes in front of a caller who has decided to read the result,
where a predicate lets that caller read one and forget the rest. Each variant keeps the validation
the current compact constructor carries: a negative status code still describes a send that cannot
have happened.

## The line between a result and an exception

**What could differ on another attempt is a result; what will fail identically until someone changes
something is an exception.** Applying it:

- **A transport failure becomes `RetryableFailure`** with a status code of zero and the exception as
  its cause. The push transport seam keeps its contract — a `PushHttpClient` still signals transport
  failure by throwing `PushDeliveryException` — and it is the facade that stops rethrowing. Only that
  type converts; any other `RuntimeException` out of a transport propagates as a defect in the
  implementation, which is the rule `EndpointPolicy` already states for its own seam. This reverses
  the library's current position, which retries statuses and declines to retry a transport failure at
  all, and the reversal is right: a connection that timed out may well connect next time.
- **A signer whose key service cannot be reached becomes `RetryableFailure` too.**
  `PushCryptoException` today covers both "this JVM has no `AES/GCM/NoPadding`" and "Vault did not
  answer", deliberately and in its own words. Those sit on opposite sides of the line, so a signer
  that cannot reach its key service throws `VapidSignerUnavailableException` and `PushCryptoException`
  returns to meaning a cryptographic defect that recurs. The new type extends `RuntimeException`
  directly rather than the type it splits from: a subtype would let the existing catch clause keep
  swallowing both, which is the ambiguity being removed. It lives in the core, whose package is
  already exported, because the core reads it and the Vault module raises it.
- **`EndpointRejectedException` and `IllegalArgumentException` keep propagating.** A payload that does
  not fit will not fit next time. A refused endpoint is different and is an exception by decision
  rather than by observation: `EndpointPolicy` is consumer-implemented and its contract contemplates
  mutable state and name resolution, so a later attempt genuinely may be judged differently — and the
  library will not invite a caller to retry past a deployment's egress verdict.
- **An interrupted send is an exception**, and this is the second override of the rule rather than an
  instance of it: an attempt after the flag is cleared might well succeed. It is not a delivery
  outcome, and reporting it as a retryable one makes the caller's loop spin — every retry failing
  instantly on an interrupt status nobody cleared. The conversion is therefore skipped, on both the
  push and the signer paths, when the cause chain carries an `InterruptedException` **or** the current
  thread's interrupt status is set. Neither test alone is sound: an interruption surfacing as
  `ClosedByInterruptException` or `InterruptedIOException` carries no `InterruptedException` beneath
  it, and a transport may attach a cause without re-setting the flag or the reverse. The obligation
  to do both is added to the transport contracts, which the shipped implementations already meet.

`VaultHttpTransport` — the fourth seam ADR-005 names — keeps its contract unchanged, including
`PushCryptoException` on a Vault transport failure. It faces Vault rather than the caller, and the
translation belongs at the boundary the core actually reads: `VaultTransitVapidSigner` raises the new
type. That keeps one seam's vocabulary out of the other's, which is the reason ADR-005 gave for
having two.

Everything else about the exception surface — the `IllegalArgumentException` ambiguity reported as
https://github.com/the13haven/push2u/issues/87, and what shape the hierarchy settles into — belongs
to that work. This ADR decides which side of the line each failure falls on, and needs one new type
to be able to say it.

## What replaces the removed code

**The documentation is the deliverable**, and not as a paragraph appended to a README section. A
library that hands the retry decision to its caller owes that caller the material to decide with.
Four rules govern the rewrite; the file-by-file inventory belongs to the implementation task, not to
a record that cannot be corrected once it is settled.

*The status mapping is rewritten rather than amended*, wherever it appears. Every row changes: the
result column is variants instead of enum constants, the failure row splits in two, the transport row
narrows to the interrupted send, and the crypto row splits with half of it becoming a result.

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

*Published sentences are their own category, and they are restated rather than deleted.* They ship in
a `sources.jar` to readers with no repository to check them against, and they are more numerous than
the retry documentation suggests: `send`'s own `@throws` clauses and their twin on `sendAsync` state
this decision's subject directly; the SSRF threat model on the endpoint policy, its factories and the
migration guide names a status code *versus* a `PushDeliveryException` as the oracle, and that pair
becomes a variant carrying a zero status code; `EndpointRejectedException` justifies its existence by
contrast with a transport failure "worth retrying"; the delivery and crypto exceptions each enumerate
what they cover; the transport seam says the sender owns retry; the sender's own class Javadoc says it
interprets a status "with retries"; the renewal margin's Javadoc and the comment beside the token
cache reason from the retry window; and `Ticker` explains itself by reference to `Sleeper`.

The suites follow the code. Those that exist for the loop — the retry policy's, the sleeper's, the
recording sleeper in the shared fixtures — lose their subject outright. Those that encode the loop or
the attempt count in the shape of their assertions are rewritten rather than adjusted: the status
classification suite, whose subject is the enum being replaced, the `Retry-After` cases in the sender
suite that assert against a recorded sleep, and the starter's property tests, including the
filler-combination assertions that pin the property-name attribution trick, which goes with the
properties. The `Retry-After` parser's own vectors are untouched: they call the parser directly, and
the parser is unchanged and stays package-private. What becomes public is what it produced. The
response queue in the shared fixtures exists so that one send can consume several answers, and
becomes a queue of one.

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

**ADR-018 is superseded in one clause too.** Settling where the second structural check on the
encoded public key lives, it decided that a `PushCryptoException` raised by `publicKey()` itself —
naming *"a remote custodian that is unreachable or refuses to publish the key"* — propagates
untouched because it is already the right type, and that an override signals failure with that type
and no other. The sentence that rule produced is published on the `VapidSigner` contract, and that is
where the cost lands: an override uses that type *"so that one signer does not answer for one value
in two exception types."* After this decision a Vault-backed signer does — the new type when the
custodian cannot be reached, `PushCryptoException` when what came back is the wrong shape. ADR-018's
reason is understood and overridden, not overlooked: it split by value, and this splits by whether
the failure recurs, which is the axis a caller who now owns the retry has to read. The rest of
ADR-018 stands — the encoding, the name, the placement of the shape check, the `NullPointerException`
for a `null` key, and the conformance kit's agreement, which asserts no exception types.

Those two are the only ADRs whose decisions move, and each keeps its status line until this one is
implemented, as ADR-004's did until ADR-019 was. ADR-004 is untouched and reinforced: the library
holds no per-send state, and this removes the loop that came closest to holding some. ADR-005 adds no
seam and loses none, and both of the contracts this decision reaches — the push transport's
interruption obligation and `VapidSigner`'s exception vocabulary — are changes within seams rather
than to the enumeration ADR-005 defends; its own reasoning for keeping the Vault transport separate is
what decides where the signer translation goes, above. ADR-010's pluggable key custody is untouched:
which signer a deployment uses does not change, only what one of them throws. ADR-019 keeps its
decision; one derivation loses the quantity it was sized against, as recorded above. ADR-011's size
limit is unaffected. ADR-016 and ADR-017 keep theirs, and not because this change stays away from the
egress path — it decides something there, that a refusal is permanent by decision. ADR-016's threat
model rests on what a caller can observe being an oracle, and that mechanism survives in a new shape:
a variant with a zero status code where an exception used to be. It is closed by the same thing it
always was — the policy runs first and unconditionally, before the encryption, the signature and any
I/O, so neither what a rejection is nor when it is reached has moved.
