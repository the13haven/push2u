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

**It is on by default, so it wins that competition by accident.** The shipped default is three
attempts with a ceiling of sixty seconds per wait, which makes `send` — a method that looks like one
POST — a call that can legitimately block a thread for over two minutes. A consumer who never read
the retry section gets that behaviour, and a consumer who has their own retrier gets it *underneath*
theirs.

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
caller's retrier has one, and it is the only correct one.

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
- `EndpointRejectedException` and `IllegalArgumentException` keep propagating. A refused endpoint and
  a payload that does not fit are decisions about the request, and they will be the same decision on
  every attempt.
- A remote signer that cannot be reached gets its own type. `PushCryptoException` today covers both
  "this JVM has no `AES/GCM/NoPadding`" and "Vault did not answer", and says so deliberately in its
  own Javadoc — one type, with the message and the cause chain left to say which happened. Under the
  rule above that is no longer tenable, because those two sit on opposite sides of it. So a signer
  whose key service is unreachable throws `VapidSignerUnavailableException`, which the core maps to
  `RetryableFailure`, and `PushCryptoException` returns to meaning a cryptographic defect that will
  recur. It extends `RuntimeException` directly rather than the type it splits from: a subtype would
  let the old catch clause keep swallowing both, which is the ambiguity being removed.

That last point is the only claim this ADR makes about the exception surface. The rest of it — the
`IllegalArgumentException` ambiguity reported as
https://github.com/the13haven/push2u/issues/87, and whatever shape the hierarchy settles into — is
that work's to decide. What is decided here is the boundary, not the taxonomy: this ADR says which
side of the line each failure falls on, and it needs exactly one new type to be able to say it at all.

**The documentation is the deliverable that replaces the removed code.** A library that hands the
retry decision to its caller owes that caller the material to decide with, and this is not a
paragraph added to a README section — it is the feature. Each variant's Javadoc states what it means
and what a caller does about it. `README.md` gains the worked `switch`. `docs/DESIGN.md` carries the
taxonomy and the two facts a caller must not get wrong on its own: that `Retry-After` is reported
exactly as the service stated it, unclamped, so the caller's own ceiling is the only one applied; and
that RFC 8030's `TTL` counts from receipt, so a retry sent hours later re-bases the message's
lifetime unless the caller decrements the value it passes.

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
ephemeral key and salt, which is what RFC 8291 asks of a message in any case. `RetryAfter.parse` as
public API, which the report also asks for: it is needed only by the workaround the report describes,
and once the parsed value is on the result there is no caller left for it. A `PushResult` that
reports an attempt count it no longer controls, or a field whose meaning depends on which outcome it
was attached to.

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

The suites go with the code: `RetryPolicyTest` and `SleeperTest` cease to have a subject, and the
RFC vectors in `RetryAfterTest` keep theirs — they simply reach it through the result instead of
through the loop. The parser stays package-private; what becomes public is what it produced.
