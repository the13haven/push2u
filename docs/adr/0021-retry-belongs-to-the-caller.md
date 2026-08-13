# ADR-021 — Retry belongs to the caller

**Status:** Proposed

`PushSender.send` retries. Three separable things are welded into one `for` loop: **which**
responses may be retried, a private static naming 429 and the whole 5xx class; **how long** to wait
and **when to stop**, which is `RetryPolicy`, a record of three numbers whose backoff doubles until
a ceiling stops it; and **who executes** the schedule, which is the loop itself — one thread, inside
one call, sleeping through every wait. A parseable `Retry-After` overrides the computed schedule,
clamped at the same ceiling, from code in `PushSender` rather than in the record. Only the middle of
the three is configurable, and only in the numbers the record holds.

Reported as https://github.com/the13haven/push2u/issues/86, with the exception clauses below reviewed
under https://github.com/the13haven/push2u/issues/128, from the deployment where that bites
hardest: a sender whose retries are *durable*. There the next attempt is a job the engine
reschedules minutes or hours later, across a process restart or a deploy, and a `Thread.sleep`
inside `send` cannot participate in it — it holds a worker for the wait and its state dies with the
process. So the sender is configured for one attempt per call and the application owns backoff,
expiry and the 404/410 delete. The complaint is precise: the consumer that most needs the push
service's `Retry-After` is the one configuration that cannot see it, and it reschedules on a blind
exponential backoff that may POST again well before the service said it would accept anything — the
exact harm the header exists to prevent.

**This record owns the retry removal and the reshaping of the sender**, and it owns nothing else:
that the library does not retry; `PushOutcome` and its variants; the two status matrices, the push
service's and the custodian's; the surfacing of `Retry-After`; the line between an outcome and an
exception; and which signal from which seam becomes which outcome. Classifying a failure is this
record's work throughout, at the Vault transport's seam as much as at the facade's, and so is which
of ADR-022's types a failure leaves a seam wearing. The exception *types* are ADR-022's — their
names, what each one promises and what each one carries, where each one is declared, and what a
caller catching one reads from it. Where this record names a type it is naming ADR-022's, and a
decision that moves one of those supersedes that record rather than this one. This is written down so that
whoever supersedes either knows which half they are replacing.

## The decision

**The library does not retry.** `PushSender.send` performs exactly one POST and reports what became
of it. `RetryPolicy`, the internal sleep indirection, the loop and the `push2u.retry.*` properties
are removed, and no retry mechanism replaces them: no SPI, no shipped retrying wrapper, no separate
retry module.

**Every deployment that sends push at volume already owns a retrier** — Spring Retry, Resilience4j,
a job engine, a queue with redelivery — and the library's loop integrates with none of them. It
competes from ignorance: it cannot see the deployment's retry budget, its dead-letter path, its
concurrency limit, or what survives a restart. The reporter met that in the form it takes once the
collision has been noticed: they turned the library's loop off, and lost with it the one value only
that loop could see.

**It is on by default, so it wins that competition by accident.** On the shipped defaults `send` — a
method that looks like one POST — has a blocking budget approaching 93 seconds: three attempts, each
bounded by the transport's 30-second per-request timeout, plus one and two seconds of computed
backoff. A `429` carrying a large `Retry-After` raises the bound to three and a half minutes, since
an honoured hint is capped only at the 60-second ceiling the computed schedule never reaches. Both
are bounds rather than reachable durations — each attempt has to *answer* just short of its timeout,
a timeout itself not being retried today — and that a caller cannot easily tell which bound applies
is part of the same problem.

**And it can never be the better of the two.** Everything the loop does — count, wait, give up — the
caller's retrier does knowing what the library cannot. No configuration of three numbers beats a
scheduler with a persistent store.

The obvious alternative is to make the retry *pluggable* rather than absent: a policy behind a seam,
a driver the caller supplies, a resumable state the caller persists. It is rejected because every
question that shape opens — what a policy that throws does to a send, which clock measures elapsed
time, who bounds a policy that never gives up, what a driver would be handed across a restart — is a
question about retrying and none is a question about Web Push. Five further alternatives were
weighed and are recorded here for the reader who will reach for one of them:

- **Surface `Retry-After` and keep the loop**, which the report itself proposes, fixes the symptom
  and leaves the cause: a scheduler in the library, competing with the caller's, which they had
  already switched off.
- **Keep the loop but default it off** disarms the accident and nothing else. The loop still has to
  be carried — its tests, its properties, its coupling to the VAPID renewal margin — and every failure
  still has to be classified twice, once for it and once for the caller.
- **Hand the caller a resumable send** needs no mechanism: a send holds nothing across attempts that
  a second call would not rebuild. The endpoint policy re-runs, the VAPID token is re-minted or served
  from its cache (ADR-019), and the body is re-encrypted under a fresh ephemeral key and salt, which
  is what this library does per message in any case — RFC 8291 §2 has the application server generate
  both per message and says nothing about what a retransmission may reuse.
- **Declare a checked exception** so the compiler forces the handling. Rejected mechanically rather
  than stylistically: a checked contract does not travel across `CompletableFuture`, so it would
  oblige the synchronous caller and say nothing to the asynchronous one — the path recommended for
  volume. A guarantee that holds on half an API is worse than none.
- **Catch everything inside the sender** so `send` becomes total. This launders defects: a
  `NullPointerException` from a bug here would arrive as a value indistinguishable from an outcome,
  and *broken* would stop being distinguishable from *unsuccessful*.

## What the library keeps

Two things about a response would otherwise be re-derived by every caller, and neither is a loop.

**The classification of a status.** Parts of it are specified and the whole is not, which is why it
is worth publishing. RFC 8030 §8.4 has a push service answer a rate-limited delivery with `429` and
SHOULD carry a `Retry-After`; RFC 9110 §15.6.4 says a `503`'s condition is temporary and MAY carry
one; §15.5.9 lets a client repeat after `408` and §15.5.20 lets it retry a `421` on another
connection. The rest is this library's judgement, and it is taken per status rather than per class,
because the class rule in the code today — `429` plus every 5xx — is wrong in both directions:
`408` and `421` are marked repeatable and it excludes them, and the 5xx class holds registered
statuses whose own defining specification has them answer about the request, about a configuration,
or about the sending host's network rather than about this delivery at all — and a repeat is
answered identically by each. So: `2xx` accepted; `404` and `410` expired; `408`, `421`, `429` and
the 5xx class **except `501`, `505`, `506`, `508` and `511`** retryable; `413` retryable when it
carries a parseable `Retry-After` and not otherwise, because there the header rather than the number
does the classifying, as the paragraph on `413` below sets out; everything else not.

**Each carve-out is its defining specification's own words rather than a guess about a service.**
RFC 9110 §15.6.2 has a `501` say the server does not support the functionality required to fulfil
the request, and §15.6.6 has a `505` say it does not support the major HTTP version the request
used; a byte-identical POST is answered identically by both. RFC 2295 §8.1 defines `506` as "the
server has an internal configuration error: the chosen variant resource is configured to engage in
transparent content negotiation itself", which is a property of a deployment and not of a moment —
it ends when someone edits a configuration, and repeating until then is exactly the pointless repeat
this matrix exists to spare a caller. RFC 5842 §7.2 has a `508` report that the server "terminated
an operation because it encountered an infinite loop while processing a request with `Depth:
infinity`" and that "the entire operation failed", which is a statement about the resource graph the
request named. And a `511` is not the push service's answer at all: RFC 6585 §6 says it "SHOULD NOT
be generated by origin servers" and is "intended for use by intercepting proxies that are interposed
as a means of controlling access to the network", so what it reports is that the *sending* host has
no network access — which no repeat of this POST obtains, and which no push service can grant.

**`507` stays retryable, and is named so that the next reader does not carve it out on the strength
of the class.** RFC 4918 §11.5 settles it in terms: the server "is unable to store the
representation needed to successfully complete the request", and "this condition is considered to be
temporary". Storage that has run out is a state of the server that an operator or an expiry ends,
which is the whole of what the retryable side means here. The same section's "MUST NOT be repeated
until it is requested by a separate user action" does not bind this caller: it governs a user agent
replaying a user's action, and an application server delivering a notification is not replaying one
— the party that owns the repeat here is a scheduler. **`510` is deliberately not named.** The IANA
registry carries it as "Not Extended (OBSOLETED)" against RFC 2774, a document the IETF has
reclassified Historic, and this library does not read a classification off a specification with no
standing. It falls to the rule below, which is the honest place for a number no push service is
expected to send.

**A 5xx the matrix does not name is retryable, and that direction is chosen rather than defaulted
into.** The ground is the class's own definition, the same one this record reads at the custodian's
seam: RFC 9110 §15.6 has a 5xx say the server "is aware that it has erred or is incapable of
performing the requested method", a statement about the server, where §15.5 has a 4xx say "the
client seems to have erred", a statement about the request. The costs are not symmetric either. On
this seam the caller owns the repeat, so a pointless one costs it a scheduled attempt, while a
wrongly permanent verdict costs a notification that nobody sends again. A positive list of retryable
statuses would invert that — every unregistered or later-registered 5xx would be permanent by
omission — so the carve-outs are named one at a time and the class carries everything else.

`413` is the single status whose class its own answer decides, and it is the one place a header
rather than a number does the classifying. RFC 9110 §15.5.14 has a server refusing a request for its
size generate a `Retry-After` *if the condition is temporary* — which makes the header that server's
own statement that it refused this moment rather than this request, the exact distinction the two
failure variants are named for. A `413` carrying a parseable `Retry-After` is therefore retryable,
and a bare one is not. The first draft classified every `413` as non-retryable on the ground that
this library's body is the same size on every attempt; that answers a question nobody asked, since a
temporary `413` says what the server could accept just then and nothing about how large the body is.
Carrying the header on the non-retryable variant instead was the alternative: it would have kept the
value from being discarded — which the section below promises — while handing the caller a hint that
contradicts the variant's name. The header *is* the classification here, so it travels on the
variant the classification produces.

**What the `Retry-After` said** — delta-seconds or any of the three HTTP-date forms a recipient must
accept, with the two-digit-year rule and the leap second. It is reported with no ceiling applied, so
the caller's own is the only one. That this parsed value is today reachable *only* from inside the
loop is why the two changes are one: deleting the loop without surfacing it discards the parser's
whole output. It is reported where the classification leaves it actionable, which is the retryable
variant: a header on a response that has answered something about the request itself advises a wait
before repeating a request whose answer will not have changed. `413` is the one status whose
temporary reading the header alone supplies, and it is on the retryable side when it carries one for
exactly that reason — everywhere else the number says whether the moment or the request was refused,
and the header only says for how long.

That revises the report rather than meeting it, and the revision is said out loud because a promise
quietly dropped is worse than one argued down. https://github.com/the13haven/push2u/issues/86 asks
for the last response's `Retry-After` to be preserved whatever the outcome, `SubscriptionExpired`
included, and this decision publishes it on the retryable variant alone. The paragraph above is the
whole of the reason: on `404` and `410` the subscription is gone and the only correct action is to
delete it, so a wait the service named would be reported to a caller that has nothing left to wait
for.

## The outcome

`PushResult` is renamed `PushOutcome` and becomes a sealed hierarchy. The rename is not cosmetic:
the old name described the result of the HTTP attempts, and the type now reports what became of a
*requested send* — accepted, rejected, never attempted, or attempted with no answer.

```java
public sealed interface PushOutcome {

    record Accepted(int statusCode) implements PushOutcome {}

    record SubscriptionExpired(int statusCode) implements PushOutcome {}

    record RetryableFailure(int statusCode, Optional<Duration> retryAfter) implements PushOutcome {}

    record NonRetryableFailure(int statusCode) implements PushOutcome {}

    /** No POST was made, so nothing can have been delivered and a repeat cannot duplicate. */
    sealed interface NotAttempted extends PushOutcome {}

    /** Carries a cause, so a class rather than a record, for Indeterminate's reason. */
    final class SignerUnavailable implements NotAttempted {
        /* status(), retryAfter(), cause(), toString() */
    }

    record PayloadRejected(int payloadBytes, int maximumPayloadBytes) implements NotAttempted {}
    record EndpointRejected(...) implements NotAttempted {}

    /** No answer was obtained, and whether the service received the message is unknown. */
    final class Indeterminate implements PushOutcome { /* cause(), and a redacting toString() */ }
}
```

`NotAttempted` is a marker and its leaves implement it directly, so a caller switches once and
chooses its own grain: `case NotAttempted n` takes the group, `case PayloadRejected p` takes the one
carrying sizes. A variant wrapping a nested failure object was drafted and rejected for forcing two
dispatches on one decision. Each leaf carries exactly the fields its case has: a shape admitting a
combination that cannot occur costs more than a type does. The `413` rule above leaves one such
residue and it is accepted rather than designed away — `RetryableFailure(413, empty)` is
representable and cannot arise, since a bare `413` is classified as non-retryable. The alternative
is a variant per status, which pays a type for one dead pair.

**`Accepted`, not `Delivered`.** RFC 8030 §5 has the service answer with `201 Created` and is
explicit that this means the message was accepted for delivery, not that a user agent received it;
it may still expire undelivered. The constant being replaced is named `DELIVERED` while its own
Javadoc says "the push service accepted the message" — the code has known better than its name since
it was written. A delivery receipt needs RFC 8030's receipt subscription, which this library does
not implement.

**Two independent questions, and no single flag answers both.** A caller asks whether a repeat is
*safe* — could it duplicate a notification — and whether it is *useful* — could it come out
differently. Only one answer to the first is structural: under `NotAttempted` no POST was made — a
signer may well have called out over a network, but the push service was never asked for anything —
so a repeat provably duplicates nothing. `Indeterminate` is the declared unknown at the other end.
The answered failures sit between them, and the honest reading of an answer is weaker than *safe*:
it proves that something refused the request, and where that something is the push service the
message was provably not accepted. `502` and `504` are the named exception — RFC 9110 §15.6.3 and
§15.6.5 define both as an intermediary reporting that it received no valid, or no timely, response
from upstream, so the upstream may have applied the POST and answered into a connection nobody read.
That is `Indeterminate`'s situation wearing a status code. The library does not reclassify the two
into `Indeterminate`, because it cannot tell an intermediary's `502` from a push service's own, and
inventing that distinction would manufacture the wrong "definitely not sent" the paragraph above
refuses to produce. So `RetryableFailure` states that a repeat is *useful* and states nothing about
whether it is safe; RFC 9110 §9.2.2 leaves a non-idempotent repeat to a client that knows the first
request was never applied, and the caller is the only party here who can know that or price a
duplicate. (`Accepted` is not in the comparison: it is not a failure, and repeating it duplicates by
definition.) Usefulness is what the variants name.

A `RetryAdvice` enum was considered and rejected as a retry policy under another name; a single
`ResponseRejected` leaving classification to the caller was rejected because it deletes what the
section above keeps and pushes every caller into guards on status numbers. A `switch` made of guards
is not exhaustive, so each caller re-derives the judgement and carries its own copy of it; under the
adopted shape no caller has to name `501`, or any of the four statuses carved out beside it, at all.

The two names state a verdict about *this response*, not a forecast about the endpoint. `TRANSIENT`
and `PERMANENT` were the alternative and describe the failure's nature, which nobody here knows — a
`500` may well be permanent. `NonRetryableFailure` says the service has answered something about the
request itself, so an identical request has been answered already; `RetryableFailure` says it has
answered something about its own moment, so an identical request has not been. Neither promises what
the next attempt returns.

`attempts` is removed: the sender makes one POST and has no count to report, while the caller's
retrier has one and it is the only correct one. `isDelivered()` and `isSubscriptionExpired()` go
with it — not because the convention stops blessing predicates: it blesses the form, and uses
`isDelivered()` as the worked example it teaches with, which this decision therefore takes away from
`CONTRIBUTING.md` and from this repository's own instructions. They go because an exhaustive
`switch` puts every case in front of a caller who has decided to read the outcome, where a predicate
lets that caller read one and forget the rest. Each variant keeps the validation the current compact
constructor applies to it.

## The line between an outcome and an exception

**An outcome describes what became of a requested send, whether or not a POST was reached. An
exception is reserved for using the API wrongly, for a defect the caller cannot act on per send, and
for cancellation.** Everything a fan-out meets in normal running arrives as a value; nothing a
caller must decide about is delivered by a channel the compiler does not mention. The first draft
drew the line at "a POST was attempted", which was tidy and bad for the caller: it split one logical
operation across `switch` and `catch`, and across `CompletionException` under `sendAsync`.

- **A POST that goes unanswered is `Indeterminate`, and the library refuses to call it retryable.**
  A push POST is not idempotent: RFC 8030 §5 has a successful one create a new push message resource,
  and RFC 9110 §9.2.2 says a client should not automatically retry a non-idempotent request unless it
  knows the request was never applied. A read timeout after the request went out is exactly where
  nobody knows — the service may have accepted the message and lost the answer — so a repeat may
  deliver a second notification. Neither failure variant can carry that case, and the reason is not
  the duplicate: both report what an answer said about itself, and here nothing answered, so there is
  no more ground to call a repeat *useful* than to call it safe. Filing it under `RetryableFailure`
  would put the one case in which no evidence whatever bounds the duplicate risk behind a name the
  caller reads as a recommendation, where every answered failure at least carries somebody's refusal.
  The variant exists so that the unknown is named rather than averaged into a verdict, and what to
  spend on it is left to an application whose tolerance for a duplicate the library cannot see.
  `Topic` narrows that window without closing it. The library also does not split the case into
  "definitely not sent" and "unknown" even where the shipped transport could tell them apart, because
  `PushHttpClient` is a consumer seam and a wrong "definitely not sent" produces the very duplicate
  the variant prevents.

  **Indeterminacy is a property of what was called, not of how the call broke.** The same timeout,
  raised by the same JDK HTTP client, is not indeterminate when it happened on the way to the
  custodian: a signing request has no effect on the push service, so whatever became of it no
  notification exists to be duplicated by a repeat. That is the whole of why the next bullet is
  `NotAttempted` while this one is not — the failure modes are identical and the operations are not,
  and reading the symmetry off the exception instead of off the operation would hand a caller a
  false duplicate risk every time its key custodian hiccuped.
- **A key service that cannot sign *now* is `NotAttempted`.** `PushCryptoException` today covers
  both "this JVM has no `AES/GCM/NoPadding`" and "Vault did not answer", deliberately and in its own
  words, and no caller can act on a type meaning both. The split stays but becomes *internal*: a
  signer signals a custodian that cannot serve this send with `VapidSignerUnavailableException`, the
  sender catches it and reports the outcome, and `PushCryptoException` returns to meaning a
  cryptographic defect that recurs. A missing or hostile provider algorithm is such a defect and
  keeps throwing.

  **The axis is whether the failure recurs, not whether the custodian answered.** A custodian that
  answers is not thereby refusing permanently, and reading it that way would rebuild the very
  duality this decision removes — an operational condition arriving as an unchecked exception the
  fan-out has to catch out of band. The question to put to an answer is whether it describes the
  custodian's own condition — or that of a service it called — or the request that was made. Vault
  answers about itself in so many words for most of its error statuses: `500` "try again later",
  `503` "down for maintenance, currently sealed, or temporarily overloaded", `412` a request that
  cannot be processed *yet* under eventual consistency and one that "should be retried, perhaps
  with a little backoff", `501` "Vault is not initialized", `429` the default for a standby node's
  health and also "Too Many Requests", `473` the same for a performance standby, `472` the same for
  "disaster recovery mode replication secondary and active", `502` a third party Vault itself
  called. Each of those is `SignerUnavailable` — every one of them names a state of the cluster, or
  of a service the cluster itself called, that ends when an operator or a replication catches up or
  a third party comes back, and none of them names anything about the request. The last of the three
  is what recurs: `400`, `403`, `404` and `405` — a malformed call, a token without the capability,
  a key or mount that is not there, a method the path does not take — and so is a response Vault
  could not have meant, an unparseable signature or a key that is not on P-256. Those stay
  `PushCryptoException`, alongside a defect and a misconfiguration.

  Those lists are the worked cases and the question is the rule, because a status neither list names
  will arrive — from a version of Vault later than this text, or from a proxy in front of it. It
  falls by the same question, and the class answers it where the vendor does not: RFC 9110 §15.6 has
  a 5xx say the server "is aware that it has erred or is incapable of performing the requested
  method", which is a statement about the custodian, and §15.5 has a 4xx say "the client seems to
  have erred", which is one about the request. So an unrecognised 5xx is `SignerUnavailable` and an
  unrecognised 4xx is a defect — which is why `472` and `473` are named above rather than left to the
  fallback: both are 4xx numbers carrying a statement about the cluster, and only the vendor's own
  table says so.

  `501` is the sharpest illustration that this is deliberately not the push service's matrix. There
  it is carved out of the retryable 5xx class, because a push service answering "not implemented"
  has answered about the request and will answer the same next time; here Vault publishes it as "not
  initialized", a cluster state that ends the moment someone initializes it. The same number, the
  opposite class, and neither reading is a judgement this library makes — each is the vendor's, read
  off the specification that governs that seam. The asymmetry underneath is in what a mistake costs:
  there the caller owns the repeat and a pointless one costs it a scheduled attempt, while here the
  alternative to waiting is a fan-out aborted by an operator's maintenance window.

  **A signer that reaches over a network says so honestly.** The other half of what a remote
  custodian produces is no answer at all — a refused connection, a TLS handshake that failed, a
  timeout — and `PushCryptoException`'s own text concedes what happens to it today: it records that a
  signer backed by a remote key service reports its transport failures as a cryptographic one, that
  the Vault Transit signer does exactly this for a request timeout and a dropped connection, and that
  the message and the cause chain rather than the type say which happened. That was a fair trade
  while every failure left through the exception channel and a human read all of them. It stops being
  one when the caller reads outcomes: a dropped connection is not a cryptographic failure, and
  filing it as one costs an operator the first thing they would have looked at. So it leaves as
  `VapidSignerUnavailableException` too, and reaches the caller as the same `SignerUnavailable` the
  answered half produces.

  Which type that is, why `PushDeliveryException` is not reused for a failure of the same shape, and
  why the two halves — nothing answered, against a custodian that answered a refusal for now — take
  one type rather than two, are ADR-022's to settle, and it settles them there. What this record
  needs of that type is only what a seam signal has to give a facade: that it be distinguishable from
  a defect, so that a custodian's outage converts to an outcome and a broken provider does not.
  `PushCryptoException`'s own reasoning is not discarded wholesale in that move — the half of it that
  survives is named in ADR-022, beside the narrowing. What does not survive is what this record
  takes away: bundling a defect in with an outage.

  This half is the one place the axis is not settled by recurrence, and the reason is that recurrence
  is not on offer: nothing answered, so nothing states whether the condition will hold next time. A
  host name with a typo recurs identically forever and arrives here indistinguishable from a Vault
  that is down for an hour — no test this library could run tells the two apart, and the same move is
  made on the answered side when the class decides a status the vendor's table does not name. The one
  member of this half a test *does* reach is the interruption, and it is reached by the facade's
  disjunction rather than by anything the seam decided — which is why a send reports it as a
  cancellation while a `build()`, having no facade over it, sees the unavailable custodian the seam
  raised. For the rest, it falls to the honest side, where "cannot sign now" is true of both, and a
  permanent one surfaces where this decision has just put every other exhausted repeat: in the
  caller's retry budget and the dead-letter path at the end of it. The alternative is a guess, and a
  guess wrong in the likelier direction turns a maintenance window into an aborted fan-out.

  **A custodian that declares when to come back has that declaration reported.** `SignerUnavailable`
  carries an `Optional<Duration>` retry hint, the same shape and the same meaning `RetryableFailure`
  carries for the push service's `Retry-After`. The reason is the reason this decision exists: the
  caller now owns the repeat, and repeating before the moment a service named is the harm the header
  was invented to prevent. That harm does not become acceptable because the service refusing is the
  one holding the key rather than the one holding the subscription. Where Vault answers with a hint,
  the caller's scheduler is the only place it can be honoured, and dropping it in the sender would
  put the library back in the position the report opened with — parsing a value the one component
  able to act on it never sees.

  The hint is absent far more often than it is present, and that is ordinary rather than a defect in
  the shape. `LocalEcVapidSigner` never fills it — a key in a configuration file has no moment it
  becomes available again — and neither does a PKCS#11 token or a KMS refusing on quota. Vault fills
  it on a `429` alone, and there only where an operator has set `enable_rate_limit_response_headers`,
  which HashiCorp documents as defaulting to false. An earlier draft removed the field over exactly
  that arithmetic, and the arithmetic proves too much, because `RetryableFailure`'s own hint is
  optional for the same reason. Most of the statuses that variant covers — `408`, `421`, `500`, `502`
  and `504` — have no `Retry-After` provision in any specification this decision cites, and `503`'s
  is a *MAY*. Two have one: RFC 8030 §8.4's *SHOULD* on `429`, and RFC 9110 §15.5.14's on a `413`,
  which is the whole of why a `413` is classified where it is. Nobody proposes deleting the field
  over the statuses that leave it empty, because a field earns its place on the case where it is
  filled, so long as its absence is the ordinary reading rather than a surprise. The parallel is
  tighter than an analogy: on both seams the case that fills the hint is the rate-limited one, and on
  both it is the case where repeating early is worst.

  **The status the custodian answered with is reported beside the hint.** `SignerUnavailable` carries
  it as an `OptionalInt`: filled where something answered a number, empty for `LocalEcVapidSigner`,
  for a PKCS#11 token, for a KMS refusing on quota, and for the whole of the half where nothing
  answered at all. The field itself is fixed in ADR-022 with the rest of the exception's shape, since
  it has to cross the seam before it can cross the facade; what this record decides is that the
  outcome publishes it rather than swallowing it.

  An earlier draft withheld it, on the ground that `VapidSigner` is implemented by a PKCS#11 token, a
  cloud KMS and a file-backed key as well as by Vault, and that an HTTP number would oblige all of
  them to speak a protocol one of them has. That is the sum the paragraph above has just run for the
  hint, and it came out the other way: an optional field obliges nobody, and it earns its place on
  the case where it is filled. Applying it one way to a `Duration` and the other way to an `int` is
  an inconsistency and not a distinction. What withholding it costs is plainer still. Every answered
  outcome on the push side carries its `statusCode`, and this was the one seam where the answer
  arrives from a custodian and no number crosses — an asymmetry with no argument behind it — so an
  operator reading a `SignerUnavailable` out of a log at three in the morning has prose and nothing
  else.

  **It is the custodian's status and never a push service's**, and the two must not be read as one
  number: a `503` here is a sealed or overloaded Vault and no POST was made, where a `503` on
  `RetryableFailure` is the push service refusing a delivery. It is also a diagnostic rather than a
  classification the caller re-derives — the signer has already classified, which is why the outcome
  exists at all, and a caller that re-branches on the number is rebuilding a matrix this record
  publishes for it. What it is for is the log line, the metric label and the operator. It costs the
  redaction invariant nothing, which is why `SignerUnavailable`'s written `toString()` may print it:
  a status is an integer, and an integer discloses no capability URL.

  It is not free. `VaultHttpResponse` carries a status and a body today, so the hint has to cross
  that record before it can cross the signer: a second change to a published type in the Vault
  module, beside the transport's exception split above. That is the price of the header reaching the
  only component that can act on it, and it is the same price this decision pays on the push side.
  The status adds nothing to that bill — the record already carries it, and it is the signer that
  throws it away today, which is the whole of what the paragraphs above change.

  Key material that cannot be used is not in this category at all: `Subscription`'s constructor
  already applies the full on-curve check and refuses such a value at the boundary that supplied it,
  deliberately, so no outcome needs to exist for it and none is added.
- **An endpoint the policy refuses is `NotAttempted`.** The first draft threw, reasoning that an
  SSRF control should not be swallowed by a `switch` branch. The stronger argument runs the other way:
  one hostile row must not abort a fan-out over a hundred thousand subscriptions, which is a denial of
  service a deployment inflicts on itself. The policy did its job — the request never left — and the
  application records a bad row and continues.
- **A payload that does not fit is `NotAttempted`.** It is a fact about one message rather than
  about the deployment: the case that made it concrete is a translated notification that fits in one
  language and not another, discovered in production. Killing a service over it is the wrong
  behaviour. The variant covers both preconditions the pre-flight check enforces — the configured
  ceiling on the encrypted body and RFC 8291 §4's record-size rule — because both are the same
  statement, that this payload does not fit this sender's configuration, and splitting them would make
  the caller ask which bound it hit before it can shorten anything.

  **It says so in the units the caller can act in.** `payloadBytes` is the plaintext the caller
  handed over and `maximumPayloadBytes` is the largest plaintext this sender would have carried,
  which is the smaller of what the two preconditions each permit. Both convert exactly: the body
  ceiling less the fixed 103 octets of `aes128gcm` framing, and `rs` less the padding delimiter and
  the authentication tag and one more, because RFC 8291 §4 requires `rs` to be strictly greater. A
  first draft reported the encrypted body's size against the configured ceiling, and it fails the
  bullet above on its own terms twice over. It hands a caller the number it did not choose and cannot
  shorten, leaving it to subtract a framing constant the library never told it; and where the
  record-size rule is what refused, the two numbers describe a comparison that *passed* — a payload
  can sit well inside the body ceiling and still exceed an `rs` configured below it, and then the
  outcome would report a body size nothing rejected, against a limit nothing reached.

  This is not ADR-011 moving. That decision is about where the limit is *configured* — on the
  encrypted body, so an operator raising it for a push service documented to accept more converts
  nothing by hand — and it already derives the plaintext maximum from the configured one, naming
  3993 bytes at the 4096-byte default. What the outcome reports is that derivation, which the
  pre-flight check's own message already names beside the encrypted pair it leads with.

  Something is lost by collapsing the two bounds, and it is not the caller's. Today each precondition
  refuses in a sentence naming its own parameter and, for the record-size rule, the value to raise it
  to; a pair of numbers names neither. But that sentence answers a question about the configuration
  rather than about this message: an `rs` that binds before the body ceiling does so for every
  payload this sender will ever be handed, so it is knowable the moment both values are set and needs
  no per-send channel to be discovered. An operator holding the two configured numbers reads which
  one bound from the maximum reported, and ADR-011 decided deliberately that the two stay
  independent, so that raising one without the other rejects the message rather than quietly
  re-framing it. What the caller wanted — how much fits — it now has without arithmetic.

  This decides https://github.com/the13haven/push2u/issues/87 rather than deferring to it. That
  report asks for the size refusal to be told apart from a malformed subscription, and proposes a
  typed exception carrying the encrypted body's size against the configured ceiling.
  `PayloadRejected` supersedes the proposed class and answers the same need through the outcome
  channel, and the subscription's own refusals stay where they are, on a different method.

  **On one point the report is overruled rather than followed.** It rules the plaintext length out in
  terms — "reporting a plaintext number here would re-open" ADR-011's decision that the limit is
  expressed on the encrypted body. It does not: ADR-011 settles where the limit is *configured*, and
  reporting a number it already derives re-opens nothing, as the paragraphs above set out. The
  report's own account of the case is what decides it — the failing side is a healthy subscription
  and "a notification the application must render smaller", and what an application renders is
  plaintext. That the report proposed the encrypted pair regardless is not a preference it stated for
  converting by hand; it is the ADR-011 reading, corrected above, deciding the question for it. What
  remains open there is the separate question raised in its thread — whether the refusal should also
  be answerable *before* a send — which needs no decision here.
- **An interrupted send stays an exception** — the one thing above that is not an outcome. A request
  may well have gone out, but the caller asked to stop, and handing back a value it is expected to act
  on answers the wrong question; reporting it as retryable would be worse, since the loop spins, every
  attempt failing instantly on an interrupt status nobody cleared. The conversion to an outcome is
  refused, on both the push and the signer paths, when the cause chain carries an
  `InterruptedException` **or** the current thread's interrupt status is set — and what leaves instead
  is a cancellation type of its own, `PushInterruptedException`, so that a caller reads the
  cancellation from the type rather than from whichever seam happened to be blocked when it arrived.
  What that type promises a caller — which differs between `send` and `sendAsync`, because an
  interrupt status does not travel through a `CompletableFuture` — is fixed in ADR-022 with the rest
  of the taxonomy. Neither test alone is sound: an interruption surfacing as
  `ClosedByInterruptException` or `InterruptedIOException` carries no `InterruptedException`
  beneath it, and a transport may attach a cause without re-setting the flag. This is a send's rule:
  a signer that reads its key inside `build()` is outside it, and what an interruption there raises
  is the seam's own type, with the flag set for whoever is supervising the boot to test first.

What still throws is misuse and defect: a `null` where the contract forbids one, a builder
configured with a value it rejects, a JCE provider that cannot do `AES/GCM/NoPadding`, an unexpected
`RuntimeException` out of a consumer-written seam, a violated internal invariant, and the
interrupted send above — which is what "cancellation" means here, since `CompletableFuture.cancel`
does not interrupt a running task and so never reaches this path at all. None of those yields a
per-send action and none belongs in a retry queue, and there the list divides. A defect or a
misconfiguration should reach a human, because nothing else clears it. A cancellation should reach
nobody: nothing failed, the caller asked to stop, and paging someone over a shutdown is an alarm
this decision exists to remove rather than to relocate. It is propagated, not retried and not
reported.

The seams keep signalling as they do now — `PushHttpClient` throws `PushDeliveryException`,
`EndpointPolicy` throws `EndpointRejectedException`, and a signer that cannot sign now throws
`VapidSignerUnavailableException` — and it is the facade that stops rethrowing. **Those three types
convert and no others**, which is the whole of the enumeration: any other `RuntimeException` from a
consumer implementation stays a defect and propagates, which is the rule `EndpointPolicy` already
states for its own seam. The list is written out because the interrupt discipline below depends on
it — a type outside it never reaches the facade's test — and a two-item version of it, from before
the signer had a type of its own, would silently strand both that type's outcome and that test.

**No outcome discloses a capability URL unless the caller asks for it by name.** The `NotAttempted`
leaves carry a redacted endpoint or a structured reason, never a raw one, and `Indeterminate` is a
class with a written `toString()` rather than a record precisely because a record's generated one
prints its components and a JDK transport exception's cause chain can embed the subscription URL.

`cause()` is the one deliberate way out, and the invariant is about the paths a caller does not
choose: `toString()`, the `equals`, `hashCode` and component printing a record would have generated,
and a bean-convention serializer, which finds no getter on this type. Calling the accessor is a
choice, and its own Javadoc says what the returned chain may contain and that logging it verbatim
publishes a capability URL — the same responsibility a caller takes today when it catches
`PushDeliveryException` and logs that. Replacing the chain with a sanitised diagnostic — an
enumerated reason, or a message with the URL stripped — was the alternative and is rejected: the
facade has just swallowed the transport's exception, so with the chain gone nothing anywhere can
still say why a send went unanswered, and `PushHttpClient` is a consumer seam whose failure modes
cannot be enumerated in advance, which makes a closed vocabulary over an open set. The exposure is
not new — a thrown `PushDeliveryException` carries the same chain today — and what changes is only
that a value must not print it by default, which is what the written `toString()` is for.

One security clause changes with the ceiling. Today the honoured `Retry-After` is clamped at
`maxBackoff` inside the loop; reported raw, a hostile push service can hand a caller's scheduler a
delay of any size a `long` of seconds expresses. That is the right trade — the caller's ceiling
should be the only one — but `SECURITY.md` names "a retry path a hostile push service can amplify"
among the things it treats as in scope, and after this decision the amplifiable path is the caller's
rather than ours. The clause needs restating, not deleting: what the library still owes is that the
value it reports is the value that arrived.

A limit worth stating rather than implying: neither channel forces meaningful handling. A checked
exception can be caught and dropped, an outcome can be discarded at the call site, and Java has no
`#[must_use]`. What the sealed hierarchy buys is that a caller who does switch has every case put in
front of them, and that there is one place to look.

`VaultHttpTransport` — the fourth seam ADR-005 names — takes a change to its published contract
rather than none. It must signal a Vault that cannot answer *now* distinguishably from a failure
that will recur, and meet the interruption requirement above. Today it throws `PushCryptoException`
for both at once: its contract spans no connection, a timeout **and** an oversized response, and its
implementation adds an unusable request URI and an illegal request header — the documented instance
being a token from a YAML block scalar ending in a newline. A signer translating that on the way out
would have to discriminate on a message or a cause chain, and would tell a caller that a trailing
newline is a transient condition. So that split belongs at the seam, and `VaultTransitVapidSigner`
translates none of it: no connection, a failed handshake and a timeout leave as
`VapidSignerUnavailableException` — the same three the signer paragraph names, since they are the
same failures seen from the seam that raises them — while the unusable URI, the illegal header and
the oversized response stay `PushCryptoException`, which is what each of them is. This is not the
seam's vocabulary changing on ADR-005's account — the Vault transport already speaks core exception
types, and ADR-005 separates the two transports over trust domains and response bodies, a reason
this leaves untouched.

**An interrupted exchange joins that side rather than opening a fourth**, and the rule that puts it
there is one line rather than a walk through failure modes. `HttpClient.send` declares two checked
exceptions, `IOException` and `InterruptedException`, and anything it throws means it returned no
response — so what it throws is an exchange with no answer, and leaves as
`VapidSignerUnavailableException`. There is exactly one carve-out, and the transport already digs it
out of the cause chain today: its own response-size cap, which the JDK client surfaces wrapped in an
`IOException`. What sets that one apart is not that an answer had begun to arrive — a connection
dropped mid-body, or a custodian that sends headers and then stalls until the request timeout, are
exchanges whose answer had begun too, and both stay on the unavailable side where they belong. It is
that the bound is *this library's own*: a response over it is over it again on the next attempt and
the one after, whatever the custodian's health, which is the recurrence axis this record applies
everywhere else. **The transport is not asked to recognise an interruption anywhere in that**: it
re-sets the flag, which any code catching an `InterruptedException` owes and which all three sites
that raise one here already do, and the facade's disjunction does the recognising, which is where
this decision already put it. Today the interrupted case is a `PushCryptoException`, a type nothing
converts, so an interrupted wait for Vault propagates untouched and lands on a human as a
cryptographic defect — a page over a shutdown, and a defect that is neither cryptographic nor a
defect.

The status codes are the other half and they stay where they already are, in the signer, because the
transport hands back a response rather than raising on an error status — deliberately, and its
contract says so. It is `VaultTransitVapidSigner` that today turns every non-`200` into one
`PushCryptoException`, and that is the site of the temporary-versus-recurring split above. Two
seams, one axis, and neither of them the caller's problem: what leaves the signer is
`VapidSignerUnavailableException` or a defect.

`VaultHttpResponse` widens by one value in the same movement, because the retry hint above cannot
reach the signer through a record carrying a status and a body alone. It is a response header and it
stops at the transport unless the transport hands it on — which is the whole reason the header is
invisible today. What crosses is the hint and not the headers: a bag of them from a service whose
answers this library reads under a size bound is more surface than one `Retry-After` is worth, and
the transport is the component that already parses what Vault says.

## What replaces the removed code

**The documentation is the deliverable.** A library that hands the retry decision to its caller owes
that caller the material to decide with. Four rules govern the rewrite; the file-by-file inventory
belongs to the implementation task, not to a record that cannot be corrected once settled.

*The status mapping is rewritten rather than amended*, wherever it appears: its result column
becomes variants, the failure row becomes three, and the transport and crypto rows lose everything
except what still throws.

*Three facts a caller must not get wrong are stated where a caller meets them*: that `Retry-After` is
reported with no ceiling applied; that RFC 8030's `TTL` counts from receipt, so an attempt sent hours
later re-bases the message's lifetime unless the caller decrements what it passes; and that a fan-out
meeting `SignerUnavailable` should stop, because the alternative is a fan-out that hammers a custodian
that is already down. The token cache cannot help: it publishes only after a signature succeeds, so
with signing failing it never fills and every row makes its own round trip. Sequentially that is one
connect timeout per row, and asynchronously — the path recommended at volume — it is a burst of
concurrent connects against a dead host, which is the shape of a fan-out finishing a maintenance
window off. The loop this decision deletes never throttled that path in any case, because the
signature is taken before the loop begins; what changes is subtler and worse for a naive caller.
A signer failure used to be an exception, so a `for` loop over a hundred thousand rows stopped at the
first one whether or not its author had thought about it. Now it is a value, and a loop that does not
read it walks the whole list at one round trip each. Breaking on the first one is the caller's to do,
and this decision is what made it theirs, so the sentence is owed where the other two are.

And it is owed in the asynchronous shape as well, because `break` is only the synchronous half of the
advice. A caller that has already handed a hundred thousand `sendAsync` calls to an executor reads
its first outcome long after the last signing call was queued: by then the burst has been decided,
and no reaction to an outcome prevents any of it. What the asynchronous path is owed is the same
advice in the form it can act on — bound the concurrency rather than submitting the list at once,
feed rows in as outcomes come back, and stop submitting new ones once a `SignerUnavailable` has
arrived. Where the sequential caller stops the loop, this one stops the source. Anything sharper —
a fail-fast that trips on a count, a breaker that stays open and reopens on a probe — is the
caller's own, and this decision has just deleted the library's only piece of that machinery on
purpose.

*The migration guide inverts and is the one document that is dangerous rather than stale.* It warns
that an application retry loop on top of push2u multiplies and instructs the reader — in prose and
again as a numbered step — to delete theirs. After this decision push2u behaves as the library being
migrated from does, so the warning is false and the instruction silently costs a reader their retry.

*Sentences that reason from the removed behaviour are restated rather than deleted*, and a rule
finds them rather than a list, because a list in a record that cannot be corrected is worse than
none. Three shapes qualify, in Javadoc, in a comment or in a reference document alike: a sentence
that **names what a send throws** — a contract, an enumeration of what an exception covers, or a
contrast borrowing one to explain another type; a sentence that **reasons from the retry window** —
a duration, a margin, a budget, or an indirection justified by the sleeps; and a sentence that
**uses the observable difference between a status and an exception as an argument**, which is how
the SSRF threat model states its oracle everywhere it is stated. The most on-point of all are
`send`'s own `@throws` clauses and their twin on `sendAsync`, which state this decision's subject
directly and which a rewrite driven by a list could omit. These ship in a `sources.jar` to readers
with no repository to check them against.

The suites follow the same rule: those whose subject is the loop, the attempt count, the removed
properties or the replaced enum are rewritten rather than adjusted, and the shared fixtures that
exist to feed a loop several answers go with them. The `Retry-After` parser's own vectors are the
exception worth naming, because they look like they should move and do not: they call the parser
directly, and the parser is unchanged and stays package-private. What becomes public is what it
produced.

## What it costs

The reporter's channel already makes one POST per call, so its retry logic is unaffected. Its
outcome handling is not: the type is renamed and reshaped, three failures that were exceptions
become values, and that is true of every consumer rather than only of theirs. `0.1.0` shipped and
its release note declared `0.x` the window for revising names and constructor forms once real
integrations exist; this is that revision, and the next release note carries it.

A `Throwable` on `Indeterminate` compares by identity, so two values describing the same timeout are
unequal. Outcomes are switched on rather than compared, so this is accepted — and written down,
because it is the class of trap ADR-019 recorded for a `byte[]` cache key.

Two defaults elsewhere were derived partly from the retry window and deliberately do not move. The
async executor's rationale gives two reasons its tasks block for a long time and loses the second;
the library-owned virtual-thread executor stays, because a blocking HTTP call still has no business
on the common pool. The VAPID renewal margin is the sharper case, and the honest word is that it
stops being *derived*: ADR-019 sized five minutes against what it computed as a worst-case send of
about two minutes — the waiting, an honoured `Retry-After` twice at the ceiling, without the
requests around it — with clock skew as the room on top. Delete the retries and the sized quantity
is gone. The default is retained rather than recomputed, because skew against a service checking
`exp` on its own clock is minutes whatever the token's lifetime is, and the margin costs 0.7 % of a
twelve-hour token's life. ADR-019 is immutable and cannot say this, which is why it is said here.

## What else moves, and what does not

**ADR-007 is superseded in one clause.** Its decision — that `404` and `410` are an ordinary result
the caller inspects rather than exception-driven control flow — is kept and extended to every
operational failure. What does not survive is its next sentence: *"Exceptions stay for what they are
for — a transport failure (`PushDeliveryException`), a cryptographic failure
(`PushCryptoException`), an endpoint the deployment's policy refuses
(`EndpointRejectedException`)."* Two of the three leave the facade's contract outright:
`PushDeliveryException` and `EndpointRejectedException` keep signalling inside their seams, but
neither is anything `send` reports any more. `PushCryptoException` is not removed from `send` but
narrowed — to a cryptographic defect and a misconfiguration, the operational half of what it used to
mean leaving through `SignerUnavailable` instead; what the narrowed type promises a caller in so
many words is ADR-022's, and this record needs only that the operational half is gone from it. What
survives of the sentence is the principle behind it, under a sharper line than ADR-007 had occasion
to draw. The spelling it uses for its own decision, an enum constant and a predicate, changes with
it, but that is a spelling and not a clause: the decision is that the expiry is a value the caller
inspects, and a variant is that value.

**ADR-018 is superseded in part of one clause.** Deciding where the second structural check on the
encoded public key lives, it settled that a `PushCryptoException` raised by `publicKey()` itself —
naming *"a remote custodian that is unreachable or refuses to publish the key"* — propagates
untouched because it is already the right type. The line does not fall between the two cases it
names. The unreachable one moves whole, and the refusal splits: a custodian that answers has not
thereby refused for good, and a `503` from a sealed Vault or a `412` from a node that has not caught
up is a custodian that would publish the key a minute later. What keeps its type is a refusal *about
the request* — a token without the capability to read that key, a mount that is not there — which
the next call receives again unchanged. The rule produced a sentence published on the `VapidSigner`
contract, which is where the cost lands: an override uses that type *"so that one signer does not
answer for one value in two exception types."* After this decision a Vault-backed signer does.
ADR-018 refused to split at all, holding one value to one type, and this splits by whether the
failure recurs — the axis a caller who now owns the retry has to read. The rest of it stands,
including the conformance kit's agreement, which asserts no exception types.

Those two are the only ADRs whose decisions move, and each keeps its status line until this one is
implemented, as ADR-004's did until ADR-019 was. ADR-004 is untouched and reinforced: the library
holds no per-send state, and this removes the loop that came closest to holding some. **ADR-005's
enumeration of seams is untouched** — none added, none removed — and two of the four contracts it
names change: `VaultHttpTransport` takes two — the temporary-versus-recurring split, and the retry
hint its response record has to start carrying — and `VapidSigner` takes the exception vocabulary
above. `PushHttpClient`'s does not: it throws what it throws today, and the interrupt test is the
facade's, written as a disjunction precisely so that no transport has to be obliged to anything.
Both are changes *within* seams rather than to which seams exist. ADR-010's key custody is
untouched: which signer a deployment uses does not change, only what one of them throws. ADR-019
keeps its decision; one derivation loses the quantity it was sized against, as
recorded above. ADR-011's size limit is unaffected, though where its refusal is *reported* moves.
ADR-016 and ADR-017 keep theirs, though this does decide something on the egress path: a refusal is
an outcome. ADR-016's threat model rests on what a caller can observe being an oracle, and that
mechanism survives in the new shape; it is closed by the same thing it always was, the policy
running first and unconditionally, before the encryption, the signature and any I/O.
