# ADR-021 — The retry schedule is a seam, and the caller may be the driver

**Status:** Proposed

`PushSender.send` welds three separable things into one `for` loop. **Which** responses may be
retried at all is `isRetryable`, a private static naming 429 and the whole 5xx class. **How long** to
wait and **when to stop** is `RetryPolicy`, a record of three numbers — `maxAttempts`,
`initialBackoff`, `maxBackoff` — whose backoff doubles until the ceiling stops it. A parseable
`Retry-After` overrides that schedule, clamped at the same ceiling, and the override lives in
`PushSender` rather than in the record: the record knows nothing of the header. And **who executes**
the schedule is the loop itself: one thread, inside one call, sleeping through every wait.

Only the middle one is configurable, and only in the three numbers the record holds. A deployment
that wants jitter, a give-up rule expressed as a deadline rather than an attempt count, a schedule
that treats 429 differently from 503, or a retry driven by something other than a sleeping thread has
exactly one lever: `RetryPolicy.none()`, which turns the whole apparatus off. What that lever costs
is the `Retry-After` the library already parsed to the letter of RFC 9110 — genuinely unreachable
from outside, since both the parser and the parsed value stay inside the loop. The classification is
the milder loss: 429 and 5xx is a two-line function a caller can write from `statusCode`, at the cost
of keeping a private copy of the library's rule in step with it.

Reported as https://github.com/the13haven/push2u/issues/86, from the deployment where it bites
hardest: a sender whose retries are *durable*. There the next attempt is a job the engine reschedules
minutes or hours later, across a process restart or a deploy, and a `Thread.sleep` inside `send`
cannot participate in it — it holds a worker for the wait and its state dies with the process. So the
sender is configured with one attempt per call and the application owns backoff, expiry and the
404/410 delete. The report's complaint is precise: the consumer that most needs the push service's
`Retry-After` is the one configuration that cannot see it, and it reschedules on a blind exponential
backoff that may POST again well before the service said it would accept anything — the exact harm
the header exists to prevent.

That complaint is right and this decision adopts its remedy. Its self-imposed constraint is not:
the report checks off "adds no new SPI" as a virtue, and ADR-005's bar points the other way. That bar
is *an articulable difference the library cannot decide on behalf of the deployment*, and it admits
`VapidSigner` because key custody is operational, `PushHttpClient` because the HTTP stack belongs to
the application, and `EndpointPolicy` because egress is a statement about the deployment's network.
Whether a wait is a parked thread or a row in a job table is a difference of exactly that kind, and no
default the library ships can be right for both. Retry is also not a protocol step: ADR-003 keeps the
encryptor, HKDF and the origin serialization concrete because an alternative implementation of those
would only add a silent wrong-ciphertext failure mode, and nothing of that shape applies to the
choice of how long to wait before POSTing again.

## The decision

**One.** `RetryPolicy` stops being a record of three numbers and becomes the fourth SPI in the core:

```java
public interface RetryPolicy {

    /** The wait before the attempt that follows this one, or empty to stop and report the outcome. */
    Optional<Duration> delayFor(RetryContext context);

    static RetryPolicy defaults() { ... }
    static RetryPolicy none() { ... }
    static RetryPolicy exponential(int maxAttempts, Duration initialBackoff, Duration maxBackoff) { ... }
}

public record RetryContext(int attempt, int statusCode, Optional<Duration> retryAfter, Duration elapsed) {}
```

`defaults()` and `none()` keep their names and their present behaviour, and `exponential(...)` is the
record's constructor under a name that says which schedule it builds; together they are the whole of
what the library ships, and the built-in implementation stays out of the public API surface. An empty
return is "stop", not "wait zero": a policy honouring a `Retry-After` of `0` must be able to say so,
and `Optional` separates the two answers where a sentinel `Duration` would collapse them.

The context's two ambiguous fields are pinned here rather than left to the implementation. `attempt`
is one-based and numbers the POST that produced this very response, so the first call a policy ever
sees carries `1` — one letter and one meaning away from `PushResult.attempts`, which counts rather
than indexes, and the distinction is stated because nothing but the Javadoc will carry it. `elapsed`
is measured on the monotonic `Ticker` from the first POST of this send, not on the wall `Clock` and
not from the moment `send` was entered — ADR-019 exists because that difference is not cosmetic. It
is there for the deadline-shaped policies an attempt count cannot express; the built-in exponential
one ignores it.

`exponential(...)` keeps two adjacent `Duration` parameters, which the convention here would
ordinarily make swap-proof with value types. They are not, deliberately: a transposition is already
legal today — `maxBackoff` below `initialBackoff` is an accepted policy that simply caps from the
first retry — so there is no invalid state to reject, and a value type earns its place by carrying
validation or redaction, neither of which a bare backoff bound has to carry. What changes is only
that the shape is now re-declared rather than inherited, so the decision to leave it is recorded.

A seam carries the two contracts the other three already state, and it carries them for the same
reasons. **An implementation must be thread-safe** — one `PushSender` is shared across every sending
thread and `sendAsync` makes concurrent `delayFor` calls the normal case, so a policy holding a
counter or a breaker has to guard it, and the three the library ships hold nothing at all. **A policy
that throws aborts the send with that exception unchanged**, and the library neither wraps it nor
invents a taxonomy entry for it: the other three seams each map onto an exception that names a real
failure — the transport's, the signer's, the egress decision's — whereas a policy is consulted after
a POST that has already happened and has no fact about the push service to report. Converting it to a
`PushDeliveryException` would blame the service for a consumer's defect. The POSTs already made are
not undone, exactly as they are not when the transport throws on a later attempt today.

**Two.** The classification stays concrete, and a policy may only narrow it. The retryable set is
RFC-shaped rather than deployment-shaped — 429 and 5xx are what the push service is telling the sender
about itself — so the library keeps deciding it, and the sender consults the policy only for a status
it has already classified as retryable. A policy can refuse a retry the library would have made; it
can never manufacture one the library would not. That is the clause that keeps the seam from becoming
a way to POST repeatedly at a `400`, or at a `410` whose subscription is gone, which is abuse of a
push service that no consumer would intend and every unconstrained retry seam permits.

What it does not close is the other shape of the same harm: a policy answering zero for a 503, over
and over, hammers a service that has just said "not now" — with the status the library itself calls
retryable, so narrowing has nothing to catch. That is deliberate and is the subject of the
no-ceiling clause below; the two are not in tension so much as divided. The wrong *status* is a
mistake the library can recognise without knowing anything about the deployment, and it refuses it.
The wrong *rate* against a right status is indistinguishable from a legitimately aggressive schedule,
and any bound the library imposed would be a second policy silently overriding the first.

**Three.** The verdict the classification reaches, and the hint the response carried, both reach the
caller. `PushResult` gains one component and one derived predicate:

```java
public record PushResult(Status status, int statusCode, int attempts, Optional<Duration> retryAfter) {
    public boolean isRetryable() { ... }   // computed from statusCode, by the same classifier
}
```

The component is an `Optional`, and there is no second accessor beside it. A record component named
`retryAfter` already generates `retryAfter()`, so a nullable component *and* an `Optional`-returning
method of the same name is not a design choice but a compile error — the report's sketch proposes
exactly that pair. Of the two spellings that do compile, the `Optional` component is the one that
leaves the record canonical, with every part of its state inside the constructor that `equals`,
`hashCode` and `toString` are derived from. `isRetryable()` is computed rather than stored: the
boolean convention here asks a question about state to be spelled `is…` whether or not the answer is
kept in a field, and the answer is already in `statusCode`.

**Four.** The driver is not a seam. There is no `Retrier` interface, and the reason is not that such
an interface could not be declared — a `void schedule(…, Duration)` handed a descriptor type-checks
perfectly well, and `send` would simply return the last attempt's result rather than a final one. It
is that the descriptor is the problem. A durable retrier resumes in a process that does not yet
exist, after a deploy that may have replaced the code, so whatever the library handed it would have
to survive serialization and a version skew — which makes a driver seam a resumable-state schema
wearing an interface, and the paragraph below rejects the schema on its own merits. What the durable
case needs instead is an inversion, and the library turns out to need almost nothing new to support
it — a sender configured with `RetryPolicy.none()` makes exactly one POST today, and with clause
three its result carries everything the next attempt's decision is computed from. **A send holds
nothing across attempts that a second call would not rebuild**: the endpoint policy re-runs, the
VAPID token is re-minted or served from its cache (ADR-019), and the body is re-encrypted under a
fresh ephemeral key and salt, which is what RFC 8291 asks of a message in any case. So the phases
the report wants spread across time are already separable; what was missing is only the facts the
first call swallowed.

One header is the exception, and it is the exception because it is rebuilt rather than carried.
`TTL` is emitted as a count of seconds and the push service counts it from receipt (RFC 8030 §5.2),
so a second call sends the same number again and the message's retention re-bases on every attempt.
Inside the loop that difference is the backoff, seconds at the default ceiling. Driven from a job
engine it is however long the engine waited, and a message the caller declared should live an hour
can be alive an hour after each of a day's attempts. The invariant above is literally true of the
header and false of what it means, which is precisely why it is stated here: a durable driver that
wants the original deadline honoured has to decrement the value it passes, and only it knows when
the message was first meant to expire.

That is why the library defines **no resumable retry state and no serialization format for one**. The
attempt counter, the deadline and the dead-letter rule are the job engine's, which already keeps
exactly those for every other job it runs, and a state type the library published would be a schema it
then has to version — the first thing in the core a consumer is obliged to persist, and a re-run at
ADR-004 from the other end. `PushResult.attempts` is one for every attempt a caller drives, and the
global count belongs to the caller, who is the only party that knows it.

A caller driving its own attempts can still reuse the library's schedule, because a policy is a pure
function of a context rather than a step in a loop: `RetryPolicy.defaults().delayFor(context)` can be
called outside the sender. What it answers there is identical because the built-in schedule reads
only `attempt`, `statusCode` and `retryAfter`, all three of which a driver has; the promise does not
extend to `elapsed`, which no caller can reconstruct across a restart the way the sender measures it,
and a policy of the caller's own that depends on it has to define it for itself. That, and not a
published parser, is what closes the report's second request.

## What this rules out, and why

- **`RetryAfter.parse` does not become public API.** The report asks for it because a
  `PushHttpClient` decorator — the workaround it describes — can reach the header but not the parser,
  and reimplements delta-seconds plus three HTTP-date forms with their leap-second and two-digit-year
  rules. That reimplementation is real, and it exists only because the parsed value does not reach the
  caller. Once it does, on the result and inside the context, the parser has no caller left, and
  publishing it would commit the library permanently to a general-purpose HTTP header utility that has
  nothing to do with Web Push — with an `Instant now` parameter, a testing seam, in its public
  signature. Per-endpoint behaviour that genuinely needs the raw header still belongs in
  `PushHttpClient`, which already sees both.
- **Nothing the library hands out is clamped.** The raw parsed value goes into the context and onto
  the result. Today's clamp at `maxBackoff` is not the library's rule but the exponential policy's
  parameter, and that is where it stays: a caller scheduling a job hours out has a different ceiling,
  and reshaping a value the service actually stated would leave the result disagreeing with the wire.
- **The hint is not filtered by status.** It is the *final* response's `Retry-After`, present on
  every one of the three statuses — `DELIVERED` included, where a service is free to send one and
  nothing is served by pretending it did not — whenever the header was there and parseable, and never
  fabricated when it was not, so "no hint" stays distinguishable from "wait 30s". On a 404 or 410 it
  is not actionable, and saying so in the Javadoc costs less than dropping a fact the service sent.
- **The retry context carries no endpoint and no subscription.** A subscription endpoint is an
  attacker-influenced capability URL, and the discipline of keeping it out of anything that gets
  logged is one this library holds everywhere — the redaction in diagnostics, and the refusal to put
  it in a rejection message even redacted. Handing it to a consumer-written policy, a class whose
  natural implementation logs what it decided, would undo that in the one place it is least visible.
- **The library imposes no ceiling over a replaced policy.** A policy that never returns empty makes
  an in-process `send` loop forever, and that is the same class of defect as an `EndpointPolicy` that
  accepts every host: a seam is a way for the library to be wrong, and any bound the library added
  would be a second policy silently overriding the first. What is documented instead is the in-process
  driver's cost — a thread held for the whole schedule — and that a schedule measured in hours is the
  signal to drive the attempts from outside.
- **`Sleeper` stays package-private.** It is a test seam for running the loop without real waits, and
  publishing it would be a second, weaker spelling of clause four: a driver that still has to return
  inside one call.
- **There is no property spelling for a replaced policy.** `push2u.retry.*` keeps binding to the
  built-in exponential policy, and a replacement arrives as a `RetryPolicy` bean. The
  properties-or-bean exclusivity `EndpointPolicy` has is deliberately *not* copied, and it could not
  be: every `push2u.retry.*` key carries a `@DefaultValue`, so the starter cannot tell an operator
  who set one from an operator who set none — where the allowlist keys carry no defaults and their
  presence is exactly what expresses the decision. So the bean wins outright when both are there, a
  configuration the operator can see is contradictory and the starter cannot. Neither present is not
  a failure either, because retry has a defensible default and egress deliberately does not
  (ADR-016). The three-probe validation that attributes a rejected bound to its YAML key survives
  unchanged in shape, but it can no longer construct a record to make the constructor speak, so it
  moves onto `exponential(...)`.

## What it costs

The VAPID `Authorization` header must move inside the loop. It is signed once before the first POST
today, and what keeps that one signature valid to the last retry is `jwtRenewBefore`, the absolute
margin under `exp` at which a cached token stops being served. That margin is sized against how long
a send may legitimately run, and `maxBackoff` is the part of that duration the library knows — which
is exactly the part a replaced policy takes away. The margin's own documentation says the library
does not derive one knob from the other, and names the other contributor it cannot bound either: the
HTTP timeouts the transport owns. Minting per attempt removes the backoff from that sum and leaves
the timeouts where they were, so this narrows the coupling rather than closing it, and the paragraph
that reasons from the backoff ceiling is rewritten rather than kept.

Per-attempt minting is not free in every configuration, and the one where it is not is a shipped
option rather than an edge case. With token reuse on, a repeat mint is the cache lookup ADR-019 made
it. With `jwtReuse(false)` — an off switch the library documents and argues for — every mint signs,
so moving it inside the loop turns one signature per send into one per attempt: with
`LocalEcVapidSigner` a matter of microseconds, but with `VaultTransitVapidSigner` an extra Transit
round trip per retry, three-deep under the default policy and unbounded under a replaced one. The
alternative shape — mint once, re-check freshness before each attempt and sign again only when the
check fails — costs nothing in either configuration and is what implementation should reach for; it
is named here because the naive reading of "move it inside the loop" is a throughput regression
against the deployment the documentation recommends.

This supersedes one clause of ADR-005 — its enumeration of three seams, "everything else stays
concrete", becomes four. The bar ADR-005 sets is not weakened and is what admits the fourth; nothing
else in it moves, and the Vault module's separate `VaultHttpTransport` stands for the reason it
already gives.

`RetryPolicy` ceases to be a record, so `new RetryPolicy(3, …)`, its three accessors and any pattern
match over it break at source and at binary level, and `PushResult`'s canonical constructor gains a
component. `0.1.0` has shipped, and its release note declared `0.x` the window in which names and
constructor forms are revisited once real integrations exist; this is that revision, and the next
release note carries it. The report offers an alternative that would avoid the `PushResult` break —
an accessor computed from a private field the pipeline sets, canonical constructor untouched — and it
is rejected outright rather than held in reserve, for a reason stronger than the trade it proposes: a
record body may not declare an instance field at all, so the shape does not exist. Reaching it means
`PushResult` ceasing to be a record and carrying a hand-written `equals`, `hashCode` and `toString`
that either ignore the new state or are maintained by hand forever — a permanent cost, paid to avoid
a break the `0.x` window was declared to absorb.
