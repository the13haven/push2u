# ADR-021 — The retry schedule is a seam, and the caller may be the driver

**Status:** Proposed

`PushSender.send` welds three separable things into one `for` loop. **Which** responses may be
retried at all is `isRetryable`, a private static naming 429 and the whole 5xx class. **How long** to
wait and **when to stop** is `RetryPolicy`, a record of three numbers — `maxAttempts`,
`initialBackoff`, `maxBackoff` — whose backoff doubles until the ceiling stops it and which yields to
a parseable `Retry-After`, clamped at that same ceiling. And **who executes** the schedule is the loop
itself: one thread, inside one call, sleeping through every wait.

Only the middle one is configurable, and only in the three numbers the record holds. A deployment
that wants jitter, a give-up rule expressed as a deadline rather than an attempt count, a schedule
that treats 429 differently from 503, or a retry driven by something other than a sleeping thread has
exactly one lever: `RetryPolicy.none()`, which turns the whole apparatus off. That lever is a cliff.
Everything the loop knows — the classification, and the `Retry-After` the library already parsed to
the letter of RFC 9110 — stays inside the loop, so a caller who opts out of the schedule also loses
the two facts a schedule is computed from.

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

    static RetryPolicy defaults();
    static RetryPolicy none();
    static RetryPolicy exponential(int maxAttempts, Duration initialBackoff, Duration maxBackoff);
}

public record RetryContext(int attempt, int statusCode, Optional<Duration> retryAfter, Duration elapsed) {}
```

`defaults()` and `none()` keep their names and their present behaviour, and `exponential(...)` is the
record's constructor under a name that says which schedule it builds; together they are the whole of
what the library ships, and the built-in implementation stays out of the public API surface. An empty
return is "stop", not "wait zero": a policy honouring a `Retry-After` of `0` must be able to say so,
and `Optional` separates the two answers where a sentinel `Duration` would collapse them.

**Two.** The classification stays concrete, and a policy may only narrow it. The retryable set is
RFC-shaped rather than deployment-shaped — 429 and 5xx are what the push service is telling the sender
about itself — so the library keeps deciding it, and the sender consults the policy only for a status
it has already classified as retryable. A policy can refuse a retry the library would have made; it
can never manufacture one the library would not. That is the clause that keeps the seam from becoming
a way to POST repeatedly at a `400`, or at a `410` whose subscription is gone, which is abuse of a
push service that no consumer would intend and every unconstrained retry seam permits.

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

**Four.** The driver is not a seam. There is no `Retrier` interface, and the reason is not restraint
but arithmetic: a durable retrier cannot be called back. Its next attempt happens in a process that
does not yet exist, after a deploy that may replace the code, and any callback the library could
declare would have to return a `PushResult` that no attempt has produced. What the durable case needs
instead is an inversion, and the library turns out to need almost nothing new to support it — a
sender configured with `RetryPolicy.none()` makes exactly one POST today, and with clause three its
result carries everything the next attempt's decision is computed from. **A send holds nothing across
attempts that a second call would not rebuild**: the endpoint policy re-runs, the VAPID token is
re-minted or served from its cache (ADR-019), and the body is re-encrypted under a fresh ephemeral key
and salt, which is what RFC 8291 asks of a message in any case. So the phases the report wants spread
across time are already separable; what was missing is only the facts the first call swallowed.

That is why the library defines **no resumable retry state and no serialization format for one**. The
attempt counter, the deadline and the dead-letter rule are the job engine's, which already keeps
exactly those for every other job it runs, and a state type the library published would be a schema it
then has to version — the first thing in the core a consumer is obliged to persist, and a re-run at
ADR-004 from the other end. `PushResult.attempts` is one for every attempt a caller drives, and the
global count belongs to the caller, who is the only party that knows it.

A caller driving its own attempts can still reuse the library's schedule, because a policy is a pure
function of a context rather than a step in a loop: `RetryPolicy.defaults().delayFor(context)` answers
outside the sender exactly what it answers inside it. That, and not a published parser, is what closes
the report's second request.

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
  `FAILED` and on `SUBSCRIPTION_EXPIRED` alike whenever the header was there and parseable — never
  fabricated when it was not, so "no hint" stays distinguishable from "wait 30s". On a 404 or 410 it
  is not actionable, and saying so in the Javadoc costs less than dropping a fact the service sent.
- **The retry context carries no endpoint and no subscription.** A subscription endpoint is an
  attacker-influenced capability URL that the library redacts everywhere it appears in diagnostics
  (ADR-020), and handing it to a consumer-written policy — a class whose natural implementation logs
  what it decided — would undo that discipline in the one place it is least visible.
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
  built-in exponential policy, and a replacement arrives as a `RetryPolicy` bean — the shape
  `EndpointPolicy` already has, with one deliberate difference: neither present is not a startup
  failure here, because retry has a defensible default and egress does not (ADR-016).

## What it costs

The VAPID `Authorization` header must move inside the loop. It is signed once before the first POST
today, and what keeps a retry from presenting a stale token is `RetryPolicy.maxBackoff` — the very
ceiling a replaced policy removes. Minting per attempt closes that coupling outright and is nearly
free, because ADR-019 made a repeat mint a cache lookup; the `jwtExpiry` and `jwtRenewBefore`
documentation that reasons about the backoff ceiling loses its subject and is rewritten rather than
kept.

This supersedes one clause of ADR-005 — its enumeration of three seams, "everything else stays
concrete", becomes four. The bar ADR-005 sets is not weakened and is what admits the fourth; nothing
else in it moves, and the Vault module's separate `VaultHttpTransport` stands for the reason it
already gives.

`RetryPolicy` ceases to be a record, so `new RetryPolicy(3, …)`, its three accessors and any pattern
match over it break at source and at binary level, and `PushResult`'s canonical constructor gains a
component. `0.1.0` has shipped, and its release note declared `0.x` the window in which names and
constructor forms are revisited once real integrations exist; this is that revision, and the next
release note carries it. The report offers an alternative that would avoid the `PushResult` break — a
private field with an accessor, canonical constructor untouched — and it is rejected outright rather
than held in reserve: it would make `PushResult` a record whose `equals`, `hashCode` and `toString`
ignore part of its own state, which is a defect that outlives the compatibility break it buys.
