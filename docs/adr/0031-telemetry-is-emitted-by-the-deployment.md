# ADR-031 — Telemetry is emitted by the deployment, and this library publishes what it means

**Status:** Accepted

Filed as https://github.com/the13haven/push2u/issues/90, which proposed an optional
`push2u-micrometer` module: three decorators — one per seam — plus an auto-configuration in the core
starter that wraps whichever beans are present, and a suggested set of meters with `origin`,
`status` and `outcome` tags.

The gap the issue names is real and this record does not argue with it. Nothing on the send path
emits anything: no meters, and no log lines either —
[ADR-027](0027-the-endpoint-policy-answers-with-a-value.md) says so where it explains why a refusal
carries an operator's sentence rather than a code, since the core that would write it can hold no
logging dependency. The one thing in this repository that logs at all is the Spring starter's health
indicator — a warning on the transition into a failing probe, a debug line while it persists, and
one warning where the JVM's providers cannot verify ES256 — all of it readiness rather than a view
of delivery. A deployment's only view of delivery today is whatever its own call site chose
to record, and the questions an operator actually has — is one push service refusing
everything since 14:00, how long a POST takes, how often the egress allowlist fires, how many
signing operations the custodian is really being asked for — have no answer that comes for free.

Three of the issue's five questions have moved since it was filed, and the answer below is built on
the API as it stands rather than on the one it described:

- **the classification is no longer inside the sender.** The issue observes that `PushResult.Status`
  and the attempt count live inside a `final PushSender` with no interface, so a decorator cannot
  see them, and accepts a transport-level approximation instead. `PushOutcome` is now the sealed
  return value of `send` (https://github.com/the13haven/push2u/pull/193 for the endpoint-refusal
  variant), so the exact classification is held by the caller at the call site, in a `switch` the
  compiler keeps exhaustive. The approximation is not needed and would be worse than the value it
  approximates;
- **there is no retry to instrument.** [ADR-021](0021-retry-belongs-to-the-caller.md) handed the
  repeat decision to the caller (https://github.com/the13haven/push2u/pull/137), so attempts per
  send, the schedule, the budget and whether a `Retry-After` was honoured are all properties of the
  caller's scheduler and are measured there;
- **a send is no longer a custodian round trip.** [ADR-019](0019-vapid-token-reused-until-it-nears-expiry.md)
  reuses the VAPID token until it nears expiry (https://github.com/the13haven/push2u/pull/121), so
  `VapidSigner.sign` runs on a token-cache miss rather than once per message. A counter on it is
  more useful than the issue expected and means something different from what the issue said it
  would.

## The decision

**The library publishes the semantics; the deployment emits the telemetry.**

What this library owns, and already publishes as types: the classification of a send
(`PushOutcome`, its eight variants and the components each carries), the four exceptions `send`
raises — the two this library owns among them — the assessment an `EndpointPolicy` answers with, and
the redaction that decides which parts of an endpoint may be rendered at all. What a deployment
owns: the telemetry framework, the meter and span names, the tag vocabulary and its cardinality,
sampling, aggregation and export.

So the deliverable is a document, `docs/OBSERVABILITY.md` — the recipes for instrumenting the call
site and each of the three seams, the tag rules with the reason for each, what a signer counter
actually counts, the Spring wiring that has to be got right, and what cannot be measured from
outside.

**No module, no dependency, no seam, and no wrapping done on a deployment's behalf.** Specifically:
no published artifact carrying those decorators; no telemetry dependency in `push2u-core`
([ADR-002](0002-zero-dependency-core.md)) or in any starter; no listener, observer or recorder seam
inside `PushSender`; and no auto-configuration that wraps a bean the deployment did not ask to have
wrapped.

## A decorator module would own the three things it may not own

The issue's own framing is what settles this. It says, correctly, that no new extension point is
needed: the seams are sufficient, the decorators are short, and the value on offer is that
"every consumer would name the meters differently, would independently rediscover that the endpoint
must not become a tag, and would have to reimplement the status-class bucketing". That is the whole
of it — and every one of those three is a naming or a policy question, not code.

- **The names.** A convention is worth having, and a document states one at no permanent cost. An
  artifact states the same convention and additionally cannot be withdrawn.
- **The tag vocabulary and its cardinality.** This is the part a library must not decide, and the
  next section is about why.
- **The status bucketing.** It exists, it is published, and it is `PushOutcome`. A decorator around
  `PushHttpClient` cannot see it — the transport observes a status, not a classification — so it
  would have to restate the mapping from status to outcome in a second place, which is the failure
  [ADR-028](0028-the-test-kit-publishes-contracts-not-conveniences.md) already refuses for the test
  kit, for the same reason: two statements of one mapping, and no mechanism that keeps the second
  true.

There is a fourth, which the issue does not reach because its `origin` tag hides it: a bounded
service tag has to map a host to a vendor, and that mapping is the push services' zones.
[ADR-017](0017-domain-rule-in-the-endpoint-allowlist.md) rules out shipping those as a default, and
a meter's tag is not an exception to it. `docs/PUSH-SERVICES.md` carries them as a snapshot to be
copied out of, says so itself, and that is the right place for a table a vendor can invalidate
without telling us.

## The endpoint may not become a tag, and neither may what surrounds it

An endpoint is a capability URL (RFC 8030 §8.3) that arrives from a browser through the
application's registration boundary. Two consequences, and they are different from one another.

**Disclosure.** The whole library is arranged so that the endpoint reaches no diagnostic unredacted:
`Refused` carries no endpoint component at all, `EndpointRejected` carries this library's own
redaction, and `PushOutcome.Indeterminate.toString()` prints the cause's *class* because the cause's
message can embed the URL. A metrics backend is a diagnostic like any other, usually with wider read
access than the log, and a tag is the least reviewed string in a deployment.

**Cardinality.** An unbounded tag value is a resource the remote side chooses. The issue notices
this for `origin` under `EndpointPolicies.unrestricted()` and proposes to bound it by "limiting the
tag to origins the policy admits" — and that mitigation cannot be built on the seam the proposal
rests on. `EndpointPolicy` has one method answering one assessment, and
[ADR-024](0024-one-endpoint-policy-reachable-at-registration.md) rules out a second one — a
predicate, an overload, "any other second way to ask the one question the seam exists to answer" —
along with an accessor for the policy on `PushSender`; `EndpointRule` is sealed with its match
package-private. There is no supported way to ask a policy what it admits, and adding one so a tag
could be bounded by it is what the entry below rules out.

Nor does an allowlist bound the value even in principle: a domain rule covers the apex and every
subdomain at a label boundary (ADR-017), which is exactly how Apple's and Microsoft's zones are
written, so the set of admitted hosts is unbounded under a correctly configured allowlist and not
only under the unrestricted mode. Stripping the scheme and port to tag by host does not fix it and
loses a distinction this library makes.

The rule the document therefore states is not "prefer origin to endpoint" but: **a metric tag is a
closed set the deployment names.** A push-service bucket with a fixed set of values and an `other`
arm; a normalised status class rather than an arbitrary integer; the outcome variant. A raw origin
is a high-cardinality field, admissible on a trace or a log line where a deployment has decided it
wants one, never a meter tag.

## No seam inside the sender

[ADR-005](0005-public-spis-in-the-core.md) sets the bar: a seam exists only where there is an
articulable difference the library cannot decide on behalf of the deployment, and every
implementation of one becomes a way for this library to be wrong. A listener on `PushSender` clears
none of that. `send` *returns* the classification; a callback delivering the same value earlier buys
a permanent obligation — ordering, threading, what happens when a listener throws, what a listener
is allowed to be told about the subscription — in exchange for nothing the return value does not
already give.

The same ADR has already answered the transport half of the question in a half-sentence, which this
record only makes explicit: proxying, pooling and observability belong to the application's HTTP
stack, which is *why* `PushHttpClient` is a seam.

## The starter wraps nothing on its own

An auto-configuration that decorates whichever beans are present looks like the free half of the
proposal, and it is the part that must not be built. The signer bean is not the sender's alone: the
health indicator exercises the same instance, signing a probe on every evaluation the cache does not
serve. A wrapper installed by the starter would silently change what that probe runs through and
what a signer counter counts, in a deployment that asked for metrics and said nothing about health.
A deployment that decorates deliberately is accepting exactly that trade; a deployment that had it
done for it is not.

The corresponding conditions are why the Spring section of the document is the longest one: because
`PushHttpClient`, `VapidSigner` and the Vault signer are all published `@ConditionalOnMissingBean`,
an application bean of the same type does not *wrap* the default — it replaces it, and the delegate
is never created. For `EndpointPolicy` it is stronger still: a policy bean beside a configured
allowlist is a conflict the starter refuses at startup by design (ADR-024). The document gives the
recipes and their limits and recommends the one that needs none of this — instrumenting `send` where
the application calls it.

## What this record does not decide

**Whether an optional artifact ever carries those decorators.** This record refuses one now, on the
evidence available now: the recipes are short, the seams are sufficient, and nothing yet shows a
deployment that followed the document and was still worse off than a module would have left it.
Ergonomics are a legitimate reason for a library to grow, and a refusal written today should not be
read as one written for all time.

What it does say is what would oblige a fresh answer rather than a link to this record: **a new
proposal carrying both a demonstrated demand and an account of what the document's recipes cost.**
Demand, measurably — an issue whose support is sustained rather than momentary, with twenty-five
reactions as the floor; that number decides nothing on its own and is a floor for owing the question
an answer, never a vote that answers it. And content, which is the half that matters: what the
recipes failed at in a real deployment — a divergence in names between teams that both followed the
document, the cost of the Spring recipe where it had to be used, a measurement the call site cannot
produce.

Such a reconsideration takes the *stronger* form of the proposal, not the one filed as #90: an
artifact built on an observation abstraction that yields metrics and traces from one instrumentation,
rather than meters alone. That argument is better than the one this record answers, and it is named
here so that a later reader can see it was not passed over in silence. It does not change the answer
today — an observation-shaped module owns the same three things this record places with the
deployment, and adds a dependency and a permanent artifact to owning them — but it is the form the
next argument should take.

If it is taken up, it is a new record superseding this one's first ruled-out entry. The rest of the
list below is not conditional on any of that, and no amount of demand moves it: those entries are
about what this library permanently obliges itself to, not about what is convenient.

## Documents

`docs/OBSERVABILITY.md` is this record's implementation, and travels with it — README's reference
table gains its row and `CLAUDE.md` its description, in the shape every document under `docs/` has
there. Because the implementation *is* a document, this record is `Accepted` on arrival rather than
`Proposed` first; there is no second change for it to wait for.

`docs/HEALTH.md` is not extended: the probe's own reference describes what it asserts, and that its
signing shows up in a signer counter is a fact about instrumenting the signer, which is where the
new document says it. `docs/DESIGN.md` describes the architecture, which this record does not move.

## What this rules out

- A published artifact carrying meters, spans, decorators or a telemetry facade for this library —
  `push2u-micrometer` as filed, and equally the same artifact under another name or built on an
  observation abstraction instead of a meter registry. This is the one entry a later record may
  supersede, and only on the evidence named above.
- A telemetry dependency in `push2u-core`, in any scope that reaches a consumer's runtime, and in
  any starter — including an optional or `compileOnly` one whose absence a condition tests, which is
  a dependency on the artifact's presence by another spelling.
- A listener, observer, recorder or event seam on `PushSender`, in any spelling: a constructor
  argument, a builder step, a `ServiceLoader` lookup, or a hook argued for as "not really an SPI".
- A timer, counter or span opened by this library's own code anywhere on the send path, and equally
  a log line — the two are the same decision, and neither exists.
- An auto-configuration that decorates a `VapidSigner`, `PushHttpClient` or `EndpointPolicy` bean
  the deployment did not itself wrap, and any property that switches such wrapping on.
- A host-to-push-service mapping shipped as code from any module, which is ADR-017's entry reaching
  one artifact further; the table stays a document's snapshot.
- The endpoint, any component of it, a path segment, a query value or a policy's refusal reason
  offered as a metric tag, a span attribute or a meter name — the reason being a free-text sentence
  whose author is the deployment's own policy, so nothing bounds what it contains.
- A raw origin or host published as a low-cardinality tag, or a cap on a metrics backend offered as
  what makes one safe rather than as the last defence behind a closed set.
- A statement of the mapping from HTTP status to outcome anywhere but where `send` performs it —
  including a transport decorator's status buckets presented as a substitute for `PushOutcome`.
- An accessor on `EndpointPolicy`, or any other way to ask a policy which endpoints it admits, added
  so that a tag can be bounded by it.
- A promise about the thread a caller's instrumentation observes on the asynchronous path: `send`
  runs on the supplied executor or on this library's virtual-thread default, and no thread-bound
  context is propagated into it.
