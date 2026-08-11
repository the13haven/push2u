# ADR-019 — The VAPID token is reused until it nears expiry

**Status:** Proposed

`PushSender.send` builds and signs a VAPID JWT for every single message. Nothing about that token is
per-message: RFC 8292 §2 gives it three claims — `aud`, which is the *origin* of the push service
rather than the endpoint, `sub`, which is the sender's configured contact, and `exp`, which the
library sets `jwtExpiry` ahead of now and defaults to 12 hours out of a permitted 24. A fan-out to
100 000 subscriptions therefore produces 100 000 signatures over what is, at most, a handful of
distinct tokens: one per push-service origin. Reported as
https://github.com/the13haven/push2u/issues/102.

What that costs was measured, and the two modes are not the same problem. With
`LocalEcVapidSigner` the ES256 signature is 115.6 µs of a 726.6 µs send on the JDK provider — 16 %,
and 80.2 µs of 372.8 µs under BouncyCastle, which is 22 % of a faster send. Real, but not on its own
a reason to put state into a stateless sender. With `VaultTransitVapidSigner` it is an HTTP round
trip on the critical path of every push, 0.9–1.3 ms against a Vault that was a dev-mode container on
the same machine over plain HTTP — no network, no TLS, and the measurement says of itself that this
is a lower bound. Even so it is more than everything else the library does per message put together,
and the same fan-out spends one and a half to two minutes of sequential waiting on Vault for one
token that would have been valid for the whole twelve hours. That mode is the one the documentation
recommends.

Speed is the smaller half of it. Today Vault's availability, its latency and the rate limits of its
Transit mount gate *every* push: a Vault blip is a delivery outage for a workload that has no reason
to depend on Vault being reachable more than twice a day. The decision below removes the dependency
from the hot path rather than making it faster — for a signer whose `publicKey()` is a field read,
which is what both shipped ones are. The SPI permits an implementation that goes to its custodian
for its own key on every call, and a cache hit still asks it: such a signer keeps a round trip per
send by its own construction, and nothing here can take it off the path.

Nothing else in the per-message budget is worth touching, which is why this ticket is the whole of
it: the three elliptic-curve operations are 98.6 % of a local send, all validation and decoding
together is 1.7 µs, and `publicKey()` on the Vault signer — the one that could plausibly have been a
round trip — is 7 ns, a field clone.

**Decision.** The sender holds a bounded, per-instance cache of signed `Authorization` header
values, keyed by the audience together with the signer's advertised public key, and reuses an entry
until it comes within `jwtRenewBefore` of the token's `exp`. Three builder steps, three Spring
properties, no new SPI and no new dependency:

```java
PushSender.Builder.jwtRenewBefore(Duration)   // push2u.jwt-renew-before, default 5m
PushSender.Builder.jwtReuse(boolean)          // push2u.jwt-reuse,        default true
PushSender.Builder.jwtCacheSize(int)          // push2u.jwt-cache-size,   default 64
```

- **RFC 8292 does not merely permit this; it asks for it.** §5 states that "[a]pplication servers are
  therefore encouraged to reuse tokens, which permits the push service to cache the results of
  signature validation", and §2 explains the 24-hour ceiling on `exp` as a limit that "balances the
  need for reuse against the potential cost and likelihood of theft of a valid token" — a sentence
  that presupposes reuse as the expected behaviour. So the second beneficiary of this decision is the
  push service, which today is handed a distinct signature to verify for every message we send it.
  Replay is the other half of the same section and is not glossed here: §5 says the scheme "is
  vulnerable to replay attacks if an attacker can acquire a valid JWT", and the mitigation it names
  is a narrow validity period. This decision does not touch that period — `exp` is set exactly as
  before, by `jwtExpiry`, whose bounds are unchanged — so the window in which a stolen token is
  usable is the same one the library already had. What changes is only how many tokens exist inside
  it, and how long one of them stays resident in this process, which the bearer-credential bullet
  below states rather than leaves to be inferred. No claim about any push service's behaviour is made
  anywhere in this change: `docs/PUSH-SERVICES.md` takes a fact only with a first-party citation
  behind it, and none of the four vendors documents what it does with a token it has seen before. The
  specification is the ground here, and it is affirmative rather than silent — but it is still a
  specification rather than four deployed implementations, so the shape of its being wrong is worth
  recording: 401 or 403 on every send to an origin after the first, with a signature that verifies,
  and `jwtReuse(false)` as the remedy that needs no new release.
- **The report asked for this to be verified against each of the four push services before it ships,
  and that requirement is declined rather than quietly replaced.** It is worth being exact about what
  is being given up: what such a check would establish is that four services behaved a certain way on
  the day someone held a live subscription in each of four browsers, which is neither a citable
  vendor fact — none of them documents this — nor a property the repository could keep true, since
  nothing in the build can re-run it. This project's rule is that `docs/PUSH-SERVICES.md` takes a
  vendor fact only with first-party documentation behind it, and a one-off experiment is the kind of
  claim that rule exists to keep out. So the risk is accepted with the specification as its ground,
  and it is bounded by three things that are in the tree rather than in someone's memory: the
  behaviour is a `default` an operator can turn off without a release, the failure has a stated shape,
  and RFC 8292 §5 asks for the behaviour outright. Anyone who does run that check is answering a
  question this ADR left open, not correcting it — and if a service is found to refuse, the finding
  belongs in `docs/PUSH-SERVICES.md` and the default belongs back at `false`.
- **The cache is internal to `PushSender`, and the three SPIs stay three.** ADR-005 admits a seam
  when the deployment knows something the library cannot decide for it, and an in-process cache of
  a value the sender itself minted is not such a thing: it is correct for every deployment, needs no
  configuration to be correct, and has no alternative implementation that could be right where this
  one is wrong. A shared store — Redis holding one token for a fleet — was proposed and is not built;
  the section below says what would reopen it and the constraint any later version of it inherits.
- **This is not the state ADR-004 rules out.** That decision is about *subscriptions*: where they
  are stored, how they are keyed to users, when they are removed — none of which the library can
  choose on the application's behalf. A signed token is the opposite kind of value. The library
  minted it, it is derived entirely from configuration the sender already holds plus the audience of
  the endpoint it was handed, it is reconstructible at any moment by signing again, and losing it
  costs one signature. Nothing about it belongs to the application, and no application decision
  depends on it. Nor is it *per-send* state, which is ADR-004's other sentence: it is not created or
  discarded per send and holds nothing about any individual send — one entry serves every send to an
  origin. What ADR-004 does carry that this changes is one sentence — that `PushSender` holds only
  final configuration, which is what makes one instance shareable across every sending thread. The
  sharing survives (below); the sentence does not, and ADR-004's status line records that this ADR
  supersedes that clause and nothing else in it. `docs/adr/README.md` carries no form for a partial
  supersession, so this ADR fixes the wording rather than leaving it to be invented at implementation
  time — the status line ADR-004 takes, and the only edit its body ever takes, is
  `**Status:** Accepted; the clause "`PushSender` holds only final configuration" is superseded by
  [ADR-019](0019-vapid-token-reused-until-it-nears-expiry.md)`. The index's status column takes the
  same short form, and the procedure section gains the general shape of it. Nothing else in ADR-004
  is touched, and the edit happens when this ADR becomes `Accepted`, not before: until then there is
  no decision to supersede.
- **The key is the audience *and* the signer's advertised public key, and what it detects is a change
  in the *advertised* key.** What is cached is the whole header, `t` and `k` minted together in one
  call, so the two can never disagree with each other inside one entry whatever the key is — that is
  a property of the stored value, and it is worth saying because the hazard is the neighbouring one.
  A header identifies the key it was signed under, and keying on the audience alone would keep
  serving one that names a key the signer has stopped advertising, until the process restarted. A
  subscription taken out against the new key refuses it, and there is nothing in the failure pointing
  at a cache. So what the composite key buys is that an entry is only ever served to the signer that
  minted it, in the identity it currently publishes. What it cannot close is the reverse: a signer whose
  advertised key stays constant while the *signing* key moves under it. That configuration exists and
  is shipped — the Vault signer's supplied-key mode sends no `key_version` unless
  `keyVersion(int)` was set, so Vault signs with whatever version is latest, and its own
  documentation already says that form is only safe if the Transit key is never rotated. Reuse makes
  a rotation there fail *later* rather than differently: today the first send after the rotation
  presents a v2 signature beside a v1 `k` and is refused immediately, whereas a cached v1 token keeps
  verifying until it is renewed, and the refusal arrives up to `jwtExpiry` afterwards with nothing
  connecting it to the cause. That is a diagnosability cost of this decision, not a new failure —
  the deployment was already misconfigured, and the signer's own documentation says that form is only
  safe if the Transit key is never rotated — and it is recorded rather than left to be discovered.
  Once the entry is renewed the deployment fails the way it does today, continuously; `jwtReuse(false)`
  is what collapses the delay to zero while it is being diagnosed. The Vault signer's fetched mode is
  unaffected: it captures a version and its public key from one atomic metadata read and pins that
  version on every sign, precisely so the two cannot drift.
- **The `sub` claim and `jwtExpiry` are deliberately not in the key**: both are final fields of the
  sender, so one cache belongs to one contact and one expiry by construction. A change that ever made
  either per-send would have to revisit this key, and that is stated here so it is a decision rather
  than a discovery.
- **The key holds the public key as a string, not as `byte[]`.** `VapidSigner.publicKey()` is
  contractually obliged to hand back a fresh array the caller owns, so an array used as a map key
  compiles, never equals a previous one and produces a cache that silently never hits — a defect only
  a benchmark reveals. The string is the base64url encoding of what `publicKey()` returned, which is
  exactly the value the `k` parameter of the header carries, and deliberately not
  `publicKeyBase64Url()`: that method is a `default` an implementation may override, and a key taken
  from an override while the header is built from `publicKey()` would track a value the wire does
  not carry — an entry could then be served under an identity it was not minted with, which is the
  one thing this key component exists to prevent.
- **One `publicKey()` read per minted entry feeds both the header's `k` and the entry's key**, and
  the guarantee is worded to what that can actually deliver. Nothing here is atomic across the SPI:
  `sign` and `publicKey` are two calls, and a signer that re-reads a rotating key can change between
  them — which is true of the code today, before any cache, and this decision neither repairs nor
  worsens it. What the single read does close is the race the cache would otherwise add: the value
  that goes into the entry's key is the same object graph that produced the `k` beside it, so an
  entry can never be *filed* under an identity its own header does not carry. The lookup on a later
  send is a second, fresh read, and a rotation between that read and the mint that follows it costs
  a miss and a new entry, which is the harmless direction. So the guarantee is: an entry is served
  only when the signer's currently advertised key matches the one it was filed under, and a key that
  moves is detected on the next send rather than at the instant it moves.
- **The safety margin is an absolute duration, not a fraction of `jwtExpiry`.** Both things it
  protects against are absolute. The push service checks `exp` against its own clock, so what has to
  be covered is clock skew, which is minutes whatever the token's lifetime is; and a send that picks
  a token up just before the boundary must still be presenting a valid one at its last retry. On the
  default `RetryPolicy` the computed schedule is short — three attempts with waits of one and two
  seconds — but a push service's `Retry-After` overrides that schedule on any retryable status and is
  honoured up to `maxBackoff`, 60 seconds by default, so the reachable worst case is around two
  minutes rather than three seconds. A fraction lands on a sensible value only by accident of the
  default: 20 % of the permitted 24 hours is 4.8 hours of validity thrown away, and 20 % of a
  one-minute `jwtExpiry` is twelve seconds, less than plausible skew. The default of five minutes
  covers that worst-case send with room for the clocks and costs 0.7 % of a twelve-hour token's life.
  A deployment whose retry policy or `Retry-After` tolerance allows a much longer send has to raise
  it; the library does not derive one knob from the other, because the send's duration also includes
  HTTP timeouts it does not own.
- **`jwtReuse(false)` is the declared way to switch reuse off, and `Duration.ZERO` is not it.** Zero
  margin is the *most* reuse — hold the token to its last second — so giving that value the meaning
  "reuse nothing" would invert the parameter exactly where a reader is most likely to reach for it.
  It stays legal and monotone: it means what it says, with the skew consequences of saying it. A
  `jwtRenewBefore` at or above `jwtExpiry` is likewise not a switch but a consequence — the margin
  has swallowed the whole life of the token, so every send mints a fresh one, which is today's
  behaviour and never an error. That is what keeps the two values from needing cross-validation in
  `build()`, which the builder convention here does not want to do. A negative margin is an ordinary
  argument failure at the step that set it, as is a `jwtCacheSize` below one — the cap is not a
  second way to spell the switch.
- **A clock that goes backwards empties the cache, and the trigger is the step, not the entry.** The
  sender's `Clock` both mints `exp` and judges staleness, so the two never disagree about what time
  it is — but `Clock.systemUTC()` is wall-clock, and an NTP step backwards, a snapshot restore or an
  operator setting the clock leaves every cached entry over-estimating its own remaining life by the
  size of the step. Today that event is harmless, because each send mints a fresh `exp` from the same
  wrong clock; under reuse the sender keeps presenting a token the push service considers expired for
  the whole of the step, and a large enough step also puts `exp` more than 24 hours from the request,
  which RFC 8292 §4.2 makes a rejection ground of its own. Comparing an entry's own mint instant
  against `now` does *not* close this, and the point is worth stating because it is the rule that
  suggests itself: it catches only entries minted after the reading the clock stepped back to, so a
  token minted at 12:00 survives a step from 12:10 to 12:05 while its remaining life is overstated by
  five minutes. The sender therefore records the latest instant it has observed from the clock, and a
  reading earlier than that one discards every entry. It costs a field and a comparison, needs no
  second time source, catches a step of any size whenever the next send observes it, and subsumes the
  mint-instant check — an entry can only be in the future if the clock moved back after it was minted,
  which is exactly what the observation catches. What no rule here can catch is a clock that is simply
  wrong and stays wrong: that is skew, and the margin is what covers it.
- **Staleness is judged against the `exp` that went on the wire.** The claim is serialised as
  `getEpochSecond()`, so the value the push service enforces is the whole second, up to just under a
  second earlier than the `Instant` the sender computed; RFC 7519 §4.1.4 requires the current time to
  be strictly before it. An entry therefore stores `Instant.ofEpochSecond(expiry.getEpochSecond())` —
  the effective expiry, not the one with nanoseconds — and the comparison against it is strict. At the
  default margin the difference is invisible, which is exactly why it is written down: correctness at
  `jwtRenewBefore(Duration.ZERO)`, which this decision permits, must not rest on the default of
  another knob.
- **A 401 or 403 does not evict the entry that produced it**, and this is the one place the obvious
  rule is the wrong one. It looks like a rejected token is the response that says the cached value is
  no longer worth holding, which would make a rejection self-healing instead of sticky for the rest
  of the reuse window. RFC 8292 §4.2 says otherwise: it enumerates what makes `vapid` authentication
  invalid, and the last entry is "the public key used to sign the JWT doesn't match the one that was
  included in the creation of the push message subscription" — a property of the *subscription*, not
  of the token. §4.2 offers 401 for authentication that is absent and 403 for authentication that is
  invalid, and offers them as what a push service "might" use, so the library cannot even rely on
  which code arrives; what it certainly does not get is a code that separates the two causes. So the
  status does not distinguish "this token is stale"
  from "this subscription was taken out under a different application server key", and treating it as
  the former hands an attacker a cheap, permanent reversal of this whole decision: one subscription
  created at a legitimate push service under a different `applicationServerKey`, submitted like any
  other, rejects on every send and evicts the entry every legitimate send to that origin shares. It
  needs no domain rule to work — the origin is the push service's own, so a strict `allowedOrigins`
  policy admits it — which makes it cheaper than the LRU displacement recorded below. The same thing
  happens with nobody attacking: §4.2 requires an application server that replaces its signing key to
  obtain new subscriptions, so a population mixing old and new subscriptions is the *expected* state
  of a VAPID key rotation, and every send to a legacy one would cold-start the origin its healthy
  siblings share. The cache therefore ignores authentication statuses, and the remedies for a
  genuinely stale entry are the ones already named: renewal at `jwtRenewBefore`, `jwtReuse(false)`,
  or a restart.
- **The cache is bounded, with eviction, and the bound is configurable.** The audience of a send is
  the origin of the endpoint inside a `Subscription`, and that set is chosen by whoever supplies
  subscriptions — attacker-influenced wherever they arrive from clients, which is the premise ADR-016
  works from. An origin rule bounds that set exactly — it is string equality against one
  serialization, so a policy built only from origin rules admits as many audiences as it lists and no
  more. A domain rule does not: `EndpointRule.domain` covers every subdomain of the named zone at any
  depth, which is the whole reason ADR-017 added it for the two services that publish a zone rather
  than a host, and no name resolution narrows it. So an unbounded map keyed by the audience is a
  memory-exhaustion path reachable from data the library already treats as untrusted under
  `EndpointPolicies.unrestricted()`, under any policy carrying a domain rule — which is the
  cross-browser configuration `docs/PUSH-SERVICES.md` exists to hand out — and under any
  `EndpointPolicy` a deployment wrote itself, which the SPI exists to allow and this library cannot
  see inside. The bound is therefore not a tuning knob but the reason the cache is safe to hold at
  all. Eviction is least-recently-used, and
  overflow degrades to signing per send — today's behaviour, never a refusal, because a policy this
  deployment chose must not become a delivery failure. The same party can reach that degradation on
  purpose, by supplying subscriptions on enough distinct hostnames of an allowed zone to evict the
  real entries; it costs them nothing and returns the sender to the cost it pays today, which is why
  the bound is configurable and why this is recorded as a deliberate reversal of the improvement
  rather than an accident of overflow. The default of 64 is well above the four browser push services
  while leaving room for the two whose hostnames vary; how many distinct hostnames either of them
  actually issues is not asserted here, because no vendor documents it. That unknown carries a limit
  worth stating plainly: this decision helps a push service in proportion to how few origins it
  spreads its endpoints over, and a service that issued a hostname per subscription would defeat it
  outright — every audience distinct, every send a miss, the cost exactly today's. Nothing suggests
  one does; nothing published rules it out either.
- **Concurrency: a benign race, and no lock is held across a signature.** `PushSender` is shared
  across threads and `sendAsync` makes concurrent sends the normal case, so two threads missing on
  the same audience at once is expected. They produce two different but independently valid tokens,
  one of which is published and the other discarded — nothing to lock against. What *is* ruled out is
  taking the signature while holding whatever guards the cache: the signature may be a Vault round
  trip, and every send to that audience would queue behind it — the exact stall this decision exists
  to remove, reintroduced in a narrower place. Look up, release, sign, publish. This is a constraint
  on the ordering rather than on the data structure: an access-ordered LRU mutates on a read, so it
  needs mutual exclusion around the lookup too, and that is compatible with the rule as long as the
  signature happens outside it. Both the atomic-compute idiom (`computeIfAbsent` and friends, which
  run the mapping function under the map's own lock) and a synchronized region spanning the
  signature are excluded by it.
- **The cached value is a bearer credential, and holding it is the one thing this decision spends.**
  It authenticates this application server to the push service for the remainder of the token's life,
  so it never appears in a `toString`, a log line, an exception message or a health field, in the same
  way the Vault token does not. Beyond diagnostics there is a residency cost worth naming, because
  RFC 8292 §5 names it: a narrow validity period "limits the potential value of a stolen token to an
  attacker and can increase the difficulty of stealing a token", and it is the second half this
  changes. Today a token exists in the process for the length of one send; under reuse one lives in a
  map for up to twelve hours, so a heap dump, a core dump, a profiler snapshot or an attached
  debugger yields a usable credential where before it would have had to arrive during a send. The
  same section asks for reuse anyway, and the exposure is bounded by `exp`, which this decision does
  not move — but a deployment that treats process memory as reachable has `jwtRenewBefore` and
  `jwtReuse(false)` to shorten or remove the residency, and it should be told that rather than left
  to work it out.
- **Reuse within a send already exists**, which is why this is an extension rather than a new idea:
  the encrypted body and the VAPID token are held across the retries of one send today. What changes
  is the span over which one token is presented, not whether it is presented more than once.
- **Four documents and two published sentences are part of implementing this**, not a follow-up.
  `README.md` and `docs/SPRING.md` for the knobs — two of the three are ones an operator reaches for
  only after something surprised them, so the sentence that says a token is reused has to exist
  before the surprise does — and `docs/DESIGN.md` for the pipeline. `docs/PERFORMANCE.md` is the
  fourth and the one a reader would not think of: its Vault section says the JWT "is rebuilt and
  re-signed for every message" and that "a cache would remove it from the path rather than speed it
  up", and both sentences describe the code this decision changes. A figure there that no longer
  holds is deleted rather than left to age, which is that document's own rule. The two sentences are
  in `main` sources, which ship as a `sources.jar` and are read by consumers with no clone of this
  repository:
  `PushSender`'s class Javadoc says the sender "holds configuration only and derives everything a
  send needs inside the call", which is the same claim ADR-004 makes and stops being true here; and
  `VapidSigner`'s says both of its outputs "are checked on every send", which stops being true on a
  cache hit, where `sign` is not called at all — the check still runs on every miss, which is every
  path where a new value enters.
- **What the implementation has to demonstrate, named here so it is a checklist rather than a
  judgement call at review time.** Every rule above that a test can pin, has one: that concurrent
  misses on one audience produce valid tokens and no signature runs while the cache's lock is held;
  that the bound holds and eviction is least-recently-used, with overflow degrading to signing rather
  than failing; that a backwards clock reading discards the cache, including the 12:00/12:10/12:05
  case a mint-instant check would miss; that an entry is renewed on the second `exp` names and not a
  fraction of a second later; that a signer whose advertised key changes gets a new token rather than
  the old one under a new `k`; that a 401 or a 403 leaves the entry in place; that the header appears
  in no `toString`, log, exception message or health field; and that the three properties bind, with
  the failure messages naming the YAML spelling rather than the builder's camelCase. `push2u-testkit`
  is untouched: none of this is a signer's obligation.

**What this decision does not settle.** A shared token store — one signed token used by every node
of a fleet, through Redis or anything else — is deliberately not built, and not because the idea is
incoherent. Two things decide it. First, the arithmetic: with the in-process cache in place, a
twenty-node fleet talking to four push services spends eighty signatures per token lifetime instead
of four, and seventy-six Vault calls per twelve hours is not a cost anyone is paying. Second, the
latency: a Redis round trip is the same order of magnitude as the Vault signature it would replace
— hundreds of microseconds to a millisecond, dominated by the network either way — so a shared store
consulted per send trades one network dependency in the hot path for another and answers neither
half of this ticket. One argument in its favour is weighed rather than omitted: RFC 8292 §5 values
reuse partly because it lets the push service cache the result of verifying a signature, and a fleet
of N nodes presents N distinct tokens per origin where a shared one would present a single token, so
N cache entries form on their side instead of one. That is a real difference and a small one — N is
the number of nodes, not of messages, against the one-token-per-message the service is handed today.
Any later version of a shared store therefore inherits one constraint: **a shared level sits
behind the in-process cache, never in front of it**, which reduces it to something consulted about
once per node per token lifetime. What would reopen the question is a deployment whose processes are
shorter-lived than its tokens — serverless invocations, or pods that live minutes under aggressive
autoscaling — where the in-process cache never gets a second send to serve and the fleet's signature
count stops being small. Whoever opens it inherits the rest of the contract too: the value is a
bearer credential, so putting it in a shared store extends that store's blast radius to the sender's
VAPID identity, and a store that cannot be reached must cause a signature rather than a failed send.

Rejected alternatives:

- **Caching inside a `VapidSigner`.** It is not as impossible as it looks — `exp` is serialised at
  second granularity, so every send to one origin within the same wall-clock second presents a
  byte-identical signing input, and an implementation keyed on that input verbatim would collapse a
  large fan-out to roughly one signature per second. What it cannot do is what this ticket asks for.
  It leaves Vault on the critical path once a second, so neither the availability argument nor the
  rate-limit one is answered; it does nothing at all for a sender whose messages are seconds apart,
  which is most of them; it caches a value under a key that includes an `exp` its own caller chose,
  so the reuse window is an accident of send timing rather than something anyone configured; and it
  is work every implementation of the SPI has to repeat, in a seam ADR-010 exists to keep cheap to
  implement.
- **Raising `jwtExpiry` to the permitted 24 hours.** It does nothing: the token is re-signed per
  message regardless of how long it would have remained valid.
- **A fraction of `jwtExpiry` as the safety margin**, above: dimensionally wrong for both of the
  things the margin protects against.
- **`Duration.ZERO` as the off switch**, above: it inverts the parameter at its edge.
- **An unbounded cache**, on the grounds that an allowlist bounds the audience set. It does not: a
  domain rule admits every subdomain of the zone at any depth, and no name resolution happens, so the
  audience remains attacker-chosen in exactly the deployments ADR-017 was written for.
- **A cache shared between `PushSender` instances**, static or otherwise. Two senders may hold two
  key custodians; a value keyed by anything less than the identity of the signer would cross between
  them, and one keyed by that identity is what a per-instance field already gives without a lifetime
  question or a class-loader one.
- **A background thread refreshing tokens before they expire.** It would turn a library into
  something that runs when nobody called it, for a saving of one signature on one send per audience
  per twelve hours; the core owns no thread today except the lazily created executor `sendAsync`
  documents, and this would be the first that starts itself.
- **Evicting the entry that produced a 401 or 403**, above: the status is not a statement about the
  token, and reading it as one is reachable on purpose from a single subscription. The softer form —
  suspending reuse for an origin after several authentication failures rather than on the first —
  buys nothing, because the failures that would trip it are unbounded and free to produce: the same
  subscription answers every send.
- **Bounding a token's life by the signing key's.** There is nothing to bound it against and nothing
  it would protect: the push service verifies the signature against the `k` the header carries and
  has no notion of our key's lifetime, so a token signed by a Transit version that is later trimmed
  keeps verifying until its `exp` like any other. `LocalEcVapidSigner` has no expiry concept at all —
  it holds a key pair. What a dying key actually breaks is *renewal*, not the token in hand, and
  there reuse helps rather than hurts: the sender keeps delivering on the last token while the
  custodian is repaired. A key whose public half genuinely changes is not a token-lifetime question
  either — a subscription taken out with an `applicationServerKey` is bound to it, and RFC 8292 §4.2
  says an application server replacing its signing key has to request new subscriptions, so that
  event is a re-subscription of the restricted part of the client population.
- **One token for several origins**, using a JSON array for `aud`. RFC 8292 §2 says the claim "MUST
  include the Unicode serialization of the origin … of the push resource URL", and RFC 7519 allows
  `aud` to be an array, so a token naming every origin a deployment sends to is a defensible reading
  of the text. It is rejected on three counts, in order of weight: whether a push service accepts an
  array is a fact about four implementations and not about the specification, and this change asserts
  no vendor behaviour; the set of origins is discovered from the subscriptions the application hands
  us rather than known in advance, so the token could not be minted until it was already needed; and
  the saving over a per-origin token is a handful of signatures per twelve hours.
- **A fourth SPI for the token store**, now: above, under what this does not settle.

This rules out a VAPID token cache behind an SPI while the case for one is unmade; a shared cache
level in front of the in-process one; an unbounded or unevictable cache; a proportional safety
margin; a second spelling of "sign every time" through a zero margin or a zero cache size; a
signature taken while the cache's lock is held; a cache surviving a backwards clock reading, or one
that judges staleness against an expiry finer than the second the wire carries; a cache invalidated
by an authentication status; an entry filed under a key read separately from the one its header
carries; a token whose life is bounded by the signing key's or whose `aud` names more than one
origin; a `byte[]` cache key; and any claim in this repository's documents about a named push service
accepting a reused token. ADR-002 is untouched — the cache is a
map and a string, and the core gains no dependency. ADR-005 is untouched and not superseded: the three SPIs
stay three. ADR-016 and ADR-017 are untouched; the policy still runs on every send, ahead of
everything, and the cache is consulted after it. ADR-004 is superseded in the single clause named
above and in nothing else.
