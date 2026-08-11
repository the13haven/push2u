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
  and RFC 8292 §5 asks for the behaviour outright. This is an aggressive posture and is recorded as
  one rather than dressed up: a manual check before a release would not be normative documentation,
  but it would be capable of catching a live incompatibility before a default-on behaviour ships, and
  declining it trades that for not carrying a claim the build cannot keep true. Anyone who does run
  that check is answering a
  question this ADR left open, not correcting it — and if a service is found to refuse, the finding
  is an issue and then an ADR flipping the default, not a row in `docs/PUSH-SERVICES.md`. A negative
  result is a one-off experiment exactly as a positive one is, and that document's authority is the
  operator's own current documentation linked beside the claim; nothing about the answer being
  inconvenient makes an unsourced observation citable there.
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
  time. The status line ADR-004 takes, and the only edit its body ever takes, is:

  ```markdown
  **Status:** Accepted; one clause superseded by [ADR-019](0019-vapid-token-reused-until-it-nears-expiry.md)
  ```

  The index's status cell, which today reads `Accepted`, becomes
  `Accepted; one clause superseded by [019](0019-vapid-token-reused-until-it-nears-expiry.md)`. Which
  clause it is stays in ADR-019 rather than in ADR-004's status line, because naming it there would
  put this decision's reasoning into a document that may not carry it. The procedure section gains
  the general shape of both, beside the full-supersession form it already has — and so does every
  other place that today states the full form as the only one: `CLAUDE.md`, `CONTRIBUTING.md`,
  `docs/adr/README.md` itself, and the review skill in both halves, its `SKILL.md` and its ADR
  reference, where an ADR edited other than by that one status line is a finding on sight. Nothing
  else in ADR-004 is touched, and the edit happens when this ADR becomes `Accepted`, not before:
  until then there is no decision to supersede.
- **The key is the audience *and* the signer's advertised public key, and what it detects is a change
  in the *advertised* key.** What is cached is the whole header as one indivisible value, so the cache
  never combines one entry's `t` with another's `k` — that is a property of the stored value, and it
  is not a claim that the signature and the `k` beside it agree cryptographically, which only the
  signer can make and a signer breaking its contract can break (below). It is worth saying because
  the hazard is the neighbouring one.
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
- **The advertised key is stable for a signer's lifetime, and `VapidSigner` says so as part of
  implementing this.** The interface today fixes the shapes, the freshness of the returned arrays and
  thread-safety, and says nothing about whether `publicKey()` may answer differently twice. That
  silence is what makes the question look like an atomicity problem, and it is not one: VAPID's
  public key is the application server's published identity, a browser subscription is bound to the
  `applicationServerKey` it was created with, and RFC 8292 §4.2 refuses a JWT whose key is not the one
  the subscription was created under. A signer that swaps its advertised key under a live sender has
  therefore already broken every restricted subscription taken out before the swap — with or without
  a cache, and whatever the library does with the two return values. Rotation is a re-subscription
  event that produces a new signer, which is exactly what `VaultTransitVapidSigner` does today and
  says in its own Javadoc. So the missing sentence is a statement of what the protocol already
  requires, and it goes where an implementor reads it. It is not checkable in general — no more than
  thread-safety is, and it is stated for the same reason.
- **One `publicKey()` read per minted entry feeds both the header's `k` and the entry's key**, which
  `Vapid.authorizationHeader` has to stop hiding the value to allow — it reads the key inside itself
  and returns only a `String` today, so a caller that must file the entry under the same key would
  have to read it twice. The method is package-private, so no published API moves. Under
  the sentence above the two cannot disagree anyway; the single read is what makes that independent of
  the contract being honoured, so a signer that violates it still cannot produce an entry filed under
  an identity its own header does not carry. The residue is named rather than papered over, and it is
  not free: `sign` and `publicKey` remain two calls, so a violating signer can still sign under one
  key and advertise another *within one header*. That mismatch exists in the code today, before any
  cache — but today it costs one send, and a cached one is filed and re-served until renewal, with the
  no-eviction rule below keeping it there. It is the same amplification this document already records
  for the supplied-key mode: reuse makes a broken configuration fail longer rather than differently.
  The single read does not answer it, because the disagreement is between the signature and `k` rather
  than between `k` and the entry's key; what answers it is the contract sentence above, and
  `jwtReuse(false)` for a deployment that has met a signer ignoring it. Against a signer whose
  advertised key merely moves, the cache still degrades to detection rather than silence: the lookup
  on a later send is a fresh read, the moved key no longer matches what the entry was filed under, and
  the entry is replaced. So the guarantee is exact for a signer that meets the contract,
  self-correcting across sends for one whose key moves between them, and a longer version of an
  already fatal failure for one that contradicts itself inside a single header.
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
- **An entry's life is bounded by both clocks, and whichever bound is reached first ends it.** The
  sender's `Clock` mints `exp` and judges staleness, so the two never disagree about what time it is
  — but `Clock.systemUTC()` is wall-clock, and an NTP step backwards, a snapshot restore or an
  operator setting the clock leaves every cached entry over-estimating its own remaining life by the
  size of the step. Today that event is harmless, because each send mints a fresh `exp` from the same
  wrong clock; under reuse the sender would keep presenting a token the push service considers
  expired for the whole of the step, which RFC 8292 §4.2 makes a ground of invalidity in those
  words. **So a minted entry records a `System.nanoTime()` reading and then the wall reading `exp` is
  computed from — in that order — and it is renewed when either bound is reached: the wall clock
  arriving at the effective `exp` less `jwtRenewBefore`, or the monotonic reading having run for that
  same span — the effective `exp` minus the wall reading it was computed from, minus
  `jwtRenewBefore`, and not one second more.**
  Two details in that sentence are load-bearing, and each of them is the difference between the rule
  working and the rule reading as though it worked.
  *The span* is spelled out because the two candidate readings differ by exactly the margin, and the
  wrong one gives the step back what this rule exists to take from it: with the monotonic bound set to
  the whole of `jwtExpiry`, a backwards step of Δ extends an entry's life by `min(Δ, jwtRenewBefore)`
  and the token is presented right up to `exp`, with nothing left for the retry window or the skew the
  margin is there to cover. With the two spans equal, the effective life is that span for every Δ.
  *The order* is fixed for the same kind of reason. The two readings are not taken at one instant —
  nothing in Java bounds the gap between two statements — so whichever is taken first dates the pair,
  and a pause of P between them displaces one bound relative to the other by P. Read the wall clock
  first and the monotonic bound lands P *later* than the wall bound: a subsequent backwards step of Δ
  then extends the entry's life by `min(Δ, P)`, which is the very failure being closed, reintroduced
  through the ordering rather than through the span. Read the monotonic value first and the same pause
  moves the monotonic bound P *earlier*, so it can only shorten an entry's life and cost a signature.
  The general form of that, which is what the lookup path needs, is: **of the two ways to order the
  readings, the one that over-estimates monotonic elapsed time is taken.** That is a statement about
  sampling order and nothing more — it removes the pause between two readings as a source of
  under-estimation, and leaves the monotonic clock's own rate error, which can still under-estimate
  true elapsed time and is what the residual below is made of. At mint that means the anchor is
  taken as early as possible — before the wall reading. At lookup it means the opposite order for the
  same reason: the current monotonic value is taken *last*, as late as possible, because a stale one
  is permissive on exactly the bound that governs alone once a backwards step has pushed the wall
  bound out. Under that rule no upper bound on any gap is needed anywhere in this decision: the pauses
  are made to displace in the safe direction rather than made small.
  A backwards wall step then cannot extend an entry's life past its monotonic bound, because that
  bound is measured on a clock that does not step and dated before the one that does. What it can
  still move is the distance between that bound and the wall deadline the entry would have had: the
  monotonic clock has its own rate error, so the residual extension is bounded by that error over the
  span — drift-sized, quantified two bullets down, and absorbed whenever `jwtRenewBefore` exceeds it.
  A step of any size buys nothing beyond it. There is nothing to detect and no threshold to choose:
  the failure is not eliminated by diagnosis but reduced to the rate error of a clock that does not
  step.
- **Three rules that detect the step instead were rejected, the third of them after being written
  into this document.** *Comparing an entry's mint instant against `now`* catches only entries minted
  after the reading the clock stepped back to: a token minted at 12:00 survives a step from 12:10 to
  12:05 with its remaining life overstated by five minutes. *A high-water mark over the readings the
  sender has observed*, discarding everything on an earlier one, fails worse and silently: `sendAsync`
  makes concurrent sends normal, two threads reading the clock a moment apart are not ordered with
  respect to a shared field, so the one that reads a hair earlier discards the whole cache while
  nothing has moved — on a fan-out that fires continuously, reuse collapses to today's cost, and a
  single-threaded test never sees it; it is also blind to a step falling entirely inside an idle
  window. *Comparing the two elapsed times* — discarding when the wall clock advanced measurably less
  than the monotonic one — survives both of those and fails for a third reason, which is why it is
  recorded here rather than quietly replaced: the JDK gives `nanoTime` no relationship to wall-clock
  time beyond measuring elapsed time, and in particular no common rate. Drift of the masking sign
  therefore hides real steps, and it accumulates: at fifty parts per million a twelve-hour-old entry
  has banked over two seconds of surplus wall time, so a half-second rollback still leaves the wall
  clock ahead and the entry is kept — while the rule would have promised that any step beyond its
  tolerance is caught. The tolerance was unfixable on its own terms as well: the gap between the two
  readings has no upper bound in Java, where a safepoint, a collection or a suspended virtual machine
  can fall between two statements. The bound-both-ways rule needs none of it — it disarms that gap by
  the order it reads in rather than by bounding it.
- **What the two bounds leave is drift, and it is stated rather than claimed away.** The same absence
  of a common rate means the two bounds disagree by whatever the clocks drift apart over an entry's
  life — seconds over twelve hours at the tens of parts per million a raw counter typically shows,
  and nothing at all where `nanoTime` carries the same discipline as the wall clock, as on Linux.
  While both bounds are honest the shorter one wins, so the error is in the direction of renewing
  early and its size is invisible against a five-minute margin. The direction is not unconditional,
  and saying so matters at exactly one setting: once a backwards step has pushed the wall bound out,
  the monotonic bound governs alone, and it has no guaranteed rate against *true* time either — the
  same absence of a common rate the third rejected rule died of, pointing the other way. On an
  undisciplined counter running fifty parts per million slow, that bound is reached a couple of
  seconds of true time late on a twelve-hour entry. A margin larger than that drift absorbs it, which
  the default of five minutes is by about a hundred and forty at the fifty parts per million of this
  example; a margin smaller than that drift does not, and at `jwtRenewBefore(Duration.ZERO)` the
  token is presented past `exp`. That is what the setting means — no margin is no margin, and a
  drift-sized residual is what choosing it buys.
  A monotonic reading from a *later timeline* is the one case the pair cannot absorb — a
  checkpoint/restore or a live migration onto a host whose counter is behind. The JDK forbids it: the
  same origin serves every invocation within one virtual-machine instance, and a restore is that same
  instance. So a negative elapsed interval cannot arise from a conforming platform, and discarding on
  it costs a comparison against a case that must never happen.
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
- **Documents and published sentences are part of implementing this**, not a follow-up. Four
  documents describe behaviour that changes: `README.md` and `docs/SPRING.md` for the knobs — two of
  the three are ones an operator reaches for only after something surprised them, so the sentence
  that says a token is reused has to exist before the surprise does — `docs/DESIGN.md` for the
  pipeline, and `docs/PERFORMANCE.md`, the one a reader would not think of, whose Vault section says
  the JWT "is rebuilt and re-signed for every message" and that "a cache would remove it from the
  path rather than speed it up"; a figure there that no longer holds is deleted rather than left to
  age, which is that document's own rule. The partial-supersession form named above lands in several
  more:
  `docs/adr/0004-stateless-library.md` takes its status line, and `docs/adr/README.md` takes both the
  index cell and the procedure — alongside `CLAUDE.md`, `CONTRIBUTING.md` and both halves of the
  review skill, `SKILL.md` and its ADR reference, which today state the full form as the only one and
  would otherwise describe a procedure the repository no longer follows.
  Three sentences are in `main` sources, which ship as a `sources.jar` and are read by consumers with
  no clone of this repository. `PushSender`'s class Javadoc says the sender "holds configuration only
  and derives everything a send needs inside the call", which is the same claim ADR-004 makes and
  stops being true here; a comment further down says "[t]he sender holds no mutable state, so a
  policy that throws … leaves nothing to corrupt for later sends", whose conclusion survives — the
  policy runs before the cache is consulted — while its premise does not, so it is the reasoning that
  has to be rewritten rather than the guarantee; and `VapidSigner`'s says both of its outputs "are
  checked on every send", which stops being true on a cache hit, where `sign` is not called at all —
  the check still runs on every miss, which is every path where a new value enters. `VapidSigner`
  also gains the stability sentence above, beside the thread-safety one it already carries and in the
  same voice: what an implementor must guarantee, why the library cannot check it, and what breaks
  when it is not true.
- **The monotonic reading gets a package-private seam, for the same reason `clock` and `sleeper`
  have one.** Without it the second bound is untestable: a test can pin the `Clock` and step it
  anywhere, but the monotonic side would still be the real elapsed millisecond of the test's own
  runtime, so the bound never comes near being reached and every case that turns on it passes for the
  wrong reason. The alternative is a real sleep of the length being modelled, which for a
  twelve-hour token is not an alternative. It is the seam, beside the two this class already carries,
  and it is package-private like both of them: no published API moves, and the production path is the
  real `System.nanoTime()`.
- **What the implementation has to demonstrate**, kept to the rules whose only written record would
  otherwise be this document: that no signature runs while whatever guards the cache is held, and that
  concurrent misses on one audience produce valid tokens; that the monotonic bound ends an entry's
  life when the wall clock is frozen short of its own bound and the seam is driven past the span, and
  that a backwards wall step cannot push the effective life past that same span, and that a pause
  between an entry's two mint readings cannot lengthen its effective life under a later backwards
  step — the assertion the wrong reading order fails and every `P ≈ 0` test passes; that the same
  holds for the other half of the order, a pause between the two readings of a *lookup* against an
  already-stepped-back wall clock, where taking the monotonic value first serves an entry past its
  bound and taking it last does not; that a monotonic reading from a later timeline discards the
  entry; that renewal happens on the second `exp` names and
  not a fraction of a second later; that a signer whose advertised key changes between two sends gets
  a new token rather than the old one under a new `k`, and that a signer answering a different key
  from every `publicKey()` call still files each entry under the key its own header carries; that a
  401 or a 403 leaves the entry in place; that a full cache signs rather than refusing, since the
  bound is reachable on purpose by the party who supplies the subscriptions and a policy this
  deployment chose must not become a delivery failure; and that the cached header reaches neither the
  health indicator's details nor any message on the send path's exceptions — the observable surfaces,
  rather than a universal negative over a module with no logger and no `toString` to begin with. The
  rest of what this decision fixes is ordinary and needs no list here: which entry eviction picks, the
  degenerate settings of each knob, the property bindings, one cache per sender.
  **`push2u-testkit` needs no new case**, which is worth stating because the stability sentence added
  to `VapidSigner` is a new signer obligation and a new obligation with no conformance case would be a
  hole. It already has one: `publicKeyIsAFreshCopyOnEveryCall` calls `publicKey()` twice and asserts
  both that the arrays are distinct and that they still describe the same key, which is exactly the
  checkable half of stability, and `signatureIsRawRsThatVerifiesAgainstTheAdvertisedPublicKey` already
  pins a signature against the key advertised beside it. What changes is the prose: those assertions
  were written for the buffer-sharing hazard, and the second reason they now carry — the contract
  sentence they are the only enforcement of — belongs in their Javadoc, where the kit tells an
  implementor what it is holding them to. Stability across a *lifetime* stays uncheckable from
  outside, as the sentence itself says, and the kit says so too rather than implying a coverage it
  does not have.

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
VAPID identity; a store that cannot be reached must cause a signature rather than a failed send; and
the monotonic half of an entry's pair does not travel — the JDK fixes that origin within one virtual
machine, so a reading taken by another node means nothing here and a shared entry has to be judged on
its wall-clock half alone, or re-timed on arrival — and re-timed under the same over-estimation rule,
anchoring the local monotonic reading first and deriving the remaining span from the local wall clock
after it, since anchoring on arrival while keeping a span computed on another node hours earlier is
the unsafe order with the storage time as its pause.

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
- **Changing `VapidSigner` so that one call returns the signature and the key together**, which is
  what "make it atomic" means in practice. What it would genuinely offer is worth stating before it is
  refused, because the weaker claim is the honest one: a single call cannot *guarantee* a consistent
  pair — an implementation returns whatever it likes, so the guarantee is a contract sentence either
  way — but it does give an implementation somewhere to take one, under its own lock or through a
  versioned operation against its custodian, which two calls do not. It is rejected on the other two
  counts. It would be an abstract change to a published SPI: a compile error for every implementation
  outside this repository and an `AbstractMethodError` for every one already compiled, which `0.x`
  permits but does not make free, and ADR-010's premise is that implementing this seam stays cheap.
  And it is out of scope for what this decision needed: a signer whose advertised key moves mid-flight
  has already invalidated the subscriptions taken out under the old one, so a consistent pair inside
  one header rescues that deployment from nothing, and the cache's own requirement is met by the
  single read above. A later decision may still want it, on its own grounds and with the break
  budgeted.
- **A fourth SPI for the token store**, now: above, under what this does not settle.

This rules out a VAPID token cache behind an SPI while the case for one is unmade; a shared cache
level in front of the in-process one; an unbounded or unevictable cache; a proportional safety
margin; a second spelling of "sign every time" through a zero margin or a zero cache size; a
signature taken while the cache's lock is held; an entry whose life a backwards wall-clock step can
extend past its monotonic bound, or a cache that judges staleness against an expiry finer than the
second the wire carries;
a cache invalidated by an authentication status; an entry filed under a key read separately from the
one its header carries; a signature and a public key delivered by one SPI call; a token whose life is
bounded by the signing key's or whose `aud` names more than one origin; a `byte[]` cache key; and any
claim in this repository's documents about a named push service accepting a reused token. ADR-002 is
untouched — the cache is a map and a string, and the core gains no dependency. ADR-005 is untouched
and not superseded: the three SPIs stay three, and the one that gains a sentence gains no member.
ADR-016 and ADR-017 are untouched; the policy still runs on every send, ahead of everything, and the
cache is consulted after it. ADR-004 is superseded in the single clause named
above and in nothing else.
