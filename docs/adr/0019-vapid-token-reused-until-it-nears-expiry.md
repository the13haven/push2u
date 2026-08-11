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
`LocalEcVapidSigner` the ES256 signature is 118 µs of a 726.6 µs send — 16 %, real but not on its
own a reason to put state into a stateless sender. With `VaultTransitVapidSigner` it is an HTTP
round trip on the critical path of every push, 1.07 ms at the median against a Vault that was a
dev-mode container on the same machine over plain HTTP — no network, no TLS, and the measurement
says of itself that this is a lower bound. Even so it is more than everything else the library does
per message put together, and the same fan-out spends 107 seconds of sequential waiting on Vault for
one token that would have been valid for the whole twelve hours. That mode is the one the
documentation recommends.

Speed is the smaller half of it. Today Vault's availability, its latency and the rate limits of its
Transit mount gate *every* push: a Vault blip is a delivery outage for a workload that has no reason
to depend on Vault being reachable more than twice a day. The decision below removes the dependency
from the hot path rather than making it faster.

Nothing else in the per-message budget is worth touching, which is why this ticket is the whole of
it: the three elliptic-curve operations are 98.6 % of a local send, all validation and decoding
together is 1.7 µs, and `VapidSigner.publicKey()` is 7 ns — a field clone, not a network call.

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
  it. No claim about any push service's behaviour is made anywhere in this change:
  `docs/PUSH-SERVICES.md` takes a fact only with a first-party citation behind it, and none of the
  four vendors documents what it does with a token it has seen before. The specification is the
  ground here, and it is affirmative rather than silent.
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
  supersedes that clause and nothing else in it. The wording of a partial supersession, which
  `docs/adr/README.md` does not yet carry a form for, is added to its procedure section as part of
  implementing this.
- **The key is the audience *and* the signer's advertised public key, and what it detects is a change
  in the *advertised* key.** The header carries both `t` (the JWT) and `k` (the key it was signed
  under), and they must agree or every push service returns 401 for every send. Keying on the
  audience alone would keep a token signed by an old key travelling beside a new `k` value until the
  process restarted, so the key closes that. What it cannot close is the reverse: a signer whose
  advertised key stays constant while the *signing* key moves under it. That configuration exists and
  is shipped — the Vault signer's supplied-key mode sends no `key_version` unless
  `keyVersion(int)` was set, so Vault signs with whatever version is latest, and its own
  documentation already says that form is only safe if the Transit key is never rotated. Reuse makes
  a rotation there fail *later* rather than differently: today the first send after the rotation
  presents a v2 signature beside a v1 `k` and is refused immediately, whereas a cached v1 token keeps
  verifying until it is renewed, and the refusal arrives up to `jwtExpiry` afterwards with nothing
  connecting it to the cause. That is a diagnosability cost of this decision, not a new failure —
  the deployment was already misconfigured — and it is recorded rather than left to be discovered.
  The eviction rule below is what keeps it from being permanent. The Vault signer's fetched mode is
  unaffected: it captures a version and its public key from one atomic metadata read and pins that
  version on every sign, precisely so the two cannot drift.
- **The `sub` claim and `jwtExpiry` are deliberately not in the key**: both are final fields of the
  sender, so one cache belongs to one contact and one expiry by construction. A change that ever made
  either per-send would have to revisit this key, and that is stated here so it is a decision rather
  than a discovery.
- **The key holds the public key as the base64url string, not as `byte[]`.** `VapidSigner.publicKey()`
  is contractually obliged to hand back a fresh array the caller owns, so an array used as a map key
  compiles, never equals a previous one and produces a cache that silently never hits — a defect only
  a benchmark reveals. `publicKeyBase64Url()` exists for exactly this value and is the string the
  header already carries.
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
- **An entry minted in the future is discarded.** The sender's `Clock` both mints `exp` and judges
  staleness, so the two never disagree about what time it is — but `Clock.systemUTC()` is wall-clock,
  and an NTP step backwards, a snapshot restore or an operator setting the clock leaves every cached
  entry over-estimating its own remaining life by the size of the step. Today that event is harmless,
  because each send mints a fresh `exp` from the same wrong clock; under reuse the sender would keep
  presenting a token the push service considers expired for the whole of the step, and a large enough
  step also puts `exp` more than 24 hours from the request, which RFC 8292 §2 forbids outright. The
  rule that closes both is one comparison: an entry records the instant it was minted, and an entry
  whose mint instant is after `clock.instant()` is dropped and re-signed. It costs nothing on the
  normal path and needs no second time source.
- **A 401 or 403 evicts the entry that produced it.** A rejected token is the one response that says
  the cached value is no longer worth holding, and eviction is what makes two of this document's
  named risks self-healing rather than sticky for a whole reuse window: a push service that turns out
  not to accept a reused token, and an advertised key that drifted from the signing key. The bound
  that makes it safe is that eviction never triggers a re-signature *inside* the send: 401 and 403
  are not retryable statuses, the send returns `FAILED` as it does today, and the next send to that
  origin signs. So the worst case under a permanently rejecting endpoint is one signature per send —
  exactly today's behaviour — and no loop exists for an attacker-supplied endpoint that always
  refuses to drive harder than that. The status is already control flow here (2xx, 404/410, 429, 5xx
  all steer the pipeline); no response body is read, and none needs to be.
- **The cache is bounded, with eviction, and the bound is configurable.** The audience of a send is
  the origin of the endpoint inside a `Subscription`, and that set is chosen by whoever supplies
  subscriptions — attacker-influenced wherever they arrive from clients, which is the premise ADR-016
  works from. An allowlist does not bound it: an `EndpointRule.domain` covers every subdomain of the
  named zone at any depth, which is the whole reason ADR-017 added that rule for the two services
  that publish a zone rather than a host. So an unbounded map keyed by the audience is a
  memory-exhaustion path reachable from data the library already treats as untrusted, in *every*
  policy mode rather than only under `EndpointPolicies.unrestricted()`. The bound is therefore not a
  tuning knob but the reason the cache is safe to hold at all. Eviction is least-recently-used, and
  overflow degrades to signing per send — today's behaviour, never a refusal, because a policy this
  deployment chose must not become a delivery failure. The same party can reach that degradation on
  purpose, by supplying subscriptions on enough distinct hostnames of an allowed zone to evict the
  real entries; it costs them nothing and returns the sender to the cost it pays today, which is why
  the bound is configurable and why this is recorded as a deliberate reversal of the improvement
  rather than an accident of overflow. The default of 64 is well above the four browser push services
  while leaving room for the two whose hostnames vary; how many distinct hostnames either of them
  actually issues is not asserted here, because no vendor documents it.
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
- **The cached value is a bearer credential** — it authenticates this application server to the push
  service for the remainder of the token's life — so it never appears in a `toString`, a log line, an
  exception message or a health field, in the same way the Vault token does not.
- **Reuse within a send already exists**, which is why this is an extension rather than a new idea:
  the encrypted body and the VAPID token are held across the retries of one send today. What changes
  is the span over which one token is presented, not whether it is presented more than once.
- **Three documents and two published sentences are part of implementing this**, not a follow-up.
  `README.md` and `docs/SPRING.md` for the knobs — two of the three are ones an operator reaches for
  only after something surprised them, so the sentence that says a token is reused has to exist
  before the surprise does — and `docs/DESIGN.md` for the pipeline. The two sentences are in `main`
  sources, which ship as a `sources.jar` and are read by consumers with no clone of this repository:
  `PushSender`'s class Javadoc says the sender "holds configuration only and derives everything a
  send needs inside the call", which is the same claim ADR-004 makes and stops being true here; and
  `VapidSigner`'s says both of its outputs "are checked on every send", which stops being true on a
  cache hit, where `sign` is not called at all — the check still runs on every miss, which is every
  path where a new value enters.

**What this decision does not settle.** A shared token store — one signed token used by every node
of a fleet, through Redis or anything else — is deliberately not built, and not because the idea is
incoherent. Two things decide it. First, the arithmetic: with the in-process cache in place, a
twenty-node fleet talking to four push services spends eighty signatures per token lifetime instead
of four, and seventy-six Vault calls per twelve hours is not a cost anyone is paying. Second, the
latency: a Redis round trip is the same order of magnitude as the Vault signature it would replace
— hundreds of microseconds to a millisecond, dominated by the network either way — so a shared store
consulted per send trades one network dependency in the hot path for another and answers neither
half of this ticket. Any later version of it therefore inherits one constraint: **a shared level sits
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
- **Not evicting on 401/403**, leaving the entry in place and `jwtReuse(false)` as the only remedy.
  It is the simpler rule and it was rejected: it converts a transient or newly-appearing rejection
  into a delivery outage lasting the rest of the reuse window, and the failure it makes permanent is
  precisely the one this document flags as its own biggest assumption.
- **A fourth SPI for the token store**, now: above, under what this does not settle.

This rules out a VAPID token cache behind an SPI while the case for one is unmade; a shared cache
level in front of the in-process one; an unbounded or unevictable cache; a proportional safety
margin; a second spelling of "sign every time" through a zero margin or a zero cache size; a
signature taken while the cache's lock is held; a cached entry surviving a backwards clock step or
an authentication rejection; a `byte[]` cache key; and any claim in this repository's documents about
a named push service accepting a reused token. ADR-002 is untouched — the cache is a map and a
string, and the core gains no dependency. ADR-005 is untouched and not superseded: the three SPIs
stay three. ADR-016 and ADR-017 are untouched; the policy still runs on every send, ahead of
everything, and the cache is consulted after it. ADR-004 is superseded in the single clause named
above and in nothing else.
