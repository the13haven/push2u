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
round trip on the critical path of every push, 0.9–1.3 ms against a Vault on the same network,
which is more than everything else the library does per message put together; the same fan-out
spends over a hundred seconds of sequential waiting on Vault for one token that would have been
valid for the whole twelve hours. And that mode is the one the documentation recommends.

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
  depends on it. What ADR-004 does carry that this changes is one sentence — that `PushSender` holds
  only final configuration, which is what makes one instance shareable across every sending thread.
  The sharing survives (below); the sentence does not, and ADR-004's status line records that this
  ADR supersedes that clause and nothing else in it. The wording of a partial supersession, which
  `docs/adr/README.md` does not yet carry a form for, is added to its procedure section as part of
  implementing this.
- **The key is the audience *and* the signer's advertised public key.** The header carries both `t`
  (the JWT) and `k` (the key it was signed under), and they must agree or every push service returns
  401 for every send. Keying on the audience alone would keep a token signed by an old key travelling
  beside a new `k` value until the process restarted. Both shipped signers pin their key — the Vault
  signer captures a version and its public key from one atomic metadata read and signs with that
  version forever, precisely so the advertised key cannot drift from the signing key — so this
  protects an implementation the library does not own, and it costs 7 ns to consult. The `sub` claim
  and `jwtExpiry` are deliberately *not* in the key: both are final fields of the sender, so one
  cache belongs to one contact and one expiry by construction. A change that ever made either
  per-send would have to revisit this key, and that is stated here so it is a decision rather than a
  discovery.
- **The safety margin is an absolute duration, not a fraction of `jwtExpiry`.** Both things it
  protects against are absolute. The push service checks `exp` against its own clock, so what has to
  be covered is clock skew, which is minutes whatever the token's lifetime is; and a send that picks
  a token up just before the boundary must still be presenting a valid one at its last retry, which
  on the default `RetryPolicy` is around two minutes later (three attempts, backoff doubling from
  1 s, capped at 60 s). A fraction lands on a sensible value only by accident of the default: 20 % of
  the permitted 24 hours is 4.8 hours of validity thrown away, and 20 % of a one-minute `jwtExpiry`
  is twelve seconds, less than plausible skew. The default of five minutes covers that worst-case
  send with room for the clocks and costs 0.7 % of a twelve-hour token's life. A deployment whose
  retry policy allows a much longer send has to raise it; the library does not derive one knob from
  the other, because the send's duration also includes HTTP timeouts it does not own.
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
- **The cache is bounded, with eviction, and the bound is configurable.** The audience of a send is
  the origin of the endpoint inside a `Subscription`, and under `EndpointPolicies.unrestricted()`
  that set is chosen by whoever supplies subscriptions — attacker-influenced wherever they arrive
  from clients, which is the premise ADR-016 exists on. An unbounded map keyed by it is a memory
  exhaustion path reachable from data the library already treats as untrusted, so the bound is not a
  tuning knob but the reason the cache is safe to hold at all. Eviction is least-recently-used, and
  overflow degrades to signing per send — today's behaviour, never a refusal, because a policy this
  deployment chose must not become a delivery failure. The default of 64 is well above the four
  browser push services while leaving room for the two that publish a whole DNS zone whose hostnames
  vary rather than a single host.
- **Concurrency: a benign race, and no lock is held across a signature.** `PushSender` is shared
  across threads and `sendAsync` makes concurrent sends the normal case, so two threads missing on
  the same audience at once is expected. They produce two different but independently valid tokens,
  one of which is published and the other discarded — nothing to lock against. What *is* ruled out is
  signing inside the map's own computation (`ConcurrentHashMap.computeIfAbsent` and friends): the
  signature may be a Vault round trip, and running it under the bin lock would serialise every send
  to that audience behind it — the exact stall this decision exists to remove, reintroduced in a
  narrower place. Look up, sign outside, publish. The sender's `Clock` both mints `exp` and judges
  staleness, so the two never disagree about what time it is.
- **Reuse within a send already exists**, which is why this is an extension rather than a new idea:
  the encrypted body and the VAPID token are held across the retries of one send today. What changes
  is the span over which one token is presented, not whether it is presented more than once.
- **The assumption the whole decision rests on is that a VAPID token is not per-request**, and it is
  named here rather than left implicit. RFC 8292 requires no freshness and carries no replay-
  prevention claim — there is no `jti` and no `nonce` in the VAPID JWT — and the token is not secret:
  it travels to the push service in the clear on every request already. That is an argument from the
  specification, and no claim about any vendor's behaviour is made anywhere in this change:
  `docs/PUSH-SERVICES.md` takes a fact only with a first-party citation behind it, and no push
  service documents whether it accepts a token it has seen before. If the assumption ever fails for
  one of them, it fails visibly and in a shape worth recording now: 401 or 403 on sends whose
  signature is valid, on everything after the first message to that origin, with `jwtReuse(false)` as
  the immediate remedy.
- **`README.md`, `docs/SPRING.md` and `docs/DESIGN.md` are part of implementing this**, not a
  follow-up. Two of the three knobs are ones an operator reaches for only after something surprised
  them, so the sentence that says a token is reused has to exist before the surprise does.

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
bearer credential that authenticates this application server to the push service for the remainder
of its life, so putting it in a shared store extends that store's blast radius to the sender's VAPID
identity, and a store that cannot be reached must cause a signature rather than a failed send.

Rejected alternatives:

- **Caching inside a `VapidSigner`.** The seam is the wrong place and the reason is structural: the
  signing input embeds `exp`, recomputed from the clock on every send, so two consecutive sends never
  present the same input. An implementation would have to parse the JWT segments it was handed to
  discover that only `exp` moved — an SPI reverse-engineering its caller — and it would be work every
  signer had to repeat.
- **Raising `jwtExpiry` to the permitted 24 hours.** It does nothing: the token is re-signed per
  message regardless of how long it would have remained valid.
- **A fraction of `jwtExpiry` as the safety margin**, above: dimensionally wrong for both of the
  things the margin protects against.
- **`Duration.ZERO` as the off switch**, above: it inverts the parameter at its edge.
- **An unbounded cache**, on the grounds that an allowlist bounds the audience set. It does under
  ADR-017's rules, but `EndpointPolicies.unrestricted()` is a published, supported mode with no
  bound at all, and the cache must be safe in the modes the library actually ships.
- **A cache shared between `PushSender` instances**, static or otherwise. Two senders may hold two
  key custodians; a value keyed by anything less than the identity of the signer would cross between
  them, and one keyed by that identity is what a per-instance field already gives without a lifetime
  question or a class-loader one.
- **A background thread refreshing tokens before they expire.** It would turn a library into
  something that runs when nobody called it, for a saving of one signature on one send per audience
  per twelve hours; the core owns no thread today except the lazily created executor `sendAsync`
  documents, and this would be the first that starts itself.
- **A fourth SPI for the token store**, now: above, under what this does not settle.

This rules out a VAPID token cache behind an SPI while the case for one is unmade; a shared cache
level in front of the in-process one; an unbounded or unevictable cache; a proportional safety
margin; a second spelling of "sign every time" through a zero margin or a zero cache size; a
signature taken while a lock over the cache is held; and any claim in this repository's documents
about a named push service accepting a reused token. ADR-002 is untouched — the cache is a map and a
string, and the core gains no dependency. ADR-005 is untouched and not superseded: the three SPIs
stay three. ADR-016 and ADR-017 are untouched; the policy still runs on every send, ahead of
everything, and the cache is consulted after it. ADR-004 is superseded in the single clause named
above and in nothing else.
