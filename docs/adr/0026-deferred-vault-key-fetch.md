# ADR-026 — The Vault metadata read is deferrable; the advertised key still never moves

**Status:** Proposed

`VaultTransitVapidSigner`'s fetched mode reads `transit/keys/<key>` inside `build()`, taking the
latest version and that version's public key as one atomic pair. Under the Spring starter the signer
is an ordinary singleton and the sender's bean is conditional on it, so that read happens during
context refresh: a Vault that is unreachable, sealed, not yet initialized, or holding a mount that
has not been created keeps the application from starting at all. Reported as
https://github.com/the13haven/push2u/issues/91, from a deployment where web push is a secondary
channel and Vault is somebody else's service, brought up beside the application rather than before
it.

The same report asks for a second thing: a `refresh()` that re-reads the key and its version on a
live signer, so that `vault write -f transit/keys/<key>/rotate` takes effect without restarting the
fleet.

The two halves are independent, and only the first one is about when this library does its work.
ADR-025 removes a neighbouring case — a deployment that has declared it does not send never
constructs the signer, so it never pays for that read — but it says nothing about a deployment that
does send and meets a Vault that is not ready yet.

## The decision, part one: the read is deferrable, by a builder of its own

**`builderWithDeferredPublicKey(address, keyName, token)` is a third factory**, beside the two that
exist, and `push2u.signer.vault.public-key-fetch` selects it under Spring.

- **A factory rather than an optional step**, because the convention here gives one
  `builderWith<what exactly>()` to each way of assembling a type that differs in *contract*, and the
  three contracts are distinct: the eager fetched builder reads Vault inside `build()` and pins what
  it read; the supplied builder takes the key and the version from the caller and contacts nothing,
  ever; this one takes them from Vault, at first use rather than at construction. The axis is
  therefore *where the published key comes from and what `build()` promises*, and not merely whether
  `build()` performs I/O — on that narrower question the deferred and the supplied builders answer
  alike. A `fetchOnFirstUse()` step on the fetched builder would instead make one `build()` sometimes
  perform I/O and sometimes not, which is the ambiguity the split exists to prevent. The name keeps
  the form of the two shipped factories, which name the key rather than the call. The price is a
  third builder repeating `mount`, `namespace`, `transport` and `allowInsecureHttp()`; that
  duplication already exists between the two shipped builders, and it is cheaper than a terminal
  operation whose contract a reader has to reconstruct from another step.
- **`build()` still performs every check that does not depend on a Vault response**, with the same
  types — including the refusal of plain `http` to a host that is not a literal loopback, which is
  decided in `build()` because the opt-in is a builder step. The checks that move are exactly the
  three that read the response: the Transit `type`, the domain parameters and the point on the
  curve. What `build()` no longer does is contact Vault, so in this
  mode it raises neither `VapidSignerUnavailableException` nor the `PushCryptoException` that reports
  a key Vault could not have meant. The startup-supervisor contract the fetched builder documents —
  test the interruption, then the type — belongs to the eager builder alone, and the deferred one
  says so rather than inheriting a sentence about failures it cannot produce.
- **The first `sign`, `publicKey` or `publicKeyBase64Url` performs the read.** The enumeration binds
  all three because it binds an *overriding* `publicKeyBase64Url` too: the `default` implementation
  initializes through `publicKey` on its own, and an implementation that answers from a custodian's
  pre-encoded form must initialize as well rather than answer before the pair exists.
- **A successful pair is retained for the signer's lifetime**, as one immutable record published
  through a single volatile field. Both halves of that sentence are load-bearing. The pair is atomic
  because that is the whole reason the fetched mode exists — a version and a public key from one
  response, so the two can never drift — and it is retained because the advertised key is
  contractually stable for a signer's lifetime. There is no TTL, no eviction and no second read after
  a success: those would each be a way of spelling the `refresh()` that part two refuses.
- **The signing `POST` never runs while the initialization lock is held.** ADR-019 fixed that rule
  for the token cache — look up, release, sign, publish — and the reason is the same here: a
  signature that queues behind another thread's Vault call is the stall this change exists to remove,
  relocated into a narrower place.

### The property

`public-key-fetch` takes `eager` and `deferred`, and nothing else. Four readings are fixed here
rather than left to the implementation, because the record next door fixes the same kind of question
for its own switch:

- **Unset is distinguishable from a written value**, so the property is bound without a default.
  Absent, the mode is the one the other properties already imply: eager where no `public-key` is
  set, and no metadata read at all where one is.
- **A blank value is not a written one.** Spring binds an empty property to the empty string rather
  than to nothing, so the `${VAR:}` shape that ADR-025's own context is about would otherwise land
  between "unset" and "a value that is neither". It reads as unset, which is how this starter
  already reads a blank `public-key`.
- **Any written value beside a `public-key` fails the context**, naming both keys. The supplied mode
  performs no metadata read, so a deployment stating when that read happens has stated something
  about a call that does not exist — and `deferred` there would otherwise read as a promise the
  signer cannot keep.
- **A value that is neither fails the context naming the key**, rather than being read as one of
  the two.

### Why the deferred mode must cache, rather than read the key when asked

`PushSender` reads `signer.publicKey()` on **every** token-cache lookup, hit included, because the
advertised key is half of the cache key and is what detects a signer whose identity moved. Today
that read is a field clone: measured at 7 ns on the Vault signer, which is the one where it could
plausibly have been a round trip, and the same shape on the local one. A deferred mode implemented
as "go to Vault when someone asks for the key" would therefore put a `GET` on the path of every send,
hit or miss — the signer ADR-019 describes as keeping a round trip per send by its own construction,
and says nothing in the sender can take that round trip off the path. So caching after a success is
not a
tuning choice in this decision; it is the condition under which the deferred mode is allowed to
exist.

### The initialization contract

> Deferred initialization permits at most one active metadata fetch per signer. Callers already
> attached to that fetch share its successful metadata, or a fresh exception reconstructed from its
> failure description — where that failure was one of the two contract types and was not an
> interruption. They never share one thrown exception instance, and the caller that performed the
> fetch keeps the exception it was given rather than a reconstruction of its own failure. A failure
> of neither contract type is never shared: it reaches its own caller unchanged and abandons the
> flight, as a cancellation does. A cancellation belongs only to the thread that was interrupted:
> cancellation of the fetching caller abandons that flight and lets one remaining caller begin
> another, while cancellation of a waiting caller leaves the active flight untouched. After a shared
> failure, later callers may begin a new fetch; only successful metadata is retained for the signer's
> lifetime.

That paragraph is the contract, and the state machine it implies has four transitions out of a
flight rather than two:

```text
UNINITIALIZED
    │ a caller becomes the fetching one
    ▼
FETCHING(flight)
    ├── success ──────────────────► READY(metadata)   kept for the signer's lifetime
    ├── shared failure ───────────► UNINITIALIZED     each waiter throws its own exception
    ├── fetching caller cancelled ► UNINITIALIZED     waiters retry; one takes over
    └── failure of neither type ──► UNINITIALIZED     waiters retry; it reaches its own caller
```

The three returns to `UNINITIALIZED` are not one event, and conflating them is the defect this record
exists to prevent. Five consequences are contract rather than implementation advice:

- **Single flight, because a cold fan-out is a load amplifier.** Without it, N callers meeting an
  uninitialized signer make N concurrent metadata reads for one value. Against a healthy Vault that
  is N audited operations — Vault writes every request and response to each audit device and refuses
  all requests when one cannot be written, which is the same amplification argument the health
  indicator's result cache already carries. Single flight is about the signer's own record of an
  active fetch, not about I/O somewhere below: a transport whose request has been abandoned may still
  be finishing it, and nothing here can or should reach into that.
- **A failure is shared with the flight it belongs to, and then forgotten.** A caller that arrived
  while the fetch was running gets that fetch's outcome; a caller arriving afterwards starts a new
  one. There is no negative cache: a custodian that could not serve the read a moment ago is
  precisely the thing that ends on its own terms, and remembering its refusal would turn a transient
  outage into a permanent one — the failure mode ADR-021 refuses at the other end of the library.
- **Cancellation is caller-local, in both directions.** This is the half that fails silently. An
  interrupted fetch reaches this library as an unavailability with an `InterruptedException` in its
  cause chain and the flag re-set, because a transport does not sort an incomplete exchange by what
  made it incomplete — and the facade recognises a cancellation by a disjunction over exactly those
  two signals. So handing the fetching caller's exception to threads nobody interrupted converts
  their sends into an interruption: a cancellation invented for a caller that never asked for one,
  reported with an interrupt flag nothing set. The fetching caller therefore keeps its own exception,
  its flight is abandoned rather than failed, and the waiters retry. Symmetrically, a waiter that is
  interrupted while waiting takes its own cancellation and leaves the flight running for everyone
  else — it did not start the fetch and must not end it. A waiter has no transport failure to keep,
  so its cancellation takes the shape the transport would have produced: a
  `VapidSignerUnavailableException` with the `InterruptedException` beneath it and the interrupt flag
  re-set, which is what the facade's disjunction converts into the cancellation the caller asked for.
  **A flight applies that disjunction to every failure it is about to share, before classifying it by
  type**, so an interruption a defective transport wrapped in a recurring type is still not shared.
  That is deliberately broader in *scope* than where the facade applies the same test — the facade
  tests inside its two conversion sites, and a `PushCryptoException` from the signer propagates
  untested — and the two therefore differ about that one mislabelled exception on purpose. The flight
  refuses to share it; the fetching caller still sees it leave `send` as the recurring failure it was
  labelled, which is today's behaviour and not this record's to change.
- **A failure is never shared as one thrown instance.** One exception thrown from several threads
  carries the fetching caller's stack, leaves each waiter without its own, and gives them all one
  mutable suppressed-exception list. A flight therefore records an immutable description of what
  failed — the message, the cause it carried, and for an unavailability the status and the declared
  delay — and each waiter throws its own exception built from that: its own stack from its own throw
  site, and the recorded cause beneath it. The failing instance itself is not retained past the
  flight. The description does hold a `Throwable`, so what is ruled out is one instance *thrown* by
  several threads rather than one instance reached from several cause chains; a cause is diagnostics,
  and nothing in this library writes into one.
  Two details of the reconstruction are decided here. The promise is the **contract type** —
  `VapidSignerUnavailableException` or `PushCryptoException` — and not the runtime class: both are
  extensible, a subclass a custom transport raised cannot be reconstructed without reflection, and
  nothing in the published contract lets a caller branch on it. And the two declared values are read
  **exactly once**, when the description is taken, because the accessors are not final and an
  extending exception may answer differently on every call. That is not a new rule:
  `PushOutcome.SignerUnavailable` snapshots the same two values in its constructor for the same
  reason, and a test pins it.
- **A failure that is neither contract type ends the flight the way a cancellation does.** The
  transport is a consumer-replaceable seam, and any other `RuntimeException` out of it is a defect
  that must propagate unchanged. There is nothing to reconstruct it as, and laundering it into either
  contract type is exactly what the exception taxonomy forbids. So it reaches its own caller as it
  is, the flight is abandoned, and the waiters retry.

### What this costs, stated as the trade it is

Deferring the read moves the P-256 validation — the Transit `type`, the domain parameters, the point
on the curve — from startup to first use. A misconfigured key that fails the boot today would, in
this mode, fail the first send with `PushCryptoException` instead.

**That is not fail-fast relocated into the health indicator, and this record does not claim it is.**
The indicator only runs when something evaluates it: it needs Actuator on the classpath, it can be
switched off by its own property, it lands in the health endpoint's primary group, and Spring Boot
does not put an arbitrary contributor into the readiness group unless the operator says so. So the
honest name for the deferred mode's guarantee is *first-observation validation*: a deployment that
includes push2u in readiness, or polls the health endpoint, learns within seconds of starting; one
that does neither may not learn until the first send. `eager` therefore stays the default, and the
documentation states the fork rather than implying that nothing was given up.

The second cost is paid by whoever waits. A caller that arrives during a flight blocks on *another
caller's* Vault call, bounded by that flight's own connect and request timeouts and by nothing this
library adds — and a custom transport that sets no request timeout holds every waiter rather than
only the caller who started the fetch. This is the same reasoning ADR-019 used to keep a signature
out of the token cache's lock, and here it is accepted rather than refused: the call being waited on
is the one that has to complete before any send can proceed at all, and the alternative to waiting
for it is making the same call again.

### The zero-cost option that already exists

A deployment whose only requirement is that boot must not depend on Vault does not need this mode at
all: the supplied-key builder, and its `public-key` plus `key-version` properties, construct a signer
without contacting anything. The public key and the version are not secrets — they are the
deployment's published identity — so carrying them in configuration is not the duplication it would
be for key material, and the health probe as it stands today catches a mispinned pair by verifying a
signature against the advertised key. What it gives up is the single source of truth: the operator
now provisions two values that must agree with Vault. This record names that route in the
documentation as the first answer, with the deferred mode for deployments that want Vault to remain
the only place the key is stated.

## The decision, part two: `refresh()` is refused

**No method re-reads the key on a live signer**, and the advertised key stays stable for the signer's
lifetime.

- **The protocol makes a hot rotation something other than a rotation.** RFC 8292 §4.2 entitles a
  push service to refuse a JWT whose key is not the one the subscription was created under, so
  swapping the advertised key under a live sender does not adopt a new key — it invalidates every
  restricted subscription taken out under the old one. The operation an operator wants is a
  migration, not a mutation.
- **The current SPI cannot express the swap safely, and an atomic field inside the signer does not
  fix it.** A header is built from two separate calls: `sign` first, then `publicKey`. A refresh
  landing between them produces a signature from the old version beside the new key's `k` — a header
  that is internally contradictory and can only fail at the push service, far from its cause.
  ADR-019 already recorded this residue, as the one thing a signer violating its contract could do
  inside a single header; building `refresh()` would make our own shipped signer that violator, in
  its normal mode of operation. The only construction that would close it for this signer is a single
  SPI call returning the signature and the key together, which ADR-019 weighed and refused: an
  abstract addition to a published interface, for a hazard that rescues no deployment whose
  advertised key moved anyway.
- **Rotation is therefore documented as a migration**, and the recipe is more than "new signer, new
  sender": new subscriptions are created under the new `applicationServerKey`, subscriptions created
  under the previous key keep being sent through a sender holding the previous signer, and the old
  identity is retired only once that cohort is gone. Without the routing step the application cannot
  tell which sender a given stored subscription belongs to, which is the part a shorter recipe leaves
  the reader to discover in production. Raising `min_encryption_version` past the pinned version, or
  trimming it with `min_available_version`, ends the old signer's ability to sign at all — so those
  are the operations that must wait until the migration is finished, and today they fail loudly with
  a `PushCryptoException` on every send.
- **No key-version accessor is published yet.** A `keyVersion()` on the Vault signer answers what
  this process pinned and not what Vault now holds, so it detects drift only for a caller that reads
  Vault itself; it needs an absent-value shape for the supplied mode without a pin; and it invites
  reading `latest != pinned` as a fault, when for VAPID that is the normal and safe state. The
  operational check belongs in the documentation, against Vault, and an accessor is published when a
  consumer has a use for it and an action to take from its answer.

## What this does not touch

- **ADR-004.** The retained pair is not the state that record rules out. It is not a subscription and
  says nothing about one; it is not per-send state, since one pair serves every send; and it is
  reconstructible from the custodian at any moment. It is the same value the eager mode already holds
  in a final field for the life of the signer — this decision moves when it is written, not what is
  kept.
- **ADR-019.** That record rules out an unbounded or unevictable cache, and the pair here has neither
  a bound nor an eviction rule on purpose. The two are different objects: a token expires and is one
  of many, keyed by an audience an untrusted party can influence, while the pair is one published
  identity per signer that is contractually forbidden to change. Nothing about the token cache's
  bound is relaxed, and no second entry can ever exist here to bound.
- **ADR-005 and ADR-010.** No SPI gains a member, and the seam count stays three. What changes is one
  implementation's construction, behind the interface both records draw.
- **ADR-016, ADR-021, ADR-022.** The endpoint policy still runs on every send ahead of everything;
  no retry is introduced anywhere; and the exception taxonomy is applied rather than extended — this
  record adds no type and re-labels none.
- **ADR-025, whose text is not edited by this decision.** It describes the fetched mode's read as
  happening at startup, which is what that mode was when it was written and remains the context that
  record states. An ADR fixes its context at the time of the decision; what the signer does *now*
  belongs to `docs/DESIGN.md`, which is the document that may be rewritten. So the sentence stays as
  it is, and nothing here asks a future reader to reconcile the two.

## Rejected alternatives

- **A `@Lazy` injection point in the starter**, which would need no library change at all. The proxy
  turns a Vault outage into a `BeanCreationException` on first use, which leaves `send` with neither
  `SignerUnavailable` nor any other classified outcome but a foreign `RuntimeException` the facade
  must treat as a defect — the taxonomy ADR-022 settled, bypassed by the framework.
- **Retrying the startup read with backoff**, which is what the reporter's other Vault consumers do.
  It puts a schedule and a sleep inside a library that has just finished handing every schedule to
  the caller, and it only postpones the same failure while holding the context in a starting state.
- **A background refresher or a `refresh-interval` driven from a `TaskScheduler`.** ADR-019 refused a
  thread that runs when nobody called the library, and this would be a thread whose purpose is the
  mutation part two refuses.
- **A TTL on the fetched pair**, which is a refresh with the trigger hidden in a duration.
- **Remembering a failed fetch**, which converts a custodian's transient state into a permanent one.
- **Sharing one exception instance with every waiter**, and **preserving the fetching caller's
  concrete exception subclass**: the first is wrong about stacks and suppressed state, the second
  promises more than the published contract has ever offered.
- **Treating a cancelled fetch as a failure the flight can share**, which invents a cancellation for
  callers that were never interrupted.
- **`java.lang.StableValue`**, whose semantics are exactly right — lazy, write-once, single
  initialization. The bar it does not clear is the build's, not the runtime's: the compiler targets
  release 21, so an API that does not exist there cannot be referenced at all, and a preview type
  would additionally oblige every consumer to enable preview features on the one JDK version that
  ships it.
- **A `fetchOnFirstUse()` step on the existing fetched builder**, and **a boolean property**: both
  above, under why the factory and why the enum.

## What the implementation has to demonstrate

Beyond the ordinary — the property binding and its four readings, `eager` remaining the default and
still failing the boot:

- a deferred `build()` touches the transport not at all, while every local rejection it made before
  still happens there;
- a cold `publicKey()` and a cold `sign()` each perform exactly one metadata read, and the version
  that read reported is pinned in the subsequent `sign` request;
- a concurrent cold wave performs one read and every caller gets the same pair;
- a concurrent failing wave performs one read; every caller gets the contract type the fetch failed
  with — carrying the same status and declared delay where that type was the unavailability, which is
  the only one of the two that reports either — as distinct exception instances each with the
  recorded cause beneath it;
- a later caller, after a failed wave, starts a new read;
- an interrupted fetching caller keeps its own exception, and no waiter is handed a cancellation: one
  of them starts the next read, and none of their sends reports an interruption. Both halves of the
  disjunction are exercised — a cause chain carrying `InterruptedException` with the flag cleared,
  and the flag set with no such cause — and so is an interruption a transport mislabelled as a
  recurring failure, which the flight refuses to share while its own caller still receives it as
  labelled;
- an interrupted waiter takes its own cancellation while the flight continues to serve the others,
  with no second read, and its own `send` reports the interruption;
- a failure that is neither contract type reaches its own caller unchanged, and the waiters retry;
- a first read failing inside a `send` is sorted by the taxonomy rather than by where it happened: an
  unavailability arrives as the `SignerUnavailable` outcome and a `PushCryptoException` leaves `send`
  as itself. Worth its own case because the first `publicKey()` happens at the token-cache key step
  rather than where the VAPID header is built;
- the published conformance kit passes against a deferred-mode signer, whose `publicKey()` performs
  I/O on the call the kit makes first;
- after initialization, a token-cache hit performs no Vault call at all, and the initialization guard
  does not serialize signing: a second `sign` completes while a first is blocked inside the
  transport;
- the health indicator, when disabled, causes no fetch; when enabled, its first probe initializes
  through the signature it takes first and then reads the key.

The concurrent cases are gated deterministically inside the fake transport rather than by thread
timing: a wave that is only *probably* concurrent passes for the wrong reason on a busy runner.

## Documents

`README.md`, whose Vault example is the eager fetched builder; `docs/VAULT.md` for both modes, the
migration recipe and the supplied-key route stated as the zero-cost answer; `docs/SPRING.md` for the
property; `docs/DESIGN.md` §7; and `docs/PERFORMANCE.md`, whose note beside the 7 ns figure says the
fetched mode reads Vault once at startup and never again — true of one of the two modes once this
lands, and that document deletes a sentence that no longer holds rather than letting it age. The
startup-supervisor contract is stated in three places that must stop reading as though it applied to
every fetched builder — the builder's Javadoc, `docs/VAULT.md` and `docs/DESIGN.md`.

## What this rules out

A deferred mode that reads the key again after a successful read, retains anything but a successful
pair, or consults Vault on a token-cache hit; a deferred mode selected by a step on a builder whose
`build()` also reads Vault, or by a boolean property; `eager` ceasing to be the default; a deferred
`build()` that contacts Vault, or that skips a check the eager one makes without reading a Vault
response; a written `public-key-fetch` accepted beside a supplied `public-key`, an unrecognised value
read as either mode, a blank value read as a written one, and a binding that cannot tell an unset
property from a written one; a metadata read begun while the
signer records another as active; a failed or cancelled read remembered as state; a fetching caller's
cancellation delivered to a caller that was not interrupted, a waiter's cancellation ending a flight
that serves others, or a cancellation shared because it was classified by the type it was wrapped in
rather than by the disjunction that recognises it; a failure of neither contract type laundered into
one of them; one exception instance thrown by several threads, an exception's declared values read
once per observer rather than once per flight, and a promise about the concrete class of a
reconstructed failure; a signature taken while the initialization guard is held; a claim that the
health indicator makes the deferred mode fail-fast; and, on the other half, any published operation
that re-reads a key the signer has already read successfully — a `refresh()`, a TTL, a scheduled
refresher — a key-version accessor published without a consumer, and a rotation recipe that omits the
routing of subscriptions created under the previous key.
