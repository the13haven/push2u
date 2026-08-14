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

**`builderWithDeferredPublicKeyFetch(address, keyName, token)` is a third factory**, beside the two
that exist, and `push2u.signer.vault.public-key-fetch` selects it under Spring with the values
`eager` (the default, today's behaviour) and `deferred`.

- **A factory rather than an optional step**, because the convention here gives one
  `builderWith<what exactly>()` to each way of assembling a type that differs in *contract*, and
  that is exactly the axis the two existing builders are split on: `builderWithFetchedPublicKey`
  reads Vault inside `build()` and can fail there, `builderWithSuppliedPublicKey` contacts nothing.
  A `fetchOnFirstUse()` step on the fetched builder would make one `build()` sometimes perform I/O
  and sometimes not — the ambiguity the split exists to prevent, reintroduced as a flag. The price
  is a third builder repeating `mount`, `namespace`, `transport` and `allowInsecureHttp()`; that
  duplication already exists between the two shipped builders, and it is cheaper than a terminal
  operation whose contract a reader has to reconstruct from another step.
- **An enum rather than a boolean property**, because the question is *when the key is read* and a
  third answer is imaginable, while `public-key-fetch: true` names nothing. `fetch` alone is refused
  as the key: this signer makes two kinds of Vault call, a metadata `GET` and a `sign` `POST`, and
  only the first one is deferred.
- **`build()` still performs every local check**, in the same order and with the same types —
  including the refusal of plain `http` to a host that is not a literal loopback, which is decided
  in `build()` because the opt-in is a builder step. What it no longer does is contact Vault, so in
  this mode it raises neither `VapidSignerUnavailableException` nor the `PushCryptoException` that
  reports a key Vault could not have meant. The startup-supervisor contract the fetched builder
  documents — test the interruption, then the type — belongs to the eager builder alone, and the
  deferred one says so rather than inheriting a sentence about failures it cannot produce.
- **The first `sign`, `publicKey` or `publicKeyBase64Url` performs the read.** All three, because
  all three need the pair: `publicKeyBase64Url` is a `default` method over `publicKey`, and `sign`
  pins the version the advertised key belongs to.
- **A successful pair is retained for the signer's lifetime**, as one immutable record published
  through a single volatile field. Both halves of that sentence are load-bearing. The pair is
  atomic because that is the whole reason the fetched mode exists — a version and a public key from
  one response, so the two can never drift — and it is retained forever because the advertised key
  is contractually stable for a signer's lifetime. There is no TTL, no eviction and no second read
  after a success: those would each be a way of spelling the `refresh()` that part two refuses.
- **The signing `POST` never runs while the initialization lock is held.** ADR-019 fixed that rule
  for the token cache — look up, release, sign, publish — and the reason is the same here: a
  signature that queues behind another thread's Vault call is the stall this change exists to
  remove, relocated into a narrower place.

### Why the deferred mode must cache, rather than read the key when asked

`PushSender` reads `signer.publicKey()` on **every** token-cache lookup, hit included, because the
advertised key is half of the cache key and is what detects a signer whose identity moved. Today
that read is a field clone on both shipped signers, measured at 7 ns, which is what makes ADR-019's
arithmetic hold. A deferred mode implemented as "go to Vault when someone asks for the key" would
therefore put a `GET` on the path of every send, hit or miss — the signer ADR-019 describes as
keeping a round trip per send by its own construction, and says nothing in the sender can take off
the path. So caching after the first success is not a tuning choice in this decision; it is the
condition under which the deferred mode is allowed to exist.

### The initialization contract

> Deferred initialization permits at most one active metadata fetch per signer. Callers already
> attached to that fetch share its successful metadata, or a fresh exception reconstructed from its
> non-interruption failure description. They never share one thrown exception instance. A
> cancellation belongs only to the thread that was interrupted: cancellation of the fetching caller
> abandons that flight and lets one remaining caller begin another, while cancellation of a waiting
> caller leaves the active flight untouched. After a shared failure, later callers may begin a new
> fetch; only successful metadata is retained for the signer's lifetime.

That paragraph is the contract, and the state machine it implies has three transitions out of a
flight rather than two:

```text
UNINITIALIZED
    │ a caller becomes the fetching one
    ▼
FETCHING(flight)
    ├── success ──────────────────► READY(metadata)      retained for the signer's lifetime
    ├── shared failure ───────────► UNINITIALIZED        waiters get a fresh exception each
    └── fetching caller cancelled ► UNINITIALIZED        waiters retry; one becomes the next
```

The two returns to `UNINITIALIZED` are not the same event, and conflating them is the defect this
record exists to prevent. Four consequences are contract rather than implementation advice:

- **Single flight, because a cold fan-out is a load amplifier.** Without it, N threads meeting an
  uninitialized signer make N metadata reads. Against a healthy Vault that is N audited operations
  for one value — Vault writes every request and response to each audit device and refuses all
  requests when one cannot be written, which is the same amplification argument the health
  indicator's result cache already carries. Against an unreachable Vault it is worse than the
  startup failure this decision replaces: with the shipped defaults of a 10 s connect timeout and a
  30 s request timeout, a serialized queue of waiters each paying its own timeout leaves the last
  one waiting N times over.
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
  their sends into `PushInterruptedException`: a cancellation invented for a caller that never asked
  for one, and the send abandoned rather than attempted. The fetching caller therefore keeps its own
  exception, its flight is abandoned rather than failed, and the waiters retry. Symmetrically, a
  waiter that is interrupted while waiting takes its own cancellation and leaves the flight running
  for everyone else — it did not start the fetch and must not end it.
  **The cancellation test runs before the failure is classified by type**, over the same disjunction
  the facade uses: an interruption that a defective transport wrapped in a `PushCryptoException` is
  still a cancellation, and must not be shared under the type it was mislabelled with.
- **What is shared is a description, never a `Throwable`.** One exception instance thrown from
  several threads carries the fetching caller's stack, loses each waiter's own, and shares mutable
  suppressed-exception state between them. A flight therefore records an immutable description —
  the message, the cause, and for an unavailability the status and the declared delay — and each
  waiter constructs its own exception from it: the original as the cause, its own stack from its own
  throw site.
  Two details of that reconstruction are decided here rather than left to the implementation. The
  promise is the **contract type** — `VapidSignerUnavailableException` or `PushCryptoException` —
  and not the runtime class: both are extensible, a subclass a custom transport raised cannot be
  reconstructed without reflection, and nothing in the published contract lets a caller branch on
  it. And the two declared values are read **exactly once**, when the description is taken, because
  the accessors are not final and an extending exception may answer differently on every call. That
  is not a new rule: `PushOutcome.SignerUnavailable` snapshots the same two values in its
  constructor for the same reason, and a test pins it.

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

### The zero-cost option that already exists

A deployment whose only requirement is that boot must not depend on Vault does not need this mode at
all: the supplied-key builder, and its `public-key` plus `key-version` properties, construct a
signer without contacting anything. The public key and the version are not secrets — they are the
deployment's published identity — so carrying them in configuration is not the duplication it would
be for key material, and the health probe catches a mispinned pair by verifying a signature against
the advertised key. What it gives up is the single source of truth: the operator now provisions two
values that must agree with Vault. This record names that route in the documentation as the first
answer, with the deferred mode for deployments that want Vault to remain the only place the key is
stated.

## The decision, part two: `refresh()` is refused

**No method re-reads the key on a live signer**, and the advertised key stays stable for the
signer's lifetime.

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
  its normal mode of operation. The only construction that would close it is a single SPI call
  returning the signature and the key together, which ADR-019 weighed and refused: an abstract
  addition to a published interface, for a hazard that rescues no deployment whose advertised key
  moved anyway.
- **Rotation is therefore documented as a migration**, and the recipe is more than "new signer, new
  sender": new subscriptions are created under the new `applicationServerKey`, subscriptions created
  under the previous key keep being sent through a sender holding the previous signer, and the old
  identity is retired only once that cohort is gone. Without the routing step the application cannot
  tell which sender a given stored subscription belongs to, which is the part a shorter recipe
  leaves the reader to discover in production. Raising `min_encryption_version` past the pinned version, or
  trimming it with `min_available_version`, ends the old signer's ability to sign at all — so those
  are the operations that must wait until the migration is finished, and they fail loudly today with
  a `PushCryptoException` on every send.
- **No key-version accessor is published yet.** A `keyVersion()` on the Vault signer answers what
  this process pinned and not what Vault now holds, so it detects drift only for a caller that reads
  Vault itself; it needs an absent-value shape for the supplied mode without a pin; and it invites
  reading `latest != pinned` as a fault, when for VAPID that is the normal and safe state. The
  operational check belongs in the documentation, against Vault, and an accessor is published when a
  consumer has a use for it and an action to take from its answer.

## Rejected alternatives

- **A `@Lazy` injection point in the starter**, which would need no library change at all. The
  proxy turns a Vault outage into a `BeanCreationException` on first use, which leaves `send` as
  neither `SignerUnavailable` nor any other classified outcome but as a foreign `RuntimeException`
  the facade must treat as a defect — the taxonomy ADR-022 settled, bypassed by the framework.
- **Retrying the startup read with backoff**, which is what the reporter's other Vault consumers do.
  It puts a schedule and a sleep inside a library that has just finished handing every schedule to
  the caller, and it only postpones the same failure while holding the context in a starting state.
- **A background refresher or a `refresh-interval` driven from a `TaskScheduler`.** ADR-019 refused
  a thread that runs when nobody called the library, and this would be a thread whose purpose is the
  mutation part two refuses.
- **A TTL on the fetched pair**, which is a refresh with the trigger hidden in a duration.
- **Remembering a failed fetch**, which converts a custodian's transient state into a permanent one.
- **Sharing one exception instance with every waiter**, and **preserving the fetching caller's
  concrete exception subclass**: the first is wrong about stacks and suppressed state, the second
  promises more than the published contract has ever offered.
- **Treating a cancelled fetch as a failure the flight can share**, which invents a cancellation for
  callers that were never interrupted.
- **`java.lang.StableValue`**, whose semantics are exactly right — lazy, write-once, single
  initialization — and which is a preview API. The baseline is Java 21, and a preview type would
  oblige every consumer to run with preview features enabled on one JDK version.
- **A `fetchOnFirstUse()` step on the existing fetched builder**, and **a boolean property**: both
  above, under why the factory and the enum.

## What the implementation has to demonstrate

Beyond the ordinary — the property binding, the rejection of `public-key-fetch: deferred` beside an
explicit `public-key`, `eager` remaining the default and still failing the boot:

- a deferred `build()` touches the transport not at all, while every local rejection it made before
  still happens there;
- a cold `publicKey()` and a cold `sign()` each perform exactly one metadata read, and the version
  that read reported is pinned in the subsequent `sign` request;
- a concurrent cold wave performs one read and every caller gets the same pair;
- a concurrent failing wave performs one read; every caller gets the contract type the fetch failed
  with, carrying the same status and declared delay, as distinct exception instances each with the
  original beneath it;
- a later caller, after a failed wave, starts a new read;
- an interrupted fetching caller keeps its own exception, and no waiter is handed a cancellation:
  one of them starts the next read, and none of their sends reports an interruption. Both halves of
  the disjunction are exercised — a cause chain carrying `InterruptedException` with the flag
  cleared, and the flag set with no such cause — and so is an interruption mislabelled by a
  transport as a recurring failure;
- an interrupted waiter takes its own cancellation while the flight continues to serve the others,
  with no second read;
- after initialization, a token-cache hit performs no Vault call at all, and concurrent signatures
  are not serialized by whatever guards the initialization;
- the health indicator, when disabled, causes no fetch; when enabled, its first probe performs the
  metadata read and then a signature.

## Documents

`README.md`, whose Vault example is the eager fetched builder; `docs/VAULT.md` for both modes, the
migration recipe and the supplied-key route stated as the zero-cost answer; `docs/SPRING.md` for the
property; `docs/DESIGN.md` §7; the Javadoc of both fetched builders, where the startup-supervisor
contract has to stop being stated as though it applied to both.

ADR-025 is `Proposed` as this is written, and one of its sentences describes the Vault signer's
fetched mode as "a read from Vault during startup". Under this decision that is true of one of two
modes. While that record is still a draft the sentence can be generalised to the metadata read
itself; once its decision is implemented it may not be edited at all, and the description of what
the signer currently does belongs to `docs/DESIGN.md` regardless.

This rules out a Vault signer whose deferred mode reads the key more than once for a lifetime, or
consults Vault on a token-cache hit; a deferred mode selected by a step on a builder whose `build()`
also reads Vault, or by a boolean property; a metadata read performed while another one is in
flight; a failed or cancelled read remembered as state; a fetching caller's cancellation delivered
to a caller that was not interrupted, and a waiter's cancellation ending a flight that serves
others; a cancellation classified by the type it was wrapped in rather than by the disjunction that
recognises it; one exception instance thrown from several threads, an exception's declared values
read once per observer rather than once per flight, and a promise about the concrete class of a
reconstructed failure; a signature taken while the initialization guard is held; a claim that the
health indicator makes the deferred mode fail-fast; and, on the other half, any published operation
that re-reads the key on a live signer — a `refresh()`, a TTL, a scheduled refresher — a key-version
accessor published without a consumer, and a rotation recipe that omits the routing of subscriptions
created under the previous key.
