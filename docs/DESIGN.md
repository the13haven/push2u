# push2u — Design

## 1. Status and scope

push2u is an implemented, standalone Java library for server-side Web Push delivery. Artifacts are
released to Maven Central under the `com.the13haven` group ID; the version is derived from git
tags rather than stored in the build
([ADR-013](adr/0013-release-and-publication-process.md)). Java packages are
`com.the13haven.push2u.*`.

The library implements:

- RFC 8030 push delivery and response interpretation;
- RFC 8291 message encryption;
- RFC 8292 VAPID authentication;
- RFC 8188 `aes128gcm` content coding;
- RFC 5869 HKDF-SHA-256;
- local and Vault Transit VAPID signing;
- plain Java and Spring Boot integration.

The architecture keeps the protocol core free of runtime implementation dependencies and exposes
narrow seams only where applications have a legitimate reason to replace behavior.

**This document describes the architecture as it stands, and why it is that way.** The decisions
behind it — with the context they were taken in and the alternatives rejected — are one file per
decision in [`docs/adr/`](adr/README.md); they are cited here rather than restated. How to
*use* the library belongs to the consumer-facing references instead: [`README.md`](../README.md) for
the API, [`SPRING.md`](SPRING.md) and [`VAULT.md`](VAULT.md) for the two integrations,
[`HEALTH.md`](HEALTH.md) for the health indicator one of them registers, [`VAPID.md`](VAPID.md) for
generating the key pair, [`PUSH-SERVICES.md`](PUSH-SERVICES.md) for the browser push services an
endpoint allowlist names, and the Javadoc for individual contracts.

## 2. Goals and non-goals

The library exists to replace `nl.martijndwars:web-push`, the JVM's usual answer for Web Push,
whose transitive surface and BouncyCastle-typed public API are what
[ADR-002](adr/0002-zero-dependency-core.md) records as the motive for the dependency posture.
[`MIGRATION.md`](MIGRATION.md) maps the two APIs onto each other for consumers making the move.

### Goals

- Zero runtime *implementation* dependencies in `push2u-core` — its one dependency is JSpecify, an
  annotation-only jar exposed as API metadata
  ([ADR-012](adr/0012-nullness-declared-with-jspecify.md)).
- Java 21 runtime baseline.
- Standards conformance pinned by published RFC test vectors.
- A small synchronous API with an asynchronous convenience wrapper.
- Replaceable VAPID key custody and HTTP transport.
- Immutable public value types and defensive handling of key material.
- Every operational outcome of a send represented as a value rather than exception-driven control
  flow, with the repeat decision and its schedule left to the caller.
- Optional Spring Boot and Vault integrations outside the core.

### Non-goals

- Subscription persistence or browser-side service-worker code.
- Legacy `aesgcm` content coding.
- General JSON parsing.
- Multi-tenant configuration, billing, or application-specific delivery orchestration.
- A general-purpose HTTP or cryptography abstraction.

## 3. Modules

```text
push2u-core
├── immutable domain types
├── RFC 8291 / RFC 8188 encryption
├── VAPID JWT construction
├── response classification and the PushOutcome hierarchy
├── LocalEcVapidSigner
└── JdkPushHttpClient

push2u-testkit
└── VapidSignerContractTest (the published conformance kit, for a test classpath)

push2u-signer-vault
├── VaultTransitVapidSigner
└── VaultHttpTransport / JdkVaultHttpTransport

push2u-spring-boot-starter
├── PushSender auto-configuration
└── optional signer health indicator

push2u-signer-vault-spring-boot-starter
└── Vault signer properties and auto-configuration
```

The dependency direction is one-way: the optional modules depend on the core, and no Spring or
Vault type reaches it. `push2u-testkit` carries JUnit and AssertJ, which is why it is a module of
its own rather than part of the core: it belongs on a consumer's test classpath and never on an
application's runtime one.

### JPMS identity

Each artifact carries a module name it will keep
([ADR-014](adr/0014-jpms-explicit-and-automatic-modules.md)). `push2u-core` and
`push2u-signer-vault` are explicit modules with a `module-info.java`; the two starters and the
published test kit are automatic modules with a fixed `Automatic-Module-Name`:

| Artifact | Module name | Kind |
|---|---|---|
| `push2u-core` | `com.the13haven.push2u` | explicit |
| `push2u-signer-vault` | `com.the13haven.push2u.signer.vault` | explicit |
| `push2u-spring-boot-starter` | `com.the13haven.push2u.spring` | automatic |
| `push2u-signer-vault-spring-boot-starter` | `com.the13haven.push2u.signer.vault.spring` | automatic |
| `push2u-testkit` | `com.the13haven.push2u.testkit` | automatic |

The core's descriptor is three lines — `requires transitive java.net.http`, `requires static
org.jspecify`, one `exports` — and both qualifiers carry weight.

`java.net.http` is `transitive` because `HttpClient` is not an implementation detail behind the
default client: it is a parameter of the public `JdkPushHttpClient(HttpClient, Duration)`, and of
`JdkVaultHttpTransport` in the Vault module, so a consumer configuring their own client would
otherwise have to require the JDK module themselves. `javac -Xlint:exports` flagged both
constructors before the qualifier was added.

`requires static org.jspecify` means nothing resolves the JSpecify jar at runtime — which is what
keeps the zero-dependency posture true on the module path as well as the class path. What makes
that safe is not annotation retention (JSpecify's annotations are `RUNTIME`-retained) but that the
JVM ignores an annotation whose type it cannot resolve. Verified by running a module-path consumer
with the jar absent, reflecting over every annotated member: empty annotation arrays, no
exception.

**The eleven `[exports]` warnings that lint reports on the core are accepted, not overlooked.**
Every one of them is `class Nullable in module org.jspecify is not indirectly exported`, and the
change lint asks for — `requires static transitive org.jspecify` — silences all eleven and breaks
every module-path consumer that does not itself ship JSpecify: `transitive` makes the module
mandatory at the consumer's compile time, and such a consumer fails with `module not found:
org.jspecify` (measured; with plain `requires static` the same consumer compiles). The annotations
are metadata for analysers, not types a caller must name, so the warning describes a problem this
API does not have. Do not "fix" it.

## 4. Send pipeline

```text
PushSender.send(subscription, message)
    │
    ├─ Check the payload against the maximum the configured body ceiling admits
    ├─ Validate the endpoint against the sender's EndpointPolicy (always present)
    ├─ Decode the subscription P-256 public key, checking the point is on the curve
    ├─ Generate an ephemeral P-256 key pair and random salt
    ├─ ECDH + HKDF-SHA-256
    ├─ Encrypt one RFC 8188 record with AES-128-GCM
    ├─ Look the endpoint's origin up in the sender's VAPID token cache (unless reuse is off)
    ├─ On a miss, build and sign a VAPID JWT and publish it to the cache
    ├─ POST the encrypted body through PushHttpClient, exactly once
    └─ Return PushOutcome
```

**The pipeline performs one POST and does not repeat it**
([ADR-021](adr/0021-retry-belongs-to-the-caller.md)). What a repeat decision needs — the
classification of the answer, and what the response's `Retry-After` said — is published on the
outcome instead, and the schedule belongs to whoever called `send`: a deployment sending at volume
already owns a retrier that can see its retry budget, its dead-letter path and what survives a
restart, none of which a loop inside the sender could. A send holds nothing across attempts that a
second call would not rebuild — the policy re-runs, the token is re-minted or served from its cache,
and the body is re-encrypted under a fresh ephemeral key and salt, which RFC 8291 §2 has the
application server generate per message in any case.

`PushOutcome` is a sealed hierarchy, so a `switch` over it is exhaustive and a variant added later
fails a consumer's compilation rather than falling through:

| What happened | `PushOutcome` variant |
|---|---|
| `2xx` | `Accepted(statusCode)` |
| `404`, `410` | `SubscriptionExpired(statusCode)` |
| `408`, `421`, `429`, a `413` carrying a parseable `Retry-After`, or a `5xx` other than `501`, `505`, `506`, `508`, `511` | `RetryableFailure(statusCode, retryAfter)` |
| Any other answered status | `NonRetryableFailure(statusCode)` |
| The POST went out and nothing answered | `Indeterminate` |
| The key custodian cannot sign now | `SignerUnavailable` — a `NotAttempted` |
| The payload does not fit the sender's configuration | `PayloadRejected(payloadBytes, maximumPayloadBytes)` — a `NotAttempted` |
| The endpoint policy refused the endpoint | `EndpointRejected(redactedEndpoint, reason)` — a `NotAttempted` |

`NotAttempted` is a marker whose three leaves implement it directly, so one `switch` chooses its own
grain: under it no POST was made, which is the only structural answer to whether a repeat can
duplicate a notification. The two class-shaped variants, `SignerUnavailable` and `Indeterminate`,
carry a `Throwable` and therefore compare by identity; both write their own `toString()` so that a
transport's cause chain, which can embed the subscription's capability URL, is reachable only
through the `cause()` a caller asks for by name.

The classification is taken per status rather than per class, each carve-out resting on that
status's own defining specification — the grounds are on the Javadoc of the variant that carries
them, which is where a consumer reads them. A `5xx` neither list names falls to the class (RFC 9110
§15.6: a statement about the server rather than about the request), so an unregistered or
later-registered `5xx` is never permanent by omission.

Three seam signals convert to outcomes and no others: `EndpointRejectedException` from the policy,
`VapidSignerUnavailableException` from the signer, `PushDeliveryException` from the transport. Any
other `RuntimeException` out of a consumer-written seam is a defect in that implementation and
propagates unchanged rather than being laundered into a value. What `send` itself throws is
`PushCryptoException` for a failure that recurs, `PushInterruptedException` for a cancellation, and
`IllegalArgumentException`/`NullPointerException` for an argument that is not a legal value of its
parameter ([ADR-022](adr/0022-one-type-per-programmatic-action.md)).

The interruption test is the facade's rather than any seam's, written as a disjunction — an
`InterruptedException` anywhere in the cause chain, *or* the current thread's interrupt status set —
because neither half is sound alone: an interruption can surface as a `ClosedByInterruptException`
or an `InterruptedIOException` with no `InterruptedException` beneath it, and a transport can attach
a cause without re-setting the flag. It runs on the signer path as well as the transport path, and
the cause-chain walk is guarded against a cycle a defective seam could construct. The interrupt
status is re-set before the throw, which on the async path means the worker's flag is re-set before
the future completes.

The VAPID token's reuse spans sends: one signed `Authorization` value serves every send to a
push-service origin until it nears expiry
([ADR-019](adr/0019-vapid-token-reused-until-it-nears-expiry.md)). The encrypted body is confined to
one send, since it is encrypted to one subscriber under one ephemeral key pair.

The endpoint policy runs after the size preconditions and before everything else — encryption, the
VAPID signature (a remote Vault/KMS call under an external signer) and the POST — so a rejected
endpoint costs no cryptography and no I/O. It runs unconditionally: a sender cannot exist without a
policy, so the pipeline has no branch around this step and the ordering guarantee does not depend
on configuration. `sendAsync` runs the same pipeline, so the policy cannot be bypassed on the async
path either.

The VAPID `aud` claim is the endpoint's origin in the Unicode serialization of RFC 6454 §6.1, as
RFC 8292 §2 requires: lowercase scheme and host, IDNA A-labels converted to their Unicode form,
and the port omitted when it equals the scheme's default. `java.net.URI` performs none of that
normalization, so the library serializes the origin itself (`Origin.serialize`).

That origin is also what makes the token cacheable: of the three claims, it is the only one a send
supplies. `sub` is a final field of the sender, and `exp` is computed at each mint from another
final field, the expiry offset — so `exp` does differ between tokens, and what a cached entry
relies on is not that it is fixed but that it names a window the entry is retired ahead of. A
`PushSender` therefore holds one bounded map of signed `Authorization` values, keyed by the audience
together with the base64url public key the `VapidSigner` currently advertises, so an entry is only
ever served to the signer in the identity it currently publishes and a key that moved misses rather
than serving a header naming a key the signer has abandoned. The key is that base64url string
rather than the raw bytes, since `publicKey()` returns a fresh array per call by contract and an
array key would compile and never hit. The lookup runs after the endpoint policy — the policy is
still unconditional and still ahead of everything, so a rejected endpoint reaches no cache — and
`jwtReuse(false)` bypasses the cache entirely, signing per send as the library did
before. Under the default the signature is therefore not taken on every send but on every miss,
which is where every new value still enters and where `VapidSigner`'s two output checks still run.

An entry's life is bounded by two clocks and ends at whichever bound is reached first: the sender's
`Clock` arriving within `jwtRenewBefore` of the effective expiry, or a `System.nanoTime()` reading
having run for that same span since the entry was minted. The wall bound alone would let a
backwards step — an NTP correction, a snapshot restore — leave every entry over-estimating its own
remaining life, presenting a token RFC 8292 §4.2 makes invalid; the monotonic bound does not step.
The two readings are sampled in whichever order over-estimates elapsed monotonic time, the anchor
first at mint and the current reading last at lookup, so an arbitrary pause between two statements
can only shorten an entry's life. Staleness is judged against `Instant.ofEpochSecond(exp)`, the
value that went on the wire, because RFC 7519 §4.1.4 invalidates a token from the second `exp`
names. What the pair leaves is the two clocks' relative drift over an entry's life, seconds at the
tens of parts per million a raw counter shows and invisible against a five-minute margin. The
monotonic reading has a package-private seam of its own beside the sender's `Clock`, without which
that bound is untestable at any span worth modelling.

The map is an access-ordered LRU bounded at `jwtCacheSize`, and the bound is a safety property
rather than a tuning one: audiences are the origins of endpoints inside subscriptions, which an
`EndpointPolicy` built from domain rules bounds only by a DNS zone, so an unbounded map would be a
memory-exhaustion path from data ADR-016 already treats as untrusted. The entry-count bound is
absolute because each entry's size is bounded too: `Subscription` refuses an endpoint above 2048
characters ([ADR-020](adr/0020-subscription-endpoint-length-bound.md)), so the audience an entry
stores — twice, in the key and inside the retained header — cannot be inflated by the party
supplying subscriptions, and the cache deliberately carries no size mechanism of its own.
Overflow evicts and degrades
to signing per send — never to a refusal, since a bound the deployment chose must not become a
delivery failure. Two further rules are not obvious from the code's shape. A `401` or `403` never
evicts the entry that produced it: RFC 8292 §4.2 lists a subscription created under a different
application server key among the causes of an invalid `vapid` authentication, so the status is not
a statement about the token, and evicting on it would let one such subscription cold-start the
origin every healthy send shares. And no signature is taken while the cache's monitor is held —
look up, release, sign, publish — because a signature may be a Vault round trip, and holding a lock
across it would rebuild the very stall the cache removes. Two threads missing on one audience
concurrently is a benign race: each signs its own valid token, one is published.

The size precondition is evaluated first, before any cryptography or network I/O, and one number
configures it: `maxEncryptedBodyBytes`, the RFC 8030 §7.2 ceiling on the encrypted entity body,
default 4096. Everything else is derived from it, once, at `build()`
([ADR-023](adr/0023-one-size-limit-answerable-before-a-send.md)):

```text
maximumPayloadBytes = maxEncryptedBodyBytes − BODY_OVERHEAD      (103)
recordSize          = maximumPayloadBytes + RECORD_OVERHEAD + 1  (17 + 1)
```

The derived `rs` — `maxEncryptedBodyBytes − 85`, so 4011 at the default — goes into the RFC 8188
header on every send and declares exactly the plaintext capacity the sender is able to use: the
second addend is the record overhead plus the one octet RFC 8291 §4 requires `rs` to exceed the
sum by, exact rather than floored, so the record-size rule can never be the bound that binds
through `PushSender`. The pre-flight maximum is therefore a single subtraction, clamped below at
zero — a `min` over the two preconditions would be a branch no input can select, reading as a live
guard.

An oversized payload is *reported* as `PayloadRejected`, carrying the plaintext the caller handed
over and `maximumPayloadBytes`. Both numbers are plaintext octets, the unit the caller can act in,
since the remedy is a shorter notification. That is not ADR-011 moving: where the limit is
*configured* stays on the encrypted body, and the plaintext maximum is a derivation ADR-011 already
makes. The refusal is an outcome rather than an exception because it is a fact about one message —
the concrete case is a translated notification that fits in one language and not another — and
killing a fan-out over it is the wrong behaviour.

**The same question is answerable before a send.** `PushSender.assessPayloadSize(byte[])` reads the
serialized payload's length — copying nothing, retaining nothing — and answers with the sealed
`PayloadSizeAssessment`: `WithinLimit`, deliberately empty, or
`ExceedsLimit(payloadBytes, maximumPayloadBytes)`, the same pair `PayloadRejected` reports. The
assessment is the *only* way to the budget: no bare `maximumPayloadBytes()` accessor exists on the
sender, so the first comparison is always the library's and cannot be a caller's UTF-16 code units
against octets. Asking replaces nothing — `send` checks every payload again and never trusts an
earlier assessment.

**The RFC 8291 §4 rule still has a single implementation, now read in both directions**:
`maxPlaintextForRecordSize` inverts the rule into the largest plaintext a given `rs` carries, and
`recordSizeForMaxPlaintext` beside it is its exact inverse. `checkRecordSize` — the encryptor's
own last-moment refusal, since `encrypt` keeps its `rs` parameter and is reachable directly with a
value too small for its plaintext — compares against the first and names the exact minimum via the
second; the sender's `build()`-time derivation runs through the second. A second copy of the rule
is a defect even where it agrees today. The derivation deliberately does not spell its `+ 18` as
`MIN_RECORD_SIZE`: the smallest legal `rs` is the same rule applied to an empty plaintext — the
same 18 for a different reason.

The 103-byte overhead is derived from the format the encryptor emits — an 86-byte RFC 8188 header
(salt 16, `rs` 4, `idlen` 1, `keyid` 65), the padding delimiter (1) and the AES-GCM tag (16) — not
hard-coded, so the plaintext maximum tracks a configured body limit
([ADR-011](adr/0011-size-limit-expressed-on-the-encrypted-body.md)).

The arithmetic is `long`, and it is load-bearing rather than defensive: in `int`, a payload above
`Integer.MAX_VALUE - 103` wraps to a negative size and passes any limit unnoticed, a
caller-supplied `rs` near either extreme wraps the record-size subtraction the same way, and the
pre-flight maximum is clamped below at zero before it narrows back to `int` — a negative `long`
narrowed to `int` can wrap into a large positive bound, the one failure a size limit must never
have. The derived `rs` stays below `Integer.MAX_VALUE` by construction (`maxEncryptedBodyBytes −
85` for every configuration) and cannot wrap either. The boundaries are covered by tests, which
take lengths rather than payloads so they need no multi-gigabyte arrays.

`sendAsync` runs the synchronous pipeline through `CompletableFuture.supplyAsync`. By default it
uses a library-owned virtual-thread-per-task executor rather than the common `ForkJoinPool`; the
builder accepts an application-owned `Executor` when bounded concurrency or a shared execution
policy is required. The HTTP transport itself remains synchronous. That default keeps its rationale
under one attempt per call rather than two: a blocking HTTP call still has no business on the common
pool. Every outcome completes the future normally; what `send` throws completes it exceptionally,
and an interrupted send completes it exceptionally with `PushInterruptedException` rather than
cancelling it, so a caller's own `cancel` — which does not interrupt a running task — stays
distinguishable from a worker stopped mid-flight.

The `Retry-After` header is parsed for any answered failure and travels on `RetryableFailure`, where
the classification leaves it actionable. The parser accepts delta-seconds and the three HTTP-date
forms RFC 9110 requires a recipient to accept, including RFC 850's two-digit-year rule and leap
seconds; a value matching none of them, or a delta too large for a `long`, is reported as no hint
rather than as a failure. **No ceiling is applied to what it reports**: the value the caller reads
is the value that arrived, so the only bound on the wait is the one whoever schedules the repeat
chooses. The header also classifies rather than merely informing in one place — RFC 9110 §15.5.14
has a server refusing a request for its size generate it only if the condition is temporary, which
is why a `413` carrying a parseable one is retryable and a bare `413` is not. It is deliberately not
reported on `SubscriptionExpired`: on `404`/`410` the subscription is gone, so a wait the service
named would be handed to a caller with nothing left to wait for.

## 5. Public API and extension points

### Facade

`PushSender` is the primary facade. Its two required values — exactly one VAPID key source, plus
the contact — are the factory method's parameters, so an incomplete sender does not compile and
`build()` has nothing left to refuse:

- `builder(VapidKeys, String contact, EndpointPolicy)` creates `LocalEcVapidSigner`; or
- `builder(VapidSigner, String contact, EndpointPolicy)` delegates signing and public-key
  publication.

The two are overloads of one `builder(…)` rather than differently named methods: they differ only
in which required key source they take, not in contract — and the overload choosing the key source
is what makes "no key source" and "both key sources" inexpressible rather than runtime errors.

The VAPID contact is required in both modes and must be non-blank. RFC 8292 §2.1 leaves the `sub`
claim optional; requiring it is a push2u contract, on the grounds that a push service reporting a
problem with an application server has no other channel to it. A blank value is rejected outright,
because it satisfies that contract no better than an absent claim while still producing a JWT
whose `sub` a push service may well reject — the RFC requires neither the claim nor its rejection.

The endpoint policy is the third required value, and a `null` is rejected at the factory like any
other present-but-invalid one. It is a parameter rather than a builder step because which hosts a
deployment may POST to is a decision that has to be made, even though the library cannot make it —
the two are different claims, and only the first belongs to the library; the SPI section below
carries the reasoning.

Everything else on the builder is optional, and each value is validated where it is set rather
than at send time: the constraint is known at configuration time, so a bad value fails a
deployment's startup instead of its first delivery.

`send` returns `PushOutcome` and `sendAsync` a `CompletableFuture` of one; §4 has the variants and
what converts into each. `assessPayloadSize` answers the size question before a send, through the
sealed `PayloadSizeAssessment` and deliberately not through a bare number — §4 has the shape and
the reasoning. The line between the two channels is that an outcome describes what became
of a requested send, whether or not a POST was reached, while an exception is reserved for using the
API wrongly, for a defect the caller cannot act on per send, and for cancellation. Neither channel
forces meaningful handling — an exception can be caught and dropped, a value can be discarded at the
call site, and Java has no `#[must_use]`. What the sealed hierarchy buys is that a caller who does
`switch` has every case put in front of them, and that there is one place to look.

A built sender is thread-safe and shared across every sending thread — `sendAsync` makes concurrent
sends the normal case. Its configuration is final, and the one thing it holds beyond configuration
is the VAPID token cache Section 4 describes: a value the sender itself minted, reconstructible by
signing again, belonging to no application decision, so losing it costs one signature and never a
delivery. That is the single clause of [ADR-004](adr/0004-stateless-library.md) which
[ADR-019](adr/0019-vapid-token-reused-until-it-nears-expiry.md) supersedes — the library still
stores no subscriptions and keeps no per-send state, and the sharing the original clause existed to
justify is unchanged.

Three seams in the core are public, and only three
([ADR-005](adr/0005-public-spis-in-the-core.md)).

### Boundary validators

Two public utility classes let an application enforce the `Subscription` contract at its own
registration boundary — rejecting a bad registration before persisting it — instead of storing
data every later send will refuse: `Endpoints` for the endpoint (`requireSecure`, the RFC 8030
contract, plus the log-safe `redact`) and `P256PublicKeys` for the key material. One check of the
`Subscription` contract deliberately does not live in `requireSecure`: the 2048-character endpoint
length bound ([ADR-020](adr/0020-subscription-endpoint-length-bound.md)) is a resource control
with no RFC 8030 clause behind it, and `requireSecure` stays the protocol check ADR-005 named it —
the bound sits in `Subscription`'s canonical constructor, which every construction path runs.
`P256PublicKeys`
carries two checks of deliberately different strength: `requireUncompressedPoint` is structural
(65 bytes, the `0x04` X9.62 tag) and `requireOnCurve` is the full check — coordinates inside the
P-256 prime field and the curve equation satisfied. The full check runs on hard-coded FIPS 186-4
domain parameters and touches no JCA provider, so it works wherever a `Subscription` is created,
before and independently of any `PushSender`; hard-coding is sound because P-256 is a fixed named
curve, and a test (with a BC-FIPS twin) pins each constant against what a provider answers for
`secp256r1`. `Subscription`'s constructor applies `requireOnCurve` to `p256dh` — the value is
attacker-supplied, and an off-curve point would otherwise be accepted, persisted, and then raise
`PushCryptoException` on every send, far from the request that supplied it, as the recurring
failure it is. `VapidKeys` applies the same full check to its public half, catching a
corrupted configuration value where the pair is created. Section 6 describes how these checks
relate to the provider-parameter check the send pipeline still performs.

### VapidSigner

```java
byte[] sign(byte[] signingInput);
byte[] publicKey();
default String publicKeyBase64Url();
```

This SPI represents key custody ([ADR-010](adr/0010-pluggable-vapid-key-custody.md)). The
default signer holds a private scalar in process. Vault, KMS, or HSM implementations can keep
private material outside the JVM.

`LocalEcVapidSigner` verifies its configured public/private key correspondence once at
construction by signing and verifying a fixed probe. A mismatched pair therefore fails before the
first delivery attempt.

The contract requires a raw 64-byte P-256 `r || s` ES256 signature (RFC 7518 §3.4) and a 65-byte
uncompressed P-256 public point (RFC 8292 §3.2), and **both are checked wherever a new value enters
a send** — which under the default token reuse is every send that signs rather than literally every
send, since a reused header was checked when it was minted and `sign` is not called for it again. A
violation raises `PushCryptoException` naming what came back. The check exists because neither
half fails visibly on its own: a signature or key of the wrong shape still yields a syntactically
valid `Authorization` header, so without it the mistake reaches the caller as an opaque 401/403
from the push service, on every send, with nothing naming the signer. DER is the case worth
naming, and the message does: JCA's `SHA256withECDSA` returns it, and a signer forwarding its
provider's output unconverted looks correct until the wire. The library converts for its own
signer (below) but cannot here — the provider and encoding behind an external signer are unknown,
and a valid 64-byte signature may itself begin with `0x30`.

**A failure leaves an implementation in one of two types, and the axis is whether it recurs.** A
custodian that cannot sign *now* — unreachable, timed out, sealed, not yet initialized, still
catching up, rate-limiting — raises `VapidSignerUnavailableException`, from `sign` and `publicKey`
alike; the facade converts it into the `SignerUnavailable` outcome, since a signing call has no
effect on the push service and so no notification exists for a repeat to duplicate. Everything else
raises `PushCryptoException` and reaches the caller as that exception: a defect, a substrate that
cannot perform the cryptography, an answer no custodian could have meant, and a misconfiguration
that answers identically until a person edits it. The unavailable type carries what only the
custodian can declare — an `OptionalInt` status and an `Optional<Duration>` hint, both empty for a
signer that speaks no such protocol, so a signer over an HSM or a smart card fills neither and stays
conformant — because the facade cannot invent what it was not given, and with nothing carried the
`IOException` under an unreachable custodian is destroyed at the seam.

Nothing checks which of the two an implementation chose: the conformance kit asserts no exception
types, deliberately, so a signer reporting its custodian's outages as a cryptographic failure passes
every test it has while turning each outage into a permanent failure for its callers. That is a
silent break for a signer written against the older contract, which instructed an implementation to
raise `PushCryptoException` for a key service that is unreachable, timed out or refusing — it keeps
compiling, and the facade rightly refuses to sniff a cause chain to guess otherwise.

Both methods return arrays, and the arrays are the caller's. `publicKey()` in particular must
return a fresh copy on every call: a signer handing out its internal array is corrupted for every
later send by the first caller that writes into the returned bytes, and nothing would notice — the
mutated key is still a well-formed point. Both shipped signers return a `clone()`, and the
conformance kit pins both halves by identity — two successive calls must not return the same
object — rather than by mutating and looking for consequences. That choice is load-bearing: a
signer refilling one shared buffer per call survives a mutation probe (the refill undoes it before
the next call is compared) while still handing the same object to two callers, and a mutation
probe would also zero a non-conforming signer's key, failing the shape and signature checks for a
reason that has nothing to do with what they test. The shape check above cannot see aliasing at
all, on the sends that run it or on the ones that serve a cached token.

**The advertised key is also stable for a signer's lifetime**, which the interface states and the
library cannot check. VAPID's public key is the application server's published identity: a
subscription is bound to the `applicationServerKey` it was created with, and RFC 8292 §4.2 entitles
a push service to refuse a JWT whose key is not that one. A signer that swaps its advertised key
under a live sender has therefore already broken every restricted subscription taken out before the
swap, whatever the library does with the two return values — rotation is a re-subscription event
producing a *new* signer, which is what the Vault signer already documents of itself. The clause is
a statement of what the protocol requires rather than a new demand, and it is unfalsifiable from
outside for the same reason thread-safety is: two equal answers say nothing about the next one. The
conformance kit pins the two checkable moments — consecutive calls answering the same key, and one
signature verifying against the key advertised beside it — and neither reaches the lifetime the
clause is about. The token cache is what made the silence worth ending: it keys entries on the
advertised key, so a key that has moved builds a different cache key and the lookup simply misses,
which is why the next send signs under the identity the signer now publishes rather than serving
the old header. Nothing detects the move and nothing evicts on it — the entry filed under the
abandoned key stays until the bound reaches it, and would serve again if the key moved back inside
its window. A key that moves *within* one header is a self-contradiction only the contract rules
out.

`publicKeyBase64Url()` publishes the same key as the string a browser takes as its
`applicationServerKey` — unpadded base64url over the raw point
([ADR-018](adr/0018-encoded-vapid-public-key-on-the-signer.md)). It is a `default` method, never an
abstract one: a custodian that can sign and name its key should not have to learn an encoding to
implement this SPI, and the interface can derive the value itself. It is the SPI's half of the
feature because for a remote custodian this is the only place the string exists at all — nothing
configured it — and because the value is *this signer's* key, which only a member of the SPI can
promise. `VapidKeys.encodePublicKey(byte[])` is the other half, for a caller that holds the pair.

The two apply different checks, at the positions they occupy. The static's argument is a caller's
own byte array, so it is a boundary: it runs `P256PublicKeys.requireOnCurve` — what `VapidKeys`'
constructor already applies to this very value — and refuses with `IllegalArgumentException`, since
a `VapidKeys` static accepting what a `VapidKeys` refuses would hold one value to two standards and
the browser rejects an off-curve `applicationServerKey` anyway. The `default` method's value is the
signer's own output, so it runs the send path's structural check instead — the same one, shared out
of `Vapid` rather than duplicated — and raises the send path's `PushCryptoException` with the send
path's wording. The publication path is as strict as the send it precedes and no stricter: a key
this method publishes is a key the next send carries, and a consumer meeting a broken signer
through their own key-publishing endpoint reads what delivery would have told them. A `null` from
`publicKey()` stays a `NullPointerException` in both, being a broken type contract rather than a
failed cryptographic operation.

The conformance kit pins the one behaviour an override must never have — disagreement with
`publicKey()` — by comparing the signer's string against `VapidKeys.encodePublicKey(publicKey())`.
An equality rather than a round trip through a decoder: one comparison pins the alphabet, the
padding and the canonical final character at once, where decoding both sides would accept a
standard-alphabet override whenever its characters happened to avoid `+` and `/`. Whether a starter
should *serve* the value — as a bean or an endpoint — is deliberately left open; the decision makes
it reachable in one call from the type every consumer already holds.

### PushHttpClient

```java
PushResponse post(URI endpoint, Map<String, String> headers, byte[] body);
```

This SPI allows applications to replace the JDK transport for proxy, pooling, or observability
requirements. Implementations return every HTTP status as `PushResponse` and throw
`PushDeliveryException` only for an exchange that produced no response — which the facade reports as
`Indeterminate`. The contract is unchanged by the removal of the retry loop, and deliberately so: a
transport is not obliged to recognise an interruption either, since the facade's disjunction does
that. What a transport never does is repeat a request, so however a caller schedules a repeat, each
attempt arrives here as its own `post` call.

`PushResponse` carries only the status code and headers. Push delivery never consumes a response
body, and the endpoint is an untrusted capability URL, so the default `JdkPushHttpClient` discards
the body without buffering it — a hostile push endpoint cannot create memory pressure by returning
a huge response. This seam is push-delivery only; the Vault module has its own transport seam
(section 7) because Vault responses must be read.

Implementations must not follow redirects. A chased `Location` would POST the encrypted body and
the request headers to a host `EndpointPolicy` never validated, and would let the redirect
target's answer stand in for the push service's verdict. The invariant is stated in code rather
than inherited from a JDK default: `JdkPushHttpClient` builds its own client with `Redirect.NEVER`
and rejects a supplied `java.net.http.HttpClient` whose `followRedirects()` differs. For an
implementation on another stack it stays a contract only, unverifiable from here.

### EndpointPolicy

```java
void validate(URI endpoint);
```

This SPI represents deployment egress policy for push endpoints. The endpoint in a `Subscription`
is attacker-influenced (a public registration endpoint accepts the browser's `PushSubscription`
JSON verbatim), so without a policy every send is a POST from inside the network to an address of
the subscription's choosing — a blind SSRF oracle via the status code an answered outcome carries,
an unanswered `Indeterminate`, and timing. That the oracle is now read off one value rather than off
a value and an exception changes nothing about it: what closes it is the policy running first and
unconditionally, before the encryption, the signature and any I/O. `Endpoints.requireSecure` stays a
protocol check (absolute `https` URL with a host); which hosts a deployment may contact is policy,
and lives here.

**A policy is a required argument of both `PushSender` factory methods**
([ADR-016](adr/0016-endpoint-policy-is-a-required-decision.md)), not an optional builder step:
there is no default policy and no way to obtain a sender without naming one. The library still does
not choose a deployment's allowlist — that is what ADR-005 admitted the seam for — but it does not
decide on the deployment's behalf that there is none. A deployment that wants none says so with
`EndpointPolicies.unrestricted()`, which accepts every endpoint `Subscription` accepts. The
difference from the previous default is entirely in where it is visible: `unrestricted()` is a
token in the consumer's own source, appearing in their diff, their review and their grep, while an
unset builder step appeared in none of them. Requiring the argument also removes a runtime failure
mode instead of adding one — `build()` cannot refuse over a missing required value, since the
compiler refuses first.

**The policy is one value applied at both points of a subscription's life**
([ADR-024](adr/0024-one-endpoint-policy-reachable-at-registration.md)): where a subscription is
accepted, and before every send. A policy refusal is not a `410` — nothing expires the stored row —
so a row whose endpoint the policy refuses fails once per notification forever while the
subscriber's browser reports a healthy subscription; checking where the subscription is accepted
keeps that row out of the store. The core gained no API for the second point, and that was the
decision rather than an absence of work: `validate` is public and takes the endpoint URI alone,
`EndpointRejectedException` is catchable at the application's own boundary (below), and a
deployment that built its sender by hand holds the policy because it constructed it. The order at
that boundary is the seam's own contract — `validate` documents its argument as an endpoint that
already satisfies `Endpoints.requireSecure`, so the boundary builds the `Subscription` first,
applies the policy to the endpoint it carries second, and stores the row only once both have
passed. The registration check does not make the send's check redundant: the policy is deployment
configuration and changes, so `send` validates every time and never trusts that a row once passed.

The standard implementation is an allowlist of `EndpointRule` values
([ADR-017](adr/0017-domain-rule-in-the-endpoint-allowlist.md)). A rule is a value that carries its
own kind, so the entries of one list say what each of them means instead of taking their meaning
from the factory they were passed to — the same reason `TransitKeyName` and `VaultToken` are types
rather than two `String` parameters, and it makes swap-proofness a property of the types rather
than of the strings a caller happens to pass. Two kinds exist: `EndpointRule.origin`, one origin
matched exactly, and `EndpointRule.domain`, a DNS zone. `EndpointPolicies.allowedEndpoints` takes
a mixed list; `allowedOrigins` and `allowedDomains` are the single-kind convenience over it, each
mapping its strings to rules of one kind and delegating. Rules are values, equal by kind and
normalized entry, so a list of them collapses duplicates.

**The hierarchy is closed, and that is what keeps it from being a seam.** `EndpointRule` is sealed,
both implementations are private to it, and the method by which a rule matches an endpoint is
package-private, so no rule kind can be added or implemented from outside. It is an enumeration of
the kinds the library knows how to match, not an extension point — ADR-005's bar for a seam is
untouched and no SPI is added. `EndpointPolicy` remains the seam it already was, and a deployment
whose rule is neither kind still writes a lambda.

**The endpoint is parsed and normalized once, and every rule sees only that value.** Both kinds
compare on the same RFC 6454 §6.1 serialization the `aud` claim uses, so `Origin.serialize`
normalizes both sides and case, default ports and IDNA form can never disagree between them; a
second normalizer would mean two answers for one endpoint, diverging precisely in the
internationalised cases nobody exercises by hand. A domain entry is put through that same
serialization rather than merely checked, since an entry validated but not normalized would accept
spellings — `NOTIFY.WINDOWS.COM`, or an A-label facing a U-label host — that can never meet a host,
and a permanently inert entry looks configured. The two endpoint-side refusals hold for every rule
kind: userinfo is rejected outright before any comparison, and an endpoint with no scheme or host
has no origin to compare at all.

**A domain rule covers the apex and every subdomain at any depth, matched at a label boundary** —
`host.equals(domain) || host.endsWith("." + domain)`. The leading dot belongs to the suffix and not
to the string searched; without it `evilnotify.windows.com` matches `notify.windows.com`, which is
the whole vulnerability class and the bug every consumer writing this rule by hand reaches
independently. It matches only the scheme `https` and the default port, absent or an explicit
`443`. The scheme is anchored explicitly rather than inherited, because the origin serialization
enforces no scheme by its own contract — that is `Endpoints.requireSecure`'s job at the
`Subscription` boundary — while an origin rule is covered for free by comparing the whole
serialization. The port is a decision: a domain names which *hosts* are trusted, a port which
*service on a host* is, and a rule spanning every port of a zone re-creates the blind SSRF oracle
this control exists to close, relocated into an external zone. A non-default port is named exactly,
with an origin rule.

The library makes no public-suffix judgement: there is none in the JDK,
`HttpCookie.domainMatches`'s embedded-dot heuristic is wrong in both directions, a dependency is
ruled out by ADR-002, and bundled data ages between releases while going on looking authoritative.
A single label is refused, being the one case unambiguously wrong with no data at all; the rest is
stated rather than half-checked — a domain rule is worth what the DNS of that zone is worth, and
over a shared hosting zone it admits every tenant.

Malformed entries of either kind fail at construction with an `IllegalArgumentException`, validated
through the same `java.net.URI` the endpoint side uses rather than a hostname regex, which would be
a second grammar of "a valid host" to keep in step with the first. A rule entry is configuration
rather than an endpoint, and the message renders it by what it may hold: an origin entry through
`Endpoints.redact`, since a pasted capability URL is one of the mistakes being reported, and a
domain entry verbatim only while it is a bounded ASCII host-shaped token free of URI delimiters,
whitespace and control characters — otherwise omitted, with the caller left to say which entry it
was.

A rejected *endpoint*, by contrast, raises `EndpointRejectedException` inside the seam — extending
`RuntimeException`, not `IllegalArgumentException`, because the argument is well-formed
(configuration refuses it), and because web frameworks commonly map IAE to a 400 response that
would echo the redacted-but-fingerprinted message to the caller who registered the subscription.
Rejection messages never carry the capability path/query (`Endpoints.redact`).

That exception is the seam's vocabulary and not the facade's: `send` recognises exactly this type
and reports `EndpointRejected`, carrying the endpoint in this library's own redacted rendering
beside the policy's account of the refusal. The refusal is a value rather than an exception because
one hostile row must not abort a fan-out over a whole subscription store — a denial of service a
deployment would inflict on itself — and because the policy has done its job when the request never
leaves. An application calling `validate` directly, at its own registration boundary, still catches
the exception, and it means the same thing there.

A URI-level policy is a coarse filter, not a sandbox: it cannot close DNS rebinding, and redirect
behaviour belongs to the transport — where `JdkPushHttpClient` enforces `Redirect.NEVER`, so a
`3xx` is classified as a non-retryable failure rather than routing the send past the policy that
just ran. Strict guarantees require
resolution/egress pinning inside a `PushHttpClient` implementation.

### Deliberately concrete components

The RFC 8291 encryptor, the HKDF implementation and the origin serialization are not public SPIs
([ADR-003](adr/0003-concrete-hkdf-implementation.md)). Alternative implementations would not
change intended behavior and would introduce a silent wrong-ciphertext failure mode.

JCE provider selection uses the standard `java.security.Provider` abstraction rather than a custom
SPI. The selected provider backs encryption and, for the local signer, EC key import and ES256
signing. Native `SHA256withECDSAinP1363Format` is preferred; when the selected provider offers
only DER-output `SHA256withECDSA`, the signature is obtained from that same provider and strictly
converted to JOSE's raw `r || s` form. Provider lookup is never widened by the fallback. External
signers manage their own providers.

### Nullness

Every package carries JSpecify's `@NullMarked`, so a reference type in the public API is non-null
unless it is annotated `@Nullable`; the annotated exceptions are the optional message headers
(`PushMessage.ttl`, `urgency`, `topic`), the unset builder fields, and the Spring properties. The
annotations are part of the published surface — NullAway, IntelliJ and the Kotlin compiler read
the same ones ([ADR-012](adr/0012-nullness-declared-with-jspecify.md)).

## 6. Cryptography

| Operation | Implementation |
|---|---|
| P-256 ECDH | `KeyAgreement("ECDH")` |
| HKDF-SHA-256 | RFC 5869 loop over `Mac("HmacSHA256")` |
| AES-128-GCM | `Cipher("AES/GCM/NoPadding")` |
| ES256 | `Signature("SHA256withECDSAinP1363Format")`, or same-provider `SHA256withECDSA` plus strict DER → `r || s` conversion |
| EC key handling | `KeyFactory("EC")`, `KeyPairGenerator("EC")` |
| Base64url | `java.util.Base64` |

The implementation supports only modern `aes128gcm` encoding
([ADR-006](adr/0006-aes128gcm-only.md)) and emits a single RFC 8188 record. Because that one
record carries the whole payload, `rs` must be strictly greater than the plaintext plus the
padding delimiter plus the authentication tag (RFC 8291 §4); equality is rejected. The record is
not zero-padded up to `rs`, so the body size depends only on the payload.

The provider itself is not trusted to answer the `secp256r1` lookup honestly. `Jca.p256Parameters()`
is the one seam through which provider-supplied domain parameters reach an imported key — the
public-key and the private-key decode both take them from there — and it verifies the answer value
for value against the hard-coded FIPS 186-4 constants (prime field modulus, both coefficients,
generator, order, cofactor) before anything runs on it, failing closed as `PushCryptoException`.
Without that, a provider answering the name with another 256-bit prime-field curve would silently
move the ECDH agreement and the VAPID private-key import onto that curve. The parameters are a
per-instance constant, so the verified result is cached the same way as the ES256 resolution; the
verification runs before each store, never resting on the cache. On the way out, the fixed-width
coordinate serialization refuses a negative or wider-than-256-bit coordinate rather than truncating
it — truncation would publish a plausible-looking but wrong point.

The ephemeral key pair does not come through that seam — the `KeyPairGenerator` resolves the
`secp256r1` name itself — so the pair it returns is held to the same standard before it is used,
in three checks and no more: both halves must be EC keys, both halves' declared domain parameters
must equal the published NIST P-256 constants value for value (prime field modulus, both
coefficients, generator, order, cofactor), and the public point must lie on the curve of those
constants. The last two prove different things, and neither substitutes for the other: parameter
equality proves what the generator *declares*, the curve equation proves that the point it actually
*returned* lies on the declared curve. The parameter comparison is the sharper of the two. A
substituted order `n` leaves every generated point genuinely on P-256, so the equation check alone
passes — but `n` is what bounds the private scalar, and a small substituted order draws a guessable
scalar and therefore a guessable ECDH secret.

What that boundary does not reach is worth stating as plainly as the boundary itself. A provider
that declares the correct parameters and simply draws a weak or attacker-known scalar passes
undetected; no parameter verification can catch that, which is why the choice of provider remains a
trust decision. The two halves are also not checked to belong together — `W = d·G` is not
evaluated — because that needs point multiplication the library deliberately does not implement,
and it would buy nothing against a hostile provider, which can always hand over a self-consistent
pair whose scalar it knows.

The subscription public key (`p256dh`) is attacker-reachable input, and it is validated twice, on
purpose. At construction, `Subscription` runs `P256PublicKeys.requireOnCurve` (§5) against the
hard-coded FIPS 186-4 parameters — no provider involved — so a hostile off-curve key is refused at
the application's boundary. At decode time, inside the send pipeline, the point is validated again
— coordinates inside the prime field, then the P-256 curve equation — against the now-verified
parameters of the provider that is about to run ECDH, before the point reaches that provider's
`KeyFactory`. Refusing an invalid-curve point therefore never depends on whether the configured
provider validates in `KeyAgreement.doPhase`. Within the core the equation arithmetic lives once, in
`P256PublicKeys`; only the parameter source differs. The value-wise parameter comparison lives once
there as well, against the hard-coded constants, and answers for both places a provider's
`secp256r1` claim enters the core — the import seam above and the ephemeral generator. The Vault
signer performs its own, deliberately separate checks on the key it fetches (§7) — a parameter
comparison of the same shape, its own inlined copy of the curve equation, and the same
refuse-not-truncate serialization — all three duplicated because their counterparts
(`nistP256Mismatch`, `satisfiesCurveEquation`, and `EcKeys` entire) are package-private to
`push2u-core`, so no other module can call them. The parameter comparison's reference is weaker as
well as separate: there the fetched key is compared against the platform's `AlgorithmParameters`
answer for `secp256r1`, taken as given rather than verified against the published constants —
extending the lookup exactly the trust this section opens by withholding. What that costs is
diagnostic rather than secret-exposing — a platform answering the name with some other curve makes
the genuine P-256 key Vault returns fail the comparison, so such a deployment fails loudly when the
signer is built instead of signing on a curve nobody chose, and the VAPID private key never exists
locally in any case. What the module *can* call it does call: `P256PublicKeys.requireOnCurve`,
against the core's hard-coded constants, runs on the key either mode publishes.

Key and payload arrays exposed by public value types are defensively copied. `Subscription`
redacts both the `auth` secret and the capability-bearing part of its endpoint from `toString`.
Transport and validation exceptions use the same endpoint representation: push-service origin plus
a short correlation fingerprint, never the path, query, fragment, or user information.
Applications must still treat the complete endpoint as a credential and avoid logging it directly.

## 7. Vault Transit integration

`VaultTransitVapidSigner` has no public constructor: each mode has its own builder, obtained from
`builderWithFetchedPublicKey(address, keyName, token)` or `builderWithSuppliedPublicKey(address,
keyName, token, point)`. Two builders rather than one overloaded family because the modes differ
in *contract*, not only in parameters — the fetched one performs a Vault read inside `build()` and
can fail there, the supplied one contacts nothing — and because `keyVersion` belongs to exactly
one of them: in the fetched mode the version is Vault's to state, taken from the same response as
the public key. A bare `builder()` would have made one of two equal modes the default by omission.

Everything required is a factory-method parameter, so an incomplete signer does not compile and
`build()` never refuses over a missing value — and everything required is also validated at the
factory. The address must be an absolute URI with a host and no query or fragment, and its path —
legal, because a Vault behind a reverse proxy or ingress prefix is a legitimate topology — obeys
the same per-segment rule as `mount` below, since it prefixes every token-bearing request path.
The scheme must be `http` or `https` (case-insensitively), whitelisted at the factory — the signer
speaks Vault's HTTP API and nothing else, and `ftp://vault.example` used to pass validation only to
fail on the first sign inside the transport. `https` is always accepted; plain `http` is accepted
out of the box only towards a literal loopback host (`localhost`, names under `.localhost`,
`127.0.0.0/8` dotted-quads in canonical decimal, and a bracketed IP literal denoting a loopback
address — the IPv6 loopback in any spelling, and the IPv4-mapped writings such as
`[::ffff:127.0.0.1]`, which the platform resolves to the `127.0.0.0/8` address they map) — the Vault
Agent/sidecar pattern, where TLS is terminated beside the application — and to any other host
requires the builders' explicit `allowInsecureHttp()` step, because the `X-Vault-Token` header would
otherwise cross the network in clear text. That one rule lives in `build()` rather than at the
factory — the opt-in is a builder step, callable only after the factory has returned — and runs
before the fetched mode's Vault read, so a refused address contacts nothing. Loopback is decided
from the literal host text, never by resolution, keeping the rule readable from the address alone
([ADR-015](adr/0015-vault-address-scheme-policy.md)). The Spring starter deliberately adds no
opt-in property: plaintext transport for the token costs a code change (an application-supplied
signer bean), not a YAML edit. The API paths are joined onto the address by explicit normalization
— scheme and authority verbatim, the address's path with a trailing slash dropped, then `/v1/…` —
and deliberately not by `URI.resolve`: per RFC 3986 §5.3 an absolute-path reference
(`resolve("/v1/…")`) replaces the base path entirely, silently discarding a prefix like `/vault`,
and the relative form (`resolve("v1/…")`) merges by dropping everything after the base path's last
`/`, so a prefix without a trailing slash would lose its final segment — quieter, not better.
`https://gw.example/vault` and `https://gw.example/vault/` therefore address the same Vault, and a
root address like `https://vault.example:8200` joins as it reads. The key name and the token
travel as the value types `TransitKeyName` and `VaultToken` rather than bare strings: the types make the positional
arguments impossible to transpose, and each carries its value's contract. `TransitKeyName`
enforces Vault's own Transit key-name rule — `GenericNameRegex("name")`, `^\w(([\w-.]+)?\w)?$` in
Vault's `path_keys.go` — so no name Vault would accept is refused, while every URL-breaking
character (`/`, `?`, `#`, `%`, whitespace, non-ASCII) is refused without being enumerated.
`VaultToken` requires a non-empty, visible-ASCII value (0x21–0x7E) — rejecting the
trailing-newline misconfiguration, a pasted `Bearer ` prefix and stray whitespace — while
deliberately not validating the token's *format*, which has changed across Vault versions and is
arbitrary in dev mode; its `toString()` never prints the token. Because a `VaultToken` is valid by
construction, the signer validates it exactly once — in the type — instead of re-checking it on
every path that offers it to a transport.

`mount` and `namespace` are validated at their builder steps by one shared per-segment rule:
nesting (`secrets/transit`, `team-a/sub`) is legal, and every `/`-separated segment must be
non-empty, not `.` or `..`, and drawn from `[A-Za-z0-9_.-]`.

The allowed set — rather than a blacklist — is what a percent-encoded probe cannot reopen: a
literal `..` check alone admits `%2e%2e` (or `%2F`), which travels in the raw request path — the
signer assembles its request URIs by direct concatenation onto the validated base, with no
dot-segment normalization anywhere on the way, so the path goes onto the wire as written. What
happens next depends on the hops: Vault's own Go router decodes the path before routing, so a
`%2F` addresses a different mount inside Vault itself; a decoded dot segment draws a *307
redirect* to the collapsed path from Vault's handler (`cleanPath` in `http/handler.go`) — the
default `Redirect.NEVER` transport refuses it loudly, but a redirect-following custom transport
would execute it, re-sending `X-Vault-Token` to the other path; and a normalizing proxy in front
of Vault (nginx `proxy_pass` with a URI part, HAProxy `normalize-uri`) collapses the path before
Vault sees it at all.

The set is deliberately narrower than either Vault or a URL requires — policy, not necessity:
Vault accepts any printable Unicode in a mount path (`validateMountPath`, canonical per
`path.Clean`), and `~ ! $ & ' ( ) * + , ; = : @` are legal raw in a URI path segment, so a mount
like `transit+prod` is real and would otherwise be addressable through this signer. It is refused
anyway because some of that punctuation is treated specially by intermediaries (`;` reads as a
path parameter to some hops), and admitting only what every hop treats literally can be widened
later without breaking anyone — the reverse is not true. Refusing at the step also replaces
`URI.create`'s later raw "Malformed escape pair" failure.

The namespace travels differently — in the `X-Vault-Namespace` HTTP header, not the URL — so none
of those hops act on it, and the same rule is applied for two other reasons. Definite: a header
value must be header-safe, which the allowed set guarantees — a strict subset of visible ASCII
with no CR/LF or other control characters, so a validated namespace can never terminate the header
or inject another. Defence in depth: a traversal segment cannot name a real namespace either
(`namespace.Canonicalize` trims a leading slash and appends a trailing one, collapsing nothing),
so such a value is a configuration mistake whichever hop sees it, and refusing it costs nothing.
No traversal route through OSS Vault is claimed here.

`VaultTransitVapidSigner` supports two modes:

- **Fetched mode** reads `latest_version` and that version's public key atomically from one
  `transit/keys/<key>` response at construction, then pins the captured version on every sign. The
  key is validated as P-256 before the signer exists, in three independent steps: the advertised
  `type` must be `ecdsa-p256` or Vault Enterprise's `managed_key` (absent `type` is a failure);
  the parsed public key's domain parameters must match `secp256r1` by value — prime field, curve
  coefficients, generator, order, cofactor — compared against the platform's `AlgorithmParameters`
  answer for that name rather than against hard-coded constants, which §6 states the cost of; and
  the key's point must satisfy `y² = x³ + ax + b (mod p)` with both coordinates in `[0, p)`. None
  of the three implies another: the metadata is only Vault's claim, and correct parameters say
  nothing about the point — the JCA validates neither, so SunEC accepts a key at `(1, 2)` both on
  import and at verification time. Coordinates are likewise never truncated to fit the 32-byte
  P-256 fields. Without all three, an `ecdsa-p384` key yields a syntactically valid but unusable
  VAPID key, and the misconfiguration surfaces only as an unexplained push-service rejection on the
  first send. Those three are what the metadata read itself performs; the canonical constructor
  then puts the same key through `P256PublicKeys.requireOnCurve` — the core's check, against its
  hard-coded constants — before the signer exists, which is what §6 weighs against the unverified
  reference the parameter step uses. Because that `build()` is the one call in this library outside
  any send that reaches a custodian, it is also where a startup supervisor's contract is stated: a
  Vault that cannot serve the read now raises `VapidSignerUnavailableException` and is a boot worth
  retrying with backoff, while `PushCryptoException` recurs and should fail the deployment — and the
  supervisor tests the interruption *before* it reads the type, since an interrupted boot raises the
  unavailable type too and a supervisor that looped on it would sleep every backoff instantly
  against a flag nobody cleared.
- **Explicit mode** receives the public key from configuration, permitting a sign-only token.
  Supplying the matching Transit key version pins signing to that version. The supplied key gets
  the full `P256PublicKeys.requireOnCurve` check (§5): the `VapidSigner` contract — pinned by the
  published conformance kit — requires `publicKey()` to return a point on P-256, so a signer
  violating it must be unbuildable, and no legal VAPID key can fail the check. Its correspondence
  to the Transit key cannot be established here and stays with the caller; a mismatch surfaces on
  the first signature to a VAPID-bound subscription, as a push-service rejection.

Signing uses `marshaling_algorithm=jws`, so Vault returns the raw JOSE-compatible ECDSA form. A
pinned signer also sends `key_version`; taking the version and public key from the same metadata
response closes the race where Vault rotates between reading the public key and signing. Creating
a newer Transit version therefore does not break an existing signer: it continues advertising and
using the older version as one consistent VAPID identity.

The pin remains usable only while Vault permits signing with that version — raising
`min_encryption_version` above it, or deleting it through `min_available_version`, makes
subsequent sign calls fail. Every recovery from that changes the advertised VAPID identity, and so
has to be coordinated with browser re-subscription: a Web Push subscription is bound to the
application-server public key used at subscribe time.

### Vault HTTP transport

The module talks to the Vault API through its own `VaultHttpTransport` seam (`get` + `post`,
returning `VaultHttpResponse`), deliberately separate from `PushHttpClient`: push delivery POSTs
to untrusted capability URLs and discards response bodies, while the Vault API is an
operator-configured service whose JSON responses must be read. Both Vault calls — the Transit
`sign` POST and the fetched mode's startup metadata GET — go through the same transport, so an
application's mTLS, proxy, or observability configuration is never bypassed.

**The seam's failure vocabulary is split by whether the failure recurs**, and the split lives here
rather than in the signer because a signer translating it would have to discriminate on a message or
a cause chain. An exchange that produced no response — no connection, a failed handshake, a timeout,
a connection dropped mid-body, an interrupted wait — leaves as `VapidSignerUnavailableException`:
nothing about such a failure says it will happen again, and an address with a typo and a Vault that
is down for an hour arrive here indistinguishably. A failure that is this configuration's own leaves
as `PushCryptoException`: a request URI that cannot back an HTTP request, a request header carrying
a character illegal in an HTTP field value (a token from a file or a YAML block scalar commonly ends
with a newline), and a response over the transport's own size cap — that bound is this library's, so
a response over it is over it again next time, whatever Vault's health. The transport is not asked
to recognise an interruption; what it owes is what any code catching an `InterruptedException` owes,
to re-set the flag and keep the exception in the chain, and the facade's disjunction does the rest.

`VaultHttpResponse` carries a third value beside the status and the body: the parsed `Retry-After`,
where Vault declared one. A header stops at the transport unless the transport hands it on, and the
signer copies it into the exception it raises, which is the only route by which the one component
able to act on it — the caller's scheduler — ever sees it. What crosses is the parsed hint and not
the headers: a bag of them from a service whose answers are read under a size bound is more surface
than one value is worth. Empty is the ordinary case, since Vault fills the header on a rate-limited
answer alone and only where an operator enabled the rate-limit response headers.

Status classification stays in the signer, because the transport returns an answer rather than
raising on one. `VaultTransitVapidSigner` puts each non-`200` to one question — does the status
describe Vault's own condition, or that of a service Vault itself called, or the request that was
made? The worked rows are Vault's own published table: `500`, `503`, `501`, `502`, `412`, `429`,
`472` and `473` each name a state of the cluster or of something it called, and are the custodian
unable to serve *now*. A status the table does not name falls to RFC 9110's classes — an
unrecognised `5xx` is a statement about the server and joins them, an unrecognised `4xx` is a
statement about the request and recurs — which is why the four `4xx` numbers above are named
explicitly: only the vendor's table says they are about the cluster. `501` is the sharpest
illustration that this is not the push service's matrix: there it is carved out of the retryable
class because a push service answering "not implemented" has answered about the request, while Vault
publishes it as "not initialized", a cluster state that ends the moment someone initializes it.

The default `JdkVaultHttpTransport` enforces three invariants:

- a per-request timeout (`HttpRequest.timeout`), because a connect timeout alone cannot end an
  exchange with a Vault that accepts the connection and never answers — in fetched mode that would
  hang application startup;
- a response-size cap counted in raw streamed bytes (a declared `Content-Length` above the cap
  fails early, but the streaming count is authoritative). Exceeding the cap fails the whole call —
  fail-closed, never truncation, because the targeted JSON extraction could still find a
  complete-looking `data.signature` before the cut;
- no redirect following, checked at construction rather than at send time. The JDK client re-sends
  custom headers — `X-Vault-Token` among them — to a redirect target, cross-origin ones included,
  so a Vault address that can be made to answer `3xx` (DNS hijack, squatted typo host, compromised
  reverse proxy) would be handed the live token. The default client is built with `Redirect.NEVER`
  explicitly, and a supplied client whose `followRedirects()` is anything else is rejected with an
  `IllegalArgumentException`.

Transport exception messages carry the HTTP method and the query-less request URI, never the
`X-Vault-Token` header.

## 8. Spring Boot integration

`push2u-spring-boot-starter` binds `push2u.*` properties and conditionally creates a local
`VapidSigner`, a default `JdkPushHttpClient`, an autoconfigured `PushSender`, an `EndpointPolicy`
bean holding the allowlist the properties express, and — when Spring Boot health support is
present — a health indicator. Application beans of the same types override these defaults; an
application-supplied `PushSender` bypasses the starter's factory method entirely, so everything
below concerns the *autoconfigured* sender alone.

**A value the core rejects is re-thrown with the YAML property name in front of the core's own
message.** The core is where a constraint is stated once, so the starter neither restates a bound
nor validates ahead of it — two copies of a limit drift, and the core is the authority on what a
legal value is. What the core cannot know is the name the operator wrote in their configuration
file: its messages name a camelCase builder or constructor parameter. Translating at the boundary
is what turns a rejected value into a startup failure the operator can act on, and it is also why
the properties bind optionally — an unset property leaves the core's default in place rather than
restating it in a second location.

`push2u.vapid.subject` is checked explicitly rather than left to the factory's generic "contact is
required", and it is required even when the `VapidSigner` bean comes from another starter: the
Vault Transit signer starter supplies key custody, not a contact address.

Every optional property therefore travels through one translate-the-error helper, which skips an
unset value and re-throws a rejection with the YAML key in front of the core's own message. There is
no second helper any more: the one property group whose values reached a constructor validating
several at once was `push2u.retry.*`, and it is gone with the retry loop, so no property needs a
probe to be attributed.

**A property a release removed is refused, not ignored.** `push2u.record-size` went with
[ADR-023](adr/0023-one-size-limit-answerable-before-a-send.md); `push2u.health.enabled` and
`push2u.health.cache-ttl` went to `management.health.push2u.*` when the health indicator took Spring
Boot's own switch for a contributor. Binding would skip any leftover key silently — leaving the
operator believing a setting is in force that nothing reads. So the starter carries a tombstone per
removed key: entries in one `BeanFactoryPostProcessor` in `Push2uStartupChecksAutoConfiguration`,
which reads the bound environment at context refresh
through `Binder` — catching every spelling relaxed binding accepts — and fails the context naming
every dead key it finds and where each one's effect went. It retains no properties component,
publishes no type and no constant. Running as a post-processor puts it ahead of every bean-creation
failure; its position among the starter family's declared startup checks is a package-private
constant in `StartupCheckOrder`, ahead of the two allowlist checks below and numbered to leave room
for the checks [ADR-025](adr/0025-delivery-is-off-by-statement.md) adds around them. A tombstone is
carried for one minor release after the release that removed its property, and the release adding
one opens the work item that removes it — the end belongs to the entry, not to the check raising it
or the class hosting it, so retiring one is deleting one entry.

**One check for all of them, because the alternative charges the operator per key.** The keys a
release removes are held together, having been copied together out of the guide that release
replaced. A check per key could not be ordered against its siblings — no tombstone is more specific
than another, so they would share a position and the one heard would be whichever the framework
registered first — and a deployment holding several dead keys would meet them one failed startup at
a time. So the position holds one check and the entries are per key: one refusal names all of them,
one edit answers it.

**A tombstone is hosted apart from the feature whose key it names**, and the health pair is the
worked instance of the general rule below. Its natural home would be the auto-configuration that
registers the health indicator, which carries `@ConditionalOnClass(HealthIndicator.class)` — and a
deployment that dropped Actuator while keeping `push2u.health.*` holds exactly the same dead
configuration, so that condition would let through precisely the case the tombstone exists for. What
generalises is not "beware Actuator" but that a check inherits every condition standing between it
and the context, including ones that have nothing to do with what it checks.

**Every startup check lives in `Push2uStartupChecksAutoConfiguration`, and that class contributes
nothing else.** Two rules meet there. A check may be suppressed by nothing — not the delivery
switch a future release puts on the class carrying the sender, and not a condition on a class, a
bean or a property — so the hosting class carries no condition of any kind. And an
auto-configuration that contributes a bean an operator might want to remove may not also host a
check: excluding an auto-configuration is the framework's ordinary tool for removing its
contribution, and a check riding beside the bean would vanish with it — the refusal would disappear
in exactly the deployment whose operator reached for the standard tool. Excluding the checks' own
class is therefore the one deliberate way to switch them off, visible in the exclusion line that
names it, and it is the single route by which a stated allowlist can boot beside an application
policy bean.

The endpoint policy has two *sources*: the allowlist properties and an application `EndpointPolicy`
bean. `push2u.allowed-origins` and `push2u.allowed-domains` are not two of them — they are two
halves of one statement, unioned into a single allowlist, which is the shape a deployment naming
both fixed-host and zone-published services needs. The decision is expressed when at least one of
them is non-empty.

**The allowlist the properties express is a bean, in an auto-configuration of its own**
([ADR-024](adr/0024-one-endpoint-policy-reachable-at-registration.md)):
`Push2uEndpointPolicyAutoConfiguration` publishes `push2uEndpointPolicy` when the allowlist is
expressed, `@ConditionalOnMissingBean` so an application bean suppresses it, and the autoconfigured
sender resolves whichever the context holds through an `ObjectProvider`. It is not part of
`Push2uAutoConfiguration` because the deployment the bean exists for — one that accepts
subscriptions and leaves the sending to another service — has no sender, and nothing that later
conditions the sender's class (ADR-025's delivery switch) may take the policy away from it; the
policy's own auto-configuration therefore carries no condition at class level, and may never gain
one. The bean's condition is the allowlist rather than a signer (a signer condition would withhold
it from exactly that deployment) and rather than nothing (a deployment that merely carries the
starter is owed no demand for an allowlist). The bean is built from the two properties alone, so no
configuration-only path to unrestricted egress appears. The bean name is deliberately not published
as a constant, because the starter's own bean is never identified by name: the exclusivity check
below asks where a definition came from — the declaring class in its factory-method metadata — so
an application naming its own bean `push2uEndpointPolicy` is still the application's, and a
definition whose origin cannot be established counts as the application's too, erring towards a
loud conflict rather than a silently dropped allowlist.

**Two allowlist refusals are startup checks of the context, not of the sender**, hosted in
`Push2uStartupChecksAutoConfiguration` — apart from the bean they guard, for the reason the
tombstone section gives — and raised from bean-factory post-processors at declared positions in
`StartupCheckOrder` (steps 3 and 4 of the
one list [ADR-025](adr/0025-delivery-is-off-by-statement.md) carries), because both are about
values and a value is wrong whether or not this context sends. A malformed entry — attributed
exactly, by property name and index (`push2u.allowed-origins[2]`), since the starter builds each
rule itself from one entry of one named property — is refused at step 3 by a check that performs
the same rule construction the bean's factory method performs and discards it; the factory method
still builds through the one implementation of each rule kind, and constructing a handful of rules
twice at startup is the deliberate price of the message arriving ahead of every bean-creation
failure. A non-empty property beside an application bean is refused at step 4, reading bean
definitions rather than instances so nothing is forced into existence — left inside `pushSender`,
that check was unreachable in precisely the registration-only context where the contradiction
silently drops a stated allowlist. The Spring path still does not run through
`EndpointPolicies.allowedOrigins`: what an operator sees for a bad entry is the rule's own refusal,
wearing the property name and the index.

**The two refusals about an unexpressed decision stay in `pushSender`**, because they are about an
obligation and the obligation is the sender's: both properties unset with no bean fails naming the
three ways to decide, and every set property empty with no bean fails naming both keys — the
emptiness is a statement about the pair, and no single core factory can speak for both. A
registration-only context that expresses nothing simply holds no policy bean and starts. The escape
hatch is per property — an explicitly *empty* value says the property is deliberately unused here,
so a service can empty whichever key it inherited from shared configuration it cannot unset, ceding
to a bean or to the sibling property. `pushSender` never builds the policy from the properties
itself; the one reachable state with a non-empty property and no bean — the policy
auto-configuration excluded by hand — is refused naming that auto-configuration rather than
silently rebuilt.

Both properties' components are nullable and neither carries a `@DefaultValue`, so an unset key
stays distinguishable from an explicitly empty one; every rule above rests on that difference, and
a default value would collapse "this deployment has not decided" into "this deployment cedes to a
bean" — the two cases the starter has to answer differently.

There is no property for the unrestricted mode — under Spring it is an application
`@Bean EndpointPolicy` returning `EndpointPolicies.unrestricted()`, by the same reasoning ADR-015
applied to the Vault address: a YAML flag reaches production by copying a dev profile, a code change
passes a review, and a property can be added later but not removed after a release. The second
allowlist property is not an exception to that reasoning but an application of it: what is withheld
is a *mode*, a flag that removes the control and travels between profiles as a copied line, while a
list of domains is data that has no value that disables anything. What it costs to withhold decided
it — with a bean exclusive against the properties, a deployment needing one zone would have to move
its ordinary origins into code as well, and the answers left inside YAML are unrestricted egress or
an allowlist that silently excludes a browser.

The health indicator is registered when a `VapidSigner` bean exists, and asks about nothing else:
the signer is the only part of a send that can stop working while the application runs — it
reaches a backend that can go down, holds a token that can expire, names a key that can be deleted
— while the rest of a `PushSender` is configuration the builder validated at startup. It probes
end to end (sign, then verify the signature locally against the advertised public key), so a
signer whose bytes do not verify reports `DOWN` instead of failing every real send with
`401`/`403`. Because a health endpoint is polled and each probe of a remote signer is a full
backend round-trip — against Vault Transit, one operation written to every audit device, counted
against rate-limit quotas and possibly billed — the result is cached per process, with a failed
result held far more briefly than a successful one so that recovery is still noticed quickly. Its
switch and that cache's TTL are not in this library's namespace at all: they are
`management.health.push2u.enabled` and `management.health.push2u.cache-ttl`, the prefix Spring Boot
gives a contributor's own settings, so that the wholesale `management.health.defaults.enabled`
reaches this indicator like any other and the operator has one place to look rather than two. The
indicator stays out of both availability groups unless the operator declares one that includes it —
Spring Boot builds `liveness` and `readiness` from the application's own state, and the starter
registers no group customization: an unreachable Vault is not something a container restart fixes.

`push2u-signer-vault-spring-boot-starter` is ordered before the core starter. When both are
configured, the Vault signer takes precedence over the local signer unless the application
provides its own `VapidSigner`.

## 9. Verification

The automated suite covers:

- RFC 5869 HKDF vectors;
- the RFC 8291 end-to-end encryption example;
- RFC 8292 VAPID structure and signature verification;
- the RFC 6454 §6.1 Unicode serialization of the `aud` origin — case, IDNA labels, default and
  non-default ports, address literals, userinfo (`OriginTest`);
- signer contract tests, and the kit checking itself — each of its six checks run once against a
  conforming signer and once against one that breaks exactly what that check is about: a DER
  signature, a compressed or off-curve point, a shared internal key array, a shared buffer
  refilled per call, a reused signature buffer, an override encoding the advertised key some other
  way, or one publishing a different key altogether — plus the kit's DER-fallback verification and
  its minimal-DER re-encoding, exercised directly because no CI platform lacks the P1363 signature
  name (`VapidSignerContractSelfTest`);
- the RFC 8291 §4 record-size boundary, the encrypted-body overhead, and the `rs` derivation
  pinned across its whole range including both ends (`WebPushEncryptorTest`);
- the payload size limit, builder validation, the derived `rs` in the emitted header, the
  pre-flight assessment agreeing with the refusal on the same two numbers, a send leaving the
  message's payload byte-for-byte unchanged, and the `Integer.MAX_VALUE` boundary
  (`PushSenderPayloadSizeTest`, `PayloadSizeAssessmentTest`);
- HTTP delivery, the status matrix per status and per carve-out, and the conversion of each seam
  signal into its outcome — including the interrupt disjunction on both the transport and the signer
  path;
- the key-material boundary: the hard-coded P-256 constants against two providers' `secp256r1`
  parameters (`P256PublicKeysTest`, `BcFipsP256PublicKeysTest`), the invalid-curve rejection
  shapes at `Subscription` construction (`SubscriptionValueTest`), and — both in
  `EcKeysUntrustedInputTest` — those same shapes at decode time plus the generated-pair refusals,
  driven by a provider that returns them: a substituted parameter component, a non-EC or absent
  half, a point off the curve or at infinity;
- the Vault address contract: the path-preserving join for root and path-prefixed addresses, and
  every factory-level rejection (`VaultTransitVapidSignerAddressTest`);
- Spring Boot auto-configuration — the property wiring and the diagnostics that name the YAML key,
  and, reproducing the two documented Vault Spring Boot YAML examples as property values, that the
  core and Vault Transit signer starters compose into a working `PushSender`
  (`VaultSignerAutoConfigurationTest`);
- Vault Transit integration through Testcontainers.

The published vectors are the specification, not a snapshot of current behaviour: when a change
alters what the library produces, the vectors decide which of the two is wrong.

The standard verification commands are:

```bash
./gradlew clean build
./gradlew javadoc
```
