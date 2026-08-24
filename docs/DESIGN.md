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
generating the key pair and [`VAPID-KEY-ROTATION.md`](VAPID-KEY-ROTATION.md) for replacing it on a
running deployment, [`PUSH-SERVICES.md`](PUSH-SERVICES.md) for the browser push services an
endpoint allowlist names, and the Javadoc for individual contracts.

## 2. Goals and non-goals

The library exists to replace `nl.martijndwars:web-push`, the JVM's usual answer for Web Push,
whose transitive surface and BouncyCastle-typed public API are what
[ADR-002](adr/0002-zero-dependency-core.md) records as the motive for the dependency posture.
[`MIGRATION-FROM-WEB-PUSH.md`](MIGRATION-FROM-WEB-PUSH.md) maps the two APIs onto each other for
consumers making the move; [`MIGRATION.md`](MIGRATION.md) is the other journey, an application
already on push2u moving between versions of it.

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
├── VapidSignerContractTest (the published conformance kit, for a test classpath)
├── EndpointPolicyContractTest (the same, for a deployment's own endpoint policy)
├── PushHttpClientContractTest (the same, for a custom transport, over its own TLS harness)
├── VapidKeyPairFixture / SubscriptionFixture (values of the public input contracts)
└── ScriptedPushHttpClient / SentPush (a scripted, recording transport fake)

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

The kit has two sides, serving the two audiences this library has
([ADR-028](adr/0028-the-test-kit-publishes-contracts-not-conveniences.md)). The contracts are the
executable statement of what an extension point owes, and serve whoever writes one — every one of
the three SPIs has one. `VapidSignerContractTest` covers the signer — the shape and ownership of
what it returns, the agreement between the key it advertises and the key it signs with, and a
concurrency smoke check in which several threads sign at once over inputs that differ and each
signature must verify against its own, run by `SignAttempt`, package-private machinery of that class
in the shape `PostAttempt` has for the transport. `EndpointPolicyContractTest`
([ADR-029](adr/0029-the-kit-states-what-an-endpoint-policy-owes.md)) covers a deployment's own
endpoint policy — that it answers with a value rather than an exception, that concurrent calls all
come back, and that a refusal's reason keeps the capability part of the endpoint out of the logs the
outcome reaches, which is the one obligation of that seam whose breach travels past every redaction
this library performs. `PushHttpClientContractTest`
([ADR-030](adr/0030-the-kit-states-what-a-transport-owes.md)) covers a custom transport, over a
loopback TLS server the kit brings as package-private machinery of that one class — an error status
answered rather than thrown, response headers reaching the caller, exactly one byte-for-byte
faithful request per `post` call, redirects returned rather than followed, the two unanswered
shapes thrown as `PushDeliveryException`, and concurrent callers each getting their own response;
the harness's certificate is generated per test JVM and duplicates the core's internal builder on
purpose, since neither side's fixtures may be published. The fixtures serve the far larger audience
that only sends: a generated VAPID pair and a coherent
browser subscription, each published in both the typed and the base64url form and each valid by
construction against the input contracts *as they currently stand*, plus a `PushHttpClient` that
answers a declared response sequence and records what it was asked to send. What admits a member is
that the knowledge it carries is the library's own and moves with it — what the contracts accept,
what a transport owes — never that some assembly is tedious: a value produced by the library
survives an upgrade that tightens validation, where a consumer's pasted literal breaks with no
warning a release note could have carried. The fixtures reach no JCE provider by name, which the
core's two deliberately disjoint BouncyCastle test classpaths make a build constraint rather than a
preference. [`TESTKIT.md`](TESTKIT.md) is the consumer-facing reference for the fixtures and for the
endpoint-policy and transport contracts, and [`SIGNER.md`](SIGNER.md) for the signer one.

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
    ├─ Assess the endpoint against the sender's EndpointPolicy (always present)
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
| The endpoint policy answered `Refused` | `EndpointRejected(redactedEndpoint, reason)` — a `NotAttempted` |

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

**Two seam exceptions convert to outcomes, and no others**: `VapidSignerUnavailableException` from
the signer and `PushDeliveryException` from the transport. The third seam signals by returning rather
than by throwing — `EndpointPolicy.assess` answers with the sealed `EndpointAssessment`, and its
`Refused` variant is what the pipeline turns into `EndpointRejected`
([ADR-027](adr/0027-the-endpoint-policy-answers-with-a-value.md)); §5 carries why the answer is a
value. Any other `RuntimeException` out of a consumer-written seam is a defect in that
implementation and propagates unchanged rather than being laundered into a value — and for the
policy that now means an exception of *any* type, since it has no converting one left. A policy
answering `null` is the same kind of defect and surfaces as a `NullPointerException` from the
sender's own check: reading `null` as permission would fail open on the one egress control there is,
and reading it as a refusal would invent a decision the deployment never made. What `send` itself
throws is `PushCryptoException` for a failure that recurs, `PushInterruptedException` for a
cancellation, and `IllegalArgumentException`/`NullPointerException` for an argument that is not a
legal value of its parameter ([ADR-022](adr/0022-one-type-per-programmatic-action.md)).

The conversions trust the seam's classification, not its diagnostics: every member read while
converting — the signer exception's status and retry hint, the cause chain the interruption walk
traverses — is read inside a guard, so a defective accessor in a consumer's exception subclass costs
the caller that one diagnostic, never the classified outcome. The defect is recorded as a suppressed
exception where the outcome carries the seam's failure — bounded per exception instance, because
preallocating one exception and throwing it for every call is ordinary, and one such instance with a
broken accessor would otherwise grow a suppressed entry per send for as long as a fan-out runs. A
refusal's reason is read without any of that machinery: it is a component of a final record whose
accessor this library generates, so nothing a consumer writes can stand between `send` and the
string — the guard that used to sit around the policy exception's `getMessage()` guarded a failure
mode that no longer exists (§5). An `Error` out of any of those reads is not survived and
propagates.

The interruption test is the facade's rather than any seam's, written as a disjunction — an
`InterruptedException` anywhere in the cause chain, *or* the current thread's interrupt status set —
because neither half is sound alone: an interruption can surface as a `ClosedByInterruptException`
or an `InterruptedIOException` with no `InterruptedException` beneath it, and a transport can attach
a cause without re-setting the flag. It runs on the signer path as well as the transport path, and
the cause-chain walk carries two guards against a chain a defective seam could keep from ending — an
identity set against a cycle, and a depth ceiling of 1000 against an acyclic chain fabricated fresh
on every `getCause()` read — so the chain half of the disjunction strictly covers the first 1000
elements, which every honestly built chain fits with two orders of magnitude to spare. The interrupt
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
path either. The answer is read with an exhaustive `switch` over the sealed `EndpointAssessment`,
matching the permitting variant by name rather than proceeding on anything that is not a refusal, so
a variant this seam might gain in a later release fails `send`'s own compilation instead of walking
past an egress control into the network; a `Refused` becomes `EndpointRejected`, carrying this
library's redaction of the endpoint from the subscription the sender holds beside the reason the
policy wrote.

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

`PushSender` is the primary facade. Its three required values — exactly one VAPID key source, the
contact, and the endpoint policy — are the factory method's parameters, so an incomplete sender does
not compile and `build()` has nothing left to refuse:

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
outside: two equal answers say nothing about the next one. The
conformance kit pins the two checkable moments — consecutive calls answering the same key, and one
signature verifying against the key advertised beside it — and neither reaches the lifetime the
clause is about. Thread-safety at least admits a run that might catch it — the kit has several
threads sign at once over inputs that differ, and a signature verifying against none of them is a
defect every time — while a key that moves an hour later leaves nothing behind for any check to
see. The token cache is what made the silence worth ending: it keys entries on the
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
the request headers to a host `EndpointPolicy` never assessed, and would let the redirect
target's answer stand in for the push service's verdict. The invariant is stated in code rather
than inherited from a JDK default: `JdkPushHttpClient` builds its own client with `Redirect.NEVER`
and rejects a supplied `java.net.http.HttpClient` whose `followRedirects()` differs. For an
implementation on another stack it stays a contract only, unverifiable from here.

### EndpointPolicy

```java
EndpointAssessment assess(URI endpoint);
```

and the answer, a sealed type of its own beside the seam:

```java
sealed interface EndpointAssessment {
    record Allowed() implements EndpointAssessment {}
    record Refused(String reason) implements EndpointAssessment {}
}
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

**The seam answers with a value, and refusal is not an exceptional condition**
([ADR-027](adr/0027-the-endpoint-policy-answers-with-a-value.md)). A refusal is the boundary
working: where subscriptions are accepted, an inadmissible endpoint is an ordinary request from an
ordinary client, answered with a `400` and no stored row, and a caller meeting that condition
routinely should not have to write control flow around it. The exception shape made that worse on
purpose rather than by accident — the refusal could not be an `IllegalArgumentException`, since a
web framework mapping it to a `400` would echo the message back to whoever posted the subscription,
so every consumer wrote the same catch-and-translate at its own boundary. This is the same move
already made twice in this library: a delivery that failed is a `PushOutcome` rather than a thrown
exception ([ADR-021](adr/0021-retry-belongs-to-the-caller.md)), and the size question is a
`PayloadSizeAssessment` answerable before a send
([ADR-023](adr/0023-one-size-limit-answerable-before-a-send.md)). The verb is the one that move
already uses — `assess`, beside `assessPayloadSize` — and it is deliberately a *different* verb from
the one the seam had, because keeping the name across a change from `void` to a value would leave
`policy.validate(uri);` compiling unchanged as a bare statement, silently admitting every endpoint
at the one point where nothing re-checks. The seam still has exactly one method, so there remains
exactly one way to ask it.

**`Refused` carries prose, and deliberately not the endpoint.** The reason exists for observability:
this library writes no log lines on the send path and the core holds no logger — being
zero-dependency, it could not take one; the starter's health indicator is the one component in the
tree that logs, and it reports readiness — so every diagnostic the send path produces is a value
handed to a caller who renders it, and only the policy can
say what it knew at the moment it refused. That is a sentence an operator reads, not a code a
program branches on; a consumer that genuinely has to branch on the *kind* of refusal is looking at a
missing type rather than at a component this one should have grown. No endpoint component is carried
because both callers already hold the endpoint they just passed in, and because the redaction of a
capability URL stays this library's own work: `send` renders the redacted endpoint from the
subscription it holds, whatever the policy wrote, so one of `EndpointRejected`'s two components is a
structural guarantee rather than a promise resting on a seam's contract. The reason keeps the
obligation the exception message carried — an implementation naming an endpoint renders it through
`Endpoints.redact` first.

**`Refused` validates nothing, and that is a decision.** A `null` reason is stored as `""` and a
blank one is permitted, which is exactly what `PushOutcome.EndpointRejected` permits — one refusal
may not be legal in one of the two types describing it and illegal in the other. The obvious shape,
a compact constructor refusing what the name contradicts, would be a defect here: a policy
translating its own failure writes `new Refused(e.getMessage())`, `getMessage()` is `null` for every
exception built without one, and a constructor throwing on that would send a one-line slip out of the
seam as a defect. A defect propagates, and a propagating defect stops a synchronous fan-out over a
subscription store on the first row that took the shortcut — the self-inflicted denial of service the
value shape exists to prevent, reachable through an endpoint an attacker chose. So the reason is
rendered, never thrown.

**`Allowed` carries nothing and will not grow components.** An admissible endpoint needs no number or
string to act on, and a record component added later changes the canonical constructor, the accessors
and every pattern written against the type — a breaking change where a method would have been a
compatible addition, so the empty shape is a commitment rather than an omission, the same one
`WithinLimit` makes. The one candidate worth naming is an address a resolving policy vetted, for a
transport to pin; it belongs to the seam that opens the socket, and a policy that needs it holds it
already in the implementation that resolved. Nor is the variant a singleton: its canonical
constructor is public, all instances are equal, and nothing distinguishes one from another.
`EndpointPolicies` does hand every admissible endpoint one shared instance, which keeps a question
asked on every send from allocating on the answering path — an implementation property pinned by a
test, published as no promise a caller may read with `==`.

**The hierarchy is sealed and both variants are final, which closes a hatch a public exception type
could not.** A reason arrives on a record whose accessor this library generates, so the conversion
reads it with none of the machinery an overridable `getMessage()` needed (§4); and structured refusal
data cannot travel through this library on a consumer's own subtype, so a policy whose boundary
wants a rule, a zone or a ticket reference keeps that beside the assessment, in the class that
produced it.

**What the change costs is said out loud rather than netted off.** Implementations became safer:
falling off the end of a `void` is no longer a way to admit everything, and a policy must positively
return `Allowed`. Call sites became riskier by exactly the shape a discarded value has —
`policy.assess(uri);` as a bare statement compiles with no diagnostic of any kind, `-Xlint:all`
included, and admits every endpoint. No compiler help is available for that: the annotation marking a
return value as one a caller may not discard lives in a dependency the core may not take. Inside a
send the slip cannot open the network, because `send` performs the assessment itself and acts on it;
the registration boundary is the point where nothing re-checks, which is why the seam's own Javadoc
says so where a consumer reads it.

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
keeps that row out of the store. Reaching the second point cost the core no accessor on
`PushSender`, no predicate beside the one method, no overload taking a `Subscription` and no factory
joining subscription parsing to the admission decision: `assess` is public and takes the endpoint URI
alone, the value it answers is a type any caller can `switch` over, and a deployment that built its
sender by hand holds the policy because it constructed it. The order at that boundary is the seam's
own contract — `assess` documents its argument as an endpoint that already satisfies
`Endpoints.requireSecure`, so the boundary builds the `Subscription` first, applies the policy to the
endpoint it carries second, refuses to store the row on a `Refused` — typically answering `400` — and
stores it only once both have passed. The registration check does not make the send's check
redundant: the policy is deployment configuration and changes, so `send` assesses every time and
never trusts that a row once passed.

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

A refused *endpoint*, by contrast, is not an error and raises nothing: the argument is well-formed
and it is the deployment's configuration that declines it, so the allowlist answers `Refused` with
its own account. It gives three — userinfo in the endpoint, no scheme or host and therefore no origin
to compare, and no rule matching — each naming the endpoint only through `Endpoints.redact`, so no
capability path or query travels in a reason. Which rule came closest is deliberately not among them:
that would describe the allowlist to whoever supplied the endpoint. The asymmetry with the paragraph
above is the point rather than an inconsistency — a malformed rule entry is a caller's own argument
being wrong, which is what `IllegalArgumentException` is for, while a refused endpoint is the seam
doing its job on a perfectly legal argument.

The two callers read the same value and act differently on it. `send` converts a `Refused` into the
`EndpointRejected` outcome, so one hostile row never aborts a fan-out over a whole subscription
store — a denial of service a deployment would otherwise inflict on itself — and the policy has done
its job the moment the request never leaves. An application applying the same policy where it accepts
subscriptions switches on the value there and stores nothing, and the refusal means exactly what it
means inside a send: this deployment will not contact that endpoint.

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
`builderWithFetchedPublicKey(address, keyName, token)`,
`builderWithDeferredPublicKeyFetch(address, keyName, token)` or
`builderWithSuppliedPublicKey(address, keyName, token, point)`. Three builders rather than one
overloaded family because the modes differ in *contract*, not only in parameters — the fetched one
performs a Vault read inside `build()` and can fail there, the deferred one performs the same read
at first use and contacts nothing in `build()`, the supplied one contacts nothing, ever — and
because `keyVersion` belongs to exactly one of them: in the fetched modes the version is Vault's
to state, taken from the same response as the public key. The axis the split sits on is *where the
published key comes from and what `build()` promises*, not merely whether `build()` performs I/O —
on that narrower question the deferred and the supplied builders answer alike. A
`fetchOnFirstUse()` step on the fetched builder was rejected because it would make one `build()`
sometimes perform I/O and sometimes not, which is the ambiguity the split exists to prevent; and a
bare `builder()` would have made one of the equal modes the default by omission.

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

`VaultTransitVapidSigner` supports three modes:

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
  reference the parameter step uses. Because that `build()` is the one *construction-time* call in
  this library that reaches a custodian, it is also where a startup supervisor's contract is
  stated — and it is stated for this builder alone, since the deferred one below can produce
  neither failure from its `build()`: a
  Vault that cannot serve the read now raises `VapidSignerUnavailableException` and is a boot worth
  retrying with backoff, while `PushCryptoException` recurs and should fail the deployment — and the
  supervisor tests the interruption *before* it reads the type, since an interrupted boot raises the
  unavailable type too and a supervisor that looped on it would sleep every backoff instantly
  against a flag nobody cleared.
- **Deferred-fetch mode** is the fetched mode with the read moved to first use: `build()` performs
  every check that does not depend on a Vault response — the plain-`http` refusal included — and
  contacts Vault not at all, so a context can refresh while Vault is still sealing or mounting;
  the first `sign`, `publicKey` or `publicKeyBase64Url` call performs the one
  `transit/keys/<key>` read, with the same atomic pair and the same three validation steps, moved
  in time rather than weakened. What is deferred is the call, not the key — the mode exists for a
  Vault brought up beside the application, and it must cache rather than read on demand because
  the sender reads `signer.publicKey()` on every token-cache lookup, hit included; a
  read-when-asked implementation would put a Vault `GET` on the path of every send.
  Initialization permits **at most one flight per signer** — the signer's own record of an active
  fetch, which bounds the reads it starts rather than the I/O an abandoned exchange may still be
  finishing — and a flight ends in one of four distinct ways. On success the pair is published
  through a single volatile field and retained for the signer's lifetime; there is no TTL, no
  eviction and no second read, each of which would be a hidden `refresh()`. A failure of one of
  the two contract types is shared with the callers already attached to that flight — each throws
  its **own** exception, reconstructed from an immutable description taken once (the message, the
  failure itself whole as the cause, and for an unavailability the status and declared delay,
  each declared value read exactly once); the promise is the contract type, never the runtime
  class — and then the failure is forgotten: no negative cache, a later caller starts a new read.
  A cancellation is caller-local in both directions — an interrupted fetching caller keeps its own
  exception and its flight is abandoned so the waiters retry and one takes over, while an
  interrupted waiter takes its own cancellation (the unavailability type with the
  `InterruptedException` beneath it and the flag re-set, the shape the transport would have
  produced) and leaves the flight running for everyone else. The flight applies the interruption
  disjunction to every failure *before* classifying it by type, deliberately broader in scope than
  the facade's two conversion sites, so an interruption a defective transport wrapped in a
  recurring type is still not shared. Its chain half carries the same two guards the facade's does
  — an identity set against a cycle, a depth ceiling of 1000 against a chain fabricated fresh on
  every read — and here they hold more than one caller's diagnostic, since the walk runs inside the
  flight and a chain that never ends would hold the release with it. The two ends differ in what
  they leave known: a cycle is walked to its end, so the answer is sound and the failure is
  classified, while the ceiling leaves the tail unread, so the failure is shared with nobody and
  the waiters retry — an interruption beyond the cut being exactly what cannot be ruled out — with
  the cut filed on that failure the way an accessor's complaint is. The flag is asked again after
  the walk however it ended, since the walk runs a consumer's `getCause()` and a cancellation can
  land while it does: with the first look alone, a cancellation the fetching caller had already
  taken would be shared with waiters nobody interrupted. And a failure of neither contract type
  reaches its own caller unchanged and abandons the flight the way a cancellation does — laundering
  it into a contract type is what the exception taxonomy forbids. The flight is released on
  **every** exit, two of which the transport's own contract does not admit: a throwable that is not
  a `RuntimeException` at all, which an implementation in a language without checked exceptions
  delivers through a method declaring none, and a failure whose overridable accessors throw while
  the description of it is being taken. Both abandon the flight, and both leave their caller the
  failure it was given — the second with the accessor's complaint filed on that failure as a
  suppressed exception rather than thrown in its place, so far as it can be filed at all: nothing
  can suppress itself, so an accessor that threw the failure itself leaves nothing to record; the
  filing is bounded per exception instance, so a transport reusing one preallocated exception across
  an outage does not grow its suppressed list one entry per read for as long as the outage lasts;
  and a machine failure out of the recording reaches the caller in place of the failure rather than
  being hidden behind it. Neither exit is a fine point: a flight left
  recorded as active parks its waiters forever and then collects every later caller on the same
  dead latch, which is one consumer's transport defect turned into a signer that never answers
  again. No signing `POST` ever runs while the
  initialization guard is held — the guard protects the record of the active flight and nothing
  else, waiters block on the flight rather than on the guard, and an initialized signer takes a
  volatile fast path that touches neither — the same look-up-release-sign-publish discipline the
  token cache follows, for the same reason.
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
answer alone and only where an operator enabled the rate-limit response headers. Its `toString()` is
overridden for the reason `VaultToken`'s is, one step weaker: the body is not a credential by type
or by contract, but it is an arbitrary service answer under a size bound and may hold sensitive data
all the same — a token echoed back in an error message, an internal path, whatever a compromised hop
in front of Vault decides to put there — so the printed form carries its length and not the body.
The record is safe to print without a transport author having to know what came back in it.

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

**What the starters say about Spring Boot's version is a floor and nothing else**
([ADR-032](adr/0032-starters-declare-a-minimum-spring-boot.md)). One Spring Boot dependency leaves
each starter — `spring-boot-autoconfigure`, at an ordinary `require` version — and Spring Boot's
BOM leaves neither: it aligns this build's compile, annotation-processing and test classpaths and
stops there. On a published configuration it did more than align, because a Gradle consumer reads
that metadata: Spring Boot's whole version manifest became an input to their resolution and raised
their Spring, Jackson and Micrometer to whatever version this project happened to build against.
The floor's value is the same number this build compiles against — one catalog key, not two, so
that a starter cannot use an API newer than the floor it advertises and the promise is one the
compiler keeps. Where the floor binds and where it is only documentation is the consumer's build's
business rather than this library's, and `docs/SPRING.md` states which is which. Nothing in either
starter reads the framework's version at run time, deliberately: that would be a member of the
startup-refusal list below, bought for the cells where resolution does not enforce the floor
anyway.

**Delivery is off by statement, never by omission**
([ADR-025](adr/0025-delivery-is-off-by-statement.md)). `push2u.enabled` is that statement, it
defaults to on, and the third state — on, with neither a sender nor a signer in the context — fails
at startup. The invariant is deliberately narrow: *under an active auto-configuration, the absence
of a sender is incompatible with `push2u.enabled` other than `false`.* An application that excludes
the auto-configuration, supplies its own `PushSender`, or does not carry the starter has left the
decision outside the starter's reach, and the record claims nothing about it.

Only `true` and `false` are values. A value that is neither — a blank one included — fails the
context naming the property rather than being read as one of them: this is the one key where a typo
would be free to mean the opposite of what was typed, and the framework's own reading of an
`enabled` key (anything not literally `false` is on) turns `flase` into a deployment that sends
although it said not to. The condition on the delivery path is the framework's
`@ConditionalOnProperty` with `havingValue = "true"`, so an unrecognised value leaves that path
*inactive* while the check at step 1 below fails the context — a mistyped switch never builds a
signer, least of all one whose construction reads a remote custodian, for a context that is about
to fail anyway.

The switch is a condition every auto-configuration on the delivery path honours, and not a master
switch over `push2u.*`. Off: no signer, no transport, no sender; the health indicator, which lives
in its own auto-configuration so the starter stays usable without Actuator, honours the same
condition and is gone too; and every signer starter honours it, so the Vault signer is never
constructed and its fetched mode's startup read against Vault is never paid for. A signer starter's
own *diagnostic* is gated with it as well, for the reason the table below gives. It does not remove
an application's own `PushSender`, which is not this starter's to withdraw, and **it does not reach
the endpoint policy** — the constraint this places on ADR-024's bean, which is why
`Push2uEndpointPolicyAutoConfiguration` carries no condition at class level and may never gain one.
Being outside the class that carries the sender is not what makes the policy safe: the health
indicator is outside it too and is gated all the same.

A signer starter therefore reads a key another module owns, and that is not the coupling the
diagnostics avoid. Naming another module's prefixes *inside a message* copies its activation rules
and goes stale; honouring a switch copies nothing — one fact about the namespace, whose meaning
cannot drift — and the Vault starter already orders itself against the core starter by name without
depending on it, so the condition costs no dependency either.

**Reading the switch is a signer starter's; refusing a value of it that is neither is not.** That
refusal is step 1 of the list below and belongs to the module owning the key: a second
implementation in a module that cannot see the first would be one rule defined twice with nothing to
guarantee which of them an operator reads, which is the defect the list exists to prevent. One price
comes with that and is stated rather than designed away — in a composition carrying a signer starter
*without* the core one, a mistyped `push2u.enabled` is refused by nothing and the signer starter's
condition reads it the only way a condition can, as not `true` and therefore off, withholding the
signer silently. Every deployment that actually sends carries the core starter, where the refusal
is, and where it arrives ahead of everything else.

**Blank counts as unset, for the properties that activate a signer.** `@ConditionalOnProperty`
treats an empty value as present, so `public-key: ${VAPID_PUBLIC_KEY:}` beside a private key
defaulted the same way would activate the local signer and then be refused for the length of a
point the empty string never carried. Both starters therefore replace that condition with one of
their own over their activating set — the core's two `push2u.vapid.*` keys, the Vault starter's
`address`/`key-name`/`token` — reading through `Binder` and counting a blank as unset. Nothing is
lost: no blank value of any of them could have produced a signer, so the only outcomes traded are
two failures, and the one chosen names the missing configuration. The reading belongs to activation
alone and says nothing about the allowlist properties, where explicitly empty is a statement with a
meaning of its own.

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

**A property a release removed is refused while its tombstone lives, and ignored like any other
unknown key once that window closes.** `push2u.record-size` went with
[ADR-023](adr/0023-one-size-limit-answerable-before-a-send.md); `push2u.health.enabled` and
`push2u.health.cache-ttl` went to `management.health.push2u.*` when the health indicator took Spring
Boot's own switch for a contributor; and `push2u.retry.max-attempts`, `push2u.retry.initial-backoff`
and `push2u.retry.max-backoff` went nowhere at all — they were handed to the caller with the retry
loop ([ADR-021](adr/0021-retry-belongs-to-the-caller.md)), since a send now performs exactly one
POST and publishes what a repeat decision needs on the outcome, `RetryableFailure` carrying the
status the push service answered with and the `Retry-After` it asked for, uncapped.

In the release that removed them, one `BeanFactoryPostProcessor` in
`Push2uStartupChecksAutoConfiguration` failed the context naming every dead key it found and where
each one's effect had gone. **That check no longer exists**, its window having closed, and the tree
carries no successor: an operator who
still holds one of those keys now has it ignored in silence, which is what binding does with any
key nothing reads. The mechanism is described here rather than only in the history because it is
the shape the *next* removal takes — a check whose whole design is that it is temporary, entered
with the removal and deleted on a schedule set when the removal shipped, so that nothing accumulates
into code refusing keys nobody has written in years.

Two of its properties are worth keeping in view for that next time. **One check carried every key**,
because the keys a release removes are held together, having been copied together out of the guide
that release replaced: a check per key could not be ordered against its siblings — none is more
specific than another, so they would share a position and the one heard would be whichever the
framework registered first — and a deployment holding several dead keys would meet them one failed
startup at a time. And **it was hosted apart from the features whose keys it named**: the health
pair's natural home would have been the auto-configuration registering the health indicator, which
carries `@ConditionalOnClass(HealthIndicator.class)`, and a deployment that dropped Actuator while
keeping `push2u.health.*` holds exactly the same dead configuration — so that condition would have
let through precisely the case the check existed for. What generalises is not "beware Actuator" but
that a check inherits every condition standing between it and the context, including ones that have
nothing to do with what it checks.

**Every startup check of the core starter lives in `Push2uStartupChecksAutoConfiguration`, and that
class contributes nothing else.** Two rules meet there. An auto-configuration that contributes a
bean an operator might want to remove may not also host a check: excluding an auto-configuration is
the framework's ordinary tool for removing its contribution, and a check riding beside the bean
would vanish with it — the refusal would disappear in exactly the deployment whose operator reached
for the standard tool. And a check runs when its row in the table below says it runs, suppressed by
nothing the row does not mention — so the hosting class carries no condition of any kind, and the
one check that carries one carries the switch alone. Excluding the checks' own class is the
deliberate way to switch them off, visible in the exclusion line that names it, and it is the single
route by which a stated allowlist can boot beside an application policy bean.

**Which side of the switch a check falls on is decided by what it is about, never by where it is
implemented.** Most of this starter family's refusals need no decision at all: one raised *while a
bean the switch withdraws is being constructed* is on the delivery-path side by construction and
could not be anywhere else. That covers the signer's own key material, every builder value the
sender translates from a property, and every per-property translation in a signer starter. What is
left is the five that take a declared position, and they are the whole of this table:

| Startup check | `push2u.enabled: false` | `true`, or unset |
|---|---|---|
| The value of `push2u.enabled` itself | runs | runs |
| A malformed allowlist entry | runs | runs |
| An allowlist stated beside an application policy bean | runs | runs |
| A signer starter's partial-configuration diagnostic | skipped | runs |
| The general refusal over a missing signer | skipped | runs |

The rows that run on both sides are about a *value*: an entry that is not an origin is not an origin
in a context that sends nothing either. The two that are skipped are about the *delivery path* — each asks, in its own words, whether
this deployment can sign, and a deployment that has said it does not send has answered that.

A signer starter's diagnostic is gated by the switch although it is not a contribution, and the
reason is its own stand-down: that stand-down is over an existing `VapidSigner` or `PushSender`
bean, and the switch is precisely what keeps those from existing. Ungated, a deployment that
switched delivery off with half a `push2u.signer.vault.*` block left over would be refused over
configuration nothing reads — the mistake the stand-down exists to prevent, with the sign reversed.

**One declared order over every startup check.** One context can earn several at once, and the
operator reads whichever arrives first, so there is one list and every check declares its position
in it:

1. **the value of `push2u.enabled`** — a deployment that mistyped the one key deciding whether any
   of this applies is owed that sentence and not a consequence of it;
2. **a malformed allowlist entry**;
3. **an allowlist stated beside an application policy bean**;
4. **a signer starter's partial-configuration diagnostic**;
5. **the general refusal over a missing signer**;
6. everything else, which is ordinary bean creation — every refusal raised while a bean is being
   built. Those are reachable there because steps 4 and 5, the two about whether a signer exists,
   stand down once its definition does. Steps 1 to 3 have no such stand-down and must not grow one:
   none of them is about a signer.

The steps are renumbered whenever one leaves, but the *constants* behind them are not: a position is
a claim only about a check that exists, so the number the removed-property check held was vacated
where it sat and its neighbours stayed put. A number reserved for a check nobody has written would
be a claim nothing keeps true, and the next check needing that place is free to take it.

Steps 2 through 5 are specific before general, a value before the path; step 1 sits ahead of all of
it because it decides whether the configuration underneath it can be read at face value at all. The order is about which message an operator holding several faults reads first, and nothing
more: no later step's *condition* is decided by an earlier step's outcome, and none could be — a
condition on an auto-configuration is evaluated while the configuration classes are parsed, long
before any of these checks runs.

**The mechanism is narrower than it sounds, and three ways out of it are silent.** The framework
sorts post-processors of the bean factory into buckets by the *kind* of precedence they declare and
orders only within each bucket, so two checks in different buckets run in bucket order whatever
integers they carry. A post-processor of the bean definition *registry* is a different phase and
completes before any plain bucket; a check over the environment as it is being prepared precedes the
context itself, which is why every check of this family reads the environment at refresh; and the
bucket is
chosen from the **declared return type of the `@Bean` method**, not from the object it returns, so a
factory method declaring `BeanFactoryPostProcessor` lands the check in the bucket that is never
sorted, carrying an order nothing reads. So every check of this family implements `Ordered` **on its
class**, and the `@Bean` method that contributes it declares **that class** as its return type and
is `static` — which the framework instructs for a method producing a post-processor without
enforcing, and which keeps the auto-configuration itself uninstantiated in that early phase.

**The numbers cannot live in one place.** A signer starter deliberately does not depend on the core
starter, so no constant is visible to both: steps 1, 2, 3 and 5 are `StartupCheckOrder` in
`push2u-spring-boot-starter`, step 4 is `VaultStartupCheckOrder` in the Vault starter, and each
module reads its own against the list above. What pins the order is therefore not a constant's value
— a test asserting that a number here equals a number written in a document proves someone typed it
twice, and stays green while the module next door moves its own — but the message that arrives in a
context holding *every* starter that declares a position, configured to earn several refusals at
once. That context exists in exactly one place, the Vault starter's suite, which is the only one
with both starters on a classpath.

**The general refusal is raised from a post-processor, and its stand-down is a condition.** A bean
that requires a `PushSender` is instantiated before any ordinary bean an auto-configuration
contributes, so a refusal raised as one would lose the race and the operator would read the
framework's "required a bean that could not be found" instead. Raising it from a post-processor puts
it ahead of every application singleton, while the condition that decides whether to raise it stays
where it belongs: `@ConditionalOnMissingBean({VapidSigner.class, PushSender.class})` on the factory
method, decided while the auto-configurations are processed and against bean *definitions*, so
nothing is forced into existence to answer it. One price is paid knowingly, and it is ADR-024's in
the other direction: that condition sees the application's own configuration and every signer
starter ordered ahead of `Push2uStartupChecksAutoConfiguration`, which is now
`@AutoConfiguration(after = Push2uAutoConfiguration.class)` so the in-JVM signer counts too. A signer
starter that declares no order is placed by a fallback, and where that puts it afterwards the
context fails demanding a signer it holds — the alternative is a refusal raised after the
application beans it exists to precede.

Its message enumerates what the deployment may do — the switch, an application `VapidSigner` or
`PushSender` bean, the two key properties this module owns, any signer starter's own configuration,
and the framework's condition report — and stops there. It names no other module's prefixes and
counts none of its keys, and nothing collects one module's finding into another's message: that
would be a cross-module contract published for the life of the API in exchange for one better
sentence in a failure that already names both. The condition report is named by the **startup flag**
that prints it rather than by `/actuator/conditions`, which a context that failed to start does not
serve; and the message is not assembled by reading that report either, whose keys and wording are
diagnostics rather than a contract.

**A signer starter's diagnostic is not its contribution, and the two cannot share a class.** The
contribution is ordered *ahead* of `Push2uAutoConfiguration` so the signer it registers is there for
the sender's own condition to find; a diagnostic has to be ordered *behind* every contribution, the
in-JVM signer's included, or it cannot see whether any signer was contributed at all. So the Vault
starter ships two: `VaultSignerAutoConfiguration` before, `VaultSignerDiagnosticsAutoConfiguration`
after, both ahead of the general refusal in the running order. Without the split the stand-down
would be unreachable — a deployment sending through the local signer with a forgotten
`push2u.signer.vault.address` would be refused by a check that could not yet see the signer it was
about to be told to stand down for.

**The cases a refusal cannot reach are answered by failure analyzers.** A refusal speaks only where
it runs, and these two run in different places, so each goes out of reach for a reason of its own:
the general one about a signer is a post-processor a context stops contributing once delivery is
stated off, once a signer or a sender bean stands it down, or once its auto-configuration is
excluded, while the refusals the endpoint policy keeps are inside `pushSender`'s own factory method,
which a context that builds no sender never enters. Two analyzers close the two gaps; this is the
first, and the one about the policy belongs with the policy, below. An application that requires a
`PushSender` from a context where the check never ran gets `MissingPushSenderFailureAnalyzer`, which
distinguishes three causes and gives three answers: the deployment stated `false` and something
still required a sender, which is a contradiction in the application rather than a missing signer;
the check is absent because its auto-configuration was excluded; and everything else, which is the
same enumeration the refusal gives — with a context that already holds a `VapidSigner` led with the
piece that is actually missing. Answering "configure a signer" to all three would reintroduce the
record's own subject one layer down, a deliberate "off" reported as a defect; and for the same
reason no answer may state something false about the context it describes, so the signer-present
branch names both shapes that reach it — `Push2uAutoConfiguration` inactive, and
`Push2uAutoConfiguration` active but unable to see a signer an auto-configuration ordered after it
registered — rather than claiming either. The framework ships an analyzer for a missing bean of its
own, and it recognises the same failure both of these do, so each of them declares
`@Order(HIGHEST_PRECEDENCE)` rather than taking the position its `spring.factories` entry happens to
give it, and a test pins for each that its text is the one that arrives — losing that race would
leave no mark, since the output would be correct, generic and exactly what it was before either
analyzer existed. The factories file is where they are registered and deliberately not where their
precedence is decided: a position on the classpath is not a statement anyone made.

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
removed-property section gives — and raised from bean-factory post-processors at declared positions
in `StartupCheckOrder` (steps 2 and 3 of the
one list [ADR-025](adr/0025-delivery-is-off-by-statement.md) carries), because both are about
values and a value is wrong whether or not this context sends. A malformed entry — attributed
exactly, by property name and index (`push2u.allowed-origins[2]`), since the starter builds each
rule itself from one entry of one named property — is refused at step 2 by a check that performs
the same rule construction the bean's factory method performs and discards it; the factory method
still builds through the one implementation of each rule kind, and constructing a handful of rules
twice at startup is the deliberate price of the message arriving ahead of every bean-creation
failure. A non-empty property beside an application bean is refused at step 3, reading bean
definitions rather than instances so nothing is forced into existence — left inside `pushSender`,
that check was unreachable in precisely the registration-only context where the contradiction
silently drops a stated allowlist. The Spring path still does not run through
`EndpointPolicies.allowedOrigins`: what an operator sees for a bad entry is the rule's own refusal,
wearing the property name and the index.

**The two refusals about an unexpressed decision stay in `pushSender`**, because they are about an
obligation and the obligation is the sender's: both properties unset with no bean fails naming the
three ways to decide, and every set property empty with no bean fails naming both keys — the
emptiness is a statement about the pair, and no single core factory can speak for both. A
registration-only context that expresses nothing simply holds no policy bean and starts — and goes
on starting until something in it asks for the policy, which is where the second analyzer takes
over. The escape hatch is per property — an explicitly *empty* value says the property is
deliberately unused here, so a service can empty whichever key it inherited from shared
configuration it cannot unset, ceding to a bean or to the sibling property. `pushSender` never
builds the policy from the properties itself; the one reachable state with a non-empty property and
no bean — the policy auto-configuration excluded by hand — is refused naming that auto-configuration
rather than silently rebuilt.

**So the same three states are reached twice, and they are written once.** A sending deployment
meets them as a refusal, inside the factory method whose obligation they are. A registration-only
one meets them as an unsatisfied dependency, because it injects the policy at the boundary where
subscriptions arrive and holds no sender for that refusal to run inside — which is the one
deployment shape whose whole reason for wanting the policy is that a registration endpoint must not
store whatever a browser offers it, and the one that would otherwise read the framework's "required
a bean that could not be found" naming a push2u type and nothing else.
`MissingEndpointPolicyFailureAnalyzer` answers it, and `MissingEndpointPolicy` carries both the
wording and the rule that turns the two properties into one of the three states, so neither asker
restates the other. The two shapes differ in assembly and not in content: a refusal folds situation
and ways out into the one string an exception carries, an injection-failure analysis wants them
apart, because there the situation follows the framework's account of what went unsatisfied and has
to read as the next sentence rather than as the continuation of a clause. The analyzer reads the
properties from the environment rather than from the bound record — a context that failed to start
may hold neither the record nor the class that enables it — but through the same two names and the
same unset-against-emptied distinction that decide whether the bean exists at all, so the state it
reports and the state that produced the absence cannot come apart.

Two things are true of that analysis and of no refusal. **`push2u.enabled` is never the cause, and
where a deployment has stated it off, one clause says so** — the switch withdraws the delivery path
and deliberately not the policy, which is precisely what such a deployment keeps by making the
statement. The clause earns its space from its neighbour: the analysis of a missing sender *does*
answer in terms of that switch, so an operator who has just read that one will reach for it here,
and the plausible next move without the clause is to turn delivery back on in a deployment that
deliberately does not send — which fixes nothing and undoes a statement someone made on purpose. And
**an injection point can be withdrawn where a factory method has none to offer**, so the analysis
names that way out too — conditioned on a deployment that neither sends *nor accepts* subscriptions,
never on one that merely does not send. A service that takes subscriptions from clients and does not
check their endpoints is the one context this may not invite to remove the injection point: it is
the one that should start checking them, and the invitation would hand it the shape that lets
registration go on storing whatever a browser offers. As with the sender's analyzer, nothing said
may be false about the context being described, so the analysis is declined outright wherever the
enumeration would be an account of some other context — a missing bean of another type, a bean found
more than once rather than not at all, a bean factory or an environment that is not there to be read
— either because the failure came before there was one, or, for the factory, because the one that is
there cannot be asked for definitions, and either of the two missing is enough — and a context that
does hold an `EndpointPolicy` definition after all.

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
`push2u.enabled` sits upstream of that switch and the two stay independent: a deployment that turned
delivery off has no indicator left to opt out of, while one that is sending may still decline to tie
its health to a signer. Withdrawing the contributor is not the same as rewriting an operator's
health groups, and the starter does only the first — the framework validates group membership and
refuses a context naming a contributor that does not exist, so a group naming `push2u` is edited in
the same change, by whichever of the several routes removed the indicator.

`push2u-signer-vault-spring-boot-starter` ships two auto-configurations, at opposite ends of the
ordering: `VaultSignerAutoConfiguration` is ordered before the core starter, so that when both are
configured the Vault signer takes precedence over the local one unless the application provides its
own `VapidSigner`; `VaultSignerDiagnosticsAutoConfiguration` is ordered after it, for the reason
given above. Both honour `push2u.enabled`, so a deployment that has declared the custodian unused
never constructs the signer and never performs the eager fetched mode's startup read.
`push2u.signer.vault.public-key-fetch` selects between that startup read (`eager`, the default and
what an unset or blank key means) and the deferred read at first use; its refusals — a value that
is neither mode, and any written value beside a supplied `public-key`, whose mode performs no
metadata read at all — are decided while the signer bean is built, which places them at step 6 of
the startup-check order and on the delivery-path side of `push2u.enabled` by construction, so they
deliberately hold no position in the ordered list of checks.

## 9. Verification

The automated suite covers:

- RFC 5869 HKDF vectors;
- the RFC 8291 end-to-end encryption example;
- RFC 8292 VAPID structure and signature verification;
- the RFC 6454 §6.1 Unicode serialization of the `aud` origin — case, IDNA labels, default and
  non-default ports, address literals, userinfo (`OriginTest`);
- signer contract tests, and the kit checking itself — each of its seven checks run once against a
  conforming signer and once against one that breaks exactly what that check is about: a DER
  signature, a compressed or off-curve point, a shared internal key array, a shared buffer
  refilled per call, a reused signature buffer, an override encoding the advertised key some other
  way, or one publishing a different key altogether — plus the kit's DER-fallback verification and
  its minimal-DER re-encoding, exercised directly because no CI platform lacks the P1363 signature
  name (`VapidSignerContractSelfTest`). The concurrency check's subjects are shaped by what a smoke
  check can be self-tested against. Its negative subject holds one `Signature` in a field — the
  mistake the interface names — with the collision *forced* rather than waited for, callers pairing
  at a rendezvous placed between `update` and `sign`, since a self-test resting on the real race
  would be red some runs and green others, which is worse than absent; its positive subject is run
  ten times over, because a check that goes red now and then on a conforming signer is one a build
  learns to ignore. Four more subjects pin the abort and both of its edges, by admitting a chosen
  number of the burst and refusing the rest with `VapidSignerUnavailableException`: none admitted
  and one admitted both abort, two admitted reaches a verdict, and one admitted that signs under an
  unadvertised key goes red rather than aborting. The pairs either side are the point — a green on
  one observed signature would report a signer as held to something no *pair* of calls exercised,
  while a threshold refusing every burst-limited custodian outright would look equally correct with
  only the aborting half checked, and an abort placed ahead of the assertion instead of behind it
  would turn the check's strongest finding into a skip for every custodian that happened to be
  metering. Each of the four is red under a different way of moving that threshold, which is what
  makes them four and not one;
- the kit's fixtures held to the same standard, since a published value that is quietly wrong is a
  defect in every consumer's suite at once. **`VapidKeyPairFixtureTest` verifies that the scalar the
  fixture publishes really is the one belonging to the point it publishes**, by signing with it and
  verifying through `Es256Verifier` — the correspondence the library's own construction-time checks
  do not reach, since `VapidKeys.fromBase64` applies an on-curve check to the public half and a
  length check to the scalar and nothing relates the two. That check is part of the fixture rather
  than an extra: without it the fixture would carry a defect class this library's key handling does
  not have, and one whose only symptom is a push service rejecting the JWT. It runs on the pairs
  where the encoding is most likely to slip — a scalar with its high bit set, a scalar or a
  coordinate with leading zero bytes — with `FixedWidthTest` pinning the writer underneath. Beside
  it: both fixtures' decoded shapes, their alphabet and absence of padding, freshness per call, the
  subscription's three components agreeing with each other, and the endpoint refusals inherited from
  `Subscription` (`VapidKeyPairFixtureTest`, `SubscriptionFixtureTest`, `FixedWidthTest`);
- the transport fake's own obligations, which are the ones a consumer's test rests on without
  looking: answers handed out in script order, per-response headers kept apart, an exhausted script
  raising after the call is recorded, `failingWith` recording before it throws, `sent()` as an
  immutable point-in-time snapshot, and — under concurrent posts — every call drawing exactly one
  answer, all of them recorded, and the recorded order being the order answers were handed out
  (`ScriptedPushHttpClientTest`); plus `SentPush` keeping an immutable header copy and rendering
  neither the capability path nor any header value (`SentPushTest`);
- the RFC 8291 §4 record-size boundary, the encrypted-body overhead, and the `rs` derivation
  pinned across its whole range including both ends (`WebPushEncryptorTest`);
- the payload size limit, builder validation, the derived `rs` in the emitted header, the
  pre-flight assessment agreeing with the refusal on the same two numbers, a send leaving the
  message's payload byte-for-byte unchanged, and the `Integer.MAX_VALUE` boundary
  (`PushSenderPayloadSizeTest`, `PayloadSizeAssessmentTest`);
- HTTP delivery, the status matrix per status and per carve-out, and the conversion of each seam
  signal into its outcome — the two converting exception types, and the policy's `Refused` value
  becoming `EndpointRejected` — including the interrupt disjunction on both the transport and the
  signer path;
- the allowlist's matching and the entry-level refusals of both rule kinds: an origin compared on
  the whole RFC 6454 serialization, a domain matched at a label boundary and only on `https` and the
  default port, case and IDNA form settled on both sides, and duplicate entries collapsed where the
  allowlist is built (`EndpointPoliciesTest`, `EndpointRuleTest`);
- the endpoint policy as a seam that answers by value: each standard refusal carrying its own text
  and every admitting answer being the one shared `Allowed` (`EndpointPoliciesTest`), a `null` reason
  stored as `""` and an `Allowed` carrying nothing and equal by value (`EndpointAssessmentTest`), and
  a policy that answers `null` or throws anything at all read as the defect it is rather than as an
  outcome (`PushSenderEndpointPolicyTest`, `PushSenderSeamConversionTest`);
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
- the activation switch on both sides — every bean it withdraws and every one it does not, each
  value refusal running with delivery off, a value that is neither `true` nor `false`, a blank
  activating property read as unset, and each stand-down of the general refusal
  (`Push2uDeliverySwitchTest`); the missing-sender analyzer's three answers and that its text is the
  one the framework's sorted list produces (`MissingPushSenderFailureAnalyzerTest`);
- the missing-policy analyzer's three answers, the clause a context that stated the switch off gets
  and the ways out staying the allowlist's rather than the switch's, the shapes it declines rather
  than explains, and that what it says and what the sender's refusal says are one text rather than
  two that agree today — plus the same sorted-list check its sibling carries, since both analyzers
  race the framework's own (`MissingEndpointPolicyFailureAnalyzerTest`);
- the one running order over every declared startup check, pinned by the message that arrives in a
  context holding both starters and earning every refusal at once, then one fault at a time down the
  list (`StartupCheckOrderAcrossStartersTest`) — never by comparing constants, which live in two
  modules that cannot see each other;
- Vault Transit integration through Testcontainers;
- the configuration metadata each starter publishes, read out of the jar's own classpath resource
  rather than out of a build path: every key no properties record binds — the activation switch and
  the health indicator's own switch, both read by the framework — plus the Vault hint's *values*,
  which is the only part of it the failure reaches, since the hint's name is the property's name
  too and the processor emits an empty `hints` list of its own accord. Beside each, a key the
  annotation processor *does* discover, so a failure says which half broke. The half that needs pinning is the hand-written one: the processor merges
  `META-INF/additional-spring-configuration-metadata.json` only where it finds that file on the
  classpath it runs with, and where it does not, it produces metadata without those entries, fails
  no task and says nothing (`ConfigurationMetadataTest` in both starters);
- what the two starters *publish* about Spring Boot's version, read out of the generated POM and
  module metadata rather than out of the build script: no `dependencyManagement` element at all,
  every Spring Boot dependency carrying the catalog's floor literally, and no `strictly`, `prefers`
  or `rejects` in the Gradle metadata — the three spellings a POM discards while Gradle enforces
  them. `check` runs it for both starters. Everything else about the floor is enforced by
  construction, being the compile classpath; these three are properties of the published files
  alone, and undoing one of them compiles and tests green.

The published vectors are the specification, not a snapshot of current behaviour: when a change
alters what the library produces, the vectors decide which of the two is wrong.

The standard verification commands are:

```bash
./gradlew clean build
./gradlew javadoc
```

Both resolve Spring Boot at the floor the starters declare, because the catalog holds one number
for both meanings. That makes the merge-blocking run blind by construction to anything a newer
Spring Boot changes, so CI adds runs above it: one build of the two starter modules per released
Spring Boot minor line at or above the floor's own, each at its newest GA patch, with
`-Ppush2u.springBoot` substituting the catalog key for that invocation alone. Those runs are read,
not obeyed — none is a required check, and every publishing task in the build refuses to execute
while that property is set, so nothing such a run builds can be published. The check is on the task
type: a name filter would be spelled around by Gradle's own camelCase abbreviation and would miss
the Central bundle, which reaches each module's publication through tasks nobody names. Which versions there
are is computed from Spring Boot's own released list rather than written down, since a list here
would go stale the week Spring publishes.
