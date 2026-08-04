# push2u — Design

## 1. Status and scope

push2u is an implemented, standalone Java library for server-side Web Push delivery. Artifacts
are released to Maven Central under the `com.the13haven` group ID; the version is derived from
git tags rather than stored in the build (ADR-013). Java packages are `com.the13haven.push2u.*`.

The library implements:

- RFC 8030 push delivery and response interpretation;
- RFC 8291 message encryption;
- RFC 8292 VAPID authentication;
- RFC 8188 `aes128gcm` content coding;
- RFC 5869 HKDF-SHA-256;
- local and Vault Transit VAPID signing;
- plain Java and Spring Boot integration.

The architecture keeps the protocol core free of runtime implementation dependencies and exposes
narrow seams only where
applications have a legitimate reason to replace behavior.

## 2. Goals and non-goals

### Goals

- Zero runtime *implementation* dependencies in `push2u-core` — its one dependency is JSpecify,
  an annotation-only jar exposed as API metadata (ADR-012).
- Java 21 runtime baseline.
- Standards conformance pinned by published RFC test vectors.
- A small synchronous API with an asynchronous convenience wrapper.
- Replaceable VAPID key custody and HTTP transport.
- Immutable public value types and defensive handling of key material.
- Expired subscriptions represented as results rather than exception-driven control flow.
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
├── retry and response interpretation
├── LocalEcVapidSigner
└── JdkHttpPushClient

push2u-signer-vault
├── VaultTransitVapidSigner
└── VaultHttpTransport / JdkVaultHttpTransport

push2u-spring-boot-starter
├── PushSender auto-configuration
└── optional signer health indicator

push2u-signer-vault-spring-boot-starter
└── Vault signer properties and auto-configuration
```

`push2u-core` has no runtime implementation dependencies (only JSpecify's annotations, ADR-012).
The Spring Boot modules and Vault integration are
opt-in and cannot leak framework types into the core API.

Each artifact carries a JPMS identity (ADR-014). `push2u-core` and `push2u-signer-vault` are
explicit modules with a `module-info.java`; the two starters and the published test kit are
automatic modules with a fixed `Automatic-Module-Name`:

| Artifact | Module name | Kind |
|---|---|---|
| `push2u-core` | `com.the13haven.push2u` | explicit |
| `push2u-signer-vault` | `com.the13haven.push2u.signer.vault` | explicit |
| `push2u-spring-boot-starter` | `com.the13haven.push2u.spring` | automatic |
| `push2u-signer-vault-spring-boot-starter` | `com.the13haven.push2u.signer.vault.spring` | automatic |
| `push2u-core` test fixtures | `com.the13haven.push2u.testkit` | automatic |

## 4. Send pipeline

```text
PushSender.send(subscription, message)
    │
    ├─ Check the payload against the body limit and the record size
    ├─ Validate the endpoint against the configured EndpointPolicy (no policy by default)
    ├─ Decode the subscription P-256 public key
    ├─ Generate an ephemeral P-256 key pair and random salt
    ├─ ECDH + HKDF-SHA-256
    ├─ Encrypt one RFC 8188 record with AES-128-GCM
    ├─ Build and sign the VAPID JWT
    ├─ POST the encrypted body through PushHttpClient
    ├─ Retry 429 and 5xx responses according to RetryPolicy
    └─ Return PushResult
```

Status interpretation:

| HTTP result | `PushResult` |
|---|---|
| `2xx` | `DELIVERED` |
| `404`, `410` | `SUBSCRIPTION_EXPIRED` |
| Other non-retryable response | `FAILED` |
| Retryable response after attempts are exhausted | `FAILED` |
| Transport failure | `PushDeliveryException` |
| Cryptographic failure | `PushCryptoException` |
| Endpoint policy rejection | `EndpointRejectedException` |

The encrypted body and VAPID token are reused across retries of the same send operation.

The endpoint policy runs after the size preconditions and before everything else — encryption,
the VAPID signature (a remote Vault/KMS call under an external signer) and the POST — so a
rejected endpoint costs no cryptography and no I/O. `sendAsync` runs the same pipeline, so the
policy cannot be bypassed on the async path.

The VAPID `aud` claim is the endpoint's origin in the Unicode serialization of RFC 6454 §6.1, as
RFC 8292 §2 requires: lowercase scheme and host, IDNA A-labels converted to their Unicode form,
and the port omitted when it equals the scheme's default. `java.net.URI` performs none of that
normalization, so the library serializes the origin itself.

The two size preconditions are evaluated first, before any cryptography or network I/O, and are
reported independently because they constrain different things:

| Precondition | Source | Default |
|---|---|---|
| `103 + payload ≤ maxEncryptedBodyBytes` | RFC 8030 §7.2 body limit | 4096 bytes (3993 of plaintext) |
| `recordSize > payload + 1 + 16` | RFC 8291 §4 | `rs` 4096 |

Either failure is an `IllegalArgumentException`: the first names the resulting body size, the
configured limit, and the maximum plaintext; the second names the minimum `rs` required.

The 103-byte overhead is derived from the format the encryptor emits — an 86-byte RFC 8188 header
(salt 16, `rs` 4, `idlen` 1, `keyid` 65), the padding delimiter (1) and the AES-GCM tag (16) — not
hard-coded, so the plaintext maximum tracks a configured body limit. The RFC 8291 §4 rule has a
single implementation (`WebPushEncryptor.checkRecordSize`), used both by this pre-flight check and
by the encryptor itself.

Both sums are computed in `long`. For the body sum this is load-bearing and covered by a test: in
`int`, a payload above `Integer.MAX_VALUE - 103` would wrap to a negative size and pass any limit
unnoticed. For the record-size sum it matters on the encryptor path, which is reachable without
the body check; reached through the pre-flight check that sum cannot overflow, because such a
payload has already failed the body check.

`sendAsync` runs the synchronous pipeline through `CompletableFuture.supplyAsync`. By default it
uses a library-owned virtual-thread-per-task executor rather than the common `ForkJoinPool`; the
builder accepts an application-owned `Executor` when bounded concurrency or a shared execution
policy is required. The HTTP transport itself remains synchronous.

For retryable responses (`429`, `5xx`), `Retry-After` overrides the exponential schedule when it
contains either delta-seconds or a valid HTTP-date. The parser accepts the three HTTP-date forms
required by RFC 9110, including RFC 850's two-digit-year rule and leap seconds, and caps the final
delay at the retry policy's maximum backoff.

## 5. Public API and extension points

### Facade

`PushSender` is the primary facade. Its builder requires exactly one VAPID key source:

- `vapid(VapidKeys)` creates `LocalEcVapidSigner`; or
- `signer(VapidSigner)` delegates signing and public-key publication.

The VAPID contact is required in both modes and must be non-blank. RFC 8292 §2.1 leaves the `sub`
claim optional; requiring it is a push2u contract, on the grounds that a push service reporting a
problem with an application server has no other channel to it. A blank value is rejected outright,
because it satisfies that contract no better than an absent claim while still producing a JWT whose
`sub` a push service may well reject — the RFC requires neither the claim nor its rejection.
Optional settings control the HTTP transport, async executor, JCE provider, retry policy, JWT
expiry, default TTL, RFC 8188 record size, the maximum encrypted body size, and the endpoint
policy. The record size and body size are validated when configured: `recordSize` must be at
least 18 (RFC 8188 §2) and `maxEncryptedBodyBytes` must be at least the fixed 103-byte overhead —
the body an empty payload produces. The endpoint policy is off by default (backward
compatibility: with no policy, any endpoint satisfying `Endpoints.requireSecure` is sent to) and
is described under its SPI below.

### VapidSigner

```java
byte[] sign(byte[] signingInput);
byte[] publicKey();
```

This SPI represents key custody. The default signer holds a private scalar in process. Vault,
KMS, or HSM implementations can keep private material outside the JVM.

`LocalEcVapidSigner` verifies its configured public/private key correspondence once at
construction by signing and verifying a fixed probe. A mismatched pair therefore fails before the
first delivery attempt.

The contract requires a raw 64-byte P-256 `r || s` ES256 signature and a 65-byte uncompressed
P-256 public point.

### PushHttpClient

```java
PushResponse post(URI endpoint, Map<String, String> headers, byte[] body);
```

This SPI allows applications to replace the JDK transport for proxy, pooling, or observability
requirements. Implementations return every HTTP status as `PushResponse` and throw
`PushDeliveryException` only for transport failures.

`PushResponse` carries only the status code and headers. Push delivery never consumes a response
body, and the endpoint is an untrusted capability URL, so the default `JdkHttpPushClient`
discards the body without buffering it — a hostile push endpoint cannot create memory pressure
by returning a huge response. This seam is push-delivery only; the Vault module has its own
transport seam (section 7) because Vault responses must be read.

### EndpointPolicy

```java
void validate(URI endpoint);
```

This SPI represents deployment egress policy for push endpoints. The endpoint in a
`Subscription` is attacker-influenced (a public registration endpoint accepts the browser's
`PushSubscription` JSON verbatim), so without a policy every send is a POST from inside the
network to an address of the subscription's choosing — a blind SSRF oracle via
`PushResult.statusCode()`, `PushDeliveryException` and timing. `Endpoints.requireSecure` stays a
protocol check (absolute `https` URL with a host); which hosts a deployment may contact is
policy, and lives here.

`EndpointPolicies.allowedOrigins` is the standard implementation: an origin allowlist compared
on the same RFC 6454 §6.1 serialization the `aud` claim uses (`Origin.serialize` normalizes both
sides, so case, default ports and IDNA form can never disagree). Malformed allowlist entries
fail at construction; endpoint-side userinfo is rejected outright. A rejection throws
`EndpointRejectedException` — extending `RuntimeException`, not `IllegalArgumentException`,
because the argument is well-formed (configuration refuses it), and because web frameworks
commonly map IAE to a 400 response that would echo the redacted-but-fingerprinted message to
the caller who registered the subscription. Rejection messages never carry the capability
path/query (`Endpoints.redact`).

A URI-level policy is a coarse filter, not a sandbox: it cannot close DNS rebinding, and
redirect behaviour belongs to the transport (the default JDK client never follows them). Strict
guarantees require resolution/egress pinning inside a `PushHttpClient` implementation.

### Deliberately concrete components

The RFC 8291 encryptor and HKDF implementation are not public SPIs. Alternative implementations
would not change intended behavior and would introduce a silent wrong-ciphertext failure mode.

JCE provider selection uses the standard `java.security.Provider` abstraction rather than a
custom SPI. The selected provider backs encryption and, for the local signer, EC key import and
ES256 signing. Native `SHA256withECDSAinP1363Format` is preferred; when the selected provider
offers only DER-output `SHA256withECDSA`, the signature is obtained from that same provider and
strictly converted to JOSE's raw `r || s` form. Provider lookup is never widened by the fallback.
External signers manage their own providers.

## 6. Cryptography

| Operation | Implementation |
|---|---|
| P-256 ECDH | `KeyAgreement("ECDH")` |
| HKDF-SHA-256 | RFC 5869 loop over `Mac("HmacSHA256")` |
| AES-128-GCM | `Cipher("AES/GCM/NoPadding")` |
| ES256 | `Signature("SHA256withECDSAinP1363Format")`, or same-provider `SHA256withECDSA` plus strict DER → `r || s` conversion |
| EC key handling | `KeyFactory("EC")`, `KeyPairGenerator("EC")` |
| Base64url | `java.util.Base64` |

The implementation supports only modern `aes128gcm` encoding and currently emits a single
RFC 8188 record. The default record size is 4096 bytes. Because a single record carries the whole
payload, `rs` must be strictly greater than the plaintext plus the padding delimiter plus the
authentication tag (RFC 8291 §4); equality is rejected. The record is not zero-padded up to `rs`,
so the body size depends only on the payload.

Key and payload arrays exposed by public value types are defensively copied. `Subscription`
redacts both the `auth` secret and the capability-bearing part of its endpoint from `toString`.
Transport and validation exceptions use the same endpoint representation: push-service origin
plus a short correlation fingerprint, never the path, query, fragment, or user information.
Applications must still treat the complete endpoint as a credential and avoid logging it directly.

## 7. Vault Transit integration

`VaultTransitVapidSigner` supports:

- **Fetched mode:** reads `latest_version` and that version's public key atomically from one
  `transit/keys/<key>` response at construction, then pins the captured version on every sign.
  The token needs `read` on the key in addition to signing permission. The key is validated as
  P-256 before the signer exists, in three independent steps: the advertised `type` must be
  `ecdsa-p256` or Vault Enterprise's `managed_key` (absent `type` is a failure); the parsed public
  key's domain parameters must match `secp256r1` by value — prime field, curve coefficients,
  generator, order, cofactor; and the key's point must satisfy `y² = x³ + ax + b (mod p)` with
  both coordinates in `[0, p)`. None of the three implies another: the metadata is only Vault's
  claim, and correct parameters say nothing about the point — the JCA validates neither, so SunEC
  accepts a key at `(1, 2)` both on import and at verification time. Coordinates are likewise
  never truncated to fit the 32-byte P-256 fields. Without this, an `ecdsa-p384` key produced a
  syntactically valid but unusable VAPID key, and the misconfiguration surfaced only as an
  unexplained push-service rejection on the first send.
- **Explicit mode:** receives the public key from configuration, permitting a sign-only token.
  Supplying the matching Transit key version pins signing to that version. The compatibility form
  without a version uses Vault's latest version and is safe only for a key that never rotates.
  The supplied key is checked structurally only (65 bytes, `0x04` tag) — neither its point nor its
  correspondence to the Transit key can be established here; both stay with the caller.

Signing uses `marshaling_algorithm=jws`, so Vault returns the raw JOSE-compatible ECDSA form. A
pinned signer also sends `key_version`; taking the version and public key from the same metadata
response closes the race where Vault rotates between reading the public key and signing. Creating
a newer Transit version therefore does not break an existing signer: it continues advertising and
using the older version as one consistent VAPID identity.

The pin remains usable only while Vault permits signing with that version. Raising
`min_encryption_version` above it or deleting it through `min_available_version` causes sign calls
to fail. Recreating a fetched signer adopts Vault's then-latest version; explicit mode instead
requires the new version and its matching public key. Either action changes the advertised VAPID
identity and must be coordinated with browser re-subscription, because Web Push subscriptions are
bound to the application-server public key used at subscribe time.

### Vault HTTP transport

The module talks to the Vault API through its own `VaultHttpTransport` seam (`get` + `post`,
returning `VaultHttpResponse`), deliberately separate from `PushHttpClient`: push delivery POSTs
to untrusted capability URLs and discards response bodies, while the Vault API is an
operator-configured service whose JSON responses must be read. Both Vault calls — the Transit
`sign` POST and the fetched mode's startup metadata GET — go through the same transport, so an
application's mTLS, proxy, or observability configuration is never bypassed.

The default `JdkVaultHttpTransport` enforces two invariants on every request:

- a per-request timeout (`HttpRequest.timeout`), because a connect timeout alone cannot end an
  exchange with a Vault that accepts the connection and never answers — in fetched mode that
  would hang application startup;
- a response-size cap counted in raw streamed bytes (a declared `Content-Length` above the cap
  fails early, but the streaming count is authoritative). Exceeding the cap fails the whole call
  — fail-closed, never truncation, because the targeted JSON extraction could still find a
  complete-looking `data.signature` before the cut.

Defaults: 10 s connect timeout, 30 s request timeout, 1 MiB response cap. Transport exception
messages carry the HTTP method and the query-less request URI, never the `X-Vault-Token` header.

The Vault Spring Boot starter exposes the same model through `push2u.signer.vault.*`: omitting
`public-key` selects fetched mode; providing `public-key` selects explicit mode, where
`key-version` should also be set whenever the Transit key can rotate. The transport is
configurable through `request-timeout`, `connect-timeout`, and `max-response-bytes`, and
replaceable with (in priority order) an application `VaultHttpTransport` bean or a
`push2uVaultHttpClient`-qualified `java.net.http.HttpClient` bean that the starter wraps with the
bound properties.

## 8. Spring Boot integration

`push2u-spring-boot-starter` binds `push2u.*` properties and conditionally creates:

- a local `VapidSigner` when both local keys are configured;
- a default `JdkHttpPushClient`;
- an autoconfigured `PushSender` when a signer is available and `push2u.vapid.subject` is set;
- a health indicator when Spring Boot health support is present.

Application beans override these defaults; in particular, an application-supplied `PushSender`
bean bypasses the `pushSender` factory method entirely, so `push2u.vapid.subject` is not required
in that case — the requirement below is specific to the *autoconfigured* sender.

`push2u.vapid.subject` (the VAPID `sub` claim) is required to build the autoconfigured
`PushSender`, including when the `VapidSigner` bean comes from another starter — the Vault Transit
signer starter supplies only key custody, not a contact address. The `pushSender` bean checks this
explicitly and fails with a message naming `push2u.vapid.subject`, rather than surfacing
`PushSender.Builder#build()`'s generic `"contact is required"`.

`push2u.record-size` and `push2u.max-encrypted-body-bytes` follow the same optional-property
pattern as `jwt-expiry` and `default-ttl`: unset (`null`) leaves the `PushSender` builder default,
set forwards the value to `Builder#recordSize(int)` / `Builder#maxEncryptedBodyBytes(int)`. Their
own validation — the RFC 8188 §2 18-byte floor for `recordSize`, checked at startup, separately
from the RFC 8291 §4 per-payload rule checked on each `send()`; and the fixed 103-byte
`aes128gcm` overhead for `maxEncryptedBodyBytes` — governs context startup; the starter re-throws
an invalid value's `IllegalArgumentException` with the YAML property name prefixed, since the
builder's own message names its camelCase parameter instead.

`push2u.allowed-origins` binds to `EndpointPolicies.allowedOrigins` and follows the same
fail-at-startup pattern: a malformed entry's `IllegalArgumentException` is re-thrown with the
property name prefixed. Alternatively an application `EndpointPolicy` bean is picked up by the
autoconfigured sender; configuring both fails the context (naming the property and the bean)
rather than silently preferring one, because they express the same security control and the
ignored one would be believed active. The one exception: an explicitly *empty* property beside a
bean cedes to the bean — the escape hatch for a service inheriting the property from shared
configuration it cannot unset — while an empty property alone still fails ("requires at least
one origin"), so the control cannot be disabled by accident. Configuring neither keeps the core
default of no endpoint policy.

`push2u-signer-vault-spring-boot-starter` is ordered before the core starter. When both are
configured, the Vault signer takes precedence over the local signer unless the application
provides its own `VapidSigner`.

## 9. Architectural decisions

### ADR-001 — Java 21 baseline

Java 21 provides every required cryptographic and HTTP primitive while remaining an LTS runtime.
The project compiles with a newer toolchain and `--release 21`.

### ADR-002 — Zero-dependency core

The core uses only JDK APIs for its implementation; the single declared dependency is the
annotation-only JSpecify jar of ADR-012. Framework and remote-system integrations remain in
optional modules.

### ADR-003 — Concrete HKDF implementation

HKDF is a small RFC 5869 implementation over JCA HMAC and is verified by RFC vectors. It is not
an extension point.

### ADR-004 — Stateless library

The application owns subscription storage and lifecycle. The library sends to a supplied
`Subscription` and reports when it has expired.

### ADR-005 — Two public SPIs in the core

Only key custody (`VapidSigner`) and push HTTP transport (`PushHttpClient`) are replaceable in
`push2u-core`. Cryptographic protocol steps stay internal. The Vault module adds its own
transport SPI (`VaultHttpTransport`) rather than reusing `PushHttpClient`: the two seams face
opposite trust domains — push delivery must not read response bodies from untrusted capability
URLs, while the Vault API's responses must be read, bounded and under a request timeout.

*Amended:* a third seam, `EndpointPolicy` (deployment egress policy for push endpoints), was
added later under the same test — an articulable difference the library cannot decide for the
deployment. Which hosts an application may POST to is deployment security policy, not protocol;
see section 5.

### ADR-006 — `aes128gcm` only

Legacy `aesgcm` is intentionally unsupported.

### ADR-007 — Expired subscription is a result

`404` and `410` map to `SUBSCRIPTION_EXPIRED`, allowing callers to remove subscriptions without
exception-driven control flow.

### ADR-008 — Apache License 2.0

The project is licensed under Apache License 2.0, including its explicit patent grant.

*Amended:* every Java source file carries the licence in its header, in the short SPDX form rather
than the full boilerplate the licence's appendix suggests:

```java
/*
 * Copyright <year> The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
```

`LICENSE` and the POM's `licenses` element already cover the distribution, so the header is not what
makes the licence apply. It is what survives a single file being copied out of the repository, and
what per-file scanners (ScanCode, FOSSA, ORT) read — without it they classify the file as
`unknown licence`, which is friction for exactly the enterprise consumer this library targets. The
SPDX identifier is machine-readable and says the same thing far more briefly than repeating the
appendix boilerplate in a hundred files.

`LICENSE` itself keeps the appendix verbatim, placeholders and all: it is the canonical Apache text,
and the appendix is an instruction for applying the licence rather than a place to assert ownership.
Filling it in was the half-measure this amendment replaces — the notice now sits in each file, which
is what the instruction asks for. Every published jar additionally carries `META-INF/LICENSE`, so an
artifact separated from its POM still states its terms — the terms, not the copyright holder, since
the canonical appendix names nobody and compiled classes carry no comments. A scanner reading the
binary jar alone therefore sees Apache-2.0 without an owner; the owner is in the POM's `developer`
entry and its `organization`, in the source jar and in every source file, which is where it is
useful. No `NOTICE` file: §4(d) would oblige every redistributor of a derivative work to reproduce
it, and that is a real obligation to place on consumers in exchange for attribution they already
have.

The year is the year the file was created, and is never advanced: a maintained copyright range
means re-touching every file each January for no legal effect, since the notice is evidence of
authorship at a date rather than a term that lapses. Spotless writes the current year into a new
file and preserves whatever it finds afterwards.

Enforcement is split because Spotless's `LicenseHeaderStep` skips `package-info.java` and
`module-info.java` by name — their leading Javadoc would otherwise be read as a stale header and
replaced. Spotless therefore owns every other file in every source set; Checkstyle carries the
`RegexpHeader` rule that covers those two file kinds, on `main` sources under the full configuration
and on the test source sets under a header-only one (the full configuration reports hundreds of
Javadoc and naming violations there, which is why it is main-only in the first place).

### ADR-009 — Standalone repository

push2u is maintained as an independent Gradle multi-project build and has no application-specific
dependencies.

### ADR-010 — Pluggable VAPID key custody

Local signing is the default. Remote signers can improve the custody boundary without changing
the send pipeline.

### ADR-011 — Size limit expressed on the encrypted body

The configurable limit is `maxEncryptedBodyBytes`, not a plaintext maximum, because RFC 8030 §7.2
constrains the entity body. The plaintext maximum (3993 bytes at the 4096-byte default) is derived
from the format's fixed overhead rather than written into the code, and `recordSize` stays an
independent parameter: raising the body limit does not silently change what the header advertises.

### ADR-012 — Nullness declared with JSpecify

Every package carries JSpecify's `@NullMarked`: a reference type in the public API is non-null
unless it is annotated `@Nullable`. The optional message headers (`PushMessage.ttl`, `urgency`,
`topic`), the unset builder fields, and the Spring properties are the annotated exceptions.

JSpecify is declared as an `api` dependency rather than `compileOnly`, so the contract reaches
consumers: NullAway, IntelliJ and the Kotlin compiler all read the same annotations. It carries
annotations and no code, so the dependency-light core of ADR-002 is unaffected in substance — a
published contract that tools can check is worth more than an absolute artefact count. A
project-local annotation would have been free of any dependency but would mean nothing outside
NullAway.

The build enforces both halves: NullAway fails on a contract violation, and Error Prone's
`RequireExplicitNullMarking` fails on a package that forgets `@NullMarked`. NullAway's full
`JSpecifyMode` (generic nullness) is deliberately not enabled yet — its authors still describe it
as evolving.

Both run over `main` **and** `testFixtures`, and stop there. `push2u-core`'s fixtures are the
published conformance kit, so their nullness contract reaches consumers exactly as the library's
does; `test` and `fipsTest` stay out, where NullAway over unannotated code reports every builder
field and nothing worth reading. The gap was not theoretical: moving the kit to its own package
(ADR-014) left it outside any `@NullMarked` and nothing failed, because a `package-info.java`
carrying no annotation does not compile to a class file at all — the omission is invisible in the
published jar rather than merely unchecked.

### ADR-013 — Release and publication process

The version is derived from git tags of the form `vX.Y.Z` by the axion-release plugin rather
than written into a build file. A tag records the release where releases actually happen — in
git history — so the build cannot disagree with it, and between releases every checkout
identifies itself as the next `X.Y.Z-SNAPSHOT` without anyone editing a version line. The
rejected alternative, a hard-coded version bumped by a "release commit", turns every release
into a source change, invites merge conflicts on that line, and lets the tag and the declared
version drift apart.

Publication goes to Maven Central through the Central Portal, with the nmcp plugin layered on
top of the standard `maven-publish` and `signing` plugins: nmcp only aggregates what
`maven-publish` produces and uploads the bundle to the Portal
(`publishAggregationToCentralPortal`, publishing mode AUTOMATIC — after the Portal's validation
passes, the deployment proceeds to Central without a manual step). The rejected alternative, an
all-in-one publishing plugin such as vanniktech's gradle-maven-publish-plugin, generates the
publications and POM from its own conventions; keeping them in the build's `maven-publish`
configuration leaves the POM content, the artifact set (jar, `-sources`, `-javadoc`) and the
signing step explicit and under the build's control.

The Maven group ID is `com.the13haven` and the Java packages are `com.the13haven.push2u.*`. Both
are anchored on `the13haven.com`, the domain the project actually owns, and each has its own
reason to be. Central verifies namespace ownership with a DNS TXT record on the exact domain the
group ID reverses to, and `push2u.io` does not belong to the project. The package name is a
separate matter — the JLS recommends a reversed domain name one owns, for the same purpose of
guaranteed uniqueness — but the original `io.push2u.*` was anchored on that same unowned domain,
which is the part that made it a squat rather than a convention.

Two alternatives were rejected. Registering `push2u.io` solely to legitimise the shorter name
ties a permanent, immutable namespace to a recurring registration fee and an expiry risk. Keeping
`io.push2u.*` alongside a `com.the13haven` group ID would also have been defensible — nothing
requires the two to match, and Guava (`com.google.guava` → `com.google.common`) and OkHttp
(`com.squareup.okhttp3` → `okhttp3`) both diverge — but it leaves the package name resting on a
domain someone else may register, and the only moment to change a package name for free is before
the first release: afterwards it is a breaking change for every adopter.

Releases are triggered manually through `workflow_dispatch`, never by a push to `main`. A
published Maven Central version is immutable — it cannot be deleted or replaced — so the
decision "this state becomes a release" deserves an explicit human action rather than being
implied by a merge. The rejected alternative, releasing on every merge to `main`, couples review
cadence to release cadence and turns any accidental merge into a permanent artifact.

### ADR-014 — JPMS: explicit modules for the library, automatic for the starters

`push2u-core` and `push2u-signer-vault` carry a `module-info.java`. The module name is the package
name — `com.the13haven.push2u` and `com.the13haven.push2u.signer.vault` — and the core's descriptor
is three lines: `requires transitive java.net.http`, `requires static org.jspecify`, one `exports`.
Nothing else is needed, because there is nothing else: the zero-dependency posture of ADR-002 is
what makes an accurate descriptor this cheap to write, and the descriptor is what makes that posture
checkable rather than merely asserted.

Both qualifiers carry weight. `java.net.http` is `transitive` because `HttpClient` is not an
implementation detail behind the default client — it is a parameter of the public
`JdkHttpPushClient(HttpClient, Duration)`, and of `JdkVaultHttpTransport` in the Vault module, so a
consumer configuring their own client would otherwise have to require the JDK module themselves.
`javac -Xlint:exports` flagged both constructors before the qualifier was added.

`requires static org.jspecify` means nothing resolves the JSpecify jar at runtime. The reason is not
annotation retention — JSpecify's annotations are `RUNTIME`-retained — but that the JVM ignores an
annotation whose type it cannot resolve. Verified by running a module-path consumer with the jar
absent, reflecting over every annotated member: empty annotation arrays, no exception.

**The eleven `[exports]` warnings that lint still reports on the core are accepted, not overlooked.**
Every one of them is `class Nullable in module org.jspecify is not indirectly exported`, and the
change lint asks for — `requires static transitive org.jspecify` — silences all eleven and breaks
every module-path consumer that does not itself ship JSpecify: `transitive` makes the module
mandatory at the consumer's compile time, and such a consumer fails with `module not found:
org.jspecify` (measured; with plain `requires static` the same consumer compiles). The annotations
are metadata for analysers, not types a caller must name, so the warning describes a problem this
API does not have. Do not "fix" it.

The two Spring Boot starters stay **automatic** modules with a fixed `Automatic-Module-Name`. Boot's
own artifacts are automatic modules, and auto-configuration works by reflecting over classes named
in `META-INF/spring/*.imports` — a relationship no descriptor can express, and one that `requires`
would misrepresent as a compile-time dependency. What the manifest attribute buys is that the module
name stops following the jar file name: without it the starter would be `push2u.spring.boot.starter`
and would change if the artifact were ever renamed.

The published conformance kit moved from `com.the13haven.push2u` to `com.the13haven.push2u.testkit`
in the same change, and it had to. A package split across two artifacts cannot be resolved from the
module path — with the kit still in the core's package, a consumer putting both on it gets
`ResolutionException: Module … contains package com.the13haven.push2u, module com.the13haven.push2u
exports package com.the13haven.push2u to …`. That was reproduced before the move, not assumed.

Timing is the whole argument for doing this now: a module name, like a package name (ADR-013), is
free to choose before the first release and a breaking change for every adopter afterwards. The same
holds for the kit's package. Without a descriptor the name would be derived from the artifact name,
which is neither stable nor ours to keep.

One tool does not follow yet. Checkstyle 13.9.0 has no grammar for a module declaration — `module
foo {}` alone fails to parse — and a single unparseable file aborts the whole task, so
`module-info.java` is excluded from the analysing configuration. The exclusion costs nothing in
substance: naming, Javadoc and import-order rules are all about type declarations. The licence
header of ADR-008 is the exception, and it is checked by `checkstyleLicenseHeader`, whose
configuration has no `TreeWalker` and so reads the descriptor as lines rather than parsing it.

## 10. Verification

The automated suite covers:

- RFC 5869 HKDF vectors;
- the RFC 8291 end-to-end encryption example;
- RFC 8292 VAPID structure and signature verification;
- the RFC 6454 §6.1 Unicode serialization of the `aud` origin — case, IDNA labels, default and
  non-default ports, address literals, userinfo (`OriginTest`);
- signer contract tests;
- the RFC 8291 §4 record-size boundary and the encrypted-body overhead (`WebPushEncryptorTest`);
- payload size limits, builder validation, and the `Integer.MAX_VALUE` boundary
  (`PushSenderPayloadSizeTest`);
- HTTP delivery, status mapping, and retry behavior;
- Spring Boot auto-configuration, including `push2u.vapid.subject`/`push2u.record-size`/
  `push2u.max-encrypted-body-bytes` wiring and diagnostics, and — reproducing the two Vault
  Spring Boot YAML examples from the README as property values — that the core and Vault Transit
  signer starters compose into a working `PushSender` (`VaultSignerAutoConfigurationTest`);
- Vault Transit integration through Testcontainers.

The standard verification commands are:

```bash
./gradlew clean build
./gradlew javadoc
```
