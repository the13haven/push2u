# push2u — Design

## 1. Status and scope

push2u is an implemented, standalone Java library for server-side Web Push delivery. Artifacts
are released to Maven Central under the `com.the13haven` group ID; the version is derived from
git tags rather than stored in the build (ADR-013). Java packages remain `io.push2u.*`.

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

## 4. Send pipeline

```text
PushSender.send(subscription, message)
    │
    ├─ Check the payload against the body limit and the record size
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

The encrypted body and VAPID token are reused across retries of the same send operation.

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
expiry, default TTL, RFC 8188 record size, and the maximum encrypted body size. The last two are
validated when configured: `recordSize` must be at least 18 (RFC 8188 §2) and
`maxEncryptedBodyBytes` must be at least the fixed 103-byte overhead — the body an empty payload
produces.

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

### ADR-006 — `aes128gcm` only

Legacy `aesgcm` is intentionally unsupported.

### ADR-007 — Expired subscription is a result

`404` and `410` map to `SUBSCRIPTION_EXPIRED`, allowing callers to remove subscriptions without
exception-driven control flow.

### ADR-008 — Apache License 2.0

The project is licensed under Apache License 2.0, including its explicit patent grant.

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

The Maven group ID is `com.the13haven`, although the Java packages remain `io.push2u.*`. Central
verifies namespace ownership with a DNS TXT record on the exact domain, and `push2u.io` does not
belong to the project — `the13haven.com` does. The rejected alternative, registering `push2u.io`
solely to claim the matching coordinate, ties a permanent, immutable namespace to a recurring
registration fee and an expiry risk. Group ID and package name answer to different authorities —
Central's ownership verification and Java's package naming — and nothing requires them to match.

Releases are triggered manually through `workflow_dispatch`, never by a push to `main`. A
published Maven Central version is immutable — it cannot be deleted or replaced — so the
decision "this state becomes a release" deserves an explicit human action rather than being
implied by a merge. The rejected alternative, releasing on every merge to `main`, couples review
cadence to release cadence and turns any accidental merge into a permanent artifact.

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
