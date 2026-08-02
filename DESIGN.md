# push2u — Design

## 1. Status and scope

push2u is an implemented, standalone Java library for server-side Web Push delivery. The current
version is `0.1.0-SNAPSHOT`; artifacts are not yet published to Maven Central.

The library implements:

- RFC 8030 push delivery and response interpretation;
- RFC 8291 message encryption;
- RFC 8292 VAPID authentication;
- RFC 8188 `aes128gcm` content coding;
- RFC 5869 HKDF-SHA-256;
- local and Vault Transit VAPID signing;
- plain Java and Spring Boot integration.

The architecture keeps the protocol core dependency-free and exposes narrow seams only where
applications have a legitimate reason to replace behavior.

## 2. Goals and non-goals

### Goals

- Zero runtime dependencies in `push2u-core`.
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
└── VaultTransitVapidSigner

push2u-spring-boot-starter
├── PushSender auto-configuration
└── optional signer health indicator

push2u-signer-vault-spring-boot-starter
└── Vault signer properties and auto-configuration
```

`push2u-core` has no runtime dependencies. The Spring Boot modules and Vault integration are
opt-in and cannot leak framework types into the core API.

## 4. Send pipeline

```text
PushSender.send(subscription, message)
    │
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

The VAPID contact is required in both modes. Optional settings control the HTTP transport, async
executor, JCE provider, retry policy, JWT expiry, default TTL, and RFC 8188 record size.

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
RFC 8188 record. The default record size is 4096 bytes.

Key and payload arrays exposed by public value types are defensively copied. `Subscription`
redacts both the `auth` secret and the capability-bearing part of its endpoint from `toString`.
Transport and validation exceptions use the same endpoint representation: push-service origin
plus a short correlation fingerprint, never the path, query, fragment, or user information.
Applications must still treat the complete endpoint as a credential and avoid logging it directly.

## 7. Vault Transit integration

`VaultTransitVapidSigner` supports:

- **Fetched mode:** reads `latest_version` and that version's public key atomically from one
  `transit/keys/<key>` response at construction, then pins the captured version on every sign.
  The token needs `read` on the key in addition to signing permission.
- **Explicit mode:** receives the public key from configuration, permitting a sign-only token.
  Supplying the matching Transit key version pins signing to that version. The compatibility form
  without a version uses Vault's latest version and is safe only for a key that never rotates.

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

The Vault Spring Boot starter exposes the same model through `push2u.signer.vault.*`: omitting
`public-key` selects fetched mode; providing `public-key` selects explicit mode, where
`key-version` should also be set whenever the Transit key can rotate.

## 8. Spring Boot integration

`push2u-spring-boot-starter` binds `push2u.*` properties and conditionally creates:

- a local `VapidSigner` when both local keys are configured;
- a default `JdkHttpPushClient`;
- a `PushSender` when a signer is available;
- a health indicator when Spring Boot health support is present.

Application beans override these defaults.

`push2u-signer-vault-spring-boot-starter` is ordered before the core starter. When both are
configured, the Vault signer takes precedence over the local signer unless the application
provides its own `VapidSigner`.

## 9. Architectural decisions

### ADR-001 — Java 21 baseline

Java 21 provides every required cryptographic and HTTP primitive while remaining an LTS runtime.
The project compiles with a newer toolchain and `--release 21`.

### ADR-002 — Zero-dependency core

The core uses only JDK APIs. Framework and remote-system integrations remain in optional modules.

### ADR-003 — Concrete HKDF implementation

HKDF is a small RFC 5869 implementation over JCA HMAC and is verified by RFC vectors. It is not
an extension point.

### ADR-004 — Stateless library

The application owns subscription storage and lifecycle. The library sends to a supplied
`Subscription` and reports when it has expired.

### ADR-005 — Two public SPIs

Only key custody (`VapidSigner`) and HTTP transport (`PushHttpClient`) are replaceable.
Cryptographic protocol steps stay internal.

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

## 10. Verification

The automated suite covers:

- RFC 5869 HKDF vectors;
- the RFC 8291 end-to-end encryption example;
- RFC 8292 VAPID structure and signature verification;
- signer contract tests;
- HTTP delivery, status mapping, and retry behavior;
- Spring Boot auto-configuration;
- Vault Transit integration through Testcontainers.

The standard verification commands are:

```bash
./gradlew clean build
./gradlew javadoc
```
