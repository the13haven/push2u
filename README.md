![push2u banner](https://raw.githubusercontent.com/the13haven/push2u/main/.github/banner.png)

[![License](https://img.shields.io/badge/License-Apache_2.0-green.svg?style=flat-square&logo=github)](https://github.com/the13haven/push2u/blob/main/LICENSE)
[![codecov](https://codecov.io/gh/the13haven/push2u/graph/badge.svg?token=3T4SIZKKLD)](https://codecov.io/gh/the13haven/push2u)
[![CodeQL](https://github.com/the13haven/push2u/actions/workflows/codeql.yml/badge.svg)](https://github.com/the13haven/push2u/actions/workflows/codeql.yml)
[![Maven Central](https://img.shields.io/maven-central/v/com.the13haven/push2u-core)](https://central.sonatype.com/artifact/com.the13haven/push2u-core)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fthe13haven%2Fpush2u.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fthe13haven%2Fpush2u?ref=badge_shield)

# push2u

**push2u** (*push events to user*) is a Java library for sending
[Web Push](https://datatracker.ietf.org/doc/html/rfc8030) messages to browser push services.
It implements VAPID authentication, `aes128gcm` content encryption, HTTP delivery, retries,
and Spring Boot auto-configuration.

Releases are published to Maven Central under the `com.the13haven` group ID. The version is
derived from git tags of the form `vX.Y.Z`; between releases the build identifies itself as the
next `X.Y.Z-SNAPSHOT`. The first release has not been tagged yet — until it appears on Maven
Central, use the [composite build](#developing-against-unpublished-changes) described below. The
implemented architecture is described in [`DESIGN.md`](DESIGN.md).

## Features

- Java 21 baseline.
- Zero runtime *implementation* dependencies in `push2u-core`: the only artefact it brings along is
  [JSpecify](https://jspecify.dev), an annotation-only jar carrying the nullness contract
  (`@NullMarked` / `@Nullable`) that the API is verified against.
- RFC 8291 / RFC 8188 payload encryption using JDK cryptography.
- RFC 8292 VAPID authentication with a local EC key or an external signer.
- JDK `HttpClient` transport, with a small transport SPI for replacements.
- Normal result handling for expired subscriptions (`404` / `410`).
- Configurable retry policy for `429` and `5xx` responses.
- Optional HashiCorp Vault Transit signer.
- Optional Spring Boot 4 auto-configuration and health indicator.

## Modules

| Module | Purpose |
|---|---|
| `push2u-core` | Domain types, encryption, VAPID, retry logic, `PushSender`, local signer, and JDK HTTP transport |
| `push2u-signer-vault` | `VapidSigner` backed by HashiCorp Vault Transit |
| `push2u-spring-boot-starter` | Spring Boot auto-configuration for `PushSender` and optional health indicator |
| `push2u-signer-vault-spring-boot-starter` | Spring Boot auto-configuration for the Vault Transit signer |

## Requirements

- Java 21 or newer at runtime.
- A VAPID P-256 key pair, or an implementation of `VapidSigner`.
- An HTTPS Web Push subscription endpoint containing the browser-provided `p256dh` and `auth`
  values.

The build uses a JDK 26 toolchain with `--release 21`. Run it with the included Gradle wrapper.

## Installation

Add the core module from Maven Central:

```kotlin
dependencies {
    implementation("com.the13haven:push2u-core:0.1.0")
}
```

The Spring Boot starters and the Vault signer module use the same group ID and version; the
sections below show which module each integration needs.

### Developing against unpublished changes

To build against changes that have not been released yet, include this repository as a Gradle
composite build:

```kotlin
// settings.gradle.kts
includeBuild("../push2u")
```

The dependency declarations stay exactly as above — Gradle substitutes the included build for
the published Maven Central artifact.

## Core usage

### Create a subscription

The browser supplies the endpoint, `p256dh`, and `auth` values. JSON parsing remains an
application responsibility:

```java
Subscription subscription = Subscription.fromBase64(
    browserSubscription.endpoint(),
    browserSubscription.p256dh(),
    browserSubscription.auth());
```

Use only the HTTPS endpoint returned by the browser. Treat the complete endpoint as a secret:
Web Push endpoints are capability URLs.

### Create a sender with a local VAPID key

`VapidKeys.fromBase64` expects a 65-byte uncompressed P-256 public key and a 32-byte private
scalar, both encoded as unpadded base64url:

```java
PushSender sender = PushSender.builder()
    .vapid(VapidKeys.fromBase64(vapidPublicKey, vapidPrivateKey))
    .contact("mailto:ops@example.com")
    .build();
```

The contact is used as the VAPID `sub` claim and should be a `mailto:` or `https:` URI. RFC 8292
§2.1 leaves `sub` optional; push2u requires it, because a push service with a problem to report
about your application server has no other way to reach you. `build()` therefore throws
`IllegalStateException` for a `null` or whitespace-only contact.

### Send a message

```java
PushMessage message = PushMessage.builder(payloadBytes)
    .ttl(Duration.ofHours(1))
    .urgency(Urgency.NORMAL)
    .topic("account_update")
    .build();

PushResult result = sender.send(subscription, message);

if (result.delivered()) {
    // The push service accepted the message.
} else if (result.isSubscriptionExpired()) {
    subscriptionStore.delete(subscription);
} else {
    log.warn("Push rejected: HTTP {}, attempts={}",
        result.statusCode(), result.attempts());
}
```

When present, `topic` is validated locally before transport: it must contain 1–32 characters
from the URL-safe Base64 alphabet (`A-Z`, `a-z`, `0-9`, `-`, `_`) required by RFC 8030.

`404` and `410` are returned as `SUBSCRIPTION_EXPIRED`, not as exceptions. Transport failures
throw `PushDeliveryException`; cryptographic failures throw `PushCryptoException`.

`sendAsync(subscription, message)` returns a `CompletableFuture<PushResult>`. The blocking send
pipeline runs on a library-owned virtual-thread-per-task executor by default, never on the common
`ForkJoinPool`. Applications that need admission control or a shared execution policy can provide
their own executor:

```java
PushSender sender = PushSender.builder()
    .vapid(keys)
    .contact("mailto:ops@example.com")
    .executor(pushExecutor)
    .build();
```

The supplied executor remains application-owned; `PushSender` does not shut it down.

### Payload size limits

RFC 8030 §7.2 allows a push service to refuse an entity body larger than 4096 bytes, so
`PushSender` caps the encrypted body at 4096 bytes by default and rejects an oversized message
with `IllegalArgumentException` before encrypting it or contacting the push service.

The single-record `aes128gcm` body adds a fixed 103 bytes to the plaintext: the 86-byte RFC 8188
header (16 salt, 4 `rs`, 1 `idlen`, 65 `keyid`), the padding delimiter (1) and the AES-GCM
authentication tag (16). The default therefore admits **3993 bytes of plaintext**, the figure
RFC 8291 §4 derives.

```java
PushSender sender = PushSender.builder()
    .vapid(keys)
    .contact("mailto:ops@example.com")
    .maxEncryptedBodyBytes(8192)  // the endpoint is known to accept a larger body
    .recordSize(8192)             // rs must cover the payload as well
    .build();
```

Raise `maxEncryptedBodyBytes` only for endpoints documented or configured to accept more than
4096 bytes — a self-hosted or intra-organisation push service, for example. RFC 8030 §7.2 only
requires a push service to accept 4096 bytes; beyond that a service may answer with `413`.

`recordSize` is a separate protocol parameter and is never adjusted to follow the body limit.
RFC 8291 §4 requires `rs` to be *strictly greater* than the plaintext plus the padding delimiter
(1) plus the authentication tag (16), so a payload that outgrows the configured `rs` is rejected
with a message naming the minimum `rs` it needs. RFC 8188 §2 makes any `rs` below 18 invalid, and
the builder rejects such values outright.

**Behaviour change.** These limits reject configurations and payloads that earlier versions
accepted:

- a payload of 3994–4079 bytes (4079 being the largest the old, off-by-one record-size check
  admitted at the default `rs`) was previously encrypted and sent as a body of up to 4182 bytes;
  it now throws `IllegalArgumentException` before the request is built;
- `recordSize` exactly equal to plaintext + 1 + 16 was previously accepted, in violation of the
  RFC 8291 §4 `MUST`; it is now rejected;
- `recordSize(int)` now throws for values below 18 instead of accepting them silently;
- `.contact("   ")` (or any whitespace-only value) previously built a `PushSender` that would
  issue a VAPID JWT with a blank `sub` claim; `build()` now rejects it with the same
  `IllegalStateException` as a missing contact.

### Retry behavior

The default policy makes up to three attempts. Backoff starts at one second, doubles after each
retry, and is capped at 60 seconds. On retryable responses (`429` and `5xx`), a valid
`Retry-After` value overrides the computed delay and is capped by the same maximum. Both
delta-seconds and all HTTP-date forms required by RFC 9110 are accepted; malformed or overflowing
values fall back to the exponential schedule.

```java
PushSender sender = PushSender.builder()
    .vapid(keys)
    .contact("mailto:ops@example.com")
    .retryPolicy(new RetryPolicy(
        5,
        Duration.ofMillis(500),
        Duration.ofSeconds(30)))
    .build();
```

Use `RetryPolicy.none()` to disable retries.

### Custom HTTP transport

Implement `PushHttpClient` when the application needs a different HTTP stack, proxy policy, or
observability integration:

```java
PushSender sender = PushSender.builder()
    .vapid(keys)
    .contact("mailto:ops@example.com")
    .httpClient(customPushHttpClient)
    .build();
```

The default is `JdkHttpPushClient`, with a 30-second per-request timeout. Push delivery never
reads the response body: `PushResponse` carries only the status code and headers, and
`JdkHttpPushClient` discards the body without buffering it, because the endpoint is a capability
URL taken from the (untrusted) subscription and a hostile server must not be able to feed the
sender an arbitrarily large response. Custom implementations should do the same.

This seam covers push delivery only. The Vault signer module has its own transport seam
(`VaultHttpTransport`, below) because the Vault API sits in a different trust domain and its
responses must be read.

### Endpoint policy (SSRF hardening)

The endpoint inside a `Subscription` is attacker-influenced data: a typical integration accepts
the browser's `PushSubscription` JSON at a public registration endpoint, and nothing stops a
client from posting a hand-crafted subscription whose endpoint points into your own network — a
loopback port, a private-range address, a cloud metadata service. Every later send then POSTs to
that address from inside your network, and the visible outcome (`PushResult.statusCode()` versus
`PushDeliveryException`, plus timing) is a blind SSRF oracle for internal host and port
existence.

Restrict where a sender may POST with an endpoint policy — for almost every deployment, an
origin allowlist naming the browser push services its users can actually arrive from:

```java
PushSender sender = PushSender.builder()
    .vapid(keys)
    .contact("mailto:ops@example.com")
    .endpointPolicy(EndpointPolicies.allowedOrigins(
        "https://fcm.googleapis.com",           // Chrome
        "https://updates.push.services.mozilla.com", // Firefox
        "https://web.push.apple.com"))          // Safari
    .build();
```

The policy runs on every send — `sendAsync` included, it goes through the same pipeline —
before encryption, before the VAPID signature (a remote Vault/KMS call under an external
signer), and before any network I/O. A rejected endpoint throws `EndpointRejectedException`
and costs none of them. The exception extends `RuntimeException` directly (deliberately not
`IllegalArgumentException`, which web frameworks commonly map to a 400 response echoing the
message), so a loop over stored subscriptions can tell "this subscription violates policy —
flag or remove it" apart from a retryable transport failure (`PushDeliveryException`); its
message never contains the endpoint's path or query, because a push endpoint is a capability
URL.

Origins compare after RFC 6454 normalization on both sides — lowercase scheme and host, IDNA
A-labels decoded, the default `:443` dropped — so `https://PUSH.Example:443` in the
configuration matches an endpoint on `https://push.example`. Matching is exact and fail-closed:
subdomains of an allowed origin are not allowed, a host with a trailing dot (`push.example.`) is
a different origin from `push.example` and is rejected, and an endpoint carrying userinfo
(`https://allowed.example@evil.example/…`) is rejected outright — no push service issues such
endpoints, and rejecting the shape also protects custom transports that re-parse the URL string
differently. A malformed allowlist entry (unparseable, non-`https`, hostless, or carrying a
path/query/fragment/userinfo) fails at construction, so a misconfigured allowlist fails
deployment startup instead of misbehaving at send time.

`EndpointPolicy` itself is a functional interface (`void validate(URI endpoint)`), so corporate
egress rules or custom DNS checks can be expressed directly. The policy is fixed when the sender
is built and receives only the URI — a rule that varies by tenant means one sender per tenant.

With no policy configured, behaviour is unchanged: any absolute `https` endpoint accepted by
`Subscription` is sent to. Know the limits either way: a URI-level check cannot close DNS
rebinding, and it cannot see what happens after the connection. Redirects are not followed by
the default transport (the JDK client's policy is `NEVER`), but a custom `PushHttpClient` must
preserve that itself. Strict guarantees require pinning resolution and egress in the transport
layer — see the
[OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).
The policy is a coarse filter, not a sandbox.

### JCE provider selection

By default, cryptographic primitives resolve through the JVM provider chain. Passing a provider
binds the encryption primitives and, when the local signer is used, EC key import and ES256
signing to that provider:

```java
PushSender sender = PushSender.builder()
    .vapid(keys)
    .contact("mailto:ops@example.com")
    .cryptoProvider(provider)
    .build();
```

The provider must support EC key generation/import, ECDH, HMAC-SHA-256, AES-GCM, and an ES256
signature form when `LocalEcVapidSigner` is used. The library prefers
`SHA256withECDSAinP1363Format`; if the selected provider exposes only DER-output
`SHA256withECDSA` (as BC-FIPS does), it signs with that algorithm on the same provider and strictly
re-encodes the result to JOSE's 64-byte `r || s` form. The fallback never widens provider lookup.
An external `VapidSigner` controls its own signing provider.

`LocalEcVapidSigner` also performs a one-time sign-and-verify self-test when it is constructed.
A public key that does not correspond to the configured private scalar is therefore rejected at
startup instead of producing repeated `401`/`403` responses at send time.

## Spring Boot

Add the core starter:

```kotlin
dependencies {
    implementation("com.the13haven:push2u-spring-boot-starter:0.1.0")
}
```

Configure a local VAPID signer:

```yaml
push2u:
  vapid:
    public-key: "${VAPID_PUBLIC_KEY}"
    private-key: "${VAPID_PRIVATE_KEY}"
    subject: "mailto:ops@example.com"
  jwt-expiry: 12h
  default-ttl: 24h
  record-size: 4096                 # defaults, shown for reference
  max-encrypted-body-bytes: 4096    # defaults, shown for reference
  allowed-origins:                  # optional but recommended — see Endpoint policy above
    - "https://fcm.googleapis.com"
    - "https://updates.push.services.mozilla.com"
    - "https://web.push.apple.com"
  retry:
    max-attempts: 3
    initial-backoff: 1s
    max-backoff: 60s
```

The starter creates a `VapidSigner`, `PushHttpClient`, and `PushSender`. Application beans of the
same types take precedence. When Spring Boot health support is present, the starter also exposes
a health indicator that verifies the configured signer can produce a 64-byte ES256 signature.

`push2u.vapid.subject` is required to build the *autoconfigured* `PushSender`, regardless of where
the `VapidSigner` comes from; leaving it unset fails the context with a message naming the
property. It is not required when the application supplies its own `PushSender` bean — that bean
bypasses the starter's checks entirely.

`record-size` and `max-encrypted-body-bytes` are optional; unset, they leave `PushSender`'s
defaults (4096 bytes each — see [Payload size limits](#payload-size-limits)) untouched. Setting
either to a value the builder rejects (`record-size` below 18, or `max-encrypted-body-bytes` below
the fixed 103-byte `aes128gcm` overhead) fails the context with the builder's message,
prefixed with the YAML property name (the builder itself only names its Java parameter).

`allowed-origins` binds to `EndpointPolicies.allowedOrigins` — see
[Endpoint policy (SSRF hardening)](#endpoint-policy-ssrf-hardening). Unset, it leaves the
`PushSender` default of no endpoint policy. A malformed entry fails the context with the message
prefixed by the property name, like the size properties. Alternatively, supply an
`EndpointPolicy` bean, which the autoconfigured sender picks up; configuring *both* the property
and a bean fails the context, naming the property and the bean — they express the same security
control, and silently preferring one would leave the other believed-active but ignored.

One escape hatch: a service that *inherits* `push2u.allowed-origins` from a shared configuration
it does not own cannot unset the property, so setting it to an explicitly **empty** value beside
a bean means "deliberately not using the property here" and the bean wins. An empty value on its
own still fails the context (`requires at least one origin`), so the control cannot be disabled
by accident.

## Vault Transit signer

For plain Java, add the signer module:

```kotlin
dependencies {
    implementation("com.the13haven:push2u-signer-vault:0.1.0")
}
```

For Spring Boot, combine the core starter with the Vault signer starter. The latter already
brings in `push2u-signer-vault`:

```kotlin
dependencies {
    implementation("com.the13haven:push2u-spring-boot-starter:0.1.0")
    implementation("com.the13haven:push2u-signer-vault-spring-boot-starter:0.1.0")
}
```

### Fetched public key

The recommended configuration treats the Transit key as the single source of truth. At startup,
the signer reads `latest_version` and that version's public key from one
`transit/keys/<key>` response, then includes the captured `key_version` in every sign request.
The advertised public key therefore continues to match the signing key even when Vault creates a
new latest version. The token needs `update` on `transit/sign/<key>` and `read` on
`transit/keys/<key>`.

The fetched key is validated as P-256 before the signer is created: the response's `type` must be
`ecdsa-p256` (a missing `type` is a failure too), the parsed public key must carry P-256's domain
parameters, and its point must satisfy the curve equation — the JCA checks none of this on its
own. A key of another type or curve — `ecdsa-p384`, for instance — fails startup with a
`PushCryptoException` instead of producing a VAPID key that every push service rejects later.

Vault Enterprise reports HSM/KMS-backed keys as `type: managed_key`, which describes the wrapper
rather than the curve; that value is therefore also accepted and the key is admitted only if the
curve checks pass. This path has not been exercised against a real Vault Enterprise.

```java
VapidSigner signer = new VaultTransitVapidSigner(
    URI.create("https://vault.example:8200"),
    "transit",
    "vapid",
    vaultToken);
```

The equivalent Spring Boot configuration is:

```yaml
push2u:
  vapid:
    subject: "mailto:ops@example.com"
  signer:
    vault:
      address: "https://vault.example:8200"
      mount: "transit"
      key-name: "vapid"
      token: "${VAULT_TOKEN}"
```

The Vault signer starter only supplies the `VapidSigner` (key custody); it does not know the
application's contact address. `push2u.vapid.subject` therefore still comes from the core starter's
properties — it is the VAPID `sub` claim, which push2u requires even though RFC 8292 §2.1 leaves
it optional, and `Push2uAutoConfiguration` fails startup with a message naming this property if
it is left unset.

### Explicit public key

Set `public-key` when the token must be sign-only. Also set `key-version` to the Transit version
that owns that public key, so subsequent rotations cannot make Vault sign with a different private
key:

```yaml
push2u:
  vapid:
    subject: "mailto:ops@example.com"
  signer:
    vault:
      address: "https://vault.example:8200"
      mount: "transit"
      key-name: "vapid"
      token: "${VAULT_TOKEN}"
      public-key: "${VAPID_PUBLIC_KEY}"
      key-version: 3
```

As above, `push2u.vapid.subject` (the VAPID `sub` claim) comes from the core starter, not the Vault
signer starter — it must be set here too.

The equivalent plain-Java constructor takes the version after the public key:

```java
VapidSigner signer = new VaultTransitVapidSigner(
    URI.create("https://vault.example:8200"),
    "transit",
    "vapid",
    vaultToken,
    publicKeyBytes,
    3);
```

The explicit constructor/property form without a version is retained for compatibility, but it
sends no `key_version`; Vault then signs with its latest version. Use that form only when the
Transit key is guaranteed never to rotate.

An explicitly supplied `public-key` is checked structurally only — 65 bytes with the `0x04`
uncompressed tag. It is not verified to be a point on P-256, and nothing can check here that it is
the public half of the Transit key being signed with; both remain the caller's responsibility. The
P-256 validation described under *Fetched public key* applies to that mode alone.

### Vault HTTP transport

All Vault calls — the Transit `sign` POST and, in fetched mode, the startup `transit/keys/<key>`
GET — go through the module's `VaultHttpTransport` seam. The default `JdkVaultHttpTransport`
(JDK `java.net.http`) enforces a per-request timeout on every call (a Vault that accepts the
connection but never answers cannot hang application startup) and a fail-closed response-size cap
counted in raw streamed bytes (an oversized response fails the call; it is never truncated).
Defaults: 10 s connect timeout, 30 s request timeout, 1 MiB cap.

The starter exposes these as properties:

```yaml
push2u:
  signer:
    vault:
      # ... address, key-name, token ...
      request-timeout: 30s      # per-request timeout, every Vault call
      connect-timeout: 10s      # connect timeout of the default HTTP client
      max-response-bytes: 1048576
```

Resolution order (two extension points, plus the properties-only fallback):

1. A `VaultHttpTransport` bean — full control (custom HTTP stack, observability). The transport
   properties above are then ignored; the bean owns those concerns.
2. A `java.net.http.HttpClient` bean qualified `push2uVaultHttpClient` — the middle road for
   mTLS/proxy setups. The starter wraps it in a `JdkVaultHttpTransport` with the configured
   `request-timeout` and `max-response-bytes` (`connect-timeout` is ignored; the supplied client
   owns it).
3. Otherwise the default transport is built entirely from the properties.

The qualifier keeps the Vault client separate from any push-delivery `HttpClient` bean: push
transport (`PushHttpClient`) and Vault transport are deliberately independent seams.

The Vault key must be `ecdsa-p256`; the fetched mode verifies this at construction (see *Fetched
public key* above). Ordinary Vault rotation is safe for an already-running pinned signer: it
continues using the version whose public key it advertises. Raising `min_encryption_version` above
the pinned version, or removing that version with `min_available_version`, makes Vault reject
subsequent sign requests. Recover by recreating the fetched signer, or by configuring the matching
new public key and version in explicit mode. Adopting a new VAPID public key is an
application-level migration: browser subscriptions created for the previous application-server key
must be replaced.

## Protocol limits

- Only `aes128gcm` content coding is supported.
- Encryption currently uses one RFC 8188 record. The default record size is 4096 bytes; `rs`
  must be strictly greater than plaintext + 1 + 16 (RFC 8291 §4) and at least 18 (RFC 8188 §2)
  (`push2u.record-size` in the starter).
- The encrypted body is capped at 4096 bytes by default (RFC 8030 §7.2), which allows 3993 bytes
  of plaintext. Both `maxEncryptedBodyBytes` and `recordSize` must be raised to send more
  (`push2u.max-encrypted-body-bytes` / `push2u.record-size` in the starter).
- `PushMessage.topic`, when set, must contain at most 32 URL- and filename-safe base64
  characters as required by RFC 8030.
- VAPID JWT expiry must be greater than zero and no more than 24 hours.
- The library is stateless; subscription persistence and deletion belong to the application.

## Build and test

```bash
./gradlew clean build
./gradlew javadoc
```

The test suite includes RFC 5869, RFC 8291, and RFC 8292 vectors, sender/retry tests, Spring Boot
auto-configuration tests, and a Vault Transit integration contract.

## Nullness

Every package is [JSpecify](https://jspecify.dev) `@NullMarked`: a reference type in the API is
non-null unless annotated `@Nullable`. The annotated exceptions are the optional message headers
(`PushMessage.ttl` / `urgency` / `topic`), the unset builder fields and the Spring properties.

The contract is machine-checked, not just documented — NullAway fails the build on a violation, and
`RequireExplicitNullMarking` fails it on a package that forgets the mark. Because JSpecify is an
`api` dependency, the same annotations are visible to consumers' analysers, IntelliJ and the Kotlin
compiler.

## Quality checks

Static analysis and coverage are wired up as their own lifecycle tasks, so `build` stays compile +
test only:

```bash
./gradlew qualityCheck     # local: formats the code, then runs every analyser
./gradlew qualityCheckCi   # CI: verifies formatting instead of applying it
```

| Tool                 | What it enforces                                            | Configuration                                |
|----------------------|-------------------------------------------------------------|----------------------------------------------|
| Spotless             | Palantir Java Format, import order                           | `build-logic/.../push2u-quality.gradle.kts`  |
| Checkstyle           | Naming, Javadoc on the public API, import grouping           | `config/quality/checkstyle/checkstyle.xml`   |
| PMD                  | Best practices, design, error-prone patterns, performance    | `config/quality/pmd/ruleset.xml`             |
| SpotBugs             | Bytecode-level bug patterns                                  | `config/quality/spotbugs/exclusions.xml`     |
| Error Prone + NullAway | Compiler-attached checks; a named set and the nullness contract fail the build | `build-logic/.../push2u-quality.gradle.kts` |
| JaCoCo               | Aggregated coverage, minimum 80% of instructions             | `build.gradle.kts`                           |

Checkstyle, PMD and SpotBugs run on `main` sources only — test code is exempt. Error Prone covers
the test compilations as well, since its checks are about defects rather than style; NullAway runs
on `main` only, where the API contract lives. Reports land in
`<module>/build/reports/` (HTML and XML); the aggregated coverage report is in
`build/reports/jacoco/testCodeCoverageReport/`.

Rule exclusions carry a comment stating why, and a per-file exception is a `@SuppressWarnings`
("PMD.<Rule>") at the narrowest scope that covers it, next to the reason.

`./gradlew aggregateTestResults` collects the JUnit XML of every module — `push2u-core`'s
`fipsTest` suite included — into `build/test-results-aggregated/`. CI runs it after the quality
check and hands that directory, plus the aggregated JaCoCo XML, to Codecov.

## Releases

Releases are cut manually from GitHub Actions: the *Release* workflow runs the full quality
gate, tags the version, publishes signed artifacts to Maven Central through the Central Portal,
and creates a GitHub Release with generated notes. The step-by-step procedure, the required
repository secrets, and the one-time publishing setup are documented in
[`RELEASING.md`](RELEASING.md).

## License

Licensed under the [Apache License 2.0](LICENSE).

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fthe13haven%2Fpush2u.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fthe13haven%2Fpush2u?ref=badge_large)
