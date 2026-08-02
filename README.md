# push2u

**push2u** (*push events to user*) is a Java library for sending
[Web Push](https://datatracker.ietf.org/doc/html/rfc8030) messages to browser push services.
It implements VAPID authentication, `aes128gcm` content encryption, HTTP delivery, retries,
and Spring Boot auto-configuration.

The project is under active development. The current version is `0.1.0-SNAPSHOT` and artifacts
are not published to Maven Central yet. The implemented architecture is described in
[`DESIGN.md`](DESIGN.md).

## Features

- Java 21 baseline.
- Zero runtime dependencies in `push2u-core`.
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

## Using the snapshot from source

Until artifacts are published, include this repository as a Gradle composite build:

```kotlin
// settings.gradle.kts
includeBuild("../push2u")
```

Then use the normal module coordinate:

```kotlin
dependencies {
    implementation("io.push2u:push2u-core:0.1.0-SNAPSHOT")
}
```

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

The contact is used as the VAPID `sub` claim and should be a `mailto:` or `https:` URI.

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
- `recordSize(int)` now throws for values below 18 instead of accepting them silently.

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

The default is `JdkHttpPushClient`, with a 30-second per-request timeout.

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
    implementation("io.push2u:push2u-spring-boot-starter:0.1.0-SNAPSHOT")
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
  retry:
    max-attempts: 3
    initial-backoff: 1s
    max-backoff: 60s
```

The starter creates a `VapidSigner`, `PushHttpClient`, and `PushSender`. Application beans of the
same types take precedence. When Spring Boot health support is present, the starter also exposes
a health indicator that verifies the configured signer can produce a 64-byte ES256 signature.

## Vault Transit signer

For plain Java, add the signer module:

```kotlin
dependencies {
    implementation("io.push2u:push2u-signer-vault:0.1.0-SNAPSHOT")
}
```

For Spring Boot, combine the core starter with the Vault signer starter. The latter already
brings in `push2u-signer-vault`:

```kotlin
dependencies {
    implementation("io.push2u:push2u-spring-boot-starter:0.1.0-SNAPSHOT")
    implementation("io.push2u:push2u-signer-vault-spring-boot-starter:0.1.0-SNAPSHOT")
}
```

### Fetched public key

The recommended configuration treats the Transit key as the single source of truth. At startup,
the signer reads `latest_version` and that version's public key from one
`transit/keys/<key>` response, then includes the captured `key_version` in every sign request.
The advertised public key therefore continues to match the signing key even when Vault creates a
new latest version. The token needs `update` on `transit/sign/<key>` and `read` on
`transit/keys/<key>`:

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
  signer:
    vault:
      address: "https://vault.example:8200"
      mount: "transit"
      key-name: "vapid"
      token: "${VAULT_TOKEN}"
```

### Explicit public key

Set `public-key` when the token must be sign-only. Also set `key-version` to the Transit version
that owns that public key, so subsequent rotations cannot make Vault sign with a different private
key:

```yaml
push2u:
  signer:
    vault:
      address: "https://vault.example:8200"
      mount: "transit"
      key-name: "vapid"
      token: "${VAULT_TOKEN}"
      public-key: "${VAPID_PUBLIC_KEY}"
      key-version: 3
```

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

The Vault key must be `ecdsa-p256`. Ordinary Vault rotation is safe for an already-running pinned
signer: it continues using the version whose public key it advertises. Raising
`min_encryption_version` above the pinned version, or removing that version with
`min_available_version`, makes Vault reject subsequent sign requests. Recover by recreating the
fetched signer, or by configuring the matching new public key and version in explicit mode.
Adopting a new VAPID public key is an application-level migration: browser subscriptions created
for the previous application-server key must be replaced.

## Protocol limits

- Only `aes128gcm` content coding is supported.
- Encryption currently uses one RFC 8188 record. The default record size is 4096 bytes; `rs`
  must be strictly greater than plaintext + 1 + 16 (RFC 8291 §4) and at least 18 (RFC 8188 §2).
- The encrypted body is capped at 4096 bytes by default (RFC 8030 §7.2), which allows 3993 bytes
  of plaintext. Both `maxEncryptedBodyBytes` and `recordSize` must be raised to send more.
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

## License

Licensed under the [Apache License 2.0](LICENSE).
