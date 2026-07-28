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

`404` and `410` are returned as `SUBSCRIPTION_EXPIRED`, not as exceptions. Transport failures
throw `PushDeliveryException`; cryptographic failures throw `PushCryptoException`.

`sendAsync(subscription, message)` returns a `CompletableFuture<PushResult>`. The current
implementation runs the blocking send pipeline on the common `ForkJoinPool`.

### Retry behavior

The default policy makes up to three attempts. Backoff starts at one second, doubles after each
retry, and is capped at 60 seconds. A numeric `Retry-After` value on a `429` response overrides
the computed delay.

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

The provider must support EC key generation/import, ECDH, HMAC-SHA-256, AES-GCM, and
`SHA256withECDSAinP1363Format` when `LocalEcVapidSigner` is used. An external `VapidSigner`
controls its own signing provider.

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

The recommended configuration reads the public key from Vault at startup. The token needs
`update` on `transit/sign/<key>` and `read` on `transit/keys/<key>`:

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

Set `public-key` when the token must be sign-only:

```yaml
push2u:
  signer:
    vault:
      address: "https://vault.example:8200"
      mount: "transit"
      key-name: "vapid"
      token: "${VAULT_TOKEN}"
      public-key: "${VAPID_PUBLIC_KEY}"
```

The Vault key must be `ecdsa-p256`. The signer caches the advertised public key at construction,
while Vault signs with its active key version. Do not rotate that Transit key independently of
the application and browser subscriptions: VAPID subscriptions are bound to the public key used
when they were created.

## Protocol limits

- Only `aes128gcm` content coding is supported.
- Encryption currently uses one RFC 8188 record. The default record size is 4096 bytes.
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
