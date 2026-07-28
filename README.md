# push2u

**push2u** (*push events to user*) — a small, zero-dependency JVM library for the
[Web Push protocol](https://datatracker.ietf.org/doc/html/rfc8030): VAPID-authenticated,
end-to-end-encrypted delivery of push messages to browsers (FCM / Mozilla autopush / Apple
Web Push) from a Java application server.

> **Status: design / early development.** No published artifact yet. The architecture and the
> public API shape live in [`DESIGN.md`](DESIGN.md); the phased build plan is in
> [`ROADMAP.md`](ROADMAP.md). The snippets below describe the *target* API.

## Why

The de-facto JVM library, `nl.martijndwars:web-push`, is effectively unmaintained and drags an
EOL transitive surface (Apache HttpClient 4.x, jose4j, BouncyCastle) that leaks through its
public API. On a modern JDK every primitive Web Push needs — ECDH, HKDF, AES-128-GCM, ES256 —
is a platform primitive, so push2u's `core` ships with **zero runtime dependencies** (baseline
Java 21). See [`DESIGN.md`](DESIGN.md) §1, §4.

## Usage

`push2u-core` is batteries-included — one dependency sends out of the box with a local, in-JVM
VAPID signer and the JDK `HttpClient`:

```java
// Default: VAPID key pair held locally, signed in-JVM (LocalEcVapidSigner),
// transport = java.net.http.HttpClient.
PushSender pusher = PushSender.builder()
    .vapid(VapidKeys.fromBase64(publicKey, privateKey))
    .contact("mailto:ops@example.com")
    .build();

PushResult result = pusher.send(
    subscription,                                  // endpoint + p256dh + auth (from the browser)
    PushMessage.of(payloadBytes).ttl(Duration.ofHours(1)));

if (result.isSubscriptionExpired()) {              // 404 / 410 — a normal result, not an exception
    subscriptionStore.delete(subscription);        // your store; push2u is stateless
}
```

Override only what you need — absence is the default (no `withDefaultX()` ceremony):

```java
PushSender pusher = PushSender.builder()
    .vapid(VapidKeys.fromBase64(publicKey, privateKey))
    .contact("mailto:ops@example.com")
    .httpClient(new OkHttpPushClient(myOkHttpClient))   // default: JdkHttpPushClient
    .build();
```

For a key that must never touch the JVM heap, pass a remote signer instead of `.vapid(...)` —
Vault Transit signs internally, so the signer holds no private key and supplies the VAPID public
key itself; the key-pair argument is omitted:

```java
PushSender pusher = PushSender.builder()
    // Fetched mode: the signer reads its own public key from transit/keys/<key> at startup, so the
    // Vault Transit key is the single source of truth (token needs `sign` + `read` on the key).
    .signer(new VaultTransitVapidSigner(
        URI.create("https://vault.example:8200"), "transit", "vapid", vaultToken))  // push2u-signer-vault
    .contact("mailto:ops@example.com")
    .build();
```

The signer has two modes. **Fetched** (above) keeps the Transit key the single source of truth —
the published public key can never drift from the signing key, even across rotation. **Explicit**
passes the public key yourself, so the token needs only `sign` (no `read`) — useful for a strict
sign-only token or an air-gapped public key:

```java
// publicKeyBytes = the 65-byte X9.62 uncompressed P-256 point
.signer(new VaultTransitVapidSigner(
    URI.create("https://vault.example:8200"), "transit", "vapid", vaultToken, publicKeyBytes))
```

The Spring Boot starter (`push2u-signer-vault-spring-boot-starter`) exposes the same choice via
`push2u.signer.vault.*`: set `address` / `key-name` / `token` for fetched mode, and add
`public-key` (base64url) to switch to explicit mode.

Exactly one key source is required (`.vapid(...)` **or** `.signer(...)`); `.contact(...)` is
required in both. `build()` throws if that invariant is violated.

## BouncyCastle (FIPS / constrained JVMs)

push2u's `core` uses the JDK's built-in JCE providers (SunEC / SunJCE) for every crypto
primitive, which is what you want almost everywhere. Two situations call for BouncyCastle
instead:

- **FIPS compliance** — the stock Sun providers are not FIPS-validated; a regulated deployment
  must route crypto through a validated module (`bc-fips`).
- **A stripped / `jlink`-ed runtime** that omits `jdk.crypto.ec` (no SunEC) — the regular
  `bcprov` provider supplies the missing EC algorithms.

push2u deliberately ships **no** `push2u-crypto-bc` module: `java.security.Provider` is already
the JDK's provider abstraction, so there is nothing to wrap. You wire BouncyCastle one of two
ways.

### Variant A — BouncyCastle installed globally (whole JVM)

When BC is registered as a JVM-wide JCE provider, **push2u needs no special configuration** —
every `getInstance(...)` resolves through the standard provider search order and lands on BC.
This is the usual shape of a strict FIPS deployment (BC-FIPS installed, often as the only
provider, the JVM run in approved-only mode).

Add the dependency and register the provider (via the `java.security` file, or programmatically
before any crypto runs):

```kotlin
// build.gradle.kts of YOUR application (not push2u)
runtimeOnly("org.bouncycastle:bc-fips:<version>")
```

```java
// e.g. in a @PostConstruct / main() before the first PushSender.send(...)
Security.addProvider(new org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider());
```

Then build the `PushSender` normally — **do not** call `.cryptoProvider(...)`; the global provider
already backs every primitive:

```java
PushSender pusher = PushSender.builder()
    .vapid(VapidKeys.fromBase64(publicKey, privateKey))
    .contact("mailto:ops@example.com")
    .build();
```

### Variant B — BouncyCastle for push2u only (scoped)

When you want BC for push2u's content-encryption primitives but leave the rest of the JVM on
the stock providers, pass a provider *instance* to the builder. push2u threads it through every
`getInstance(algo, provider)` the encryptor makes — ECDH key agreement, the HKDF HMAC,
AES-128-GCM, and EC key import:

```java
java.security.Provider bc = new org.bouncycastle.jce.provider.BouncyCastleProvider();
// note: no Security.addProvider(...) — the provider stays scoped to push2u

PushSender pusher = PushSender.builder()
    .vapid(VapidKeys.fromBase64(publicKey, privateKey))
    .contact("mailto:ops@example.com")
    .cryptoProvider(bc)
    .build();
```

The provider you pass must supply `KeyAgreement(ECDH)`, `KeyFactory(EC)`, `Mac(HmacSHA256)`,
and `Cipher(AES/GCM/NoPadding)`.

### Caveat — the VAPID signature

The default local signer (`LocalEcVapidSigner`) produces the ES256 JWT signature via the
JDK-specific algorithm name `SHA256withECDSAinP1363Format`, which yields the raw `r‖s` JOSE
needs. Not every third-party provider registers that exact name (BouncyCastle, for one, spells
its raw-format ECDSA differently), so `.cryptoProvider(...)` (Variant B) is scoped to the
*content-encryption* primitives, **not** the signature. If your compliance boundary must also
cover the **signature**, use **Variant A** (a globally installed provider — the JVM resolves
whatever signing names BC registers) or, better, a remote `VapidSigner`
(`push2u-signer-vault` / KMS / HSM), where the FIPS-validated signing happens off-box and
push2u never computes the signature locally.

## License

To be decided at extraction ([`DESIGN.md`](DESIGN.md) ADR-008) — most likely MIT, to match the
library it replaces. Not yet published.
