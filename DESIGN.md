# push2u — Design

> **push2u** (*push events to user*) — a small, zero-dependency JVM library for the
> [Web Push protocol](https://datatracker.ietf.org/doc/html/rfc8030): VAPID-authenticated,
> end-to-end-encrypted delivery of push messages to browsers (FCM / Mozilla autopush /
> Apple Web Push) from a Java application server.
>
> Status: **design** (no code yet). Development plan: [`ROADMAP.md`](ROADMAP.md).

## 1. Motivation

The de-facto JVM Web Push library, [`nl.martijndwars:web-push`](https://github.com/web-push-libs/webpush-java),
is effectively unmaintained (no meaningful release since 2022). It drags a brittle and
partly **EOL** transitive surface — Apache HttpClient 4.x (EOL Jan 2022), `jose4j`,
BouncyCastle — and its public API leaks those types (`PushService#send` returns
`org.apache.http.HttpResponse`), so any structural fix has nowhere to land. hagit consumes
it today via `MartijnWebPushSender` and pins four libraries by hand to keep it working
(tech debt #73).

The whole job of a Web Push sender is **3 crypto primitives + 1 JWT signer + 1 HTTP POST**.
On a modern JDK every one of those is a platform primitive. push2u exists to be the clean,
maintained, **dependency-free** replacement that the JVM ecosystem currently lacks.

### What makes push2u worth existing (not just a fork)

A **pure-JDK, zero-runtime-dependency `core`**. This is the differentiator and the cure for
exactly the disease above: no BouncyCastle, no jose4j, no Apache HttpClient in the default
path. See §4.

## 2. Goals / Non-goals

**Goals**
- Zero runtime dependencies in `core` (pure JDK, baseline Java 21 — see ADR-001).
- Full conformance to RFC 8030 / 8291 / 8292 / 8188, pinned by published test vectors (§7).
- Clean, narrow extension points for the two things that *legitimately* vary: the **VAPID
  signer** (key custody) and the **HTTP transport** (§5).
- Ergonomic result handling: a dead subscription (404/410) is a normal *result*, not an
  exception (ADR-007).
- Sync and async (`CompletableFuture`) send APIs.
- A Spring Boot starter as an opt-in module (the hagit consumption path).

**Non-goals**
- **Subscription storage.** push2u is stateless — the application owns persistence and
  hands the library a `Subscription`. No JDBC/JPA store modules (ADR-004).
- **Browser-side code.** Service-worker / `PushManager.subscribe()` is the consumer's app.
- **Legacy `aesgcm` content coding.** `aes128gcm` (RFC 8188) only — universally supported
  since ~2017 (ADR-006).
- **CI/CD, multi-tenant config, billing** — those are hagit concerns, not library concerns.

## 3. Standards

| RFC | Role in push2u |
|---|---|
| [RFC 8030](https://datatracker.ietf.org/doc/html/rfc8030) | Generic Event Delivery Using HTTP Push — the POST-to-endpoint transport + status semantics |
| [RFC 8291](https://datatracker.ietf.org/doc/html/rfc8291) | Message Encryption for Web Push — ECDH P-256 + HKDF + AES-128-GCM |
| [RFC 8292](https://datatracker.ietf.org/doc/html/rfc8292) | VAPID — ES256 JWT identifying the application server |
| [RFC 8188](https://datatracker.ietf.org/doc/html/rfc8188) | Encrypted Content-Encoding (`aes128gcm`) — the record framing of the body |
| [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) | HKDF — hand-rolled over `javax.crypto.Mac` (ADR-003) |

## 4. The zero-dependency core

Every primitive Web Push needs is in the JDK on the Java 21 baseline:

| Operation | JDK primitive (no BouncyCastle, no jose4j) |
|---|---|
| ECDH P-256 key agreement (RFC 8291) | `KeyAgreement.getInstance("ECDH")` |
| HKDF-SHA256 (RFC 5869) | hand-rolled `extract`/`expand` over `Mac.getInstance("HmacSHA256")` (~25 lines) |
| AES-128-GCM (RFC 8188) | `Cipher.getInstance("AES/GCM/NoPadding")` |
| **ES256 JWT signature** | `Signature.getInstance("SHA256withECDSAinP1363Format")` — P1363 yields the raw `r‖s` that JOSE wants; **no DER→R\|\|S conversion, no jose4j** |
| EC key import (`p256dh`, VAPID keys) | `KeyFactory.getInstance("EC")` + `ECPublicKeySpec` / `PKCS8EncodedKeySpec` |
| base64url | `java.util.Base64.getUrlEncoder().withoutPadding()` |
| VAPID JWT JSON | hand-written — claims are tiny (`aud`/`exp`/`sub`); **no JSON library** |
| HTTP POST | `java.net.http.HttpClient` (`send` + `sendAsync`) |

The actual cryptography (HMAC, ECDSA, AES-GCM, ECDH) is the JDK's vetted implementation in
*both* the hand-rolled and any native path — see ADR-003 on why HKDF stays hand-rolled and
is **not** an extension point.

> The browser `PushSubscription` JSON is parsed by the *application* (it arrives at the
> app's REST endpoint); `core` never parses JSON, so it carries no JSON dependency.

### 4.1. Send pipeline

```
send(Subscription sub, PushMessage msg)
  │
  ├─ 1. Encrypt (RFC 8291 / 8188, aes128gcm)
  │      ephemeral as_keypair ← P-256
  │      ecdh        ← ECDH(as_private, sub.p256dh)
  │      salt        ← random 16 bytes
  │      IKM         ← HKDF(salt=sub.auth, ikm=ecdh, info="WebPush: info\0"‖ua_pub‖as_pub, 32)
  │      PRK         ← HKDF-Extract(salt, IKM)
  │      CEK         ← HKDF-Expand(PRK, "Content-Encoding: aes128gcm\0", 16)
  │      nonce       ← HKDF-Expand(PRK, "Content-Encoding: nonce\0", 12)
  │      body        ← aes128gcm header(salt,rs,as_pub) ‖ AES-128-GCM(CEK, nonce, padded payload)
  │
  ├─ 2. VAPID auth (RFC 8292)
  │      jwt    ← ES256.sign({aud: origin(sub.endpoint), exp: now+12h, sub: contact})  ← VapidSigner
  │      header ← "Authorization: vapid t=<jwt>, k=<base64url(vapid_public)>"
  │
  ├─ 3. POST sub.endpoint  (RFC 8030)                                                  ← PushHttpClient
  │      Content-Encoding: aes128gcm; TTL; Urgency; Topic
  │
  └─ 4. Interpret status → PushResult
         201            → delivered
         404 | 410      → SUBSCRIPTION_EXPIRED  (caller deletes — NOT an exception)
         429            → retry honoring Retry-After
         5xx            → retry with backoff
         400 | 413 | …  → failed (no retry)
```

## 5. Architecture & modules

`core` is **batteries-included**: it bundles the default `VapidSigner` (local, in-JVM
signing) and the default `PushHttpClient` (JDK `HttpClient`), so a single `push2u-core`
dependency can send out of the box. Extension modules are opt-in upgrades; each one that
drags a third-party SDK (Vault, AWS, OkHttp) lives outside `core` so `core` stays zero-dep.

```
push2u-core                 ← zero-dep: domain, RFC 8291 encryption, VAPID JWT, retry policy,
                              sync+async facade
                              + bundled defaults: LocalEcVapidSigner, JdkHttpPushClient
push2u-signer-vault         ← VapidSigner via HashiCorp Vault Transit (key never leaves Vault)
push2u-signer-aws-kms       ← VapidSigner via AWS KMS
push2u-signer-pkcs11        ← VapidSigner via PKCS#11 / HSM
push2u-http-okhttp          ← PushHttpClient via OkHttp
push2u-http-apache5         ← PushHttpClient via Apache HttpClient 5
push2u-spring-boot-starter  ← auto-config + @ConfigurationProperties + actuator health
push2u-micrometer           ← metrics (send latency, status counts)  [post-PoC]
push2u-bom                  ← BOM aligning module versions             [at publish time]
```

### 5.1. Extension points (SPI)

Two interfaces. The litmus for an extension point: *would a downstream user make a
different choice here for an articulable reason that changes observable behaviour or a
compliance posture?*

| SPI | Default (in `core`) | Why it is a real seam |
|---|---|---|
| `VapidSigner` — `byte[] sign(byte[] signingInput)` + `publicKey()` | `LocalEcVapidSigner` (in-JVM, key in memory) | **Key custody.** Vault Transit / KMS / HSM keep the private key off the JVM heap — a genuinely different security posture (ADR-010) |
| `PushHttpClient` — `Response post(URI, headers, body)` | `JdkHttpPushClient` (`java.net.http`) | Users standardize on a stack (OkHttp, HC5) for pooling, proxies, observability |

**JCE provider is a builder option, not an SPI.** FIPS-validated and constrained JREs need
the crypto primitives backed by a specific JCE provider (BC-FIPS, or a non-Sun EC provider) —
but `java.security.Provider` *is already* the JDK's provider abstraction, so wrapping it in a
bespoke `CryptoProvider` interface would buy nothing. The builder instead takes an optional
`.cryptoProvider(java.security.Provider)` that the concrete encryptor threads through every
`getInstance(algo, provider)` it makes (ECDH, HKDF's HMAC, AES-128-GCM, EC key import);
default = the platform provider chain. (The local ES256 signature uses the JDK-specific
`SHA256withECDSAinP1363Format` name, which not every provider registers — for a FIPS-validated
*signature* prefer a globally-installed provider or a remote `VapidSigner`; see the README.)
There is **no** `push2u-crypto-bc` module — BouncyCastle is served by this one builder option,
documented (both globally-installed and push2u-scoped) in the library README.

**Deliberately NOT extension points:**
- **The encryptor (RFC 8291).** No externalizable secret — the per-message ECDH key is
  ephemeral and the `auth` secret is the *client's*. Nothing to delegate to an HSM. One
  concrete in-`core` implementation (parameterised only by the optional JCE provider above).
- **HKDF.** A component *inside* the encryptor; same bytes regardless of implementation;
  exposing it would put a pluggable seam in the crypto core whose failure mode is silent
  wrong ciphertext. See ADR-003.
- **JCE provider selection.** A builder option (`java.security.Provider`), not a custom SPI —
  see above.

### 5.2. Facade

```java
// Default path — VAPID key pair held locally, signed in-JVM (LocalEcVapidSigner).
PushSender pusher = PushSender.builder()
    .vapid(VapidKeys.fromBase64(publicKey, privateKey))
    .contact("mailto:ops@example.com")
    // .httpClient(new OkHttpPushClient(...))            // default: JdkHttpPushClient
    // .cryptoProvider(new BouncyCastleFipsProvider())   // default: platform JCE provider chain
    .build();

// External-signer path — private key never on the JVM heap; the signer supplies the VAPID
// public key via publicKey(), so .vapid(...) is omitted (it would be redundant).
PushSender viaVault = PushSender.builder()
    .signer(new VaultTransitVapidSigner(...))
    .contact("mailto:ops@example.com")
    .build();

PushResult r = pusher.send(subscription, PushMessage.of(payloadBytes).ttl(Duration.ofHours(1)));
if (r.isSubscriptionExpired()) {
    subscriptionStore.delete(subscription);   // app concern
}
```

The builder needs exactly one key source: `.vapid(keys)` (which constructs the default
`LocalEcVapidSigner`) **or** `.signer(externalSigner)` (which supplies the public key via
`publicKey()`). `.contact(...)` — the VAPID `sub` claim, a `mailto:`/`https:` the push service
can reach you at — is required in both paths and is orthogonal to key custody, so it is its
own builder step, not a `.vapid(...)` argument. `build()` enforces this: it throws if neither
key source is given, or if both are. Optional overrides (`.httpClient(...)`,
`.cryptoProvider(...)`) fall back to documented defaults when omitted — there are no
`withDefaultSigner()`-style no-op steps, since absence already *is* the default (the
`java.net.http.HttpClient.newBuilder()` idiom this library follows).

`PushMessage` carries the payload plus protocol headers (`TTL`, `Urgency`, `Topic`).
`PushResult` exposes `delivered()`, `isSubscriptionExpired()`, `statusCode()`, and the
retry history. Value types are immutable records; the public surface throws only on genuine
errors (I/O, crypto misconfiguration), never on "subscription gone".

## 6. Design decisions (ADRs)

- **ADR-001 — Baseline = Java 21 LTS.** A library baseline is a *floor, not a ceiling*: a
  21-baselined artifact runs unchanged on 25/26/29, so "stay current" is satisfied for free
  while still serving the 17/21 cohort that a *replacement for web-push* must reach. 25
  would serve only a strict subset and buys nothing user-visible (its only win is calling
  `javax.crypto.KDF` instead of ~25 hand-rolled lines). Going up later is free; going down
  later is a breaking change.
- **ADR-002 — Zero runtime dependencies in `core`.** Pure-JDK crypto + HTTP + base64url +
  hand-written JWT JSON. This is the differentiator vs `nl.martijndwars:web-push`.
- **ADR-003 — HKDF is hand-rolled and NOT an extension point.** ~25 lines of RFC 5869 over
  the JDK's `Mac`, pinned by RFC 8291 §5 vectors. The native `javax.crypto.KDF` (JDK 25+)
  produces byte-identical output and wraps the same HMAC, so it adds no functional/security/
  perf value. A "JDK-25 HKDF" opt-in module is rejected (it would require an `Hkdf` SPI in
  the crypto core — silent-wrong-ciphertext failure mode — for zero benefit); MRJAR is also
  rejected as over-engineering for 25 frozen lines. The hand-rolled path runs on every
  baseline including 25/26, so it is the single code path.
- **ADR-004 — Stateless library.** Subscription persistence is the application's job. No
  store modules. (Optional browser-JSON parsing helper is the only concession, and is under
  review.)
- **ADR-005 — Two SPIs (`VapidSigner`, `PushHttpClient`); encryptor & HKDF stay concrete;
  the JCE provider is a builder option, not an SPI.** Per the §5.1 litmus.
  `java.security.Provider` is already the JDK's provider abstraction, so a bespoke
  `CryptoProvider` interface (and a `push2u-crypto-bc` module) would wrap an existing seam for
  zero gain — replaced by an optional `.cryptoProvider(java.security.Provider)` on the builder,
  with BouncyCastle / FIPS usage documented in the README.
- **ADR-006 — `aes128gcm` content coding only.** Legacy `aesgcm` dropped.
- **ADR-007 — Dead subscription is a result, not an exception.** 404/410 → `PushResult`
  flag, so callers prune their store without exception-driven control flow (the chief
  ergonomic failure of the old library).
- **ADR-008 — License decided at extraction.** Most likely **MIT** to match
  `nl.martijndwars:web-push`; Apache-2.0 considered for its patent grant. Not blocking
  in-repo development.
- **ADR-009 — Develop in-repo, extract before publishing.** Lives at `backend/lib/push2u/`
  during the hagit PoC (hagit is the dogfood consumer). Designed with **no hagit
  dependencies** so extraction to a standalone repo + Maven Central is a directory move. It is
  its **own Gradle build** (composite) — wired into the hagit root via
  `includeBuild("backend/lib/push2u")`, with its own `settings.gradle.kts`, shared
  `build.gradle.kts`, and version catalog — so it carries none of hagit's build conventions.
  hagit consumers (phase 6) depend on the `io.push2u:*` coordinate, which the included build
  substitutes locally and which resolves from Maven Central after publish (no dependency
  rewiring); extraction is then a directory move plus deleting the `includeBuild` line. Build
  it standalone with `./gradlew -p backend/lib/push2u <task>`.
- **ADR-010 — Signer adoption is staged.** `core` ships `LocalEcVapidSigner` (key sourced
  at-rest, e.g. from Vault via hagit's secrets path, signs in-JVM). The Vault-Transit signer
  (key never leaves Vault, `ecdsa-p256`, `marshaling_algorithm=jws`) is a follow-up module —
  hagit wires the local signer first (proving drop-in parity with `MartijnWebPushSender`),
  then swaps to Vault Transit.

## 7. Conformance & testing

This is a cryptography library — conformance vectors are non-negotiable.

- **RFC 8291 §5** worked example (known `as_private` / `ua_public` / `auth` / `salt` /
  plaintext → known ciphertext) pins the entire ECDH→HKDF→AES-128-GCM path end-to-end.
- **RFC 8292** examples pin the VAPID JWT structure and ES256 signature shape.
- **RFC 5869** test vectors pin the hand-rolled HKDF in isolation.
- An **integration test** against a local mock push receiver (and optionally Mozilla
  autopush staging) exercises the full POST + status interpretation.

## 8. Relationship to hagit

push2u replaces `MartijnWebPushSender` in the `web-push-notification-channel` plugin,
closing tech debt #73. The plugin imports `push2u-core` (+ later `push2u-signer-vault`);
hagit's `WebPushSender` facade is satisfied by a thin adapter over `PushSender`. The library
itself stays free of any `io.hagit.*` reference. Naming/packaging is provisional
(`io.push2u`) pending the Maven coordinate chosen at extraction (ADR-008/009).
