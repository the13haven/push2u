# Migrating from `nl.martijndwars:web-push`

push2u exists because the JVM's usual answer for Web Push, [`nl.martijndwars:web-push`][webpush-java],
pulls a large transitive surface into the graph of anything that depends on it, and puts
BouncyCastle types in its own public API. This guide is for teams already on that library: what
the two APIs look like side by side, what leaves the dependency graph, and — the part that decides
whether a straight port is safe — where push2u behaves differently on purpose.

Everything below about the other library was read from the published artifact and its sources:
**`nl.martijndwars:web-push:5.1.2`**, its latest release (published 2025-02-17), together with its
POM, its Gradle module metadata and its `README`. Where a statement could not be verified from
those, it is marked as such rather than guessed.

Nothing here is a criticism of a library that solved this problem for the JVM years before push2u
existed. It is a map, not a verdict.

## Contents

- [What a migration removes](#what-a-migration-removes)
- [What stays the same](#what-stays-the-same)
- [Side by side](#side-by-side)
- [Type and method mapping](#type-and-method-mapping)
- [Differences that change behaviour](#differences-that-change-behaviour)
- [If you wrote your own signing](#if-you-wrote-your-own-signing)
- [Migration checklist](#migration-checklist)

## What a migration removes

`web-push` declares five dependencies; resolved, its runtime graph is **26 artifacts** beyond the
library itself. Reproduce it with `mvn dependency:tree` on a POM whose only dependency is
`nl.martijndwars:web-push:5.1.2`:

| What it brings | Artifacts |
|---|---|
| Apache HttpComponents (the `PushService` transport) | `httpasyncclient`, `httpcore`, `httpcore-nio`, `httpclient`, `commons-codec`, `commons-logging` |
| AsyncHttpClient and Netty (the `PushAsyncService` transport) | `async-http-client`, `async-http-client-netty-utils`, `netty-buffer`, `netty-codec`, `netty-codec-http`, `netty-codec-socks`, `netty-common`, `netty-handler`, `netty-handler-proxy`, `netty-resolver`, `netty-transport`, `netty-transport-native-epoll` (`linux-x86_64`), `netty-transport-native-kqueue` (`osx-x86_64`), `netty-transport-native-unix-common`, `netty-reactive-streams`, `reactive-streams`, `jakarta.activation`, `slf4j-api` |
| JOSE (the VAPID JWT) | `jose4j` |
| The library's own CLI argument parser | `jcommander` |

Both HTTP stacks arrive whichever one you use — `PushService` needs Apache, `PushAsyncService`
needs Netty, and the dependencies are declared unconditionally. Together with `web-push` itself
that is 27 jars and 6.2 MB on the classpath, two of them platform-specific native transports.

**BouncyCastle is the one you have to add yourself, and it does not leave silently.**
`org.bouncycastle:bcprov-jdk15on:1.70` is declared `<optional>true</optional>` in the POM (and in
the Gradle metadata it appears only in the shaded `shadowRuntimeElements` variant), so it is not
transitive — a consumer declares it. It is nevertheless mandatory: `Utils.loadPublicKey`,
`Utils.loadPrivateKey` and the ephemeral key generation all resolve through the provider *by name*
(`KeyFactory.getInstance("ECDH", "BC")`), so the application must register the provider before the
first send:

```java
Security.addProvider(new BouncyCastleProvider());   // required by web-push
```

That line, and the jar behind it, disappear on push2u. Worth knowing about the jar: the
`bcprov-jdk15on` artifact line ends at 1.70 (December 2021) — BouncyCastle's maintained
distribution moved to `bcprov-jdk18on` — so a graph pinned by `web-push`'s POM version is pinned to
an artifact that receives no further releases.

push2u's side of the same table: `push2u-core` declares exactly one dependency,
[JSpecify][jspecify] — annotations, no code — carried as `api` so the nullness contract reaches
consumers, and as `requires static` on the module path so nothing resolves it at runtime
([ADR-002 and ADR-012 in `DESIGN.md`](DESIGN.md)). The Vault signer and the Spring Boot starters
are separate optional modules; neither can reach the core.

```diff
 dependencies {
-    implementation("nl.martijndwars:web-push:5.1.2")
-    implementation("org.bouncycastle:bcprov-jdk15on:1.70")
+    implementation("com.the13haven:push2u-core:<version>")
 }
```

See [`README.md` → Installation](README.md#installation) for the current coordinates; this file
deliberately carries no version number, so it cannot go stale against a release.

## What stays the same

- **Your VAPID key pair.** The public key is what browsers subscribed with
  (`applicationServerKey`), so keeping it means existing subscriptions keep working. Changing it
  would require every user to re-subscribe. The *encoding* needs one check — see
  [VAPID key encoding](#vapid-key-encoding).
- **Your stored subscriptions.** `endpoint`, `p256dh` and `auth` come from the browser and are
  unchanged. Both libraries leave the parsing of the browser's `PushSubscription` JSON to the
  application; push2u brings no JSON parser either.
- **The wire protocol**, when you were already sending `aes128gcm`. Same RFC 8291 encryption, same
  RFC 8292 VAPID header. Push services cannot tell the two senders apart.

## Side by side

### Constructing the sender

```java
// web-push
Security.addProvider(new BouncyCastleProvider());

PushService pushService = new PushService(
        vapidPublicKey, vapidPrivateKey, "mailto:ops@example.com");   // throws GeneralSecurityException
```

```java
// push2u
PushSender sender = PushSender.builder(
                VapidKeys.fromBase64(vapidPublicKey, vapidPrivateKey), "mailto:ops@example.com")
        .build();
```

The key source and the contact are required, so they are parameters of the factory method rather
than builder steps — `build()` has no missing value left to refuse. Everything else (`retryPolicy`,
`endpointPolicy`, `httpClient`, `defaultTtl`, `jwtExpiry`, `recordSize`, `maxEncryptedBodyBytes`,
`executor`, `cryptoProvider`) is optional and lives on the builder. A `PushSender` is immutable and
thread-safe once built; build it once and share it, as you would a `PushService`.

`PushSender.builder(signer, contact)` takes a `VapidSigner` instead of the keys, which is how the
Vault Transit signer is plugged in. `web-push` has no equivalent seam — `AbstractPushService`
signs with a `java.security.PrivateKey` it holds.

### Turning a browser subscription into the library's type

```java
// web-push
Subscription subscription = new Subscription(
        endpoint, new Subscription.Keys(p256dh, auth));   // fields are public and mutable, nothing is validated
```

```java
// push2u
Subscription subscription = Subscription.fromBase64(endpoint, p256dh, auth);
```

`push2u`'s `Subscription` is a record that validates on construction: an absolute `https` endpoint
with a host, a 65-byte uncompressed `p256dh` (`0x04` prefix), a 16-byte `auth`. A bad subscription
fails where it is registered instead of on every later send, and the failure message never contains
the endpoint's path or query — a push endpoint is a capability URL. `Endpoints.requireSecure` is
public so you can apply the same check at your own registration boundary before persisting.

### Sending

```java
// web-push — synchronous
HttpResponse response = pushService.send(
        new Notification(endpoint, p256dh, auth, payloadBytes),
        Encoding.AES128GCM);
// throws GeneralSecurityException, IOException, JoseException, ExecutionException, InterruptedException
```

```java
// push2u
PushMessage message = PushMessage.builder(payloadBytes)
        .ttl(Duration.ofHours(1))
        .urgency(Urgency.NORMAL)
        .topic("account_update")
        .build();

PushResult result = sender.send(subscription, message);
```

`PushMessage.of(payloadBytes)` is the shorthand when no header is being set. TTL, urgency and topic
belong to the message in both libraries; in push2u a message carries no endpoint, so one
`PushMessage` can be sent to many subscriptions.

### Handling the result

```java
// web-push — you map the status yourself
int status = response.getStatusLine().getStatusCode();
if (status >= 200 && status < 300) {
    // delivered
} else if (status == 404 || status == 410) {
    subscriptionStore.delete(subscription);
} else {
    // decide whether to retry, and implement it
}
```

```java
// push2u
if (result.isDelivered()) {
    // 2xx — the push service accepted the message
} else if (result.isSubscriptionExpired()) {
    subscriptionStore.delete(subscription);          // 404 / 410
} else {
    log.warn("Push rejected: HTTP {}, attempts={}", result.statusCode(), result.attempts());
}
```

`PushResult` has three statuses (`DELIVERED`, `SUBSCRIPTION_EXPIRED`, `FAILED`), the final
`statusCode()` and the number of POSTs actually made, `attempts()`. Transport failure throws
`PushDeliveryException`, a cryptographic failure `PushCryptoException`, a policy rejection
`EndpointRejectedException` — all unchecked, all extending `RuntimeException` directly. The five
checked exceptions on `PushService.send` have no counterpart; a `try`/`catch` block written for
them will not compile against push2u and should be rewritten around the two runtime exceptions.

### Asynchronous sending

```java
// web-push
CompletableFuture<Response> future = new PushAsyncService(...).send(notification);   // AsyncHttpClient/Netty
int status = future.join().getStatusCode();
```

```java
// push2u
CompletableFuture<PushResult> future = sender.sendAsync(subscription, message);
```

One `PushSender` serves both modes — there is no second service class, and no second HTTP stack.
The blocking pipeline runs on a library-owned virtual-thread-per-task executor, never on the common
`ForkJoinPool`; `.executor(myExecutor)` on the builder substitutes your own, which the library will
not shut down. Note that `PushAsyncService` constructs an `AsyncHttpClient` in a field and exposes
no way to close it; nothing equivalent is left running by push2u, whose default `HttpClient` is a
JDK one.

## Type and method mapping

| `nl.martijndwars.webpush` | push2u | Note |
|---|---|---|
| `PushService` | `PushSender` | Immutable, built once; both sync and async |
| `PushAsyncService` | `PushSender.sendAsync` | No separate class, no second HTTP stack |
| `PushService.send(Notification, Encoding)` | `PushSender.send(Subscription, PushMessage)` | No encoding parameter — see below |
| `Subscription` / `Subscription.Keys` | `Subscription` (record) | Validating, immutable, defensive copies |
| `Notification` | `PushMessage` + `Subscription` | The target and the message are separate values |
| `Notification.builder()` | `PushMessage.builder(payload)` | Payload is required, so it is a factory parameter |
| `Encoding.AES128GCM` | (implicit) | `aes128gcm` is the only content coding |
| `Encoding.AESGCM` | — | Not supported ([ADR-006](DESIGN.md)) |
| `Urgency.NORMAL`, `.getHeaderValue()` | `Urgency.NORMAL`, `.headerValue()` | Same four values |
| `org.apache.http.HttpResponse` / `org.asynchttpclient.Response` | `PushResult` | Status interpreted, body never read |
| `Utils.loadPublicKey`, `Utils.loadPrivateKey` | `VapidKeys.fromBase64` / `VapidKeys.of` | No BouncyCastle types in the API |
| `AbstractPushService.setSubject` | `PushSender.builder(…, contact)` | Required, not optional |
| `setGcmApiKey`, `Notification.isGcm()` | — | Legacy GCM is not supported |
| — | `VapidSigner` | External key custody (Vault Transit, KMS) |
| — | `EndpointPolicy` | Egress allowlist |
| — | `RetryPolicy` | Retries are built in |

## Differences that change behaviour

These are the ones that bite on day one of a port. Read them before deleting the old dependency.

### The default content encoding differs, and push2u supports only one

`PushService.send(Notification)` — the single-argument overload — defaults to `Encoding.AESGCM`,
the legacy content coding, not `aes128gcm`. (The other entry points differ:
`PushService.sendAsync(Notification)` and `PushAsyncService.send(Notification)` both default to
`AES128GCM`.) If your code calls the blocking single-argument `send`, you are on `aesgcm` today
whether or not you meant to be.

push2u implements `aes128gcm` only, deliberately and permanently: RFC 8291 is the standard, and
there is no builder option to change it (ADR-006 in [`DESIGN.md`](DESIGN.md)). For anything running
a current browser this is a no-op — `aes128gcm` is what the user agents that matter negotiate. But
the encryption is end-to-end to the *user agent*, so if you knowingly serve clients old enough to
understand only `aesgcm`, push2u cannot reach them and is not a drop-in for that traffic. We have
not measured which user agents in the wild still require `aesgcm`; if that population matters to
you, measure it before switching rather than trusting either library's docs.

### Endpoints must be `https`, with no loopback exception

`web-push` never inspects the endpoint: `Notification.getOrigin()` takes whatever `new URL(...)`
parses and derives `protocol + "://" + host` from it, so an `http://localhost:8080/...` endpoint
works end to end.

push2u rejects it. `Subscription` requires an absolute `https` URL with a host (RFC 8030 mandates
TLS between application server and push service) and grants loopback no exception. **A local test
setup that pointed the endpoint at a plain-HTTP mock server stops working at construction time**,
with `IllegalArgumentException`. Terminate TLS in front of the mock — the library's own suite runs
a loopback HTTPS receiver rather than relaxing the rule.

### Expired subscriptions are a result, and so is every other status

Neither library throws on `404`/`410`. The difference is who interprets the status: `web-push`
hands back the transport's response object and you write the mapping; push2u has already made it
(`DELIVERED` / `SUBSCRIPTION_EXPIRED` / `FAILED`), and expiry is deliberately not an exception so
that pruning a dead subscription stays ordinary control flow (ADR-007).

Two consequences for a port:

- Any `switch` on status codes you kept around collapses into `isDelivered()` /
  `isSubscriptionExpired()`. Keep `statusCode()` for logging — it is the final code, after retries.
- **You cannot read the response body.** `PushResponse` carries the status and headers only, and
  `JdkPushHttpClient` discards the body without buffering it, because the endpoint is a capability
  URL from an untrusted subscription and a hostile server must not be able to feed the sender an
  arbitrarily large response. If you were logging the push service's error text for diagnostics,
  that goes away — a custom `PushHttpClient` could reinstate it, but the SPI contract asks you not
  to.

### Retries now exist — check that yours does not double up

`web-push` performs no retries: one POST per `send`, and `Retry-After` is not read. Most production
integrations therefore wrapped it in a retry loop of their own.

push2u retries `429` and `5xx` by default — up to three attempts, exponential backoff from one
second, capped at 60 seconds, with a valid `Retry-After` (delta-seconds or any RFC 9110 HTTP-date
form) overriding the computed delay under the same cap. **An application retry loop on top of that
multiplies**: three attempts inside your three is nine POSTs and up to three minutes of blocking.
Either delete yours or configure `RetryPolicy.none()`:

```java
PushSender sender = PushSender.builder(keys, "mailto:ops@example.com")
        .retryPolicy(RetryPolicy.none())
        .build();
```

### The default TTL is different by a factor of 28

`web-push`'s `Notification` defaults to `28 * 86400` seconds — 28 days — when no TTL is given.
push2u's default is **one day**, and it is a property of the sender rather than the message:

```java
PushSender sender = PushSender.builder(keys, "mailto:ops@example.com")
        .defaultTtl(Duration.ofDays(28))    // only if you were relying on the old default
        .build();
```

A per-message `ttl(...)` on `PushMessage` still wins over it. If your code always set a TTL
explicitly, nothing changes.

### Payload and record size are checked before anything is sent

`web-push` performs no size checks; an oversized payload is encrypted, POSTed, and refused by the
push service (typically `413`) — you pay the cryptography and the round trip to find out.

push2u checks first, and throws `IllegalArgumentException` before encryption or network I/O:

- **Encrypted body ≤ 4096 bytes** by default, the size RFC 8030 §7.2 lets a push service refuse
  beyond. The single-record `aes128gcm` body adds a fixed 103 bytes to the plaintext, so the
  default admits **3993 bytes of plaintext** — the figure RFC 8291 §4 derives. Raise it with
  `.maxEncryptedBodyBytes(…)` only for an endpoint documented to accept more.
- **Record size (`rs`)** must be strictly greater than plaintext + 1 + 16 (RFC 8291 §4); values
  below 18 are invalid outright (RFC 8188 §2) and the builder rejects them. Raising
  `maxEncryptedBodyBytes` without raising `.recordSize(…)` to match will be rejected at send time
  with a message naming the minimum `rs` needed.

A payload that used to squeeze through at 4000-odd bytes now throws locally. That is the intended
behaviour, but it is a throw where there used to be a `413` — make sure the caller handles it.

### VAPID `sub` is required

RFC 8292 §2.1 leaves the `sub` claim optional, and `web-push` treats it that way: construct a
`PushService` without a subject and the JWT simply carries no `sub`. push2u requires a contact —
it is a parameter of `PushSender.builder(…)`, omitting it does not compile, and a blank value is
rejected with `IllegalArgumentException`. Use the `mailto:` or `https:` URI a push service could
actually reach you at.

### VAPID key encoding

`VapidKeys.fromBase64` expects base64url (padded or not) of a **65-byte uncompressed public point**
and a **32-byte private scalar**. Two encoding details of the old library's keys matter here:

- **The private key may be 33 bytes.** `web-push`'s key generator prints
  `privateKey.getD().toByteArray()` — a `BigInteger` two's-complement encoding, which carries a
  leading `0x00` whenever the scalar's high bit is set (and is *shorter* than 32 bytes when the
  scalar has leading zero bytes). The example key in that library's own README decodes to 33 bytes
  beginning with `0x00`. push2u requires exactly 32 and rejects anything else with
  `IllegalArgumentException: VAPID private key must be a 32-byte P-256 scalar`. Strip a leading
  zero byte, or left-pad with zeros to 32 — the scalar value is unchanged, so this is a re-encoding
  and not a new key. Roughly half of all generated keys are affected, so a key that imports cleanly
  on one environment is no evidence about the next one.
- **Padded base64 is fine, standard base64 is not.** The old CLI prints with `=` padding, which
  push2u's decoder tolerates. It decodes URL-safe base64 (`-`, `_`) only; a key stored in standard
  base64 (`+`, `/`) must be converted.

The public key needs no conversion: both sides use the 65-byte uncompressed X9.62 point. (Strictly,
`web-push` also accepts a *compressed* point, because it decodes through BouncyCastle's
`decodePoint`; push2u requires the uncompressed form. No browser or key generator emits compressed
VAPID keys, so this only matters if something in your pipeline compressed them deliberately.)

The same applies to the browser's `p256dh`: push2u requires the 65-byte uncompressed point browsers
actually send, where `web-push` would have accepted a compressed one.

### `Topic` is validated locally

`web-push` puts whatever string you pass into the `Topic` header. push2u validates it first: 1–32
characters from the URL-safe base64 alphabet, the RFC 8030 §5.4 grammar. A topic outside that shape
— a colon, a slash, 40 characters — now throws `IllegalArgumentException` at `PushMessage.build()`
instead of drawing an HTTP `400`.

### An empty payload is still encrypted

`web-push` sends no body and no `Content-Encoding` when the payload is zero-length. push2u always
encrypts and always sends a body — an empty payload produces a 103-byte `aes128gcm` record. If you
were sending payload-less "tickle" pushes deliberately, the request shape changes (the message
still arrives; the service worker's `event.data` becomes an empty payload rather than absent).

### Legacy GCM support is gone

`setGcmApiKey`, `Notification.isGcm()`, the `Authorization: key=…` header, and the rewriting of
`https://fcm.googleapis.com/fcm/send/…` to `…/wp/…` under `aes128gcm` have no counterpart. push2u
sends the endpoint the browser gave it, with a VAPID `Authorization` header and nothing else. Modern
FCM endpoints work as ordinary RFC 8030 endpoints; if you still hold pre-VAPID GCM registrations,
they are not migrated by this library.

### `EndpointPolicy` — off by default, and worth turning on

Neither library restricts where a send may POST unless you ask. push2u has the seam for it, and it
addresses a real exposure: the endpoint inside a `Subscription` is attacker-influenced data, since a
typical integration accepts the browser's subscription JSON at a public registration endpoint.
Nothing stops a client posting a hand-crafted subscription pointing into your own network, and the
visible outcome (`PushResult.statusCode()` versus `PushDeliveryException`, plus timing) then works
as a blind SSRF oracle for internal host and port existence.

```java
PushSender sender = PushSender.builder(keys, "mailto:ops@example.com")
        .endpointPolicy(EndpointPolicies.allowedOrigins(
                "https://fcm.googleapis.com",                 // Chrome
                "https://updates.push.services.mozilla.com",  // Firefox
                "https://web.push.apple.com"))                // Safari
        .build();
```

The policy runs before encryption, before the VAPID signature and before any I/O; a rejection
throws `EndpointRejectedException` and costs none of them. Matching is exact and fail-closed —
subdomains are not included, and a malformed allowlist entry fails at construction so the mistake
surfaces at deployment. With no policy configured the behaviour matches what you have today: any
absolute `https` endpoint is sent to. See
[`README.md` → Endpoint policy](README.md#endpoint-policy-ssrf-hardening) for the limits of a
URI-level check — it is a coarse filter, not a sandbox.

### Redirects are never followed

push2u's transports refuse to follow a `3xx`, and both `JdkPushHttpClient` and the Vault transport
reject an `HttpClient` whose `followRedirects()` is anything but `Redirect.NEVER`. A redirect would
carry the encrypted body and the request headers to a host `EndpointPolicy` never saw. If you
supply your own `java.net.http.HttpClient` or implement `PushHttpClient` over another stack, turn
redirect following off explicitly — several stacks are permissive by default. We did not audit what
`web-push`'s two transports do here, so treat this as a contract push2u adds rather than as a
statement about the other library.

## If you wrote your own signing

Nothing in `web-push` is pluggable at the key-custody boundary — `AbstractPushService` signs with a
`PrivateKey` it holds, so a team keeping VAPID keys in an HSM or KMS had to fork or wrap the
library. push2u makes that a supported SPI:

```java
public interface VapidSigner {
    byte[] sign(byte[] signingInput);   // raw 64-byte r || s (RFC 7518 §3.4)
    byte[] publicKey();                 // 65-byte uncompressed P-256 point (RFC 8292 §3.2)
}
```

The contract is narrow and unforgiving: return DER instead of `r || s`, or a compressed point, and
every send draws an opaque `401`/`403`. Extend the published conformance kit in your own test suite
rather than finding out in production:

```kotlin
dependencies {
    testImplementation("com.the13haven:push2u-testkit:<version>")
}
```

```java
class MySignerContractTest extends VapidSignerContractTest {

    @Override
    protected VapidSigner signer() {
        return new MySigner(...);
    }
}
```

`push2u-signer-vault` is a ready-made implementation over HashiCorp Vault Transit, so the private
key never enters the JVM at all. Both are documented in
[`README.md`](README.md#conformance-kit-for-a-custom-signer).

## Migration checklist

1. Replace the two dependencies with `com.the13haven:push2u-core`, and delete the
   `Security.addProvider(new BouncyCastleProvider())` call.
2. Re-encode the VAPID private key to a 32-byte scalar if the stored one decodes to 33 bytes
   (or fewer). The key itself does not change — do **not** generate a new pair, or every subscriber
   has to re-subscribe.
3. Replace `PushService` with a single shared `PushSender`, built once with the keys and the
   contact.
4. Replace `Notification` with `Subscription` + `PushMessage`; move the endpoint and the browser
   keys into the subscription, the payload and headers into the message.
5. Rewrite result handling around `PushResult`, and replace the `catch` blocks for the five checked
   exceptions with `PushDeliveryException` / `PushCryptoException`.
6. Delete your retry loop, or set `RetryPolicy.none()`.
7. Set `defaultTtl` explicitly if you were relying on the old 28-day default.
8. Check that every endpoint you send to — test fixtures included — is `https`.
9. Check payload sizes against the 3993-byte plaintext default, and topics against the
   RFC 8030 §5.4 shape.
10. Configure `EndpointPolicies.allowedOrigins(…)` with the push services your users arrive from.
11. On Spring Boot, consider `push2u-spring-boot-starter` — it binds `push2u.*`, builds the
    `PushSender` bean and adds an Actuator health indicator that signs a probe and verifies it. See
    [`README.md` → Spring Boot](README.md#spring-boot).

[webpush-java]: https://github.com/web-push-libs/webpush-java
[jspecify]: https://jspecify.dev
