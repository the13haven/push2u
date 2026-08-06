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
next `X.Y.Z-SNAPSHOT`, which is not published anywhere — anything ahead of the latest release is
consumed through the [composite build](#developing-against-unpublished-changes) below. The
implemented architecture is described in [`DESIGN.md`](DESIGN.md).

Coming from `nl.martijndwars:web-push`? [`MIGRATION.md`](MIGRATION.md) maps the two APIs onto each
other, lists the 26 transitive artifacts and the BouncyCastle provider registration a migration
removes, and is explicit about where push2u is stricter — `https`-only endpoints, up-front size
limits, `aes128gcm` only, and a VAPID private key that has to be exactly 32 bytes.

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

| Module | Purpose | JPMS module name |
|---|---|---|
| `push2u-core` | Domain types, encryption, VAPID, retry logic, `PushSender`, local signer, and JDK HTTP transport | `com.the13haven.push2u` |
| `push2u-testkit` | The `VapidSigner` conformance contract, for a **test** classpath | `com.the13haven.push2u.testkit` |
| `push2u-signer-vault` | `VapidSigner` backed by HashiCorp Vault Transit | `com.the13haven.push2u.signer.vault` |
| `push2u-spring-boot-starter` | Spring Boot auto-configuration for `PushSender` and optional health indicator | `com.the13haven.push2u.spring` |
| `push2u-signer-vault-spring-boot-starter` | Spring Boot auto-configuration for the Vault Transit signer | `com.the13haven.push2u.signer.vault.spring` |

`push2u-core` and `push2u-signer-vault` are explicit JPMS modules — they ship a `module-info.java`
and work on the module path as they do on the class path:

```java
module com.example.app {
    requires com.the13haven.push2u;
}
```

The core requires only `java.net.http` from the JDK, and it is `transitive`, so a consumer supplying
its own configured `HttpClient` to `JdkPushHttpClient` does not have to require it as well. JSpecify
is a `requires static`, so nothing resolves that jar at runtime and the module stays dependency-free
on the module path exactly as it is on the class path. You do not need JSpecify to compile against
push2u — the nullness annotations are readable from the class files either way. You need it only if
something reads them reflectively at runtime, and then the module has to be added explicitly
(`--add-modules org.jspecify`), because a `static` requires is not resolved on its own.

The two Spring Boot starters are automatic modules with a fixed `Automatic-Module-Name`, because
Boot's own artifacts are automatic modules and its auto-configuration is reflective. `push2u-testkit`
is likewise automatic: it carries JUnit and AssertJ, which are automatic modules themselves.

## Requirements

- Java 21 or newer at runtime.
- A VAPID P-256 key pair ([how to get one](#vapid-keys)), or an implementation of `VapidSigner`.
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

## VAPID keys

Every send is signed with a VAPID (RFC 8292) P-256 key pair, and push2u never produces one: it has
no key generator, and nothing in it derives, rotates or replaces a key. The pair is your
application's identity to the push services, so it is created once, outside the application, and
handed to it as configuration.

### The lifecycle

- **One pair per application**, generated once — not per user, per subscription, per instance or
  per deployment. Every instance of the same application signs with the same pair.
- **The public half is handed to the browser** as the `applicationServerKey` argument of
  `pushManager.subscribe(...)`. The push service records it with the subscription and afterwards
  accepts only pushes signed by the matching private half.
- **The pair is loaded on every boot, never generated at one.** The private half comes from a secret
  store, the public half alongside it. Generating a pair at startup would look like it works — the
  first subscriptions taken after that boot are valid — and would break every subscription taken
  before it.
- **Rotating the pair invalidates every existing subscription.** There is no re-keying: the push
  service refuses a request whose VAPID key is not the one the subscription was created with, and
  every affected client has to call `subscribe(...)` again with the new public key. Treat a
  rotation as a migration, not as routine hygiene.

The private key is a secret with no recovery path — lose it and every subscriber has to
re-subscribe. The public key is not secret; it is published to browsers by design.

### Generate a pair

Any P-256 generator will do, as long as it emits what
[RFC 8292 §3.2](https://datatracker.ietf.org/doc/html/rfc8292#section-3.2) and browsers expect: the
public key as the **65-byte uncompressed X9.62 point** and the private key as the **raw 32-byte
scalar**, both unpadded base64url. The JDK you already build with can do it, through `jshell`.

Run it where you would handle any other secret — a workstation or a bastion, not CI. The private
half is printed to the terminal, so it lands in scrollback and in whatever your multiplexer or
terminal emulator keeps; move it into the secret store, then clear the buffer. Nothing here writes
it to disk, and the heredoc keeps it out of shell history, which records the command and not its
output.

<!-- vapid-keygen:begin -->
```bash
jshell -q - <<'EOF'
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.Base64;

byte[] fixed32(BigInteger value) {
    byte[] raw = value.toByteArray(), out = new byte[32];
    int len = Math.min(raw.length, 32);
    System.arraycopy(raw, raw.length - len, out, 32 - len, len);
    return out;
}

var generator = KeyPairGenerator.getInstance("EC");
generator.initialize(new ECGenParameterSpec("secp256r1"));
var pair = generator.generateKeyPair();

var point = ((ECPublicKey) pair.getPublic()).getW();
var publicKey = new byte[65];
publicKey[0] = 0x04;
System.arraycopy(fixed32(point.getAffineX()), 0, publicKey, 1, 32);
System.arraycopy(fixed32(point.getAffineY()), 0, publicKey, 33, 32);
var privateKey = fixed32(((ECPrivateKey) pair.getPrivate()).getS());

var base64url = Base64.getUrlEncoder().withoutPadding();
System.out.println("public:  " + base64url.encodeToString(publicKey));
System.out.println("private: " + base64url.encodeToString(privateKey));
/exit
EOF
```
<!-- vapid-keygen:end -->

That block is POSIX-shell syntax — `bash`, `zsh` or `sh`. On PowerShell or `cmd.exe`, save everything
between the `jshell -q - <<'EOF'` line and the closing `EOF` to a file, say `vapid.jsh`, and run
`jshell -q vapid.jsh` instead.

**`fixed32` is the reason this is longer than a three-liner, and it is not optional.** `BigInteger`
values are what the JCA hands out, and `toByteArray()` is a two's-complement encoding, not a fixed
32-byte field element. Over 3000 generated pairs it returned **33 bytes for 1504 of them** — a
leading `0x00` sign byte whenever the high bit is set. That is exactly the defect
`nl.martijndwars:web-push`'s own generator has (see
[`MIGRATION.md`](MIGRATION.md#vapid-key-encoding)). In the other direction, 7 scalars and 10 X
coordinates came back **shorter than 32 bytes**, because leading zeros are dropped — npm's
`web-push` carries a patch for precisely that case. So "strip the sign byte" is wrong about half the
time and "strip but do not left-pad" is wrong about once in two hundred, which is the worse of the
two: the key looks perfectly fine right up to the point where a signature does not verify. Copying
the block whole avoids both.

push2u's own test suite executes this block straight out of this file, so what is checked is what
you see here: it runs the whole thing and feeds the printed pair to `VapidKeys.fromBase64` and
`LocalEcVapidSigner`, then calls this `fixed32` on fixed values covering each *shape*
`toByteArray()` produces — 33 bytes, exactly 32, fewer, and one — and compares all 32 output bytes.
Four statements are pinned as text as well — the three that call `fixed32`, and the one that picks
the encoder — because no run over random keys can show either: a call that is gone, or a standard
alphabet whose output differs from url-safe only on the roughly two draws in a hundred where a `+`
or `/` appears. What that pins is the text, not that the printed value came from it. An edit that
breaks the padding, or quietly stops applying it, fails the build rather than waiting for an
unlucky key. What the test cannot see is the shell: the body goes to `jshell` directly, so the
heredoc wrapper around it is checked as text and not as something a shell ran.

If you already have Node.js around, the npm `web-push` package prints the same two values in the
same encoding, and either source is equally good:

```bash
npx web-push generate-vapid-keys
```

**The Java `nl.martijndwars:web-push` generator is not usable here.** It prints the `BigInteger`
encoding described above, so its private key is frequently 33 bytes and `VapidKeys` rejects it with
`IllegalArgumentException`. If you are migrating and already hold such a key, do not generate a new
one — re-encode the one you have, as
[`MIGRATION.md`](MIGRATION.md#vapid-key-encoding) describes.

### Where the two values go

With the Spring Boot starter, as `push2u.vapid.public-key` and `push2u.vapid.private-key` (see
[Spring Boot](#spring-boot)):

```yaml
push2u:
  vapid:
    public-key: "${VAPID_PUBLIC_KEY}"
    private-key: "${VAPID_PRIVATE_KEY}"
    subject: "mailto:ops@example.com"
```

With the core alone, through `VapidKeys.fromBase64(publicKey, privateKey)` — see
[Create a sender with a local VAPID key](#create-a-sender-with-a-local-vapid-key). Either way the
public key is also what the browser needs as `applicationServerKey`; the private key never leaves
the application server.

Holding the private key in a secret store you would rather not hand to the application at all is
what the [Vault Transit signer](#vault-transit-signer) is for: the key stays in Vault, and push2u
sends signing requests instead of loading a scalar. **If that is where you are heading, do not run
the snippet above at all** — create the key inside Vault, so the scalar never exists outside it:

```bash
vault write -f transit/keys/<name> type=ecdsa-p256
```

The signer reads the public half from Vault itself; see
[Vault Transit signer](#vault-transit-signer).

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
scalar, both encoded as unpadded base64url — [VAPID keys](#vapid-keys) covers where that pair comes
from and how long it lives:

```java
PushSender sender = PushSender.builder(
        VapidKeys.fromBase64(vapidPublicKey, vapidPrivateKey), "mailto:ops@example.com")
    .build();
```

The contact is used as the VAPID `sub` claim and should be a `mailto:` or `https:` URI. RFC 8292
§2.1 leaves `sub` optional; push2u requires it, because a push service with a problem to report
about your application server has no other way to reach you. It is therefore a parameter of the
factory method — omitting it does not compile — and `PushSender.builder(…)` throws
`IllegalArgumentException` for a whitespace-only value. Everything on the returned builder is
optional; `build()` has nothing left to refuse.

To delegate signing to an external `VapidSigner` (for example Vault Transit, below), pass the
signer instead of the keys: `PushSender.builder(signer, "mailto:ops@example.com")`. The two
overloads differ only in the required key source — exactly one, chosen by the overload.

### Send a message

```java
PushMessage message = PushMessage.builder(payloadBytes)
    .ttl(Duration.ofHours(1))
    .urgency(Urgency.NORMAL)
    .topic("account_update")
    .build();

PushResult result = sender.send(subscription, message);

if (result.isDelivered()) {
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
PushSender sender = PushSender.builder(keys, "mailto:ops@example.com")
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
PushSender sender = PushSender.builder(keys, "mailto:ops@example.com")
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
- a whitespace-only contact previously built a `PushSender` that would issue a VAPID JWT with a
  blank `sub` claim; the contact is now a parameter of `PushSender.builder(…)`, which rejects a
  blank value with `IllegalArgumentException` — and a missing contact no longer compiles at all.

### Retry behavior

The default policy makes up to three attempts. Backoff starts at one second, doubles after each
retry, and is capped at 60 seconds. On retryable responses (`429` and `5xx`), a valid
`Retry-After` value overrides the computed delay and is capped by the same maximum. Both
delta-seconds and all HTTP-date forms required by RFC 9110 are accepted; malformed or overflowing
values fall back to the exponential schedule.

```java
PushSender sender = PushSender.builder(keys, "mailto:ops@example.com")
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
PushSender sender = PushSender.builder(keys, "mailto:ops@example.com")
    .httpClient(customPushHttpClient)
    .build();
```

The default is `JdkPushHttpClient`, with a 30-second per-request timeout. Push delivery never
reads the response body: `PushResponse` carries only the status code and headers, and
`JdkPushHttpClient` discards the body without buffering it, because the endpoint is a capability
URL taken from the (untrusted) subscription and a hostile server must not be able to feed the
sender an arbitrarily large response. Custom implementations should do the same.

This seam covers push delivery only. The Vault signer module has its own transport seam
(`VaultHttpTransport`, below) because the Vault API sits in a different trust domain and its
responses must be read.

### Redirects must never be followed

> [!WARNING]
> Neither transport seam may follow HTTP redirects. A `3xx` is a result to report, not a
> `Location` to chase — on the push side it would carry the encrypted body and the request
> headers (`TTL`, `Topic`, `Urgency`) to a host `EndpointPolicy` never saw, defeating the
> allowlist and letting the redirect target's answer count as a successful delivery; on the
> Vault side it would replay `X-Vault-Token` to whatever host a hijacked or mis-resolved Vault
> address names. The JDK strips `Authorization` across origins, but nothing else, and a
> permissive policy will also follow `https` down to `http`.

**Supplying your own `java.net.http.HttpClient`.** Build it with `Redirect.NEVER`; both
`JdkPushHttpClient(HttpClient, Duration)` and `JdkVaultHttpTransport(HttpClient, Duration, int)`
reject a client whose `followRedirects()` is anything else, with an `IllegalArgumentException`
naming the policy it found. Under the Vault starter — where a `push2uVaultHttpClient`-qualified
`HttpClient` bean is the supported injection point — that surfaces as a startup failure. Every
`HttpClient` the library builds for itself sets `Redirect.NEVER` explicitly rather than relying on
the JDK's default:

```java
HttpClient client = HttpClient.newBuilder()
    .followRedirects(HttpClient.Redirect.NEVER)   // required
    .connectTimeout(Duration.ofSeconds(10))
    .build();

PushSender sender = PushSender.builder(keys, "mailto:ops@example.com")
    .httpClient(new JdkPushHttpClient(client, Duration.ofSeconds(30)))
    .build();
```

**Implementing `PushHttpClient` or `VaultHttpTransport` yourself.** The interface contract
requires it and **nothing can verify it** — the library sees only the seam, so this one is on the
implementation. Turn redirect following off in whatever stack you wrap; several are unsafe by
default, OkHttp among them (`followRedirects` and `followSslRedirects` are both `true` until you
set `followRedirects(false).followSslRedirects(false)`). Return the `3xx` as an ordinary status
and let the caller judge it — `PushSender` for a `PushHttpClient`, the Vault signer for a
`VaultHttpTransport`.

If a redirect is genuinely part of your Vault topology — typically an HA standby with
`disable_clustering = true` answering `307` towards the active node — point the Vault address at
the active node's `api_addr` (or a load balancer in front of it), or terminate the redirect in
the proxy. On the push side there is nothing to accommodate: RFC 8030 §5 delivery has no redirect
step.

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
PushSender sender = PushSender.builder(keys, "mailto:ops@example.com")
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
rebinding, and it cannot see what happens after the connection. The one gap it would otherwise
leave — a `3xx` steering the POST to a host the allowlist never saw — is closed in the transport
(see [Redirects must never be followed](#redirects-must-never-be-followed)). Strict guarantees
require pinning resolution and egress in the transport layer — see the
[OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).
The policy is a coarse filter, not a sandbox.

### JCE provider selection

By default, cryptographic primitives resolve through the JVM provider chain. Passing a provider
binds the encryption primitives and, when the local signer is used, EC key import and ES256
signing to that provider:

```java
PushSender sender = PushSender.builder(keys, "mailto:ops@example.com")
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

Whatever the signer, its two outputs are checked on every send: the signature must be the raw
64-byte `r || s` pair (RFC 7518 §3.4) and the key the 65-byte uncompressed point (RFC 8292 §3.2).
A violation raises `PushCryptoException` saying what was returned — otherwise it would surface as
an opaque `401`/`403` on every send, with nothing pointing at the signer. If your implementation
signs through JCA, note that `SHA256withECDSA` produces DER: ask for
`SHA256withECDSAinP1363Format` or convert before returning, and the rejection message will say so
if you forget.

### Conformance kit for a custom signer

The check above is what your signer meets on every send; `push2u-testkit` is how it finds out in
its own test suite instead. It is a test-scoped artifact holding one abstract JUnit 5 class:

```kotlin
dependencies {
    testImplementation("com.the13haven:push2u-testkit:0.1.0")
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

Five checks run: the advertised public key is 65 bytes with the X9.62 uncompressed prefix, its
coordinates really do satisfy the P-256 curve equation (a well-framed off-curve point is imported
by the JCA without complaint), `publicKey()` and `sign()` each hand out a fresh array rather than
one the signer keeps — two successive calls must not return the same object — and a signature is
the raw 64-byte `r || s` that verifies against that key. Verification uses the JDK alone and runs
on a FIPS-only JVM: the kit prefers
`SHA256withECDSAinP1363Format` and, where a provider registers only DER-form `SHA256withECDSA`
(BC-FIPS), re-encodes the raw signature to minimal DER and verifies through that name — the same
fallback the library itself makes. It is the same contract `LocalEcVapidSigner` and the Vault
Transit signer are held to. The kit brings JUnit 5 and AssertJ with it, which is why it is a
separate artifact and never a dependency of `push2u-core`.

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
a health indicator that exercises the configured signer end to end: it signs a probe input and
verifies the resulting 64-byte ES256 signature locally against the signer's advertised public
key — so a signer that returns bytes which do not verify (a mispinned Vault `public-key`, for
instance) reports `DOWN` instead of failing every real send with `401`/`403`. On the rare JVM
whose providers offer no ES256 verification primitive at all, the probe degrades to checking the
signature length only and says so in the payload with a fixed `verification: unavailable` detail
(plus a one-time WARN); the detail's absence means the `UP` went through full verification.

Because the health endpoint is polled (Kubernetes probes commonly hit it every ~10 seconds per
pod) and each probe of a remote signer is a full backend round-trip — against Vault Transit, one
sign operation that is written to every audit device, counted against rate-limit quotas and, for
`managed_key`-backed keys, billed as an HSM operation — the probe result is cached per process:

```yaml
push2u:
  health:
    enabled: true      # default — false removes the indicator, so health never touches the signer
    cache-ttl: 30s     # default — how long a successful probe result is reused
```

A successful result is served from cache for `cache-ttl`; a *failed* result for at most 5 seconds
(the shorter of `cache-ttl` and 5s), so recovery is noticed quickly even under a long TTL.
Concurrent health evaluations are collapsed into a single signing operation. `cache-ttl: 0s`
disables caching entirely; negative values fail startup naming the property. The cache is
per-process by design — probes ask about the pod they run in.

The indicator participates in the health endpoint's primary group only. Spring Boot's `liveness`
group contains just the application's own liveness state, so a signer outage can never restart
pods — an unreachable Vault is not something a container restart fixes.

The indicator is registered when a `VapidSigner` bean exists, and asks about nothing else. The
signer is the only part of a send that can stop working while the application runs — it reaches a
backend that can go down, holds a token that can expire, names a key that can be deleted. The rest
of a `PushSender` is immutable configuration the builder already validated, and an incomplete
configuration fails startup rather than showing up here: health answers "what broke", not "what was
set up wrong".

While the main autoconfiguration is active, a signer bean gives you a `PushSender` bean as well (or
a startup failure naming `push2u.vapid.subject`), so this changes nothing there. Where it matters
is a context that *excludes* `Push2uAutoConfiguration` and wires its own `PushSender` around a
signer kept as a bean: the probe then applies to exactly the signer that sender uses. An
application that supplies its own `PushSender` and no `push2u.vapid.*` gets no indicator — that
sender's signer lives inside it, where the starter cannot reach it, and an indicator reporting
health it never established would be worse than its absence. When the entry is missing and you
expected it, `/actuator/conditions` (or starting with `--debug`) names the bean the condition did
not find. Note the flip side of probing a bean: an application that supplies both its own
`PushSender` *and* `push2u.vapid.*` gets an indicator that exercises the signer built from those
properties, not the one inside its sender.

`push2u.vapid.subject` is required to build the *autoconfigured* `PushSender`, regardless of where
the `VapidSigner` comes from; leaving it unset fails the context with a message naming the
property. It is not required when the application supplies its own `PushSender` bean — that bean
bypasses the starter's checks entirely.

`jwt-expiry`, `default-ttl`, `record-size` and `max-encrypted-body-bytes` are optional; unset, they
leave `PushSender`'s defaults untouched (12h, 24h, 4096 bytes and 4096 bytes respectively — see
[Payload size limits](#payload-size-limits) for the two size properties). The three `retry.*`
properties carry their own defaults instead (3 attempts, 1s initial backoff, 60s ceiling), which
match `RetryPolicy.defaults()`, so a `RetryPolicy` is always built explicitly.

Setting any of them to a value the builder — or, for `retry.*`, `RetryPolicy` itself — rejects
(`jwt-expiry` not strictly positive or over 24h, `default-ttl` negative, `record-size` below 18,
`max-encrypted-body-bytes` below the fixed 103-byte `aes128gcm` overhead, `retry.max-attempts`
below 1, or either `retry.*` backoff negative) fails the context with that message, prefixed by the
YAML property name (the builder and `RetryPolicy` only name their Java parameters). Both backoff
bounds share one message in `RetryPolicy`, so the prefix is the only thing that says which of the
two you got wrong.

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
VapidSigner signer = VaultTransitVapidSigner.builderWithFetchedPublicKey(
        URI.create("https://vault.example:8200"),
        new TransitKeyName("vapid"),
        new VaultToken(vaultToken))
    .build();
```

Everything required — the address, the key name and the token — goes into the factory method, so
an incomplete signer does not compile and `build()` never refuses over a missing value. The key
name and the token are the value types `TransitKeyName` and `VaultToken` rather than bare strings:
they cannot be swapped in the argument list, and each enforces its value's contract.
`TransitKeyName` applies Vault's own Transit key-name rule (letters, digits, `_`, `-` and `.`,
beginning and ending with a word character — Vault's `GenericNameRegex`), so no name Vault would
accept is refused while every URL-breaking character is. `VaultToken` requires non-empty visible
ASCII — rejecting the trailing newline picked up from a file or a YAML block scalar, a pasted
`Bearer ` prefix, or a stray space — without echoing the token; its format (`hvs.`, legacy `s.`,
or a dev-mode arbitrary string) is deliberately not checked, and its `toString()` prints
`VaultToken[REDACTED]`, never the value. The builder holds only the optional steps: `mount`
defaults to `transit` (in both the builder and the properties), Vault's own default mount for the
Transit secrets engine, `namespace` defaults to none (see *Vault namespaces* below), and
`transport` defaults to a `JdkVaultHttpTransport` (see *Vault HTTP
transport* below). `mount` is validated where it is set, per segment: nested mounts like
`secrets/transit` are legal, and every `/`-separated segment must be non-empty, not `.` or `..`,
and use only `[A-Za-z0-9_.-]`. The explicit allowed set exists because a literal `..` check can be
reopened by encoding: a `%2e%2e` or `%2F` segment travels in the raw request path (`URI.resolve` does not normalize dot
segments in an absolute-path reference) — Vault's own router decodes a `%2F` before routing and addresses
a different mount, a decoded dot segment draws a 307 redirect to the collapsed path from Vault's
handler (harmless under the default `Redirect.NEVER` transport, executed — `X-Vault-Token`
included — by a redirect-following custom one), and a normalizing proxy in front of Vault
collapses the path before Vault sees it. The set is deliberately narrower than Vault and URLs
allow: URL-legal punctuation like `+` or `~` in a mount name is refused by this validator's
policy, not because such a mount could not be addressed — some of that punctuation is treated
specially by intermediaries, and a conservative set can be widened later without breaking
compatibility.

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

The equivalent plain Java takes the public key at the factory method, alongside the other required
values, and the version as an optional step:

```java
VapidSigner signer = VaultTransitVapidSigner.builderWithSuppliedPublicKey(
        URI.create("https://vault.example:8200"),
        new TransitKeyName("vapid"),
        new VaultToken(vaultToken),
        publicKeyBytes)
    .keyVersion(3)
    .build();
```

There are two builders rather than one because the two modes differ in contract, not only in
parameters: `builderWithFetchedPublicKey(…)` reads Vault inside `build()` and can fail there, while
`builderWithSuppliedPublicKey(…)` contacts nothing. `keyVersion(...)` exists only on the second
one — in the fetched mode the version comes from Vault, together with the public key it belongs to.

Leaving `keyVersion` (or the `key-version` property) out sends no `key_version`; Vault then signs
with its latest version. Use that form only when the Transit key is guaranteed never to rotate.

An explicitly supplied `public-key` is checked structurally only — 65 bytes with the `0x04`
uncompressed tag. It is not verified to be a point on P-256, and nothing can check here that it is
the public half of the Transit key being signed with; both remain the caller's responsibility. The
P-256 validation described under *Fetched public key* applies to that mode alone.

### Vault namespaces (Enterprise / HCP)

Vault Enterprise and HCP Vault partition a server into
[namespaces](https://developer.hashicorp.com/vault/docs/enterprise/namespaces), addressed by the
`X-Vault-Namespace` request header. When the Transit engine lives inside one, set the namespace
and the signer sends that header on **both** Vault calls — the Transit `sign` POST and, in fetched
mode, the startup `transit/keys/<key>` GET — so no custom `VaultHttpTransport` is needed just to
add the header. When it is not set, no such header is sent at all, which is what Vault OSS (no
namespaces) expects.

In the builder it is the optional `namespace(...)` step, on both builders:

```java
VapidSigner signer = VaultTransitVapidSigner.builderWithFetchedPublicKey(
        URI.create("https://vault.example:8200"),
        new TransitKeyName("vapid"),
        new VaultToken(vaultToken))
    .namespace("team-a")
    .build();
```

In Spring Boot it is the optional `namespace` property:

```yaml
push2u:
  signer:
    vault:
      # ... address, key-name, token ...
      namespace: "team-a"
```

Nested namespaces (`team-a/sub`) are legal. Note that Vault's own CLI prints namespace paths with
a trailing slash (`team-a/`) — drop it here, since the value must not begin or end with `/`. The
value is validated where it is set, by the same
per-segment rule as `mount`: every `/`-separated segment must be non-empty, not `.` or `..`, and
use only `[A-Za-z0-9_.-]`. Two reasons, one definite: the value lands in an HTTP header, which the
allowed set keeps safe by construction (visible ASCII only, no control characters). The other is
defence in depth — a `..` cannot name a real namespace, so a value carrying one is a configuration
mistake worth refusing at startup rather than sending.

### Vault HTTP transport

All Vault calls — the Transit `sign` POST and, in fetched mode, the startup `transit/keys/<key>`
GET — go through the module's `VaultHttpTransport` seam. The default `JdkVaultHttpTransport`
(JDK `java.net.http`) enforces a per-request timeout on every call (a Vault that accepts the
connection but never answers cannot hang application startup), a fail-closed response-size cap
counted in raw streamed bytes (an oversized response fails the call; it is never truncated), and
`Redirect.NEVER` (see [Redirects must never be followed](#redirects-must-never-be-followed)).
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
   properties above are then ignored; the bean owns those concerns. Implementations must honour
   the interface contract: a response-size cap, a per-request timeout, no redirect following, and
   no request headers in exception messages.
2. A `java.net.http.HttpClient` bean qualified `push2uVaultHttpClient` — the middle road for
   mTLS/proxy setups. The starter wraps it in a `JdkVaultHttpTransport` with the configured
   `request-timeout` and `max-response-bytes` (`connect-timeout` is ignored; the supplied client
   owns it). The client must be built with `Redirect.NEVER` or startup fails — see
   [Redirects must never be followed](#redirects-must-never-be-followed), which also covers what
   to do when a Vault HA standby is the source of the redirect.
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
on `main` and on `testFixtures`, which share `main`'s packages and so its nullness contract. Reports
land in `<module>/build/reports/` (HTML and XML); the aggregated coverage report is in
`build/reports/jacoco/testCodeCoverageReport/`.

Rule exclusions carry a comment stating why, and a per-file exception is a `@SuppressWarnings`
("PMD.<Rule>") at the narrowest scope that covers it, next to the reason.

`./gradlew aggregateTestResults` collects the JUnit XML of every module — `push2u-core`'s
`fipsTest` suite included — into `build/test-results-aggregated/`. CI runs it after the quality
check and hands that directory, plus the aggregated JaCoCo XML, to Codecov.

## Contributing

Bug reports, proposals and pull requests are welcome. [`CONTRIBUTING.md`](CONTRIBUTING.md) covers
the build, what the quality gate enforces, and the two design constraints most changes run into —
the zero-dependency core and the small set of extension points.

## Security

Do not report a vulnerability in a public issue. Use GitHub's private reporting —
[Report a vulnerability](https://github.com/the13haven/push2u/security/advisories/new) — and see
[`SECURITY.md`](SECURITY.md) for the scope, the response targets and how to test safely.

## Releases

Releases are cut manually from GitHub Actions: the *Release* workflow runs the full quality
gate, tags the version, publishes signed artifacts to Maven Central through the Central Portal,
and creates a GitHub Release with generated notes. The step-by-step procedure, the required
repository secrets, and the one-time publishing setup are documented in
[`RELEASING.md`](RELEASING.md).

## License

Licensed under the [Apache License 2.0](LICENSE).

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fthe13haven%2Fpush2u.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fthe13haven%2Fpush2u?ref=badge_large)
