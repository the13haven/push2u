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

[Quick start](#quick-start) · [VAPID keys](#vapid-keys) · [Sending in detail](#sending-in-detail) ·
[Spring Boot](#spring-boot) · [Vault Transit signer](#vault-transit-signer) ·
[Endpoint policy](#endpoint-policy-ssrf-hardening) · [Modules](#modules)

Coming from `nl.martijndwars:web-push`? [`MIGRATION.md`](docs/MIGRATION.md) maps the two APIs onto
each other, lists the 26 transitive artifacts and the BouncyCastle provider registration a migration
removes, and is explicit about where push2u is stricter — `https`-only endpoints, up-front size
limits, `aes128gcm` only, and a VAPID private key that has to be exactly 32 bytes.
[`DESIGN.md`](docs/DESIGN.md) has the architecture and the decisions behind it.

## Features

- Zero runtime *implementation* dependencies in `push2u-core`: the only artefact it brings along is
  [JSpecify](https://jspecify.dev), an annotation-only jar of nullness annotations.
- RFC 8291 / RFC 8188 payload encryption using JDK cryptography.
- RFC 8292 VAPID authentication with a local EC key or an external signer.
- JDK `HttpClient` transport, with a small transport SPI for replacements.
- Normal result handling for expired subscriptions (`404` / `410`).
- Configurable retry policy for `429` and `5xx` responses.
- Optional HashiCorp Vault Transit signer.
- Optional Spring Boot 4 auto-configuration and health indicator.

## Requirements

- Java 21 or newer at runtime.
- A VAPID P-256 key pair ([how to get one](#vapid-keys)), or an implementation of `VapidSigner`.
- An HTTPS Web Push subscription endpoint containing the browser-provided `p256dh` and `auth`
  values.
- Spring Boot 4.x, for either of the two starters — see [Spring Boot](#spring-boot).

## Installation

Add the core module from Maven Central:

```kotlin
dependencies {
    implementation("com.the13haven:push2u-core:0.1.0")
}
```

## Quick start

The browser supplies the endpoint, `p256dh`, and `auth` values — the endpoint at the top level of
`PushSubscription.toJSON()`, the two keys under its `keys` object:

```json
{"endpoint": "https://…", "keys": {"p256dh": "BN…", "auth": "k8…"}}
```

JSON parsing remains an application responsibility. Use only the HTTPS endpoint returned by the
browser, and treat the complete endpoint as a secret: Web Push endpoints are capability URLs.

`Subscription` validates what it accepts: the endpoint must be an absolute `https` URL, `auth`
must be 16 bytes, and `p256dh` must decode to a real point on the P-256 curve — not merely a
65-byte value of the right shape. Both `p256dh` and the endpoint are attacker-influenced (a
registration endpoint accepts whatever a client posts), and a subscription carrying an off-curve
point can never be sent to, so it is rejected with an `IllegalArgumentException` where the
subscription is created instead of failing as a `PushCryptoException` on every later send. The
curve check runs on the fixed FIPS 186-4 P-256 parameters and needs no JCA provider, so it works
wherever the subscription is built. To enforce the same contract at your own registration
boundary — rejecting a bad registration before persisting it — the checks are public:
`Endpoints.requireSecure(endpoint)` for the endpoint, `P256PublicKeys.requireOnCurve(bytes,
"p256dh")` for the key material (and `P256PublicKeys.requireUncompressedPoint` when only the
shape matters).

```java
Subscription subscription = Subscription.fromBase64(
    browserSubscription.endpoint(),
    browserSubscription.p256dh(),
    browserSubscription.auth());

PushSender sender = PushSender.builder(
        VapidKeys.fromBase64(vapidPublicKey, vapidPrivateKey), "mailto:ops@example.com",
        EndpointPolicies.allowedOrigins("https://fcm.googleapis.com"))
    .build();

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

`VapidKeys.fromBase64` expects a 65-byte uncompressed P-256 public key and a 32-byte private
scalar, both encoded as unpadded base64url — [VAPID keys](#vapid-keys) covers where that pair comes
from and how long it lives. The contact is used as the VAPID `sub` claim and should be a `mailto:`
or `https:` URI. RFC 8292 §2.1 leaves `sub` optional; push2u requires it, because a push service
with a problem to report about your application server has no other way to reach you. It is
therefore a parameter of the factory method — omitting it does not compile, and a blank one is
rejected with an `IllegalArgumentException`. To delegate signing to an external `VapidSigner` (for
example the [Vault Transit signer](#vault-transit-signer)), pass the signer instead of the keys:
`PushSender.builder(signer, "mailto:ops@example.com", policy)`.

The third parameter is the [endpoint policy](#endpoint-policy-ssrf-hardening), and it is required
for the same reason the contact is: a subscription's endpoint decides where the send goes, and a
sender built without a rule would POST wherever that endpoint points. The library does not choose
the rule for you — `EndpointPolicies.allowedEndpoints(…)` takes the allowlist naming the push
services your users arrive from, and `EndpointPolicies.unrestricted()` says, in your own source,
that this deployment applies no restriction.

A `PushSender` holds only final configuration and keeps no per-send state, so build one at startup
and share that instance across every thread that sends. A custom `PushHttpClient` or `VapidSigner`
has to be thread-safe for the same reason; the ones shipped here are.

The three message headers are optional. Without `ttl`, the message goes out with the sender's
default of **24 hours** — how long the push service may hold it for a client that is offline;
`Duration.ZERO` means deliver now or drop it. `Urgency` is `VERY_LOW`, `LOW`, `NORMAL` or `HIGH`
(RFC 8030 §5.3): it tells the push service whether waking a battery-constrained device is worth it,
and `NORMAL` is what it assumes when the header is absent.

`404` and `410` are returned as `SUBSCRIPTION_EXPIRED`, not as exceptions. Transport failures
throw `PushDeliveryException`; cryptographic failures throw `PushCryptoException`. When present,
`topic` is validated locally before transport: it must contain 1–32 characters from the URL-safe
Base64 alphabet (`A-Z`, `a-z`, `0-9`, `-`, `_`) required by RFC 8030.

## VAPID keys

Every send is signed with a VAPID (RFC 8292) P-256 key pair, and push2u never produces one: it has
no key generator, and nothing in it derives, rotates or replaces a key. The pair is your
application's identity to the push services, so it is created once, outside the application, and
handed to it as configuration.

### The lifecycle

- **One pair per application**, generated once — not per user, per subscription, per instance or
  per deployment. Every instance of the same application signs with the same pair.
- **The public half is handed to the browser** as the `applicationServerKey` option of
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

The public key is the **65-byte uncompressed X9.62 point** that
[RFC 8292 §3.2](https://datatracker.ietf.org/doc/html/rfc8292#section-3.2) defines and browsers take
as `applicationServerKey`; the private key is the **raw 32-byte scalar** `VapidKeys` takes. Both
unpadded base64url. [`VAPID.md`](docs/VAPID.md) is the recipe — a `jshell` block that prints exactly
those two, and an npm alternative. It prints the private half to the terminal, so run it where you
would handle any other secret: a workstation or a bastion, not CI.

### Where the two values go

With the Spring Boot starter, as `push2u.vapid.public-key` and `push2u.vapid.private-key` — see
[Spring Boot](#spring-boot) for the block they go in. With the core alone, through
`VapidKeys.fromBase64(publicKey, privateKey)` — see [Quick start](#quick-start). Either way the
public key is also what the browser needs as `applicationServerKey`; the private key never leaves
the application server.

### Publishing the public key to the browser

The frontend needs that key as a string, and push2u produces it rather than leaving you to spell it:

```java
String applicationServerKey = VapidKeys.encodePublicKey(keys.publicKey()); // from a pair you hold
String sameValue = signer.publicKeyBase64Url();                            // from any VapidSigner
```

`VapidSigner.publicKeyBase64Url()` is a `default` method, so every signer has it — including one
whose key lives in a remote custodian and never appears in configuration at all, which is the
[Vault Transit signer](#vault-transit-signer)'s recommended mode. Asking the signer is also the only
way to be sure the key you advertise is the key the next send will be signed with.

Both produce unpadded base64url in the URL-safe alphabet (`-` and `_`, never `+`, `/` or `=`) over
the raw 65-byte X9.62 point — not a `SubjectPublicKeyInfo`, which is what `ECPublicKey.getEncoded()`
returns and what the browser cannot read. All three are contract rather than taste, and the same
contract on both sides: `pushManager.subscribe(...)` reads a string `applicationServerKey` as
[RFC 7515 §2](https://datatracker.ietf.org/doc/html/rfc7515#section-2) base64url — the URL-safe
alphabet with every trailing `=` omitted — and RFC 8292 §3.2 spells the `k` parameter the same way.
So the standard alphabet and the padding each break the browser's contract and the header's alike.

What differs is how the browser reports them. A string it will not decode rejects with an
`InvalidCharacterError`, while a `SubjectPublicKeyInfo` decodes perfectly well and is then refused
for not describing a valid point on P-256, with an `InvalidAccessError` — steps 10.2 and 10.3 of
[`subscribe()`](https://www.w3.org/TR/push-api/#subscribe-method). Either lands in a console far
from the code that produced the string.

`VapidKeys.encodePublicKey` additionally refuses bytes that are not a
point on P-256 with an `IllegalArgumentException`, since they may have come from anywhere;
`publicKeyBase64Url()` applies exactly the check a send applies to the same value, and raises the
same `PushCryptoException` with the same wording when a signer returns the wrong shape.

Holding the private key in a secret store you would rather not hand to the application at all is
what the [Vault Transit signer](#vault-transit-signer) is for: the key stays in Vault, and push2u
sends signing requests instead of loading a scalar. **If that is where you are heading, do not
generate a pair at all** — create the key inside Vault, so the scalar never exists outside it:

```bash
vault write -f transit/keys/<name> type=ecdsa-p256
```

The signer reads the public half from Vault itself; see
[Vault Transit signer](#vault-transit-signer).

## Sending in detail

Everything on the builder is optional — the key source, the contact and the endpoint policy are the
factory method's three parameters, and there is nothing else a sender needs. Two steps are named
nowhere else here: `defaultTtl(Duration)` is the `TTL` header used when a message carries none —
24 hours unless you change it — and `jwtExpiry(Duration)` is how long each VAPID JWT stays valid,
12 hours by default, with RFC 8292 §2 capping it at 24 (the builder rejects more, and anything not
strictly positive).

The examples below are about one builder step each, so they pass the policy as a variable built
once at startup — the allowlist itself is in [Endpoint policy](#endpoint-policy-ssrf-hardening):

```java
EndpointPolicy pushServices = EndpointPolicies.allowedOrigins("https://fcm.googleapis.com");
```

### VAPID token reuse

**One signed token serves every message to a push-service origin, not one per message.** Nothing in
a VAPID token is per-message: RFC 8292 §2 gives it three claims — the push service's *origin*, your
contact, and the expiry `jwtExpiry(Duration)` puts 12 hours out by default. So `PushSender` signs
one token per origin and reuses it for every later send to that origin, until it comes within
`jwtRenewBefore(Duration)` of the expiry — five minutes by default — and signs a fresh one. RFC
8292 §5 encourages this outright, because reuse also lets a push service cache the result of
verifying the signature. A fan-out to 100 000 subscriptions therefore pays for a handful of
signatures rather than 100 000 — a useful saving on a local key pair, and a decisive one with the
[Vault Transit signer](#vault-transit-signer), where every signature is a network round trip and
Vault's availability would otherwise gate every push.

The tokens sit in a per-sender cache bounded at `jwtCacheSize(int)` entries — 64 by default,
evicting the least recently used. That bound is not a tuning knob but the reason the cache is safe
to hold: the origins a sender meets come from the endpoints inside the subscriptions it is handed,
which are as trustworthy as wherever those subscriptions arrive from. A full cache costs a
signature per send, never a delivery.

```java
PushSender sender = PushSender.builder(keys, "mailto:ops@example.com", pushServices)
    .jwtRenewBefore(Duration.ofMinutes(15))  // a longer margin for slow sends or loose clocks
    .jwtCacheSize(128)
    .build();
```

The margin is an absolute duration rather than a fraction of `jwtExpiry`, because both things it
covers are absolute: clock skew against the push service, which checks `exp` against its own clock,
and a send that picked a token up just before the boundary and must still present a valid one at
its last retry — with `Retry-After` honoured up to the retry policy's ceiling, that is minutes
rather than seconds. Raise it if your retry policy or HTTP timeouts allow a longer send. A negative
value is rejected; `Duration.ZERO` is legal and means the *most* reuse — the token is held to its
last second, with the skew consequences of saying so — and a value at or above `jwtExpiry` means
the margin has swallowed the token's whole life, so every send signs afresh. `jwtCacheSize(0)` is
rejected rather than read as "cache nothing": the bound is not a second spelling of the switch
below, and the two mean different things.

**`jwtReuse(false)` switches reuse off**, and every send builds and signs its own token, exactly as
this library always did:

```java
PushSender sender = PushSender.builder(keys, "mailto:ops@example.com", pushServices)
    .jwtReuse(false)
    .build();
```

Three situations call for it. A push service that refuses a token it has seen before would answer
`401` or `403` on every send to that origin after the first, with a signature that verifies — this
is the remedy, and it needs no new release of anything. A deployment that treats process memory as
reachable may not want a bearer credential resident at all: nothing sweeps the cache, so an entry
leaves it only when a later send to that origin finds it stale and replaces it, or when the bound
evicts it — an origin that goes quiet keeps its header, and the token inside stays usable until its
own `exp`, which `jwtRenewBefore` does not move. Lowering the margin therefore shortens residency
only where sends to that origin keep arriving; `jwtReuse(false)` is what puts a token in the
process for the length of one send and no longer, which is what this library did before. And it
makes a signer whose signing key rotates under an unchanged advertised key fail at once rather than
up to `jwtExpiry` later.

### Asynchronous sending

`sendAsync(subscription, message)` returns a `CompletableFuture<PushResult>`. The blocking send
pipeline runs on a library-owned virtual-thread-per-task executor by default, never on the common
`ForkJoinPool`. Applications that need admission control or a shared execution policy can provide
their own executor:

```java
PushSender sender = PushSender.builder(keys, "mailto:ops@example.com", pushServices)
    .executor(pushExecutor)
    .build();
```

The supplied executor remains application-owned; `PushSender` does not shut it down.

### Payload size limits

RFC 8030 §7.2 allows a push service to refuse an entity body larger than 4096 bytes, so
`PushSender` caps the encrypted body at 4096 bytes by default and rejects an oversized message
with `IllegalArgumentException` before encrypting it or contacting the push service.

The single-record `aes128gcm` body adds a fixed 103 bytes of header, padding delimiter and
authentication tag to the plaintext ([`DESIGN.md` §4](docs/DESIGN.md#4-send-pipeline) breaks the
figure down), so the default admits **3993 bytes of plaintext** — the figure RFC 8291 §4 derives.
The record size defaults to 4096 as well, so raising one without the other rejects the message.

```java
PushSender sender = PushSender.builder(keys, "mailto:ops@example.com", pushServices)
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

### Retry behavior

The default policy makes up to three attempts. Backoff starts at one second, doubles after each
retry, and is capped at 60 seconds. On retryable responses (`429` and `5xx`), a valid
`Retry-After` value overrides the computed delay and is capped by the same maximum. Both
delta-seconds and all HTTP-date forms required by RFC 9110 are accepted; malformed or overflowing
values fall back to the exponential schedule.

```java
PushSender sender = PushSender.builder(keys, "mailto:ops@example.com", pushServices)
    .retryPolicy(new RetryPolicy(
        5,
        Duration.ofMillis(500),
        Duration.ofSeconds(30)))
    .build();
```

Use `RetryPolicy.none()` to disable retries.

**Budget for the worst case before calling `send` from a request thread.** On the defaults, three
attempts at the default 30-second per-request timeout plus 1 s and 2 s of backoff is **93
seconds** of blocking; a push service that answers `429` with a large `Retry-After` raises that to
the 60-second ceiling per wait, so **3.5 minutes**. Either lower the numbers, or use
`sendAsync(…)` and let the request thread go.

## Spring Boot

`push2u-spring-boot-starter` binds the `push2u.*` properties to an autoconfigured `PushSender`,
adds a default `PushHttpClient`, and — when Spring Boot health support is present — a health
indicator that probes the configured signer. Application beans of the same types take precedence.
Both starters require **Spring Boot 4.x**. They do not work on Boot 3.x — among other things, the
health indicator sits on `spring-boot-health`, a module that arrived in Boot 4.0.

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
  allowed-origins:
    - "https://fcm.googleapis.com"
    - "https://updates.push.services.mozilla.com"
  allowed-domains:
    - "push.apple.com"
    - "notify.windows.com"
```

That is a complete configuration: everything else has a default. The allowlist is not optional,
though — it is the [endpoint policy](#endpoint-policy-ssrf-hardening), and a context with neither
of the two properties set nor an `EndpointPolicy` bean fails to start with a message naming every
way to fix it. The two properties are not alternatives: they are unioned into one allowlist, and a
deployment covering all four browser push services writes both. There is deliberately no property
for the unrestricted mode: under Spring it is an application `@Bean EndpointPolicy` returning
`EndpointPolicies.unrestricted()`, so that turning the control off is a code change someone reviews
rather than a line copied between profiles. [`SPRING.md`](docs/SPRING.md) is the reference — every
`push2u.*` property and what a rejected value does to startup, the two allowlist properties beside
an `EndpointPolicy` bean, and the health indicator with its cache.

## Vault Transit signer

An optional `VapidSigner` that keeps the VAPID private key inside HashiCorp Vault: push2u sends
signing requests to the Transit engine, and the scalar never reaches the application. For plain
Java, add the signer module:

```kotlin
dependencies {
    implementation("com.the13haven:push2u-signer-vault:0.1.0")
}
```

```java
VapidSigner signer = VaultTransitVapidSigner.builderWithFetchedPublicKey(
        URI.create("https://vault.example:8200"),
        new TransitKeyName("vapid"),
        new VaultToken(vaultToken))
    .build();

PushSender sender = PushSender.builder(signer, "mailto:ops@example.com", pushServices).build();
```

For Spring Boot, combine the core starter with the Vault signer starter. The latter already
brings in `push2u-signer-vault`:

```kotlin
dependencies {
    implementation("com.the13haven:push2u-spring-boot-starter:0.1.0")
    implementation("com.the13haven:push2u-signer-vault-spring-boot-starter:0.1.0")
}
```

[`VAULT.md`](docs/VAULT.md) is the reference — the two key modes and what each validates, the
`push2u.signer.vault.*` properties, Vault namespaces on Enterprise/HCP, and the transport seam
every Vault call goes through.

## Endpoint policy (SSRF hardening)

The endpoint inside a `Subscription` is attacker-influenced data: a typical integration accepts
the browser's `PushSubscription` JSON at a public registration endpoint, and nothing stops a
client from posting a hand-crafted subscription whose endpoint points into your own network — a
loopback port, a private-range address, a cloud metadata service. Every later send then POSTs to
that address from inside your network, and the visible outcome (`PushResult.statusCode()` versus
`PushDeliveryException`, plus timing) is a blind SSRF oracle for internal host and port
existence.

Which endpoints a sender may POST to is therefore a decision the deployment has to make, and
`PushSender` takes it as the third parameter of its factory method rather than as an optional
builder step — there is no way to obtain a sender without naming a policy. For almost every
deployment that policy is an allowlist naming the browser push services its users can actually
arrive from:

```java
EndpointPolicy pushServices = EndpointPolicies.allowedEndpoints(
    EndpointRule.origin("https://fcm.googleapis.com"),                // Chrome and Chromium
    EndpointRule.origin("https://updates.push.services.mozilla.com"), // Firefox
    EndpointRule.domain("push.apple.com"),                            // Safari, through APNs
    EndpointRule.domain("notify.windows.com"));                       // Edge, through WNS

PushSender sender = PushSender.builder(keys, "mailto:ops@example.com", pushServices).build();
```

An allowlist entry is a value that carries its own kind, so the list says what each entry means
rather than leaving the meaning to the factory it was passed to. An **origin** rule matches one
origin exactly. A **domain** rule matches a whole DNS zone — the apex and every subdomain at any
depth — which is what two of the four standard services ask for, each in its own documentation.
Apple tells a server in control of its push endpoints to "allow URLs from `*.push.apple.com`"
([Web Push for Web Apps on iOS and iPadOS](https://webkit.org/blog/13878/web-push-for-web-apps-on-ios-and-ipados/)),
and Microsoft gives `*.notify.windows.com` as the FQDN a cloud service sending to WNS — which is
where Edge's endpoints live — must be allowed to reach, "because these will not change"
([Firewall allowlist configuration](https://learn.microsoft.com/en-us/windows/apps/develop/notifications/push-notifications/firewall-allowlist-config)).
`allowedEndpoints` is therefore the ordinary cross-browser call, not an advanced one.
[`PUSH-SERVICES.md`](docs/PUSH-SERVICES.md) carries the four services and this same allowlist in
both spellings, ready to copy, with what each vendor's page does and does not say and why no
browser is missing from it.

`EndpointPolicies.allowedOrigins(…)` and `EndpointPolicies.allowedDomains(…)` are the convenience
over it for a list of one kind — they take plain strings and build the rules for you. The rule
kinds are closed: `EndpointRule` is sealed and holds exactly these two, because they are what the
library knows how to match, not a place to add a third from outside.

The policy runs on every send — `sendAsync` included, it goes through the same pipeline —
before encryption, before the VAPID signature (a remote Vault/KMS call under an external
signer), and before any network I/O. A rejected endpoint throws `EndpointRejectedException`
and costs none of them. The exception extends `RuntimeException` directly (deliberately not
`IllegalArgumentException`, which web frameworks commonly map to a 400 response echoing the
message), so a loop over stored subscriptions can tell "this subscription violates policy —
flag or remove it" apart from a retryable transport failure (`PushDeliveryException`); its
message never contains the endpoint's path or query, because a push endpoint is a capability
URL.

The endpoint is normalized once, and every rule compares against that one value — RFC 6454
normalization on both sides, so lowercase scheme and host, IDNA A-labels decoded and the default
`:443` dropped, and `https://PUSH.Example:443` in the configuration matches an endpoint on
`https://push.example`. Whatever the rule, an endpoint carrying userinfo
(`https://allowed.example@evil.example/…`) is rejected outright — no push service issues such
endpoints, and rejecting the shape also protects custom transports that re-parse the URL string
differently.

**An origin rule is exact and fail-closed**: subdomains of an allowed origin are not allowed, and
a host with a trailing dot (`push.example.`) is a different origin from `push.example` and is
rejected.

**A domain rule matches at a label boundary**, so `notify.windows.com` admits
`cloud.notify.windows.com` and any depth below it, and refuses `evilnotify.windows.com` — the dot
belongs to the boundary, which is the whole of the difference. It matches only the scheme `https`
and the default port, absent or an explicit `443`: a domain is a statement about which *names* are
trusted, while a port is a statement about which service on a host is, and a rule spanning every
port of a zone would be an SSRF oracle again, relocated. A deployment that needs
`https://push.internal.example:8443` names it exactly with an origin rule.

The library makes **no public-suffix judgement** — there is none in the JDK, and it will not carry
a data file that ages between releases while looking authoritative. A domain rule is worth exactly
what the DNS of that zone is worth, and over a shared hosting zone it permits every tenant of it.
The rule of thumb is that a domain rule belongs only where the service operator *publishes the
zone* rather than the host — by documenting that its hostnames vary within it, or by naming the
zone as what your server should be allowed to reach. Anything else is an origin rule.

A malformed allowlist entry fails at construction, so a misconfigured allowlist fails deployment
startup instead of misbehaving at send time. An origin entry is refused when it is unparseable,
non-`https`, hostless, or carries a path, query, fragment or userinfo. A domain entry is refused
when it carries a control character — a line copied out of a terminal, or a carriage return from a
file written on Windows — or any URI delimiter at all, a scheme, a port, a path, a query, a fragment
or an `@`, or a `*`, a leading dot, an empty label, a trailing root dot, a single label such as
`com`, an IP literal, or raw Unicode; spell an internationalised host in its A-label form. The
refusal names the entry the way a rejection names an endpoint: an origin entry is rendered with its
path and query stripped, since a pasted capability URL is exactly the mistake being reported, and a
domain entry appears verbatim only when it is a plain host-shaped token.

`EndpointPolicy` itself is a functional interface (`void validate(URI endpoint)`), so corporate
egress rules or custom DNS checks can be expressed directly — that seam is where a rule neither of
the two kinds can express belongs. The policy is fixed when the sender is built and receives only
the URI — a rule that varies by tenant means one sender per tenant.

**Sending anywhere is still possible, and has a name.** `EndpointPolicies.unrestricted()` accepts
every endpoint `Subscription` accepts — loopback, private-range and cloud-metadata addresses
included — and is the right choice where subscriptions never arrive from untrusted clients (they
are entered by operators, or imported from a system inside your trust boundary), or where egress
is already pinned in a proxy or firewall this library cannot see. It is a required argument like
any other, so choosing it puts a line in your own source that shows up in a diff, a review and a
grep. That is the whole difference from an omitted configuration step, which shows up in none of
them.

Know the limits either way: a URI-level check cannot close DNS rebinding, and it
cannot see what happens after the connection. The one gap it would otherwise leave — a `3xx`
steering the POST to a host the allowlist never saw — is closed in the transport (see
[Redirects must never be followed](#redirects-must-never-be-followed)). Strict guarantees
require pinning resolution and egress in the transport layer — see the
[OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).
The policy is a coarse filter, not a sandbox.

## Custom HTTP transport

Implement `PushHttpClient` when the application needs a different HTTP stack, proxy policy, or
observability integration:

```java
PushSender sender = PushSender.builder(keys, "mailto:ops@example.com", pushServices)
    .httpClient(customPushHttpClient)
    .build();
```

The default is `JdkPushHttpClient`, with a 30-second per-request timeout. Push delivery never
reads the response body: `PushResponse` carries only the status code and headers, and
`JdkPushHttpClient` discards the body without buffering it, because the endpoint is a capability
URL taken from the (untrusted) subscription and a hostile server must not be able to feed the
sender an arbitrarily large response. Custom implementations should do the same.

This seam covers push delivery only. The Vault signer module has its own —
[`VaultHttpTransport`](docs/VAULT.md#vault-http-transport) — because the Vault API sits in a
different trust domain and its responses must be read.

## Redirects must never be followed

> [!WARNING]
> Neither transport seam may follow HTTP redirects. A `3xx` is a result to report, not a
> `Location` to chase — on the push side it would carry the encrypted body and the request
> headers (`TTL`, `Topic`, `Urgency`) to a host [`EndpointPolicy`](#endpoint-policy-ssrf-hardening)
> never saw, defeating the allowlist and letting the redirect target's answer count as a successful
> delivery; on the Vault side it would replay `X-Vault-Token` to whatever host a hijacked or
> mis-resolved Vault address names. The JDK strips `Authorization` across origins, but nothing else, and a
> permissive policy will also follow `https` down to `http`.

**Supplying your own `java.net.http.HttpClient`.** Build it with `Redirect.NEVER`; both
`JdkPushHttpClient(HttpClient, Duration)` and `JdkVaultHttpTransport(HttpClient, Duration, int)`
reject a client whose `followRedirects()` is anything else, with an `IllegalArgumentException`
naming the policy it found — under the Vault starter, where a `push2uVaultHttpClient`-qualified
`HttpClient` bean is the supported injection point, that surfaces as a startup failure. Every
`HttpClient` the library builds for itself sets `Redirect.NEVER` explicitly rather than relying on
the JDK's default:

```java
HttpClient client = HttpClient.newBuilder()
    .followRedirects(HttpClient.Redirect.NEVER)   // required
    .connectTimeout(Duration.ofSeconds(10))
    .build();

PushSender sender = PushSender.builder(keys, "mailto:ops@example.com", pushServices)
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

On the push side there is nothing to accommodate: RFC 8030 §5 delivery has no redirect step. A
Vault topology that genuinely answers `307` — an HA standby, typically — is dealt with in
[`VAULT.md`](docs/VAULT.md#vault-http-transport).

## JCE provider selection

By default, cryptographic primitives resolve through the JVM provider chain. Passing a provider
binds the encryption primitives and, when the local signer is used, EC key import and ES256
signing to that provider:

```java
PushSender sender = PushSender.builder(keys, "mailto:ops@example.com", pushServices)
    .cryptoProvider(provider)
    .build();
```

The choice is not only about policy: the elliptic-curve work is almost all of what a send costs
locally, and providers differ on it by a factor worth confirming on your own hardware.
[`PERFORMANCE.md`](docs/PERFORMANCE.md) records one such comparison, step by step, with the machine
it was taken on.

The provider must support EC key generation/import, ECDH, HMAC-SHA-256, AES-GCM, and an ES256
signature form when `LocalEcVapidSigner` is used. The library prefers
`SHA256withECDSAinP1363Format`; if the selected provider exposes only DER-output
`SHA256withECDSA` (as BC-FIPS does), it signs with that algorithm on the same provider and strictly
re-encodes the result to JOSE's 64-byte `r || s` form. The fallback never widens provider lookup.
An external `VapidSigner` controls its own signing provider.

`LocalEcVapidSigner` also performs a one-time sign-and-verify self-test when it is constructed.
A public key that does not correspond to the configured private scalar is therefore rejected at
startup instead of producing repeated `401`/`403` responses at send time.

Whatever the signer, its two outputs are checked wherever a new one enters a send: the signature
must be the raw 64-byte `r || s` pair (RFC 7518 §3.4) and the key the 65-byte uncompressed point
(RFC 8292 §3.2). Under the default token reuse that is every send that signs — a reused
`Authorization` value was checked when it was signed, and `sign` is not called for it again — so a
misencoded signer is still caught the first time it is asked, on the send that asks. A violation
raises `PushCryptoException` saying what was returned; otherwise it would surface as an opaque
`401`/`403`, with nothing pointing at the signer. If your implementation signs through JCA, note
that `SHA256withECDSA` produces DER: ask for `SHA256withECDSAinP1363Format` or convert before
returning, and the rejection message will say so if you forget.

**The key a signer advertises must stay the same for that signer's lifetime.** VAPID's public key
is your application server's published identity: a browser subscription is bound to the
`applicationServerKey` it was created with, and RFC 8292 §4.2 lets a push service refuse a JWT
whose key is not the one that subscription was created under. So a signer that starts answering
`publicKey()` differently has already broken every restricted subscription taken out before the
change — rotation is a re-subscription event that produces a *new* signer, not a new answer from
the existing one. The library cannot check this from outside, since two equal answers say nothing
about the next one, and states it as contract instead.

## Conformance kit for a custom signer

The checks above are what your signer meets on the sends that reach it; `push2u-testkit` is how it
finds out in its own test suite instead. It is a test-scoped artifact holding one abstract JUnit
Jupiter class:

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
Transit signer are held to. The kit brings JUnit Jupiter and AssertJ with it, which is why it is a
separate artifact and never a dependency of `push2u-core`.

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
is a `requires static`: nothing resolves that jar at runtime, and you need it only if something
reads the annotations reflectively — then add the module explicitly (`--add-modules org.jspecify`),
since a `static` requires is not resolved on its own.

The two Spring Boot starters are automatic modules with a fixed `Automatic-Module-Name`, because
Boot's own artifacts are automatic modules and its auto-configuration is reflective. `push2u-testkit`
is likewise automatic: it carries JUnit and AssertJ, which are automatic modules themselves.

## Protocol limits

Four things this library will not do, whatever it is configured with:

- Content coding other than `aes128gcm`, or more than one RFC 8188 record per message.
- A VAPID JWT valid for longer than 24 hours (RFC 8292 §2).
- Anything with the subscription after the send: the library is stateless, and persisting or
  deleting one belongs to the application.
- A body over the configured limits — see [Payload size limits](#payload-size-limits) for the two
  that are raisable and how they interact.

## Nullness

Every package is [JSpecify](https://jspecify.dev) `@NullMarked`: a reference type in the API is
non-null unless annotated `@Nullable` — the annotated exceptions are the optional message headers,
the unset builder fields and the Spring properties. NullAway fails the build on a violation, and
consumers' analysers, IntelliJ and the Kotlin compiler read the same annotations
([ADR-012](docs/adr/0012-nullness-declared-with-jspecify.md)).

## Contributing

Bug reports, proposals and pull requests are welcome. [`CONTRIBUTING.md`](CONTRIBUTING.md) covers
the build, what the quality gate enforces, [how to build against a local
checkout](CONTRIBUTING.md#developing-against-unpublished-changes), and the two design constraints
most changes run into — the zero-dependency core and the small set of extension points.

## Security

Do not report a vulnerability in a public issue. Use GitHub's private reporting —
[Report a vulnerability](https://github.com/the13haven/push2u/security/advisories/new) — and see
[`SECURITY.md`](SECURITY.md) for the scope, the response targets and how to test safely.

## Releases

Releases are cut manually from GitHub Actions; the procedure, the required repository secrets and
the one-time publishing setup are in [`RELEASING.md`](docs/RELEASING.md).

## License

Licensed under the [Apache License 2.0](LICENSE).

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fthe13haven%2Fpush2u.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fthe13haven%2Fpush2u?ref=badge_large)
