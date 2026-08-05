# push2u — Design

## 1. Status and scope

push2u is an implemented, standalone Java library for server-side Web Push delivery. Artifacts
are released to Maven Central under the `com.the13haven` group ID; the version is derived from
git tags rather than stored in the build (ADR-013). Java packages are `com.the13haven.push2u.*`.

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
└── JdkPushHttpClient

push2u-testkit
└── VapidSignerContractTest (the published conformance kit, for a test classpath)

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
opt-in and cannot leak framework types into the core API. `push2u-testkit` carries JUnit and
AssertJ, which is why it is a module of its own and not part of the core: it belongs on a
consumer's test classpath and never on an application's runtime one.

Each artifact carries a JPMS identity (ADR-014). `push2u-core` and `push2u-signer-vault` are
explicit modules with a `module-info.java`; the two starters and the published test kit are
automatic modules with a fixed `Automatic-Module-Name`:

| Artifact | Module name | Kind |
|---|---|---|
| `push2u-core` | `com.the13haven.push2u` | explicit |
| `push2u-signer-vault` | `com.the13haven.push2u.signer.vault` | explicit |
| `push2u-spring-boot-starter` | `com.the13haven.push2u.spring` | automatic |
| `push2u-signer-vault-spring-boot-starter` | `com.the13haven.push2u.signer.vault.spring` | automatic |
| `push2u-testkit` | `com.the13haven.push2u.testkit` | automatic |

## 4. Send pipeline

```text
PushSender.send(subscription, message)
    │
    ├─ Check the payload against the body limit and the record size
    ├─ Validate the endpoint against the configured EndpointPolicy (no policy by default)
    ├─ Decode the subscription P-256 public key, checking the point is on the curve
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
| Endpoint policy rejection | `EndpointRejectedException` |

The encrypted body and VAPID token are reused across retries of the same send operation.

The endpoint policy runs after the size preconditions and before everything else — encryption,
the VAPID signature (a remote Vault/KMS call under an external signer) and the POST — so a
rejected endpoint costs no cryptography and no I/O. `sendAsync` runs the same pipeline, so the
policy cannot be bypassed on the async path.

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

`PushSender` is the primary facade. Its two required values — exactly one VAPID key source, plus
the contact — are the factory method's parameters, so an incomplete sender does not compile and
`build()` has nothing left to refuse:

- `builder(VapidKeys, String contact)` creates `LocalEcVapidSigner`; or
- `builder(VapidSigner, String contact)` delegates signing and public-key publication.

The two are overloads of one `builder(…)` rather than differently named methods: they differ only
in which required key source they take, not in contract — and the overload choosing the key source
is what makes "no key source" and "both key sources" inexpressible rather than runtime errors.

The VAPID contact is required in both modes and must be non-blank. RFC 8292 §2.1 leaves the `sub`
claim optional; requiring it is a push2u contract, on the grounds that a push service reporting a
problem with an application server has no other channel to it. A blank value is rejected outright,
because it satisfies that contract no better than an absent claim while still producing a JWT whose
`sub` a push service may well reject — the RFC requires neither the claim nor its rejection.
Optional settings control the HTTP transport, async executor, JCE provider, retry policy, JWT
expiry, default TTL, RFC 8188 record size, the maximum encrypted body size, and the endpoint
policy. The record size and body size are validated when configured: `recordSize` must be at
least 18 (RFC 8188 §2) and `maxEncryptedBodyBytes` must be at least the fixed 103-byte overhead —
the body an empty payload produces. The endpoint policy is off by default (backward
compatibility: with no policy, any endpoint satisfying `Endpoints.requireSecure` is sent to) and
is described under its SPI below.

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

The contract requires a raw 64-byte P-256 `r || s` ES256 signature (RFC 7518 §3.4) and a 65-byte
uncompressed P-256 public point (RFC 8292 §3.2), and **both are checked on every send** — a
violation raises `PushCryptoException` naming what came back. The check exists because neither
half fails visibly on its own: a signature or key of the wrong shape still yields a syntactically
valid `Authorization` header, so without it the mistake reaches the caller as an opaque 401/403
from the push service, on every send, with nothing naming the signer. DER is the case worth
naming, and the message does: JCA's `SHA256withECDSA` returns it, and a signer forwarding its
provider's output unconverted looks correct until the wire. The library converts for its own
signer (above) but cannot here — the provider and encoding behind an external signer are unknown,
and a valid 64-byte signature may itself begin with `0x30`.

Both methods return arrays, and the arrays are the caller's. `publicKey()` in particular must
return a fresh copy on every call: a signer handing out its internal array is corrupted for every
later send by the first caller that writes into the returned bytes, and nothing would notice — the
mutated key is still a well-formed point. Both shipped signers return a `clone()`, and the
conformance kit pins both halves by identity — two successive calls must not return the same object
— rather than by mutating and looking for consequences. That choice is load-bearing: a signer
refilling one shared buffer per call survives a mutation probe (the refill undoes it before the next
call is compared) while still handing the same object to two callers, and a mutation probe would
also zero a non-conforming signer's key, failing the shape and signature checks for a reason that
has nothing to do with what they test. The per-send shape check above cannot see aliasing at all.

### PushHttpClient

```java
PushResponse post(URI endpoint, Map<String, String> headers, byte[] body);
```

This SPI allows applications to replace the JDK transport for proxy, pooling, or observability
requirements. Implementations return every HTTP status as `PushResponse` and throw
`PushDeliveryException` only for transport failures.

`PushResponse` carries only the status code and headers. Push delivery never consumes a response
body, and the endpoint is an untrusted capability URL, so the default `JdkPushHttpClient`
discards the body without buffering it — a hostile push endpoint cannot create memory pressure
by returning a huge response. This seam is push-delivery only; the Vault module has its own
transport seam (section 7) because Vault responses must be read.

Implementations must not follow redirects: a `3xx` is returned like any other status and the
sender classifies it as a failure. Chasing a `Location` would POST the encrypted body and the
request headers to a host `EndpointPolicy` never validated (the JDK strips `Authorization`
across origins, but not custom headers or the body), would let the redirect target's answer
stand in for the push service's verdict, and under a permissive policy would follow `https` down
to `http`. `JdkPushHttpClient` builds its own client with `Redirect.NEVER` and rejects a supplied
`java.net.http.HttpClient` whose `followRedirects()` differs — the invariant is stated in code,
not inherited from a JDK default. For an implementation on another stack it stays a contract
only, unverifiable from here.

### EndpointPolicy

```java
void validate(URI endpoint);
```

This SPI represents deployment egress policy for push endpoints. The endpoint in a
`Subscription` is attacker-influenced (a public registration endpoint accepts the browser's
`PushSubscription` JSON verbatim), so without a policy every send is a POST from inside the
network to an address of the subscription's choosing — a blind SSRF oracle via
`PushResult.statusCode()`, `PushDeliveryException` and timing. `Endpoints.requireSecure` stays a
protocol check (absolute `https` URL with a host); which hosts a deployment may contact is
policy, and lives here.

`EndpointPolicies.allowedOrigins` is the standard implementation: an origin allowlist compared
on the same RFC 6454 §6.1 serialization the `aud` claim uses (`Origin.serialize` normalizes both
sides, so case, default ports and IDNA form can never disagree). Malformed allowlist entries
fail at construction; endpoint-side userinfo is rejected outright. A rejection throws
`EndpointRejectedException` — extending `RuntimeException`, not `IllegalArgumentException`,
because the argument is well-formed (configuration refuses it), and because web frameworks
commonly map IAE to a 400 response that would echo the redacted-but-fingerprinted message to
the caller who registered the subscription. Rejection messages never carry the capability
path/query (`Endpoints.redact`).

A URI-level policy is a coarse filter, not a sandbox: it cannot close DNS rebinding, and redirect
behaviour belongs to the transport — where `JdkPushHttpClient` enforces `Redirect.NEVER`, so a
`3xx` cannot route the send past the policy that just ran. Strict guarantees require
resolution/egress pinning inside a `PushHttpClient` implementation.

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

The subscription public key (`p256dh`) is attacker-reachable input, and the library validates the
point itself at decode time — coordinates inside the prime field, then the P-256 curve equation —
before it reaches the provider's `KeyFactory`. Refusing an invalid-curve point therefore does not
depend on whether the configured provider validates in `KeyAgreement.doPhase`; with a provider
whose `secp256r1` parameters are not over a prime field, the check fails closed. The Vault signer
performs its own, deliberately separate check on the key it fetches (§7), which additionally
compares domain parameters by value because there the parameters come from the input.

Key and payload arrays exposed by public value types are defensively copied. `Subscription`
redacts both the `auth` secret and the capability-bearing part of its endpoint from `toString`.
Transport and validation exceptions use the same endpoint representation: push-service origin
plus a short correlation fingerprint, never the path, query, fragment, or user information.
Applications must still treat the complete endpoint as a credential and avoid logging it directly.

## 7. Vault Transit integration

`VaultTransitVapidSigner` has no public constructor: each mode has its own builder, obtained from
`builderWithFetchedPublicKey(address, keyName, token)` or
`builderWithSuppliedPublicKey(address, keyName, token, point)`. Two builders rather than one
overloaded family because the modes differ in *contract*, not only in parameters — the fetched one
performs a Vault read inside `build()` and can fail there, the supplied one contacts nothing — and
because `keyVersion` belongs to exactly one of them: in the fetched mode the version is Vault's to
state, taken from the same response as the public key. A bare `builder()` would have made one of
two equal modes the default by omission.

Everything required is a factory-method parameter, so an incomplete signer does not compile and
`build()` never refuses over a missing value. The key name and the token travel as the value types
`TransitKeyName` and `VaultToken` rather than bare strings: the types make the positional
arguments impossible to transpose, and each carries its value's contract. `TransitKeyName`
enforces Vault's own Transit key-name rule — `GenericNameRegex("name")`, `^\w(([\w-.]+)?\w)?$` in
Vault's `path_keys.go` — so no name Vault would accept is refused, while every URL-breaking
character (`/`, `?`, `#`, `%`, whitespace, non-ASCII) is refused without being enumerated.
`VaultToken` requires a non-empty, visible-ASCII value (0x21–0x7E) — rejecting the
trailing-newline misconfiguration, a pasted `Bearer ` prefix and stray whitespace — while
deliberately not validating the token's *format* (Vault issues `hvs.`/`hvb.`/`hvr.` today, issued
`s.`/`b.` before 1.10, and dev mode accepts an arbitrary string); its `toString()` never prints
the token. Because a `VaultToken` is valid by construction, the signer validates it exactly once —
in the type — instead of re-checking it on every path that offers it to a transport. The builders
hold only the optional steps: `mount` defaults to `transit` (Vault's own default mount),
`namespace` to none (no `X-Vault-Namespace` header is sent — the Vault OSS shape), `transport` to
a `JdkVaultHttpTransport`, and the supplied-key builder alone has `keyVersion`.
`mount` and `namespace` are validated at their steps by one shared per-segment rule: nesting
(`secrets/transit`, `team-a/sub`) is legal, and every `/`-separated segment must be non-empty, not
`.` or `..`, and drawn from `[A-Za-z0-9_.-]`.
The allowed set — rather than a blacklist — is what a percent-encoded probe cannot reopen: a
literal `..` check alone admits `%2e%2e` (or `%2F`), which travels in the raw request path —
`URI.resolve` does *not* normalize dot segments in the absolute-path references this signer
builds, so the path goes onto the wire as written. What
happens next depends on the hops: Vault's own Go router decodes the path before routing, so a
`%2F` addresses a different mount inside Vault itself; a decoded dot segment draws a *307
redirect* to the collapsed path from Vault's handler (`cleanPath` in `http/handler.go`) — the
default `Redirect.NEVER` transport refuses it loudly, but a redirect-following custom transport
would execute it, re-sending `X-Vault-Token` to the other path; and a normalizing proxy in front
of Vault (nginx `proxy_pass` with a URI part, HAProxy `normalize-uri`) collapses the path before
Vault sees it at all. The set is deliberately narrower than either Vault or a URL requires —
policy, not necessity: Vault accepts any printable Unicode in a mount path (`validateMountPath`,
canonical per `path.Clean`), and `~ ! $ & ' ( ) * + , ; = : @` are legal raw in a URI path
segment, so a mount like `transit+prod` is real and was addressable through this signer before
the rule. It is refused anyway because some of that punctuation is treated specially by
intermediaries (`;` reads as a path parameter to some hops), and admitting only what every hop
treats literally can be widened later without breaking anyone — the reverse is not true.
Refusing at the step also replaces `URI.create`'s later raw "Malformed escape pair" failure.
The namespace travels differently — in the `X-Vault-Namespace` HTTP header, not the URL — so none
of those hops act on it, and the same rule is applied for two other reasons. Definite: a header
value must be header-safe, which the allowed set guarantees — a strict subset of visible ASCII with
no CR/LF or other control characters, so a validated namespace can never terminate the header or
inject another. Defence in depth: a traversal segment cannot name a real namespace either
(`namespace.Canonicalize` trims a leading slash and appends a trailing one, collapsing nothing),
so such a value is a configuration mistake whichever hop sees it, and refusing it costs nothing.
No traversal route through OSS Vault is claimed here.

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
  Supplying the matching Transit key version pins signing to that version. Omitting `keyVersion`
  uses Vault's latest version and is safe only for a key that never rotates.
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
application's mTLS, proxy, or observability configuration is never bypassed. Each call carries
`X-Vault-Token`, plus `X-Vault-Namespace` on both calls when a namespace (Vault Enterprise/HCP)
is configured — and no namespace header at all when it is not.

The default `JdkVaultHttpTransport` enforces three invariants:

- a per-request timeout (`HttpRequest.timeout`), because a connect timeout alone cannot end an
  exchange with a Vault that accepts the connection and never answers — in fetched mode that
  would hang application startup;
- a response-size cap counted in raw streamed bytes (a declared `Content-Length` above the cap
  fails early, but the streaming count is authoritative). Exceeding the cap fails the whole call
  — fail-closed, never truncation, because the targeted JSON extraction could still find a
  complete-looking `data.signature` before the cut;
- no redirect following, checked at construction rather than at send time. The JDK client
  re-sends custom headers — `X-Vault-Token` among them — to a redirect target, cross-origin ones
  included, so a Vault address that can be made to answer `3xx` (DNS hijack, squatted typo host,
  compromised reverse proxy) would be handed the live token. The default client is built with
  `Redirect.NEVER` explicitly, and a supplied client whose `followRedirects()` is anything else
  is rejected with an `IllegalArgumentException`.

Defaults: 10 s connect timeout, 30 s request timeout, 1 MiB response cap. Transport exception
messages carry the HTTP method and the query-less request URI, never the `X-Vault-Token` header.

The Vault Spring Boot starter exposes the same model through `push2u.signer.vault.*`: omitting
`public-key` selects fetched mode; providing `public-key` selects explicit mode, where
`key-version` should also be set whenever the Transit key can rotate. The optional `namespace`
property maps to the builders' `namespace(...)` step. The transport is
configurable through `request-timeout`, `connect-timeout`, and `max-response-bytes`, and
replaceable with (in priority order) an application `VaultHttpTransport` bean or a
`push2uVaultHttpClient`-qualified `java.net.http.HttpClient` bean that the starter wraps with the
bound properties.

## 8. Spring Boot integration

`push2u-spring-boot-starter` binds `push2u.*` properties and conditionally creates:

- a local `VapidSigner` when both local keys are configured;
- a default `JdkPushHttpClient`;
- an autoconfigured `PushSender` when a signer is available and `push2u.vapid.subject` is set;
- a health indicator when Spring Boot health support is present and a `VapidSigner` bean exists —
  the signer is the only part of a send that can fail after startup, so it is the only thing the
  probe asks about; without a signer bean there is nothing to probe and no indicator is registered.

Application beans override these defaults; in particular, an application-supplied `PushSender`
bean bypasses the `pushSender` factory method entirely, so `push2u.vapid.subject` is not required
in that case — the requirement below is specific to the *autoconfigured* sender.

`push2u.vapid.subject` (the VAPID `sub` claim) is required to build the autoconfigured
`PushSender`, including when the `VapidSigner` bean comes from another starter — the Vault Transit
signer starter supplies only key custody, not a contact address. The `pushSender` bean checks this
explicitly and fails with a message naming `push2u.vapid.subject`, rather than surfacing the
`PushSender.builder(…)` factory's generic `"contact is required"`.

`push2u.jwt-expiry`, `push2u.default-ttl`, `push2u.record-size`, `push2u.max-encrypted-body-bytes`
and the three `push2u.retry.*` keys share one optional-property pattern: unset (`null`, or for the
retry keys their `@DefaultValue`) leaves the `PushSender`/`RetryPolicy` default, set forwards the
value to `Builder#jwtExpiry(Duration)`, `Builder#defaultTtl(Duration)`, `Builder#recordSize(int)`,
`Builder#maxEncryptedBodyBytes(int)`, or — for the retry keys — to `new RetryPolicy(…)`. Each one's
own validation governs context startup, not just the send-time path: `jwtExpiry` must be strictly
positive and at most 24h (RFC 8292 §2); `defaultTtl` must not be negative; `recordSize` enforces the
RFC 8188 §2 18-byte floor at startup, separately from the RFC 8291 §4 per-payload rule checked on
each `send()`; `maxEncryptedBodyBytes` enforces the fixed 103-byte `aes128gcm` overhead;
`maxAttempts` must be at least 1 and neither backoff may be negative. The starter re-throws each
`IllegalArgumentException` with the YAML property name prefixed, since the builder's — and
`RetryPolicy`'s — own message names its camelCase parameter instead.

The `retry.*` keys need one extra step, because `RetryPolicy`'s constructor validates all three
components together and reports both backoff bounds through a single shared message — so a
rejection cannot be attributed to a key without asking the constructor about one real value at a
time. The starter probes each key separately, filling the other two components with `1` and
`Duration.ZERO`, the triple `RetryPolicy.none()` is built from. The attribution rests on those
filler values staying acceptable beside any value of the key being probed — which `none()` alone
does not witness, since it fixes all three — and **not** on the order of the checks inside the
compact constructor. A test asserts the filler combinations directly — the `RetryPolicy.none()`
baseline plus one per probe — rather than leaving the invariant to a comment; it *samples* the
invariant rather than deciding it, since a constraint biting only above some threshold would pass
those points, and no black-box check can do better. Restating the bounds in the starter was rejected
for the usual reason: two copies of a limit drift, and the core is the authority on what a legal
value is.

`push2u.allowed-origins` binds to `EndpointPolicies.allowedOrigins` and follows the same
fail-at-startup pattern: a malformed entry's `IllegalArgumentException` is re-thrown with the
property name prefixed. Alternatively an application `EndpointPolicy` bean is picked up by the
autoconfigured sender; configuring both fails the context (naming the property and the bean)
rather than silently preferring one, because they express the same security control and the
ignored one would be believed active. The one exception: an explicitly *empty* property beside a
bean cedes to the bean — the escape hatch for a service inheriting the property from shared
configuration it cannot unset — while an empty property alone still fails ("requires at least
one origin"), so the control cannot be disabled by accident. Configuring neither keeps the core
default of no endpoint policy.

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

*Amended:* a third seam, `EndpointPolicy` (deployment egress policy for push endpoints), was
added later under the same test — an articulable difference the library cannot decide for the
deployment. Which hosts an application may POST to is deployment security policy, not protocol;
see section 5.

### ADR-006 — `aes128gcm` only

Legacy `aesgcm` is intentionally unsupported.

### ADR-007 — Expired subscription is a result

`404` and `410` map to `SUBSCRIPTION_EXPIRED`, allowing callers to remove subscriptions without
exception-driven control flow.

### ADR-008 — Apache License 2.0

The project is licensed under Apache License 2.0, including its explicit patent grant.

*Amended:* every Java source file carries the licence in its header, in the short SPDX form rather
than the full boilerplate the licence's appendix suggests:

```java
/*
 * Copyright <year> The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
```

`LICENSE` and the POM's `licenses` element already cover the distribution, so the header is not what
makes the licence apply. It is what survives a single file being copied out of the repository, and
what per-file scanners (ScanCode, FOSSA, ORT) read — without it they classify the file as
`unknown licence`, which is friction for exactly the enterprise consumer this library targets. The
SPDX identifier is machine-readable and says the same thing far more briefly than repeating the
appendix boilerplate in a hundred files.

`LICENSE` itself keeps the appendix verbatim, placeholders and all: it is the canonical Apache text,
and the appendix is an instruction for applying the licence rather than a place to assert ownership.
Filling it in was the half-measure this amendment replaces — the notice now sits in each file, which
is what the instruction asks for. Every published jar additionally carries `META-INF/LICENSE`, so an
artifact separated from its POM still states its terms — the terms, not the copyright holder, since
the canonical appendix names nobody and compiled classes carry no comments. A scanner reading the
binary jar alone therefore sees Apache-2.0 without an owner; the owner is in the POM's `developer`
entry and its `organization`, in the source jar and in every source file, which is where it is
useful. No `NOTICE` file: §4(d) would oblige every redistributor of a derivative work to reproduce
it, and that is a real obligation to place on consumers in exchange for attribution they already
have.

The year is the year the file was created, and is never advanced: a maintained copyright range
means re-touching every file each January for no legal effect, since the notice is evidence of
authorship at a date rather than a term that lapses. Spotless writes the current year into a new
file and preserves whatever it finds afterwards.

Enforcement is split because Spotless's `LicenseHeaderStep` skips `package-info.java` and
`module-info.java` by name — their leading Javadoc would otherwise be read as a stale header and
replaced. Spotless therefore owns every other file in every source set; Checkstyle carries the
`RegexpHeader` rule that covers those two file kinds, on `main` sources under the full configuration
and on the test source sets under a header-only one (the full configuration reports hundreds of
Javadoc and naming violations there, which is why it is main-only in the first place).

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

Both run over `main` and `testFixtures`, and stop before `test`/`fipsTest`. NullAway is configured
in `OnlyNullMarked` mode, so what decides coverage is whether the code sits in a `@NullMarked`
scope, not which source set holds it. Both modules' fixtures deliberately share the package of
their `main`, whose `package-info.java` carries the mark — they inherit it from the classpath, need
no `package-info.java` of their own, and covering them therefore costs nothing. `test` and
`fipsTest` are excluded on their own merits: that is where a nullness complaint is least likely to
be a defect and most likely to be scaffolding written to fail. They inherit the same mark, so if
covering them is ever measured to pay for itself, only the source-set predicate has to change.

The check the kit's coverage buys is not theoretical: moving it to its own package (ADR-014) left it
outside any `@NullMarked` and nothing failed, because a `package-info.java` carrying no annotation
does not compile to a class file at all — the omission is invisible in the published jar rather than
merely unchecked. In `push2u-testkit` that same check is the module's ordinary `compileJava`.

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

The Maven group ID is `com.the13haven` and the Java packages are `com.the13haven.push2u.*`. Both
are anchored on `the13haven.com`, the domain the project actually owns, and each has its own
reason to be. Central verifies namespace ownership with a DNS TXT record on the exact domain the
group ID reverses to, and `push2u.io` does not belong to the project. The package name is a
separate matter — the JLS recommends a reversed domain name one owns, for the same purpose of
guaranteed uniqueness — but the original `io.push2u.*` was anchored on that same unowned domain,
which is the part that made it a squat rather than a convention.

Two alternatives were rejected. Registering `push2u.io` solely to legitimise the shorter name
ties a permanent, immutable namespace to a recurring registration fee and an expiry risk. Keeping
`io.push2u.*` alongside a `com.the13haven` group ID would also have been defensible — nothing
requires the two to match, and Guava (`com.google.guava` → `com.google.common`) and OkHttp
(`com.squareup.okhttp3` → `okhttp3`) both diverge — but it leaves the package name resting on a
domain someone else may register, and the only moment to change a package name for free is before
the first release: afterwards it is a breaking change for every adopter.

Releases are triggered manually through `workflow_dispatch`, never by a push to `main`. A
published Maven Central version is immutable — it cannot be deleted or replaced — so the
decision "this state becomes a release" deserves an explicit human action rather than being
implied by a merge. The rejected alternative, releasing on every merge to `main`, couples review
cadence to release cadence and turns any accidental merge into a permanent artifact.

### ADR-014 — JPMS: explicit modules for the library, automatic for the starters

`push2u-core` and `push2u-signer-vault` carry a `module-info.java`. The module name is the package
name — `com.the13haven.push2u` and `com.the13haven.push2u.signer.vault` — and the core's descriptor
is three lines: `requires transitive java.net.http`, `requires static org.jspecify`, one `exports`.
Nothing else is needed, because there is nothing else: the zero-dependency posture of ADR-002 is
what makes an accurate descriptor this cheap to write, and the descriptor is what makes that posture
checkable rather than merely asserted.

Both qualifiers carry weight. `java.net.http` is `transitive` because `HttpClient` is not an
implementation detail behind the default client — it is a parameter of the public
`JdkPushHttpClient(HttpClient, Duration)`, and of `JdkVaultHttpTransport` in the Vault module, so a
consumer configuring their own client would otherwise have to require the JDK module themselves.
`javac -Xlint:exports` flagged both constructors before the qualifier was added.

`requires static org.jspecify` means nothing resolves the JSpecify jar at runtime. The reason is not
annotation retention — JSpecify's annotations are `RUNTIME`-retained — but that the JVM ignores an
annotation whose type it cannot resolve. Verified by running a module-path consumer with the jar
absent, reflecting over every annotated member: empty annotation arrays, no exception.

**The eleven `[exports]` warnings that lint still reports on the core are accepted, not overlooked.**
Every one of them is `class Nullable in module org.jspecify is not indirectly exported`, and the
change lint asks for — `requires static transitive org.jspecify` — silences all eleven and breaks
every module-path consumer that does not itself ship JSpecify: `transitive` makes the module
mandatory at the consumer's compile time, and such a consumer fails with `module not found:
org.jspecify` (measured; with plain `requires static` the same consumer compiles). The annotations
are metadata for analysers, not types a caller must name, so the warning describes a problem this
API does not have. Do not "fix" it.

The two Spring Boot starters stay **automatic** modules with a fixed `Automatic-Module-Name`. Boot's
own artifacts are automatic modules, and auto-configuration works by reflecting over classes named
in `META-INF/spring/*.imports` — a relationship no descriptor can express, and one that `requires`
would misrepresent as a compile-time dependency. What the manifest attribute buys is that the module
name stops following the jar file name: without it the starter would be `push2u.spring.boot.starter`
and would change if the artifact were ever renamed.

The published conformance kit moved from `com.the13haven.push2u` to `com.the13haven.push2u.testkit`
in the same change, and it had to. A package split across two artifacts cannot be resolved from the
module path — with the kit still in the core's package, a consumer putting both on it gets
`ResolutionException: Module … contains package com.the13haven.push2u, module com.the13haven.push2u
exports package com.the13haven.push2u to …`. That was reproduced before the move, not assumed.

Timing is the whole argument for doing this now: a module name, like a package name (ADR-013), is
free to choose before the first release and a breaking change for every adopter afterwards. The same
holds for the kit's package. Without a descriptor the name would be derived from the artifact name,
which is neither stable nor ours to keep.

One tool does not follow yet. Checkstyle 13.9.0 has no grammar for a module declaration — `module
foo {}` alone fails to parse — and a single unparseable file aborts the whole task, so
`module-info.java` is excluded from the analysing configuration. The exclusion costs nothing in
substance: naming, Javadoc and import-order rules are all about type declarations. The licence
header of ADR-008 is the exception, and it is checked by `checkstyleLicenseHeader`, whose
configuration has no `TreeWalker` and so reads the descriptor as lines rather than parsing it.

**Amended: the kit is `push2u-testkit`, an artifact of its own, and it too is an automatic module.**
It was `push2u-core`'s published test fixtures, which made one source set carry two things that
cannot travel together: the kit, meant for a consumer's test classpath, and the plumbing the core's
own suites share — an in-process mock push service, a self-signed loopback certificate factory, the
RFC vectors — which has no business on Maven Central. A source set cannot be half published, so the
split had to be an artifact boundary. `push2u-core`'s fixtures now skip their variants from the
publication (the mechanism `push2u-signer-vault` already used for `RecordingHttpClient`), and
`fipsTest` reaches them through an ordinary `testFixtures(project(":push2u-core"))` dependency
rather than by borrowing `test`'s compiled output on its classpath.

The package name does not change, but its reason does. It is no longer that the core's own artifact
would collide with itself: the collision it avoids is the same one, now between two artifacts a
consumer genuinely puts on the module path together. `com.the13haven.push2u.testkit` was already
right, and stays right for a reason that outlives the layout that produced it.

Automatic, not explicit, and for the reason the starters are: the kit's API carries JUnit and
AssertJ, themselves automatic modules, so a `module-info.java` here would `requires` names derived
from jar files. `Automatic-Module-Name` in the manifest is what keeps the kit's own name from being
derived that way — without it the jar name would make it `push2u.testkit`.

Timing, again, is why this happened before the first release rather than after: the repository
carried no release tag, so the kit's coordinates were still free to choose. A consumer would
otherwise have reached it through a `test-fixtures` classifier on `push2u-core`, and moving it later
would break every one of them.

## 10. Verification

The automated suite covers:

- RFC 5869 HKDF vectors;
- the RFC 8291 end-to-end encryption example;
- RFC 8292 VAPID structure and signature verification;
- the RFC 6454 §6.1 Unicode serialization of the `aud` origin — case, IDNA labels, default and
  non-default ports, address literals, userinfo (`OriginTest`);
- signer contract tests, and the kit checking itself — each of its five checks run once against a
  conforming signer and once against one that breaks exactly what that check is about: a DER
  signature, a compressed or off-curve point, a shared internal key array, a shared buffer refilled
  per call, or a reused signature buffer — plus the kit's DER-fallback verification and its
  minimal-DER re-encoding, exercised directly because no CI platform lacks the P1363 signature name
  (`VapidSignerContractSelfTest`);
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
