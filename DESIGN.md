# push2u — Design

## 1. Status and scope

push2u is an implemented, standalone Java library for server-side Web Push delivery. Artifacts are
released to Maven Central under the `com.the13haven` group ID; the version is derived from git
tags rather than stored in the build
([ADR-013](docs/adr/0013-release-and-publication-process.md)). Java packages are
`com.the13haven.push2u.*`.

The library implements:

- RFC 8030 push delivery and response interpretation;
- RFC 8291 message encryption;
- RFC 8292 VAPID authentication;
- RFC 8188 `aes128gcm` content coding;
- RFC 5869 HKDF-SHA-256;
- local and Vault Transit VAPID signing;
- plain Java and Spring Boot integration.

The architecture keeps the protocol core free of runtime implementation dependencies and exposes
narrow seams only where applications have a legitimate reason to replace behavior.

**This document describes the architecture as it stands, and why it is that way.** The decisions
behind it — with the context they were taken in and the alternatives rejected — are one file per
decision in [`docs/adr/`](docs/adr/README.md); they are cited here rather than restated. How to
*use* the library belongs to the consumer-facing references instead: [`README.md`](README.md) for
the API, [`SPRING.md`](SPRING.md) and [`VAULT.md`](VAULT.md) for the two integrations, and the
Javadoc for individual contracts.

## 2. Goals and non-goals

The library exists to replace `nl.martijndwars:web-push`, the JVM's usual answer for Web Push,
whose transitive surface and BouncyCastle-typed public API are what
[ADR-002](docs/adr/0002-zero-dependency-core.md) records as the motive for the dependency posture.
[`MIGRATION.md`](MIGRATION.md) maps the two APIs onto each other for consumers making the move.

### Goals

- Zero runtime *implementation* dependencies in `push2u-core` — its one dependency is JSpecify, an
  annotation-only jar exposed as API metadata
  ([ADR-012](docs/adr/0012-nullness-declared-with-jspecify.md)).
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

The dependency direction is one-way: the optional modules depend on the core, and no Spring or
Vault type reaches it. `push2u-testkit` carries JUnit and AssertJ, which is why it is a module of
its own rather than part of the core: it belongs on a consumer's test classpath and never on an
application's runtime one.

### JPMS identity

Each artifact carries a module name it will keep
([ADR-014](docs/adr/0014-jpms-explicit-and-automatic-modules.md)). `push2u-core` and
`push2u-signer-vault` are explicit modules with a `module-info.java`; the two starters and the
published test kit are automatic modules with a fixed `Automatic-Module-Name`:

| Artifact | Module name | Kind |
|---|---|---|
| `push2u-core` | `com.the13haven.push2u` | explicit |
| `push2u-signer-vault` | `com.the13haven.push2u.signer.vault` | explicit |
| `push2u-spring-boot-starter` | `com.the13haven.push2u.spring` | automatic |
| `push2u-signer-vault-spring-boot-starter` | `com.the13haven.push2u.signer.vault.spring` | automatic |
| `push2u-testkit` | `com.the13haven.push2u.testkit` | automatic |

The core's descriptor is three lines — `requires transitive java.net.http`, `requires static
org.jspecify`, one `exports` — and both qualifiers carry weight.

`java.net.http` is `transitive` because `HttpClient` is not an implementation detail behind the
default client: it is a parameter of the public `JdkPushHttpClient(HttpClient, Duration)`, and of
`JdkVaultHttpTransport` in the Vault module, so a consumer configuring their own client would
otherwise have to require the JDK module themselves. `javac -Xlint:exports` flagged both
constructors before the qualifier was added.

`requires static org.jspecify` means nothing resolves the JSpecify jar at runtime — which is what
keeps the zero-dependency posture true on the module path as well as the class path. What makes
that safe is not annotation retention (JSpecify's annotations are `RUNTIME`-retained) but that the
JVM ignores an annotation whose type it cannot resolve. Verified by running a module-path consumer
with the jar absent, reflecting over every annotated member: empty annotation arrays, no
exception.

**The eleven `[exports]` warnings that lint reports on the core are accepted, not overlooked.**
Every one of them is `class Nullable in module org.jspecify is not indirectly exported`, and the
change lint asks for — `requires static transitive org.jspecify` — silences all eleven and breaks
every module-path consumer that does not itself ship JSpecify: `transitive` makes the module
mandatory at the consumer's compile time, and such a consumer fails with `module not found:
org.jspecify` (measured; with plain `requires static` the same consumer compiles). The annotations
are metadata for analysers, not types a caller must name, so the warning describes a problem this
API does not have. Do not "fix" it.

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

The endpoint policy runs after the size preconditions and before everything else — encryption, the
VAPID signature (a remote Vault/KMS call under an external signer) and the POST — so a rejected
endpoint costs no cryptography and no I/O. `sendAsync` runs the same pipeline, so the policy
cannot be bypassed on the async path.

The VAPID `aud` claim is the endpoint's origin in the Unicode serialization of RFC 6454 §6.1, as
RFC 8292 §2 requires: lowercase scheme and host, IDNA A-labels converted to their Unicode form,
and the port omitted when it equals the scheme's default. `java.net.URI` performs none of that
normalization, so the library serializes the origin itself (`Origin.serialize`).

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
hard-coded, so the plaintext maximum tracks a configured body limit
([ADR-011](docs/adr/0011-size-limit-expressed-on-the-encrypted-body.md)). The RFC 8291 §4 rule has
a single implementation (`WebPushEncryptor.checkRecordSize`), used both by this pre-flight check
and by the encryptor itself.

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
because it satisfies that contract no better than an absent claim while still producing a JWT
whose `sub` a push service may well reject — the RFC requires neither the claim nor its rejection.

Everything else on the builder is optional, and each value is validated where it is set rather
than at send time: the constraint is known at configuration time, so a bad value fails a
deployment's startup instead of its first delivery. The endpoint policy is the one option whose
default is *absence* — with no policy, any endpoint satisfying `Endpoints.requireSecure` is sent
to — because which hosts a deployment may POST to is a statement about its egress that the library
cannot make on its behalf; it is described under its SPI below.

Three seams in the core are public, and only three
([ADR-005](docs/adr/0005-public-spis-in-the-core.md)).

### VapidSigner

```java
byte[] sign(byte[] signingInput);
byte[] publicKey();
```

This SPI represents key custody ([ADR-010](docs/adr/0010-pluggable-vapid-key-custody.md)). The
default signer holds a private scalar in process. Vault, KMS, or HSM implementations can keep
private material outside the JVM.

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
signer (below) but cannot here — the provider and encoding behind an external signer are unknown,
and a valid 64-byte signature may itself begin with `0x30`.

Both methods return arrays, and the arrays are the caller's. `publicKey()` in particular must
return a fresh copy on every call: a signer handing out its internal array is corrupted for every
later send by the first caller that writes into the returned bytes, and nothing would notice — the
mutated key is still a well-formed point. Both shipped signers return a `clone()`, and the
conformance kit pins both halves by identity — two successive calls must not return the same
object — rather than by mutating and looking for consequences. That choice is load-bearing: a
signer refilling one shared buffer per call survives a mutation probe (the refill undoes it before
the next call is compared) while still handing the same object to two callers, and a mutation
probe would also zero a non-conforming signer's key, failing the shape and signature checks for a
reason that has nothing to do with what they test. The per-send shape check above cannot see
aliasing at all.

### PushHttpClient

```java
PushResponse post(URI endpoint, Map<String, String> headers, byte[] body);
```

This SPI allows applications to replace the JDK transport for proxy, pooling, or observability
requirements. Implementations return every HTTP status as `PushResponse` and throw
`PushDeliveryException` only for transport failures.

`PushResponse` carries only the status code and headers. Push delivery never consumes a response
body, and the endpoint is an untrusted capability URL, so the default `JdkPushHttpClient` discards
the body without buffering it — a hostile push endpoint cannot create memory pressure by returning
a huge response. This seam is push-delivery only; the Vault module has its own transport seam
(section 7) because Vault responses must be read.

Implementations must not follow redirects. A chased `Location` would POST the encrypted body and
the request headers to a host `EndpointPolicy` never validated, and would let the redirect
target's answer stand in for the push service's verdict. The invariant is stated in code rather
than inherited from a JDK default: `JdkPushHttpClient` builds its own client with `Redirect.NEVER`
and rejects a supplied `java.net.http.HttpClient` whose `followRedirects()` differs. For an
implementation on another stack it stays a contract only, unverifiable from here.

### EndpointPolicy

```java
void validate(URI endpoint);
```

This SPI represents deployment egress policy for push endpoints. The endpoint in a `Subscription`
is attacker-influenced (a public registration endpoint accepts the browser's `PushSubscription`
JSON verbatim), so without a policy every send is a POST from inside the network to an address of
the subscription's choosing — a blind SSRF oracle via `PushResult.statusCode()`,
`PushDeliveryException` and timing. `Endpoints.requireSecure` stays a protocol check (absolute
`https` URL with a host); which hosts a deployment may contact is policy, and lives here.

`EndpointPolicies.allowedOrigins` is the standard implementation: an origin allowlist compared on
the same RFC 6454 §6.1 serialization the `aud` claim uses, so `Origin.serialize` normalizes both
sides and case, default ports and IDNA form can never disagree between the two. Malformed
allowlist entries fail at construction; endpoint-side userinfo is rejected outright. A rejection
throws `EndpointRejectedException` — extending `RuntimeException`, not `IllegalArgumentException`,
because the argument is well-formed (configuration refuses it), and because web frameworks
commonly map IAE to a 400 response that would echo the redacted-but-fingerprinted message to the
caller who registered the subscription. Rejection messages never carry the capability path/query
(`Endpoints.redact`).

A URI-level policy is a coarse filter, not a sandbox: it cannot close DNS rebinding, and redirect
behaviour belongs to the transport — where `JdkPushHttpClient` enforces `Redirect.NEVER`, so a
`3xx` cannot route the send past the policy that just ran. Strict guarantees require
resolution/egress pinning inside a `PushHttpClient` implementation.

### Deliberately concrete components

The RFC 8291 encryptor, the HKDF implementation and the origin serialization are not public SPIs
([ADR-003](docs/adr/0003-concrete-hkdf-implementation.md)). Alternative implementations would not
change intended behavior and would introduce a silent wrong-ciphertext failure mode.

JCE provider selection uses the standard `java.security.Provider` abstraction rather than a custom
SPI. The selected provider backs encryption and, for the local signer, EC key import and ES256
signing. Native `SHA256withECDSAinP1363Format` is preferred; when the selected provider offers
only DER-output `SHA256withECDSA`, the signature is obtained from that same provider and strictly
converted to JOSE's raw `r || s` form. Provider lookup is never widened by the fallback. External
signers manage their own providers.

### Nullness

Every package carries JSpecify's `@NullMarked`, so a reference type in the public API is non-null
unless it is annotated `@Nullable`; the annotated exceptions are the optional message headers
(`PushMessage.ttl`, `urgency`, `topic`), the unset builder fields, and the Spring properties. The
annotations are part of the published surface — NullAway, IntelliJ and the Kotlin compiler read
the same ones ([ADR-012](docs/adr/0012-nullness-declared-with-jspecify.md)).

## 6. Cryptography

| Operation | Implementation |
|---|---|
| P-256 ECDH | `KeyAgreement("ECDH")` |
| HKDF-SHA-256 | RFC 5869 loop over `Mac("HmacSHA256")` |
| AES-128-GCM | `Cipher("AES/GCM/NoPadding")` |
| ES256 | `Signature("SHA256withECDSAinP1363Format")`, or same-provider `SHA256withECDSA` plus strict DER → `r || s` conversion |
| EC key handling | `KeyFactory("EC")`, `KeyPairGenerator("EC")` |
| Base64url | `java.util.Base64` |

The implementation supports only modern `aes128gcm` encoding
([ADR-006](docs/adr/0006-aes128gcm-only.md)) and emits a single RFC 8188 record. Because that one
record carries the whole payload, `rs` must be strictly greater than the plaintext plus the
padding delimiter plus the authentication tag (RFC 8291 §4); equality is rejected. The record is
not zero-padded up to `rs`, so the body size depends only on the payload.

The subscription public key (`p256dh`) is attacker-reachable input, and the library validates the
point itself at decode time — coordinates inside the prime field, then the P-256 curve equation —
before it reaches the provider's `KeyFactory`. Refusing an invalid-curve point therefore does not
depend on whether the configured provider validates in `KeyAgreement.doPhase`; with a provider
whose `secp256r1` parameters are not over a prime field, the check fails closed. The Vault signer
performs its own, deliberately separate check on the key it fetches (§7), which additionally
compares domain parameters by value because there the parameters come from the input.

Key and payload arrays exposed by public value types are defensively copied. `Subscription`
redacts both the `auth` secret and the capability-bearing part of its endpoint from `toString`.
Transport and validation exceptions use the same endpoint representation: push-service origin plus
a short correlation fingerprint, never the path, query, fragment, or user information.
Applications must still treat the complete endpoint as a credential and avoid logging it directly.

## 7. Vault Transit integration

`VaultTransitVapidSigner` has no public constructor: each mode has its own builder, obtained from
`builderWithFetchedPublicKey(address, keyName, token)` or `builderWithSuppliedPublicKey(address,
keyName, token, point)`. Two builders rather than one overloaded family because the modes differ
in *contract*, not only in parameters — the fetched one performs a Vault read inside `build()` and
can fail there, the supplied one contacts nothing — and because `keyVersion` belongs to exactly
one of them: in the fetched mode the version is Vault's to state, taken from the same response as
the public key. A bare `builder()` would have made one of two equal modes the default by omission.

Everything required is a factory-method parameter, so an incomplete signer does not compile and
`build()` never refuses over a missing value. The key name and the token travel as the value types
`TransitKeyName` and `VaultToken` rather than bare strings: the types make the positional
arguments impossible to transpose, and each carries its value's contract. `TransitKeyName`
enforces Vault's own Transit key-name rule — `GenericNameRegex("name")`, `^\w(([\w-.]+)?\w)?$` in
Vault's `path_keys.go` — so no name Vault would accept is refused, while every URL-breaking
character (`/`, `?`, `#`, `%`, whitespace, non-ASCII) is refused without being enumerated.
`VaultToken` requires a non-empty, visible-ASCII value (0x21–0x7E) — rejecting the
trailing-newline misconfiguration, a pasted `Bearer ` prefix and stray whitespace — while
deliberately not validating the token's *format*, which has changed across Vault versions and is
arbitrary in dev mode; its `toString()` never prints the token. Because a `VaultToken` is valid by
construction, the signer validates it exactly once — in the type — instead of re-checking it on
every path that offers it to a transport.

`mount` and `namespace` are validated at their builder steps by one shared per-segment rule:
nesting (`secrets/transit`, `team-a/sub`) is legal, and every `/`-separated segment must be
non-empty, not `.` or `..`, and drawn from `[A-Za-z0-9_.-]`.

The allowed set — rather than a blacklist — is what a percent-encoded probe cannot reopen: a
literal `..` check alone admits `%2e%2e` (or `%2F`), which travels in the raw request path —
`URI.resolve` does *not* normalize dot segments in the absolute-path references this signer
builds, so the path goes onto the wire as written. What happens next depends on the hops: Vault's
own Go router decodes the path before routing, so a `%2F` addresses a different mount inside Vault
itself; a decoded dot segment draws a *307 redirect* to the collapsed path from Vault's handler
(`cleanPath` in `http/handler.go`) — the default `Redirect.NEVER` transport refuses it loudly, but
a redirect-following custom transport would execute it, re-sending `X-Vault-Token` to the other
path; and a normalizing proxy in front of Vault (nginx `proxy_pass` with a URI part, HAProxy
`normalize-uri`) collapses the path before Vault sees it at all.

The set is deliberately narrower than either Vault or a URL requires — policy, not necessity:
Vault accepts any printable Unicode in a mount path (`validateMountPath`, canonical per
`path.Clean`), and `~ ! $ & ' ( ) * + , ; = : @` are legal raw in a URI path segment, so a mount
like `transit+prod` is real and was addressable through this signer before the rule. It is refused
anyway because some of that punctuation is treated specially by intermediaries (`;` reads as a
path parameter to some hops), and admitting only what every hop treats literally can be widened
later without breaking anyone — the reverse is not true. Refusing at the step also replaces
`URI.create`'s later raw "Malformed escape pair" failure.

The namespace travels differently — in the `X-Vault-Namespace` HTTP header, not the URL — so none
of those hops act on it, and the same rule is applied for two other reasons. Definite: a header
value must be header-safe, which the allowed set guarantees — a strict subset of visible ASCII
with no CR/LF or other control characters, so a validated namespace can never terminate the header
or inject another. Defence in depth: a traversal segment cannot name a real namespace either
(`namespace.Canonicalize` trims a leading slash and appends a trailing one, collapsing nothing),
so such a value is a configuration mistake whichever hop sees it, and refusing it costs nothing.
No traversal route through OSS Vault is claimed here.

`VaultTransitVapidSigner` supports two modes:

- **Fetched mode** reads `latest_version` and that version's public key atomically from one
  `transit/keys/<key>` response at construction, then pins the captured version on every sign. The
  key is validated as P-256 before the signer exists, in three independent steps: the advertised
  `type` must be `ecdsa-p256` or Vault Enterprise's `managed_key` (absent `type` is a failure);
  the parsed public key's domain parameters must match `secp256r1` by value — prime field, curve
  coefficients, generator, order, cofactor; and the key's point must satisfy `y² = x³ + ax + b
  (mod p)` with both coordinates in `[0, p)`. None of the three implies another: the metadata is
  only Vault's claim, and correct parameters say nothing about the point — the JCA validates
  neither, so SunEC accepts a key at `(1, 2)` both on import and at verification time. Coordinates
  are likewise never truncated to fit the 32-byte P-256 fields. Without this, an `ecdsa-p384` key
  produced a syntactically valid but unusable VAPID key, and the misconfiguration surfaced only as
  an unexplained push-service rejection on the first send.
- **Explicit mode** receives the public key from configuration, permitting a sign-only token.
  Supplying the matching Transit key version pins signing to that version. The supplied key is
  checked structurally only (65 bytes, `0x04` tag) — neither its point nor its correspondence to
  the Transit key can be established here, so both stay with the caller.

Signing uses `marshaling_algorithm=jws`, so Vault returns the raw JOSE-compatible ECDSA form. A
pinned signer also sends `key_version`; taking the version and public key from the same metadata
response closes the race where Vault rotates between reading the public key and signing. Creating
a newer Transit version therefore does not break an existing signer: it continues advertising and
using the older version as one consistent VAPID identity.

The pin remains usable only while Vault permits signing with that version — raising
`min_encryption_version` above it, or deleting it through `min_available_version`, makes
subsequent sign calls fail. Every recovery from that changes the advertised VAPID identity, and so
has to be coordinated with browser re-subscription: a Web Push subscription is bound to the
application-server public key used at subscribe time.

### Vault HTTP transport

The module talks to the Vault API through its own `VaultHttpTransport` seam (`get` + `post`,
returning `VaultHttpResponse`), deliberately separate from `PushHttpClient`: push delivery POSTs
to untrusted capability URLs and discards response bodies, while the Vault API is an
operator-configured service whose JSON responses must be read. Both Vault calls — the Transit
`sign` POST and the fetched mode's startup metadata GET — go through the same transport, so an
application's mTLS, proxy, or observability configuration is never bypassed.

The default `JdkVaultHttpTransport` enforces three invariants:

- a per-request timeout (`HttpRequest.timeout`), because a connect timeout alone cannot end an
  exchange with a Vault that accepts the connection and never answers — in fetched mode that would
  hang application startup;
- a response-size cap counted in raw streamed bytes (a declared `Content-Length` above the cap
  fails early, but the streaming count is authoritative). Exceeding the cap fails the whole call —
  fail-closed, never truncation, because the targeted JSON extraction could still find a
  complete-looking `data.signature` before the cut;
- no redirect following, checked at construction rather than at send time. The JDK client re-sends
  custom headers — `X-Vault-Token` among them — to a redirect target, cross-origin ones included,
  so a Vault address that can be made to answer `3xx` (DNS hijack, squatted typo host, compromised
  reverse proxy) would be handed the live token. The default client is built with `Redirect.NEVER`
  explicitly, and a supplied client whose `followRedirects()` is anything else is rejected with an
  `IllegalArgumentException`.

Transport exception messages carry the HTTP method and the query-less request URI, never the
`X-Vault-Token` header.

## 8. Spring Boot integration

`push2u-spring-boot-starter` binds `push2u.*` properties and conditionally creates a local
`VapidSigner`, a default `JdkPushHttpClient`, an autoconfigured `PushSender`, and — when Spring
Boot health support is present — a health indicator. Application beans of the same types override
these defaults; an application-supplied `PushSender` bypasses the starter's factory method
entirely, so everything below concerns the *autoconfigured* sender alone.

**Every rejection is re-thrown with the YAML property name in front of it.** The core is where a
constraint is stated once, so the starter neither restates a bound nor validates ahead of it — two
copies of a limit drift, and the core is the authority on what a legal value is. What the core
cannot know is the name the operator wrote in their configuration file: its messages name a
camelCase builder or constructor parameter. Translating at the boundary is what turns a rejected
value into a startup failure the operator can act on, and it is also why the properties bind
optionally — an unset property leaves the core's default in place rather than restating it in a
second location.

`push2u.vapid.subject` is checked explicitly rather than left to the factory's generic "contact is
required", and it is required even when the `VapidSigner` bean comes from another starter: the
Vault Transit signer starter supplies key custody, not a contact address.

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
those points, and no black-box check can do better.

`push2u.allowed-origins` and an application `EndpointPolicy` bean express the same security
control, so configuring both fails the context (naming the property and the bean) rather than
silently preferring one and leaving the other believed-active. The one exception is an explicitly
*empty* property beside a bean — the escape hatch for a service inheriting the property from
shared configuration it cannot unset — while an empty property on its own still fails, so the
control cannot be disabled by accident.

The health indicator is registered when a `VapidSigner` bean exists, and asks about nothing else:
the signer is the only part of a send that can stop working while the application runs — it
reaches a backend that can go down, holds a token that can expire, names a key that can be deleted
— while the rest of a `PushSender` is configuration the builder validated at startup. It probes
end to end (sign, then verify the signature locally against the advertised public key), so a
signer whose bytes do not verify reports `DOWN` instead of failing every real send with
`401`/`403`. Because a health endpoint is polled and each probe of a remote signer is a full
backend round-trip — against Vault Transit, one operation written to every audit device, counted
against rate-limit quotas and possibly billed — the result is cached per process, with a failed
result held far more briefly than a successful one so that recovery is still noticed quickly. The
indicator stays out of the `liveness` group: an unreachable Vault is not something a container
restart fixes.

`push2u-signer-vault-spring-boot-starter` is ordered before the core starter. When both are
configured, the Vault signer takes precedence over the local signer unless the application
provides its own `VapidSigner`.

## 9. Verification

The automated suite covers:

- RFC 5869 HKDF vectors;
- the RFC 8291 end-to-end encryption example;
- RFC 8292 VAPID structure and signature verification;
- the RFC 6454 §6.1 Unicode serialization of the `aud` origin — case, IDNA labels, default and
  non-default ports, address literals, userinfo (`OriginTest`);
- signer contract tests, and the kit checking itself — each of its five checks run once against a
  conforming signer and once against one that breaks exactly what that check is about: a DER
  signature, a compressed or off-curve point, a shared internal key array, a shared buffer
  refilled per call, or a reused signature buffer — plus the kit's DER-fallback verification and
  its minimal-DER re-encoding, exercised directly because no CI platform lacks the P1363 signature
  name (`VapidSignerContractSelfTest`);
- the RFC 8291 §4 record-size boundary and the encrypted-body overhead (`WebPushEncryptorTest`);
- payload size limits, builder validation, and the `Integer.MAX_VALUE` boundary
  (`PushSenderPayloadSizeTest`);
- HTTP delivery, status mapping, and retry behavior;
- Spring Boot auto-configuration — the property wiring and the diagnostics that name the YAML key,
  and, reproducing the two documented Vault Spring Boot YAML examples as property values, that the
  core and Vault Transit signer starters compose into a working `PushSender`
  (`VaultSignerAutoConfigurationTest`);
- Vault Transit integration through Testcontainers.

The published vectors are the specification, not a snapshot of current behaviour: when a change
alters what the library produces, the vectors decide which of the two is wrong.

The standard verification commands are:

```bash
./gradlew clean build
./gradlew javadoc
```
