# push2u — Design

## 1. Status and scope

push2u is an implemented, standalone Java library for server-side Web Push delivery. Artifacts are
released to Maven Central under the `com.the13haven` group ID; the version is derived from git
tags rather than stored in the build
([ADR-013](adr/0013-release-and-publication-process.md)). Java packages are
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
decision in [`docs/adr/`](adr/README.md); they are cited here rather than restated. How to
*use* the library belongs to the consumer-facing references instead: [`README.md`](../README.md) for
the API, [`SPRING.md`](SPRING.md) and [`VAULT.md`](VAULT.md) for the two integrations,
[`VAPID.md`](VAPID.md) for generating the key pair, and the Javadoc for individual contracts.

## 2. Goals and non-goals

The library exists to replace `nl.martijndwars:web-push`, the JVM's usual answer for Web Push,
whose transitive surface and BouncyCastle-typed public API are what
[ADR-002](adr/0002-zero-dependency-core.md) records as the motive for the dependency posture.
[`MIGRATION.md`](MIGRATION.md) maps the two APIs onto each other for consumers making the move.

### Goals

- Zero runtime *implementation* dependencies in `push2u-core` — its one dependency is JSpecify, an
  annotation-only jar exposed as API metadata
  ([ADR-012](adr/0012-nullness-declared-with-jspecify.md)).
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
([ADR-014](adr/0014-jpms-explicit-and-automatic-modules.md)). `push2u-core` and
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
    ├─ Validate the endpoint against the sender's EndpointPolicy (always present)
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
endpoint costs no cryptography and no I/O. It runs unconditionally: a sender cannot exist without a
policy, so the pipeline has no branch around this step and the ordering guarantee does not depend
on configuration. `sendAsync` runs the same pipeline, so the policy cannot be bypassed on the async
path either.

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
([ADR-011](adr/0011-size-limit-expressed-on-the-encrypted-body.md)). The RFC 8291 §4 rule has
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

- `builder(VapidKeys, String contact, EndpointPolicy)` creates `LocalEcVapidSigner`; or
- `builder(VapidSigner, String contact, EndpointPolicy)` delegates signing and public-key
  publication.

The two are overloads of one `builder(…)` rather than differently named methods: they differ only
in which required key source they take, not in contract — and the overload choosing the key source
is what makes "no key source" and "both key sources" inexpressible rather than runtime errors.

The VAPID contact is required in both modes and must be non-blank. RFC 8292 §2.1 leaves the `sub`
claim optional; requiring it is a push2u contract, on the grounds that a push service reporting a
problem with an application server has no other channel to it. A blank value is rejected outright,
because it satisfies that contract no better than an absent claim while still producing a JWT
whose `sub` a push service may well reject — the RFC requires neither the claim nor its rejection.

The endpoint policy is the third required value, and a `null` is rejected at the factory like any
other present-but-invalid one. It is a parameter rather than a builder step because which hosts a
deployment may POST to is a decision that has to be made, even though the library cannot make it —
the two are different claims, and only the first belongs to the library; the SPI section below
carries the reasoning.

Everything else on the builder is optional, and each value is validated where it is set rather
than at send time: the constraint is known at configuration time, so a bad value fails a
deployment's startup instead of its first delivery.

Three seams in the core are public, and only three
([ADR-005](adr/0005-public-spis-in-the-core.md)).

### Boundary validators

Two public utility classes let an application enforce the `Subscription` contract at its own
registration boundary — rejecting a bad registration before persisting it — instead of storing
data every later send will refuse: `Endpoints` for the endpoint (`requireSecure`, the RFC 8030
contract, plus the log-safe `redact`) and `P256PublicKeys` for the key material. `P256PublicKeys`
carries two checks of deliberately different strength: `requireUncompressedPoint` is structural
(65 bytes, the `0x04` X9.62 tag) and `requireOnCurve` is the full check — coordinates inside the
P-256 prime field and the curve equation satisfied. The full check runs on hard-coded FIPS 186-4
domain parameters and touches no JCA provider, so it works wherever a `Subscription` is created,
before and independently of any `PushSender`; hard-coding is sound because P-256 is a fixed named
curve, and a test (with a BC-FIPS twin) pins each constant against what a provider answers for
`secp256r1`. `Subscription`'s constructor applies `requireOnCurve` to `p256dh` — the value is
attacker-supplied, and an off-curve point would otherwise be accepted, persisted, and then raise
`PushCryptoException` (documented as "the deployment is broken") on every send, far from the
request that supplied it. `VapidKeys` applies the same full check to its public half, catching a
corrupted configuration value where the pair is created. Section 6 describes how these checks
relate to the provider-parameter check the send pipeline still performs.

### VapidSigner

```java
byte[] sign(byte[] signingInput);
byte[] publicKey();
```

This SPI represents key custody ([ADR-010](adr/0010-pluggable-vapid-key-custody.md)). The
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

**A policy is a required argument of both `PushSender` factory methods**
([ADR-016](adr/0016-endpoint-policy-is-a-required-decision.md)), not an optional builder step:
there is no default policy and no way to obtain a sender without naming one. The library still does
not choose a deployment's allowlist — that is what ADR-005 admitted the seam for — but it does not
decide on the deployment's behalf that there is none. A deployment that wants none says so with
`EndpointPolicies.unrestricted()`, which accepts every endpoint `Subscription` accepts. The
difference from the previous default is entirely in where it is visible: `unrestricted()` is a
token in the consumer's own source, appearing in their diff, their review and their grep, while an
unset builder step appeared in none of them. Requiring the argument also removes a runtime failure
mode instead of adding one — `build()` cannot refuse over a missing required value, since the
compiler refuses first.

The standard implementation is an allowlist of `EndpointRule` values
([ADR-017](adr/0017-domain-rule-in-the-endpoint-allowlist.md)). A rule is a value that carries its
own kind, so the entries of one list say what each of them means instead of taking their meaning
from the factory they were passed to — the same reason `TransitKeyName` and `VaultToken` are types
rather than two `String` parameters, and it makes swap-proofness a property of the types rather
than of the strings a caller happens to pass. Two kinds exist: `EndpointRule.origin`, one origin
matched exactly, and `EndpointRule.domain`, a DNS zone. `EndpointPolicies.allowedEndpoints` takes
a mixed list; `allowedOrigins` and `allowedDomains` are the single-kind convenience over it, each
mapping its strings to rules of one kind and delegating. Rules are values, equal by kind and
normalized entry, so a list of them collapses duplicates the way the origins path always did
through its set.

**The hierarchy is closed, and that is what keeps it from being a seam.** `EndpointRule` is sealed,
both implementations are private to it, and the method by which a rule matches an endpoint is
package-private, so no rule kind can be added or implemented from outside. It is an enumeration of
the kinds the library knows how to match, not an extension point — ADR-005's bar for a seam is
untouched and no SPI is added. `EndpointPolicy` remains the seam it already was, and a deployment
whose rule is neither kind still writes a lambda.

**The endpoint is parsed and normalized once, and every rule sees only that value.** Both kinds
compare on the same RFC 6454 §6.1 serialization the `aud` claim uses, so `Origin.serialize`
normalizes both sides and case, default ports and IDNA form can never disagree between them; a
second normalizer would mean two answers for one endpoint, diverging precisely in the
internationalised cases nobody exercises by hand. A domain entry is put through that same
serialization rather than merely checked, since an entry validated but not normalized would accept
spellings — `NOTIFY.WINDOWS.COM`, or an A-label facing a U-label host — that can never meet a host,
and a permanently inert entry looks configured. The two endpoint-side refusals hold for every rule
kind: userinfo is rejected outright before any comparison, and an endpoint with no scheme or host
has no origin to compare at all.

**A domain rule covers the apex and every subdomain at any depth, matched at a label boundary** —
`host.equals(domain) || host.endsWith("." + domain)`. The leading dot belongs to the suffix and not
to the string searched; without it `evilnotify.windows.com` matches `notify.windows.com`, which is
the whole vulnerability class and the bug every consumer writing this rule by hand reaches
independently. It matches only the scheme `https` and the default port, absent or an explicit
`443`. The scheme is anchored explicitly rather than inherited, because the origin serialization
enforces no scheme by its own contract — that is `Endpoints.requireSecure`'s job at the
`Subscription` boundary — while an origin rule is covered for free by comparing the whole
serialization. The port is a decision: a domain names which *hosts* are trusted, a port which
*service on a host* is, and a rule spanning every port of a zone re-creates the blind SSRF oracle
this control exists to close, relocated into an external zone. A non-default port is named exactly,
with an origin rule.

The library makes no public-suffix judgement: there is none in the JDK,
`HttpCookie.domainMatches`'s embedded-dot heuristic is wrong in both directions, a dependency is
ruled out by ADR-002, and bundled data ages between releases while going on looking authoritative.
A single label is refused, being the one case unambiguously wrong with no data at all; the rest is
stated rather than half-checked — a domain rule is worth what the DNS of that zone is worth, and
over a shared hosting zone it admits every tenant.

Malformed entries of either kind fail at construction, validated through the same `java.net.URI`
the endpoint side uses rather than a hostname regex, which would be a second grammar of "a valid
host" to keep in step with the first. A rejection throws `EndpointRejectedException` — extending
`RuntimeException`, not `IllegalArgumentException`, because the argument is well-formed
(configuration refuses it), and because web frameworks commonly map IAE to a 400 response that
would echo the redacted-but-fingerprinted message to the caller who registered the subscription.
Rejection messages never carry the capability path/query (`Endpoints.redact`). A rule entry is
configuration rather than an endpoint and is rendered by what it may hold: an origin entry through
the same redaction, since a pasted capability URL is one of the mistakes being reported, and a
domain entry verbatim only while it is a bounded ASCII host-shaped token free of URI delimiters,
whitespace and control characters — otherwise omitted, with the caller left to say which entry it
was.

A URI-level policy is a coarse filter, not a sandbox: it cannot close DNS rebinding, and redirect
behaviour belongs to the transport — where `JdkPushHttpClient` enforces `Redirect.NEVER`, so a
`3xx` cannot route the send past the policy that just ran. Strict guarantees require
resolution/egress pinning inside a `PushHttpClient` implementation.

### Deliberately concrete components

The RFC 8291 encryptor, the HKDF implementation and the origin serialization are not public SPIs
([ADR-003](adr/0003-concrete-hkdf-implementation.md)). Alternative implementations would not
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
the same ones ([ADR-012](adr/0012-nullness-declared-with-jspecify.md)).

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
([ADR-006](adr/0006-aes128gcm-only.md)) and emits a single RFC 8188 record. Because that one
record carries the whole payload, `rs` must be strictly greater than the plaintext plus the
padding delimiter plus the authentication tag (RFC 8291 §4); equality is rejected. The record is
not zero-padded up to `rs`, so the body size depends only on the payload.

The provider itself is not trusted to answer the `secp256r1` lookup honestly. `Jca.p256Parameters()`
is the one seam through which provider-supplied domain parameters reach an imported key — the
public-key and the private-key decode both take them from there — and it verifies the answer value
for value against the hard-coded FIPS 186-4 constants (prime field modulus, both coefficients,
generator, order, cofactor) before anything runs on it, failing closed as `PushCryptoException`.
Without that, a provider answering the name with another 256-bit prime-field curve would silently
move the ECDH agreement and the VAPID private-key import onto that curve. The parameters are a
per-instance constant, so the verified result is cached the same way as the ES256 resolution; the
verification runs before each store, never resting on the cache. On the way out, the fixed-width
coordinate serialization refuses a negative or wider-than-256-bit coordinate rather than truncating
it — truncation would publish a plausible-looking but wrong point.

The ephemeral key pair does not come through that seam — the `KeyPairGenerator` resolves the
`secp256r1` name itself — so the pair it returns is held to the same standard before it is used,
in three checks and no more: both halves must be EC keys, both halves' declared domain parameters
must equal the published NIST P-256 constants value for value (prime field modulus, both
coefficients, generator, order, cofactor), and the public point must lie on the curve of those
constants. The last two prove different things, and neither substitutes for the other: parameter
equality proves what the generator *declares*, the curve equation proves that the point it actually
*returned* lies on the declared curve. The parameter comparison is the sharper of the two. A
substituted order `n` leaves every generated point genuinely on P-256, so the equation check alone
passes — but `n` is what bounds the private scalar, and a small substituted order draws a guessable
scalar and therefore a guessable ECDH secret.

What that boundary does not reach is worth stating as plainly as the boundary itself. A provider
that declares the correct parameters and simply draws a weak or attacker-known scalar passes
undetected; no parameter verification can catch that, which is why the choice of provider remains a
trust decision. The two halves are also not checked to belong together — `W = d·G` is not
evaluated — because that needs point multiplication the library deliberately does not implement,
and it would buy nothing against a hostile provider, which can always hand over a self-consistent
pair whose scalar it knows.

The subscription public key (`p256dh`) is attacker-reachable input, and it is validated twice, on
purpose. At construction, `Subscription` runs `P256PublicKeys.requireOnCurve` (§5) against the
hard-coded FIPS 186-4 parameters — no provider involved — so a hostile off-curve key is refused at
the application's boundary. At decode time, inside the send pipeline, the point is validated again
— coordinates inside the prime field, then the P-256 curve equation — against the now-verified
parameters of the provider that is about to run ECDH, before the point reaches that provider's
`KeyFactory`. Refusing an invalid-curve point therefore never depends on whether the configured
provider validates in `KeyAgreement.doPhase`. Within the core the equation arithmetic lives once, in
`P256PublicKeys`; only the parameter source differs. The value-wise parameter comparison lives once
there as well, against the hard-coded constants, and answers for both places a provider's
`secp256r1` claim enters the core — the import seam above and the ephemeral generator. The Vault
signer performs its own, deliberately separate checks on the key it fetches (§7) — a parameter
comparison of the same shape, its own inlined copy of the curve equation, and the same
refuse-not-truncate serialization — all three duplicated because their counterparts
(`nistP256Mismatch`, `satisfiesCurveEquation`, and `EcKeys` entire) are package-private to
`push2u-core`, so no other module can call them. The parameter comparison's reference is weaker as
well as separate: there the fetched key is compared against the platform's `AlgorithmParameters`
answer for `secp256r1`, taken as given rather than verified against the published constants —
extending the lookup exactly the trust this section opens by withholding. What that costs is
diagnostic rather than secret-exposing — a platform answering the name with some other curve makes
the genuine P-256 key Vault returns fail the comparison, so such a deployment fails loudly when the
signer is built instead of signing on a curve nobody chose, and the VAPID private key never exists
locally in any case. What the module *can* call it does call: `P256PublicKeys.requireOnCurve`,
against the core's hard-coded constants, runs on the key either mode publishes.

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
`build()` never refuses over a missing value — and everything required is also validated at the
factory. The address must be an absolute URI with a host and no query or fragment, and its path —
legal, because a Vault behind a reverse proxy or ingress prefix is a legitimate topology — obeys
the same per-segment rule as `mount` below, since it prefixes every token-bearing request path.
The scheme must be `http` or `https` (case-insensitively), whitelisted at the factory — the signer
speaks Vault's HTTP API and nothing else, and `ftp://vault.example` used to pass validation only to
fail on the first sign inside the transport. `https` is always accepted; plain `http` is accepted
out of the box only towards a literal loopback host (`localhost`, names under `.localhost`,
`127.0.0.0/8` dotted-quads in canonical decimal, and a bracketed IP literal denoting a loopback
address — the IPv6 loopback in any spelling, and the IPv4-mapped writings such as
`[::ffff:127.0.0.1]`, which the platform resolves to the `127.0.0.0/8` address they map) — the Vault
Agent/sidecar pattern, where TLS is terminated beside the application — and to any other host
requires the builders' explicit `allowInsecureHttp()` step, because the `X-Vault-Token` header would
otherwise cross the network in clear text. That one rule lives in `build()` rather than at the
factory — the opt-in is a builder step, callable only after the factory has returned — and runs
before the fetched mode's Vault read, so a refused address contacts nothing. Loopback is decided
from the literal host text, never by resolution, keeping the rule readable from the address alone
([ADR-015](adr/0015-vault-address-scheme-policy.md)). The Spring starter deliberately adds no
opt-in property: plaintext transport for the token costs a code change (an application-supplied
signer bean), not a YAML edit. The API paths are joined onto the address by explicit normalization
— scheme and authority verbatim, the address's path with a trailing slash dropped, then `/v1/…` —
and deliberately not by `URI.resolve`: per RFC 3986 §5.3 an absolute-path reference
(`resolve("/v1/…")`) replaces the base path entirely, silently discarding a prefix like `/vault`,
and the relative form (`resolve("v1/…")`) merges by dropping everything after the base path's last
`/`, so a prefix without a trailing slash would lose its final segment — quieter, not better.
`https://gw.example/vault` and `https://gw.example/vault/` therefore address the same Vault, and a
root address like `https://vault.example:8200` joins as it reads. The key name and the token
travel as the value types `TransitKeyName` and `VaultToken` rather than bare strings: the types make the positional
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
literal `..` check alone admits `%2e%2e` (or `%2F`), which travels in the raw request path — the
signer assembles its request URIs by direct concatenation onto the validated base, with no
dot-segment normalization anywhere on the way, so the path goes onto the wire as written. What
happens next depends on the hops: Vault's own Go router decodes the path before routing, so a
`%2F` addresses a different mount inside Vault itself; a decoded dot segment draws a *307
redirect* to the collapsed path from Vault's handler (`cleanPath` in `http/handler.go`) — the
default `Redirect.NEVER` transport refuses it loudly, but a redirect-following custom transport
would execute it, re-sending `X-Vault-Token` to the other path; and a normalizing proxy in front
of Vault (nginx `proxy_pass` with a URI part, HAProxy `normalize-uri`) collapses the path before
Vault sees it at all.

The set is deliberately narrower than either Vault or a URL requires — policy, not necessity:
Vault accepts any printable Unicode in a mount path (`validateMountPath`, canonical per
`path.Clean`), and `~ ! $ & ' ( ) * + , ; = : @` are legal raw in a URI path segment, so a mount
like `transit+prod` is real and would otherwise be addressable through this signer. It is refused
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
  coefficients, generator, order, cofactor — compared against the platform's `AlgorithmParameters`
  answer for that name rather than against hard-coded constants, which §6 states the cost of; and
  the key's point must satisfy `y² = x³ + ax + b (mod p)` with both coordinates in `[0, p)`. None
  of the three implies another: the metadata is only Vault's claim, and correct parameters say
  nothing about the point — the JCA validates neither, so SunEC accepts a key at `(1, 2)` both on
  import and at verification time. Coordinates are likewise never truncated to fit the 32-byte
  P-256 fields. Without all three, an `ecdsa-p384` key yields a syntactically valid but unusable
  VAPID key, and the misconfiguration surfaces only as an unexplained push-service rejection on the
  first send. Those three are what the metadata read itself performs; the canonical constructor
  then puts the same key through `P256PublicKeys.requireOnCurve` — the core's check, against its
  hard-coded constants — before the signer exists, which is what §6 weighs against the unverified
  reference the parameter step uses.
- **Explicit mode** receives the public key from configuration, permitting a sign-only token.
  Supplying the matching Transit key version pins signing to that version. The supplied key gets
  the full `P256PublicKeys.requireOnCurve` check (§5): the `VapidSigner` contract — pinned by the
  published conformance kit — requires `publicKey()` to return a point on P-256, so a signer
  violating it must be unbuildable, and no legal VAPID key can fail the check. Its correspondence
  to the Transit key cannot be established here and stays with the caller; a mismatch surfaces on
  the first signature to a VAPID-bound subscription, as a push-service rejection.

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

**A value the core rejects is re-thrown with the YAML property name in front of the core's own
message.** The core is where a constraint is stated once, so the starter neither restates a bound
nor validates ahead of it — two copies of a limit drift, and the core is the authority on what a
legal value is. What the core cannot know is the name the operator wrote in their configuration
file: its messages name a camelCase builder or constructor parameter. Translating at the boundary
is what turns a rejected value into a startup failure the operator can act on, and it is also why
the properties bind optionally — an unset property leaves the core's default in place rather than
restating it in a second location.

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

The endpoint policy has two *sources*: the allowlist properties and an application `EndpointPolicy`
bean. `push2u.allowed-origins` and `push2u.allowed-domains` are not two of them — they are two
halves of one statement, unioned into a single allowlist, which is the shape a deployment serving
Edge beside the three fixed-host services needs. The decision is expressed when at least one of
them is non-empty, and exclusivity holds between the properties and the bean, never between the
two properties: expressing it while also supplying a bean fails the context, naming whichever
property is non-empty and naming the bean, rather than silently preferring one and leaving the
other believed-active. The escape hatch is per property, as it always was — an explicitly *empty*
value says the property is deliberately unused here, so a service can empty whichever key it
inherited from shared configuration it cannot unset. Every set property empty with no bean is
answered by the starter itself, naming both keys: the emptiness is then a statement about the pair,
and no single core factory can speak for both. Expressing neither — both unset, no bean — fails the
context as well, with a message naming the three ways to fix it: the sender the starter builds
needs a policy like any other, and the decision has to come from the deployment.

Both components are nullable and neither carries a `@DefaultValue`, so an unset key stays
distinguishable from an explicitly empty one; every rule above rests on that difference, and a
default value would collapse "this deployment has not decided" into "this deployment cedes to a
bean" — the two cases the starter has to answer differently.

A malformed entry is attributed exactly, by property name and index (`push2u.allowed-origins[2]`),
and needs no machinery to be: the starter builds each rule itself from one entry of one named
property, so at the moment the rule refuses, the property name and the index are both in hand. The
consequence is that the commonest consumer path no longer runs through
`EndpointPolicies.allowedOrigins` at all — what an operator sees for a bad entry comes from the
rule.

There is no property for the unrestricted mode — under Spring it is an application
`@Bean EndpointPolicy` returning `EndpointPolicies.unrestricted()`, by the same reasoning ADR-015
applied to the Vault address: a YAML flag reaches production by copying a dev profile, a code change
passes a review, and a property can be added later but not removed after a release. The second
allowlist property is not an exception to that reasoning but an application of it: what is withheld
is a *mode*, a flag that removes the control and travels between profiles as a copied line, while a
list of domains is data that has no value that disables anything. What it costs to withhold decided
it — with a bean exclusive against the properties, a deployment needing one zone would have to move
its ordinary origins into code as well, and the answers left inside YAML are unrestricted egress or
an allowlist that silently excludes a browser.

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
- the key-material boundary: the hard-coded P-256 constants against two providers' `secp256r1`
  parameters (`P256PublicKeysTest`, `BcFipsP256PublicKeysTest`), the invalid-curve rejection
  shapes at `Subscription` construction (`SubscriptionValueTest`), and — both in
  `EcKeysUntrustedInputTest` — those same shapes at decode time plus the generated-pair refusals,
  driven by a provider that returns them: a substituted parameter component, a non-EC or absent
  half, a point off the curve or at infinity;
- the Vault address contract: the path-preserving join for root and path-prefixed addresses, and
  every factory-level rejection (`VaultTransitVapidSignerAddressTest`);
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
