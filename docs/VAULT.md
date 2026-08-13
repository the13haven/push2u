# Vault Transit signer

`VaultTransitVapidSigner` keeps the VAPID private key inside HashiCorp Vault: push2u sends signing
requests to the Transit engine instead of loading a scalar. This is the configuration reference —
[`README.md` → Vault Transit signer](../README.md#vault-transit-signer) carries the dependency
coordinates and the minimal working example.

## Vault address

The address — the builders' first factory parameter, the starter's `push2u.signer.vault.address` —
is the base every Vault API path is appended to: the signer calls
`{address}/v1/{mount}/sign/{key}` and, in fetched mode, `{address}/v1/{mount}/keys/{key}`. Two
shapes are legal:

- a root address, `https://vault.example:8200` — Vault serving its API directly;
- a path-prefixed address, `https://gw.example/vault` — Vault behind a reverse proxy or Kubernetes
  ingress that mounts it under a sub-path. The prefix is preserved in front of every API path
  (`https://gw.example/vault/v1/transit/sign/vapid`), and a trailing slash changes nothing:
  `https://gw.example/vault/` is the same base.

The address is validated at the factory methods (and the starter names the property on failure).
It must be an absolute URI with a host and must carry neither a query nor a fragment — a base
address has no use for either, and neither could survive the path join. The path prefix follows
the same per-segment rule as `mount`: every `/`-separated segment must be non-empty, not `.` or
`..`, and drawn from `[A-Za-z0-9_.-]` — an allowed set rather than a blacklist, so a
percent-encoded `%2e%2e` cannot reopen what the literal check closes. The prefix rides in front of
every token-bearing request path, which is why a segment a normalizing hop would rewrite is
refused at configuration ([`DESIGN.md` §7](DESIGN.md#7-vault-transit-integration)).

The scheme must be `http` or `https` (case-insensitively — RFC 3986 §3.1): the signer speaks
Vault's HTTP API and nothing else, so any other scheme is rejected at the factory (and at startup,
naming the property). `https` is always accepted. Plain `http` is accepted without ceremony only
when the host is a *literal loopback* — `localhost`, a name under `.localhost`, an IPv4
dotted-quad in `127.0.0.0/8` (canonical decimal, no leading zeros), or a bracketed IP literal that
denotes a loopback address. The bracketed form is parsed rather than string-matched, so it covers
`[::1]` in any of its spellings *and* the IPv4-mapped writings of a `127.0.0.0/8` address —
`[::ffff:127.0.0.1]`, `[::ffff:7f00:1]` — which the platform resolves to that IPv4 loopback, so
they reach exactly where `127.0.0.1` does. A mapped form of anything else (`[::ffff:8.8.8.8]`) is
refused, as is the deprecated IPv4-compatible `[::127.0.0.1]`, which denotes an IPv6 address that
is not the loopback. That carve-out is the Vault Agent Injector and service-mesh sidecar pattern:
the application talks plain HTTP to `http://127.0.0.1:8200` and the agent beside it terminates TLS
— a mainstream production deployment that works out of the box (and covers Vault's plain-`http`
dev server too).

Plain `http` to any other host is refused by `build()` unless the builder's `allowInsecureHttp()`
step was called: the `X-Vault-Token` header would cross the network in clear text. In the fetched
mode the refusal happens *before* the startup Vault read, so a misconfigured address fails without
contacting anything. Loopback is decided from the literal host text, never by resolving the name —
resolution would be a network call inside validation and would make the rule depend on the
environment rather than on the address — so `http://my-vault` pointing at `127.0.0.1` through
`/etc/hosts` still needs the opt-in.

The Spring starter exposes no property for the opt-in, deliberately: sending the Vault token over
plaintext HTTP to a remote host should cost a code change and a review, not a YAML edit that can
arrive by copying a dev profile into production. A deployment that accepts the risk defines its
own `VaultTransitVapidSigner` bean (built with `allowInsecureHttp()`), and the starter's
`@ConditionalOnMissingBean` backs off to it.

Userinfo in the address (`https://user:password@gw.example/vault`) is preserved but unused by the
built-in transport; a custom `VaultHttpTransport` may honour it, for a basic-auth proxy in front of
Vault. It is treated as a credential everywhere push2u prints an address: `JdkVaultHttpTransport`
drops it from the URIs it names in failure messages, and the starter's
`VaultSignerProperties.toString()` renders it as `https://***@gw.example/vault` — masked, the same
way it renders the token as `***`, rather than dropped, so a configuration dump cannot read as "no
proxy credentials configured". Both renderings are composed from the URI's parsed components and
fail closed: an address Java did not parse as `scheme://host` (a schemeless
`user:pass@vault.example:8200`, a relative reference), one carrying a query or fragment, or one
whose *raw* path carries `@` or `%` — the tail of a credential whose head happened to parse as
`host:port`, as in `https://u:1971/restOfPassword@vault.example:8200`, whether the delimiter is
literal or percent-encoded at any depth (`%40`, `%2540`) — is replaced whole by the fixed marker
`<unrenderable address>`, because a credential in such a string can sit outside anything Java
reports as userinfo. Neither `@` nor `%` can appear in a valid Vault address path, so the marker
never swallows an address the signer would accept. Routes push2u does not own still print what was configured: Spring
Boot's startup failure report echoes the raw property value (`Value: "…"`) when a value fails to
bind, so a malformed address that carries userinfo is reported verbatim.

## Fetched public key

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
`PushCryptoException` instead of producing a VAPID key that every push service rejects later. That
is the recurring half of what this `build()` can throw; *[What the signer
throws](#what-the-signer-throws)* below has the other half and the order a startup supervisor reads
them in.

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
an incomplete signer does not compile. The key name and the token are the value types
`TransitKeyName` and `VaultToken` rather than bare strings, so they cannot be swapped in the
argument list, and each enforces its value's contract. `TransitKeyName` applies Vault's own Transit
key-name rule (letters, digits, `_`, `-` and `.`, beginning and ending with a word character —
Vault's `GenericNameRegex`), so no name Vault would accept is refused while every URL-breaking
character is. `VaultToken` requires non-empty visible ASCII — rejecting the trailing newline picked
up from a file or a YAML block scalar, a pasted `Bearer ` prefix, or a stray space — without
echoing the token; the token's *format* is deliberately not checked, and its `toString()` prints
`VaultToken[REDACTED]`, never the value.

The builder holds only the optional steps: `mount` defaults to `transit` (in both the builder and
the properties), Vault's own default mount for the Transit secrets engine, `namespace` defaults to
none (see *Vault namespaces* below), `transport` defaults to a `JdkVaultHttpTransport` (see
*Vault HTTP transport* below), and `allowInsecureHttp()` defaults to off (see *Vault address*
above — plain `http` beyond a literal loopback host is refused without it). `mount` is validated
where it is set, per segment: nested mounts like `secrets/transit` are legal, and every
`/`-separated segment must be non-empty, not `.` or `..`, and use only `[A-Za-z0-9_.-]`. That it is
an allowed set rather than a `..` blacklist is what percent-encoding cannot reopen, and the set is
deliberately narrower than either Vault or a URL permits
— [`DESIGN.md` §7](DESIGN.md#7-vault-transit-integration) has the routes it closes and why a
conservative set can be widened later but not narrowed.

The equivalent Spring Boot configuration is:

```yaml
push2u:
  vapid:
    subject: "mailto:ops@example.com"
  allowed-origins:
    - "https://fcm.googleapis.com"
  signer:
    vault:
      address: "https://vault.example:8200"
      mount: "transit"
      key-name: "vapid"
      token: "${VAULT_TOKEN}"
```

The Vault signer starter only supplies the `VapidSigner` (key custody); it does not know the
application's contact address, nor which endpoints the deployment may POST to.
`push2u.vapid.subject` — the VAPID `sub` claim — and the endpoint policy therefore both come from
the core starter's properties, in this mode and in the explicit one below, and
`Push2uAutoConfiguration` fails startup with a message naming whatever is left unset. The policy
comes from either or both of `push2u.allowed-origins` and `push2u.allowed-domains`, whose entries
are unioned into one allowlist, or equally from an application `EndpointPolicy` bean instead of the
properties; [`SPRING.md`](SPRING.md#endpoint-policy) has every route.

### Serving the public key to your frontend

In this mode the public key exists nowhere but in Vault and in the signer that read it. There is
deliberately no `public-key` property to echo back — the Transit key is the single source of truth,
which is what keeps the advertised key from drifting away from the signing key. So ask the signer:

```java
String applicationServerKey = signer.publicKeyBase64Url();
```

`VapidSigner.publicKeyBase64Url()` is a `default` method on the SPI, so it is available on this
signer and on every other. It returns the unpadded URL-safe base64 of the key this signer will
actually sign with — the same string the `Authorization` header carries as its `k` parameter, and
the value the browser needs as the `applicationServerKey` option of `pushManager.subscribe(...)`.
Because it is derived from the signer's own key rather than from configuration, it stays correct in
this mode by construction. See
[`README.md` → Publishing the public key to the browser](../README.md#publishing-the-public-key-to-the-browser)
for the encoding details and for the pair-level `VapidKeys.encodePublicKey(...)`.

Serving it over HTTP is the application's own route: push2u adds no bean and no endpoint for it, so
the path, the authentication and the caching stay yours to decide.

## Explicit public key

Set `public-key` when the token must be sign-only. Also set `key-version` to the Transit version
that owns that public key, so subsequent rotations cannot make Vault sign with a different private
key:

```yaml
push2u:
  vapid:
    subject: "mailto:ops@example.com"
  allowed-origins:
    - "https://fcm.googleapis.com"
  signer:
    vault:
      address: "https://vault.example:8200"
      mount: "transit"
      key-name: "vapid"
      token: "${VAULT_TOKEN}"
      public-key: "${VAPID_PUBLIC_KEY}"
      key-version: 3
```

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

There are two builders rather than one because the modes differ in contract:
`builderWithFetchedPublicKey(…)` reads Vault inside `build()` and can fail there, while
`builderWithSuppliedPublicKey(…)` contacts nothing. `keyVersion(...)` exists only on the second
one — in the fetched mode the version comes from Vault, with the public key it belongs to.

Leaving `keyVersion` (or the `key-version` property) out sends no `key_version`; Vault then signs
with its latest version. Use that form only when the Transit key is guaranteed never to rotate.

An explicitly supplied `public-key` is validated as a point on P-256 — 65 bytes with the `0x04`
uncompressed tag, coordinates in the field, the curve equation satisfied — because the
`VapidSigner` contract requires exactly that of `publicKey()`, and no legal VAPID key can fail the
check. What nothing can check here is that it is the public half of the Transit key being signed
with; that remains the caller's responsibility, and a mismatch surfaces on the first signature to a
subscription bound to your `applicationServerKey`, as a push-service rejection of the JWT. The Vault-side validation described under *Fetched public key*
(the Transit `type`, the atomic version/key pair) applies to that mode alone.

## What the signer throws

Every failure of this signer leaves in one of two types, and the axis is whether waiting can clear
it. It matters twice: at startup, where a supervisor decides whether to retry the boot, and on every
send, where the sender converts one of the two into an outcome and rethrows the other.

- **`VapidSignerUnavailableException` — Vault cannot serve the request *now*.** Either nothing
  answered (no connection, a failed TLS handshake, a timeout, an interrupted wait), or Vault
  answered a status naming its own condition rather than the request's. The signer reads those
  statuses off [Vault's own published
  table](https://developer.hashicorp.com/vault/api-docs#http-status-codes): `500` "try again later",
  `503` sealed, in maintenance or overloaded, `501` not initialized, `502` a third party Vault
  itself called, `412` eventually-consistent data not yet present, `429` a standby node or too many
  requests, `472` a disaster-recovery secondary, `473` a performance standby. A status the table
  does not name falls to RFC 9110's classes — an unrecognised `5xx` joins these, an unrecognised
  `4xx` does not.
- **`PushCryptoException` — the failure recurs until a person changes something.** Vault answering
  about the request or about what this deployment supplied: `400` a malformed call, `403` a token
  without the capability, `404` a mount or key that is not there, `405` a method the path does not
  take, and a key of a type VAPID cannot use or a pinned version Vault no longer holds. Also an
  answer Vault could not have meant — an unparseable signature, a key that is not on P-256 — and a
  substrate that cannot perform the cryptography at all.

**On a send** the first type never reaches the application: `PushSender.send` reports it as the
`PushOutcome.SignerUnavailable` outcome, carrying the status Vault answered with and, where Vault
declared one, how long to wait. Nothing was signed, so nothing was sent and no repeat can duplicate
a notification — but the whole fan-out is meeting the same outage, so the advice is to stop rather
than to reschedule row by row. The second type is rethrown as it is: stop the sender and fetch a
person.

**On a fetched-mode `build()`**, which reads the key over the network, both reach a startup
supervisor, and the order it tests them in is part of the contract:

1. **The interruption first** — the current thread's interrupt status set, *or* an
   `InterruptedException` somewhere in the cause chain; neither half of that disjunction is sound
   alone. A boot interrupted while the key is being read raises the *unavailable* type as well,
   because a transport does not sort an incomplete exchange by what made it incomplete. A supervisor
   that reads the type first therefore answers a shutdown by looping its own boot, with every
   backoff it sleeps failing instantly on a flag nobody cleared.
2. **`VapidSignerUnavailableException`** — a boot worth retrying with backoff, and not before any
   moment its `retryAfter()` names.
3. **`PushCryptoException`** — fail the deployment. Retrying the boot over it only postpones the
   page.

**The retry hint is present far more rarely than it is absent**, and that is ordinary rather than a
defect. Vault sets `Retry-After` on a rate-limited answer alone, and only where an operator enabled
the rate-limit response headers on `sys/quotas/config` — [an API-managed
setting](https://developer.hashicorp.com/vault/api-docs/system/quotas-config) that defaults to
false. Where it is present it is reported exactly as it arrived, with no ceiling applied, so the
only bound on the wait is the one whoever schedules the next attempt chooses.

## Vault namespaces (Enterprise / HCP)

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
value is validated where it is set, by the same per-segment rule as `mount`: it lands in an HTTP
header, which the allowed set keeps header-safe by construction, and a traversal segment cannot
name a real namespace anyway, so it is a configuration mistake worth refusing at startup
([`DESIGN.md` §7](DESIGN.md#7-vault-transit-integration)).

## Vault HTTP transport

All Vault calls — the Transit `sign` POST and, in fetched mode, the startup `transit/keys/<key>`
GET — go through the module's `VaultHttpTransport` seam. The default `JdkVaultHttpTransport`
(JDK `java.net.http`) enforces a per-request timeout on every call (a Vault that accepts the
connection but never answers cannot hang application startup), a fail-closed response-size cap
counted in raw streamed bytes (an oversized response fails the call; it is never truncated), and
`Redirect.NEVER` (see
[`README.md` → Redirects must never be followed](../README.md#redirects-must-never-be-followed)).
Defaults: 10 s connect timeout, 30 s request timeout, 1 MiB cap.

Vault answering — any status — comes back as a `VaultHttpResponse` rather than as an exception,
because classifying a status is the signer's job. That record carries three values: the status, the
UTF-8 body, and the parsed `Retry-After` where Vault declared one. The hint is on the record because
a response header stops at the transport unless the transport hands it on, and the signer copies it
into the exception it raises — which is the only route by which the one component able to act on it,
the caller's scheduler, ever sees it. What crosses is the parsed hint and not the headers: a bag of
them from a service read under a size bound is more surface than one value is worth.

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
   no request headers in exception messages. They must also signal in the two types the seam
   declares, since that split lives at the transport rather than in the signer — an exchange that
   produced no response leaves as `VapidSignerUnavailableException`, while a failure that recurs
   whatever Vault's health leaves as `PushCryptoException`: an unusable request URI, a request
   header carrying a character illegal in an HTTP field value, and a response over the
   implementation's own size cap, which is over it again on the next attempt too. An implementation
   is never asked to recognise an interruption; what it owes there is what any code catching an
   `InterruptedException` owes — re-set the flag on its own thread, and keep that exception in the
   cause chain.
2. A `java.net.http.HttpClient` bean qualified `push2uVaultHttpClient` — the middle road for
   mTLS/proxy setups. The starter wraps it in a `JdkVaultHttpTransport` with the configured
   `request-timeout` and `max-response-bytes` (`connect-timeout` is ignored; the supplied client
   owns it). The client must be built with `Redirect.NEVER` or startup fails — see
   [`README.md` → Redirects must never be followed](../README.md#redirects-must-never-be-followed)
   for why.
3. Otherwise the default transport is built entirely from the properties.

If a redirect is genuinely part of your Vault topology — typically an HA standby with
`disable_clustering = true` answering `307` towards the active node — point the Vault address at
the active node's `api_addr` (or a load balancer in front of it), or terminate the redirect in
the proxy. Following it is not an option: a `3xx` chased by the transport replays `X-Vault-Token`
to whatever host the `Location` names.

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
