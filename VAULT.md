# Vault Transit signer

`VaultTransitVapidSigner` keeps the VAPID private key inside HashiCorp Vault: push2u sends signing
requests to the Transit engine instead of loading a scalar. This is the configuration reference —
[`README.md` → Vault Transit signer](README.md#vault-transit-signer) carries the dependency
coordinates and the minimal working example.

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
none (see *Vault namespaces* below), and `transport` defaults to a `JdkVaultHttpTransport` (see
*Vault HTTP transport* below). `mount` is validated where it is set, per segment: nested mounts
like `secrets/transit` are legal, and every `/`-separated segment must be non-empty, not `.` or
`..`, and use only `[A-Za-z0-9_.-]`. That it is an allowed set rather than a `..` blacklist is what
percent-encoding cannot reopen, and the set is deliberately narrower than either Vault or a URL
permits — [`DESIGN.md` §7](DESIGN.md#7-vault-transit-integration) has the routes it closes and why
a conservative set can be widened later but not narrowed.

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
application's contact address. `push2u.vapid.subject` — the VAPID `sub` claim — therefore still
comes from the core starter's properties, in this mode and in the explicit one below, and
`Push2uAutoConfiguration` fails startup with a message naming it if it is left unset.

## Explicit public key

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

An explicitly supplied `public-key` is checked structurally only — 65 bytes with the `0x04`
uncompressed tag. It is not verified to be a point on P-256, and nothing can check here that it is
the public half of the Transit key being signed with; both remain the caller's responsibility. The
P-256 validation described under *Fetched public key* applies to that mode alone.

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
[`README.md` → Redirects must never be followed](README.md#redirects-must-never-be-followed)).
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
   [`README.md` → Redirects must never be followed](README.md#redirects-must-never-be-followed),
   which also covers what to do when a Vault HA standby is the source of the redirect.
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
