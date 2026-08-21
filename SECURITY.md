# Security Policy

push2u encrypts and authenticates push messages. A defect in it can silently weaken the
confidentiality of every message an application sends, so security reports get priority over
everything else in this repository.

## Reporting a vulnerability

**Do not open a public issue for a security report.** A public issue about a cryptographic or
authentication defect discloses it to everyone before a fix exists.

Report it through GitHub's private vulnerability reporting:

**[Report a vulnerability](https://github.com/the13haven/push2u/security/advisories/new)**
(repository → *Security* → *Advisories* → *Report a vulnerability*)

The report stays private between you and the maintainers until an advisory is published.

Please include, as far as you can establish them:

- the affected version or commit, and the affected module;
- which of the properties below you believe is broken, and how;
- a proof of concept — a failing test against this repository is the most useful form;
- your assessment of impact and of who is exposed.

Redact anything sensitive from what you attach: a subscription endpoint is a capability URL,
and `p256dh`/`auth`, VAPID private keys and Vault tokens are secrets. A synthetic key pair
demonstrates the same defect.

## What to expect

| Stage | Target |
|---|---|
| Acknowledgement of the report | 3 business days |
| Initial assessment — accepted, needs more information, or out of scope | 10 business days |
| Fix, released version and published advisory | as soon as practical, timeline shared with you |

This is a small project without a paid on-call rotation; the targets are what the maintainers aim
for, not a contractual guarantee. Disclosure is coordinated: the advisory is published together
with the fixed release, and the default window is 90 days from acknowledgement if a fix takes
longer. You are credited in the advisory unless you ask not to be. There is no bug bounty.

## Supported versions

| Version | Supported |
|---|---|
| `main` | Yes |
| Latest released minor | Yes |
| Any earlier release | No |

Security fixes go to the latest minor of the latest major; before 1.0 there are no backports to
earlier minors.

## Scope

In scope — the properties the library is responsible for:

- **Message encryption** (RFC 8291 / RFC 8188): key derivation, ECDH, `aes128gcm` record
  construction, salt and ephemeral key generation, anything that could repeat a nonce, reuse a
  keypair, or emit a body that leaks plaintext.
- **VAPID authentication** (RFC 8292): JWT construction and claims, the `aud` origin
  serialization, ES256 signing, and the DER → `r || s` conversion.
- **Key handling**: EC key import and validation — including the point-on-curve and
  domain-parameter checks on a public key from Vault — and any path that exposes private key
  material through an exception message, log record, or `toString`.
- **Endpoint policy**: a bypass of `EndpointPolicy` or of an `EndpointPolicies` allowlist — an
  endpoint matching a rule that should not admit it, or an entry accepted at construction that
  covers more than what was written — and any path that reaches the network before the policy
  runs. The endpoint in a `Subscription` is attacker-influenced, so this is the SSRF control point.
- **Secret exposure in diagnostics**: `X-Vault-Token`, the Vault address, or the capability
  path/query of an endpoint reaching an exception message, log record, or health payload.
- **Integrity of a diagnostic something else reads**: text chosen by a push service, or by whatever
  answers on the Vault address, reaching an exception message, log record or health payload without
  being escaped — so that it can forge a line an operator reads as the application's own, steer a
  terminal with an escape sequence, or reverse the printed order of what follows it. This is a
  different property from the item above and not a weaker form of it: what breaks is the
  trustworthiness of the record, not the confidentiality of a value inside it.
- **Resource exhaustion reachable from a remote peer**: an unbounded read, a missing timeout, or an
  unbounded internal cache. The library performs one POST per send and schedules no repeat, so the
  path a hostile push service could amplify by naming a large `Retry-After` is the caller's
  scheduler and not ours — what remains in scope here is that the value reported is the value that
  arrived: unmodified, with no ceiling of ours applied and none silently removed, so that the
  caller's own bound is the only one and is applied to a number the service really sent.
- **The Spring Boot starters**: a property binding or conditional that silently disables one of
  the controls above.

Out of scope here — report these as ordinary issues, or to the party that owns them:

- Browser-side code, service workers, and the push services themselves.
- Subscription storage, deletion, and access control — the library is stateless by design
  ([ADR-004](docs/adr/0004-stateless-library.md)); those belong to the application.
- Applications that misconfigure the library, unless the configuration surface makes the unsafe
  outcome the silent default.
- Advisories against build-time or test-only dependencies (Gradle plugins, analysers,
  Testcontainers). They never reach a consumer's classpath; the build pins them as maintenance —
  see the constraints in `build.gradle.kts`. If a vulnerable version reaches a *published*
  artifact's runtime classpath, that is in scope.
- Automated scanner output with no demonstrated impact on this codebase.

## Testing safely

Please research against your own infrastructure. Do not use a real browser push service (FCM,
Mozilla autopush, WNS) or anyone else's endpoint as a target while probing endpoint or transport
behaviour — the endpoint-policy paths in particular are about where the library can be induced to
send requests, and exercising them against third parties makes them the victim. The test suite
runs entirely against local mocks and a Testcontainers Vault instance; that is enough to
demonstrate anything in scope.

Good-faith research that follows this policy is welcome, and the maintainers will not pursue or
support action against a reporter who follows it.
