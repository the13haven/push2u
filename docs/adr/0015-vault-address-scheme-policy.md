# ADR-015 — Vault address scheme: https, or loopback/opted-in http

**Status:** Accepted

The Vault token rides in the `X-Vault-Token` header of every request the Transit signer makes, so
the address's scheme is a security boundary: over plain HTTP to a remote host the token crosses the
network in clear text. Until this decision the validator never looked at the scheme —
`ftp://vault.example` passed both builders and failed only on the first sign, inside the HTTP
transport — while the documentation asked, without enforcing, that "a production address must be
`https`". A documented expectation with nothing behind it protects nobody.

The decision:

- **Only `http` and `https` are acceptable schemes**, compared case-insensitively (RFC 3986 §3.1).
  Anything else is rejected at the factory methods, where every other invalid-but-present address
  is already rejected — no later builder step can rescue a scheme the transport cannot speak.
- **`https` is always accepted.**
- **Plain `http` to a literal loopback host is always accepted, with no opt-in.** This is not a
  developer convenience: it is the Vault Agent Injector and service-mesh sidecar pattern, where the
  application talks to `http://127.0.0.1:8200` and the agent beside it terminates TLS — a
  mainstream production deployment that must work out of the box. The literal set is the browsers'
  secure-context set: `localhost`, names under `.localhost`, `127.0.0.0/8` IPv4 dotted-quads in
  canonical decimal, and the IPv6 loopback as a bracketed literal.
- **Plain `http` to anything else requires the builders' explicit `allowInsecureHttp()` step**;
  without it `build()` throws. The rule cannot live at the factory — the opt-in is a builder step,
  callable only after the factory has returned — so this is a deliberate exception to the habit of
  rejecting an invalid-but-present value at the factory: the value is not invalid in itself, its
  acceptability depends on a later optional step. In the fetched mode the check runs before the
  startup Vault read, so a refused address fails without contacting anything.
- **Loopback is decided from the literal host text, never by resolving the name.** Resolution would
  be a network call inside validation, could disagree with whatever the transport's resolver
  answers later, and would make the rule depend on the environment rather than on the address. The
  accepted price is that `http://my-vault` pointing at `127.0.0.1` through `/etc/hosts` needs the
  opt-in.
- **The Spring starter exposes no property for the opt-in.** A YAML flag can arrive in production
  by copying a dev profile; a code change — an application-supplied `VaultTransitVapidSigner` bean
  built with `allowInsecureHttp()`, to which the starter's `@ConditionalOnMissingBean` yields —
  passes a review. The asymmetry decides it: a property can be added later without breaking anyone,
  while removing one after a release cannot.

Rejected alternatives: refusing plain `http` entirely (breaks the sidecar pattern and the dev
server for no security gain — a loopback hop never leaves the machine); accepting `http` whenever
the host *resolves* to a loopback (resolution inside validation, environment-dependent, and a
different answer than the transport may get); a Spring opt-in property (see above); and warning
instead of refusing (a log line is not a control, and the signer module has no logger to warn
with).

This rules out any further scheme joining the whitelist without a new decision, any loopback
determination that consults the environment, and a configuration-only path to plaintext transport
of the Vault token.
