# ADR-005 — Public SPIs in the core

**Status:** Accepted

A seam is a permanent commitment: it ships to Maven Central, every implementation of it becomes a
way for the library to be wrong, and the failure modes an implementation introduces are ones no
test here can see. So a seam exists only where there is an articulable difference the library
cannot decide on behalf of the deployment.

Three things in `push2u-core` meet that bar:

- `VapidSigner` — key custody. Where the VAPID private key lives is an operational decision (in
  process, in Vault, in a KMS or an HSM), and no default can be right for every deployment.
- `PushHttpClient` — push transport. Proxying, pooling and observability belong to the
  application's HTTP stack.
- `EndpointPolicy` — which hosts a deployment may POST to. Added after the first two, under the
  same test: that is a statement about an application's egress, and the library has no basis for
  making it. `Endpoints.requireSecure` stays a protocol check, not a security control.

Everything else stays concrete. Cryptographic protocol steps in particular are not seams
(ADR-003).

The Vault module adds a fourth seam of its own, `VaultHttpTransport`, rather than reusing
`PushHttpClient`. The two face opposite trust domains — push delivery POSTs to an untrusted
capability URL and must never read the response body, while the Vault API is an
operator-configured service whose JSON responses must be read, bounded and under a request timeout
— and one interface carrying both contracts would let an implementation satisfy the wrong one.
