# ADR-016 — The endpoint policy is a required decision

**Status:** Proposed

The endpoint inside a `Subscription` is attacker-influenced: the ordinary integration accepts the
browser's `PushSubscription` JSON at a public registration endpoint, and nothing stops a client
from posting a hand-crafted subscription whose endpoint names a loopback port, a private-range
address or a cloud metadata service. Every later send then POSTs to that address from inside the
network, and what the caller can observe — `PushResult.statusCode()` against
`PushDeliveryException`, and timing — is a blind SSRF oracle for internal host and port existence.

ADR-005 admitted `EndpointPolicy` as a seam because which hosts a deployment may contact is a
statement about that deployment's egress, and the library has no basis for making it. That reasoning
is intact and this decision does not touch it. What it did not settle is what happens when nobody
makes the statement, and the answer the code arrived at by default — an unset optional builder step,
a nullable field, a policy skipped when absent — turned "the library does not choose your allowlist"
into "the library sends anywhere until you notice". Those are different claims, and only the first
one was ever decided.

`SECURITY.md` keeps an application's misconfiguration out of scope *unless the configuration surface
makes the unsafe outcome the silent default*, which is a description of the shape that was shipping.
A library cannot both name that shape as a vulnerability it accepts reports about and offer it as
its own default.

The decision:

- **`EndpointPolicy` is a required argument of both `PushSender` factory methods**, alongside the
  keys or signer and the contact. There is no default policy and no way to obtain a sender without
  naming one. The library still does not choose the allowlist for the deployment; it refuses to
  decide on the deployment's behalf whether there is one.
- **The unsafe mode continues to exist and acquires a name**: `EndpointPolicies.unrestricted()`,
  beside `allowedOrigins`. Sending to any `https` endpoint a `Subscription` accepts is legitimate
  where subscriptions never come from untrusted clients, and a control that cannot be turned off
  gets worked around rather than considered. The point of the name is that it is a token in the
  consumer's own source: it appears in their diff, their review and their grep. An absent line
  appears in none of those, which is the whole difference between this and the previous default.
- **The optional builder step is removed rather than kept beside the parameter.** Required values
  belong in the factory method, and `build()` must not be able to refuse over a missing required
  one — that is the compiler's job. A step that can override a value the factory already demanded
  would also give the same sender two spellings and one of them a silently losing precedence.
- **The policy therefore runs on every send, unconditionally.** The pipeline loses its
  "if configured" branch, so the ordering guarantee — policy before encryption, before the VAPID
  signature and its possible remote call, before any network I/O — stops being conditional on
  configuration.
- **The Spring starter fails to start when no decision is expressed.** Its two existing sources
  stay as they are — `push2u.allowed-origins`, or an application-supplied `EndpointPolicy` bean,
  never both — and only the third case changes: neither present is now a context failure naming
  both ways to fix it, instead of a sender quietly built without a policy.
- **The unrestricted mode gets no Spring property.** ADR-015 settled this shape of question for the
  Vault address: a YAML flag reaches production by copying a dev profile, while a code change passes
  a review. A `@Bean EndpointPolicy` returning `EndpointPolicies.unrestricted()` is that code
  change. The asymmetry noted there decides it here too — a property can be added later without
  breaking anyone, and cannot be removed after a release.
- **Every published example builds a sender with an allowlist.** An example is the shape a consumer
  copies, so one that omits the policy would reinstate the old default in the only place it still
  could. `allowedOrigins` is the ordinary case wherever this project shows a sender being built, and
  `unrestricted()` appears only where the surrounding text is about that exception and says what
  makes it safe there.

This has to be settled before `0.1.0`, because settling it later costs a breaking change to both
the API and the configuration: a required parameter added to a factory method consumers already
call, and a permitted configuration turned into a startup failure. No published consumer contract
depends on the current signatures yet — the call sites that do are in this repository, and they move
with the change.

Rejected alternatives:

- **Leaving the policy off and documenting it harder.** It was already documented — in the Javadoc
  of the builder step, in `DESIGN.md` and in a README section with the threat model spelled out.
  Prose is not a control, and the reader who most needs it is the one who never reaches that
  section.
- **Shipping a built-in allowlist of the known browser push services.** That is the library
  choosing the allowlist, which ADR-005 rules out — and it would be wrong in both directions: it
  goes stale as push services appear, and it silently breaks the self-hosted and intra-organisation
  services that are a legitimate deployment. An allowlist that is mostly right is worse than none,
  because it hides that the question was never asked.
- **Blocking loopback, private-range and link-local addresses by default.** A URI-level check
  cannot see the address a name will resolve to, and resolving inside validation is what ADR-015
  already refused: a network call in a validator, an answer that may differ from the one the
  transport's resolver gets, and a rule that depends on the environment rather than on the value.
  Restricted to IP literals it would catch `https://127.0.0.1/…` and nothing that uses a name —
  protection in appearance only, which is worse than a decision the deployment had to make.
- **Keeping the two-argument factory and refusing in `build()`.** A runtime refusal over a missing
  required value is precisely what the factory-method convention exists to prevent, and it moves
  the failure from compile time to the first deployment that boots.
- **Warning instead of refusing.** The core has no logger, by the zero-dependency constraint, and
  a log line is not a control.

This rules out a `PushSender` that exists without an egress decision behind it, an allowlist shipped
by the library, an endpoint policy derived by resolving the endpoint, and a configuration-only path
to unrestricted egress under Spring. `Endpoints.requireSecure` is unaffected and stays what ADR-005
called it: a protocol check, not a security control.
