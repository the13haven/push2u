# ADR-024 — One endpoint policy, reachable where subscriptions are accepted

**Status:** Proposed

ADR-016 made the endpoint policy a required argument of every `PushSender` factory: a deployment
that has not said which endpoints it will contact does not get a sender. What it did not settle is
*where* that decision is applied, and the library applies it in one place — immediately before a
send, on the endpoint the subscription carries.

The decision is older than the send. A subscription arrives as browser `PushSubscription` JSON at a
public registration endpoint and is written to a store; whether this deployment will ever contact
that endpoint is answerable at that moment, from the same rule that will answer it later.

Applying it only at send has a cost that does not decay. A policy refusal is not a `410` and not a
push service's answer at all: nothing marks the stored row as dead, nothing expires it, and no later
send will ever succeed. The row fails once per notification, forever, while the subscriber's browser
reports a healthy subscription — and the deployment's own logs blame an endpoint that was never
acceptable rather than a boundary that let it in.
https://github.com/the13haven/push2u/issues/93 reports exactly that, from a deployment whose
allowlist does not name the push origins of one of the browsers it serves.

**The core is already shaped for the second application point, and turning that finding into a
decision is what this record is for.** `EndpointPolicy.validate` is public, takes the endpoint URI
and nothing else, and reports its refusal as `EndpointRejectedException` — a type that deliberately
does not extend `IllegalArgumentException` precisely so that an application catching it at its own
boundary decides what to answer, instead of a web framework mapping it to a `400` that echoes the
message (ADR-022). `Endpoints.requireSecure` and `P256PublicKeys.requireOnCurve` are public for the
same boundary. A deployment that builds its sender by hand holds the policy because it constructed
it, so for that deployment the second application point is a method call it can already make.

The Spring starter is the one place in the tree where the value is created and not represented: the
auto-configuration builds it from `push2u.allowed-origins` and `push2u.allowed-domains` inside the
sender's factory method, and nothing else in the context can reach it. The shape ADR-016 gives a
plain-Java deployment — the deployment states the decision and hands it to the sender — is the shape
the starter inverted: it states the decision *for* the deployment and keeps it.

## The decision

**The endpoint policy is one value the deployment owns, applied at both points of a subscription's
life: where a subscription is accepted, and before every send.** One instance, not two that agree.

Three things follow, and only one of them is code:

- the core gains no API, and that is a decision rather than an absence of work;
- the core describes the policy by both application points rather than by the send alone;
- under Spring the policy exists as a bean, and the sender takes it as an ordinary dependency.

## Why the core gains no API

Four additions were considered. Each would answer the issue, and each is refused.

**`PushSender.endpointPolicy()`** — the alternative the issue itself offers. It publishes an
accessor for the life of the API, and it states the opposite of ADR-016: the policy stops being a
decision the deployment hands to a sender and becomes a property of the sender that anything holding
one may ask for. It also makes the path that accepts subscriptions depend on a sender it has no
other use for — that path stores a row, it does not send.

**A predicate beside `validate`** — `boolean isAllowed(URI)`. A second way to ask one question,
which every implementation of the seam then has to keep consistent with the first, with nothing able
to check that it did. `EndpointPolicy` is a functional interface with a single method, and staying
one is what lets a corporate egress rule be written as a lambda.

**`validate(Subscription)`** — the same second spelling wearing a different argument. The policy
sees a URI on purpose: it decides about an address, and key material is not its business.

**An acceptance factory in the core** — `Subscriptions.accept(policy, endpoint, p256dh, auth)`. It
joins two checks of different natures: what RFC 8030 requires of an endpoint, which the library
decides for everyone, and which hosts this deployment admits, which it decides for nobody. It would
fix an order the application is entitled to choose, and report two unrelated refusals through one
call.

The library does not perform the registration check itself for a reason that is already settled:
ADR-004 keeps subscription storage and lifecycle outside the library, so there is no boundary here
at which a subscription appears. The library owns the rule and the call; the application owns the
moment.

## Two instances that agree is not the decision

A deployment can already read `push2u.allowed-origins` out of the environment and build a second
policy from it, without registering it as a bean. It works, and it is what the reporting deployment
does today. It is not what this record chooses, because a rule living in two objects is a rule that
differs at the next rule kind — and it already has. ADR-017 added `push2u.allowed-domains`; a
deployment expressing its allowlist as a zone now has a registration boundary that refuses endpoints
its sender would accept. Nothing reports the disagreement, because there is no place where the two
are compared: registration simply starts answering `400` to subscriptions that would have been
delivered to.

It also reads a property namespace the application does not own, which is the coupling
`@ConfigurationProperties` exists to prevent, and it is silently wrong for a deployment that supplies
its own policy bean and leaves the properties unset.

## Under Spring: the policy is a bean

The auto-configuration publishes the policy it already builds, and `pushSender` takes it as an
ordinary parameter:

```java
@Bean(ENDPOINT_POLICY_BEAN_NAME)          // "push2uEndpointPolicy"
@ConditionalOnMissingBean
@ConditionalOnBean(VapidSigner.class)
EndpointPolicy push2uEndpointPolicy(Push2uProperties properties) { … }
```

**The signer condition is not symmetry.** Without it, a deployment that has the starter on its
classpath and has not configured web push starts failing at startup for want of an allowlist. Today
the allowlist failures are reachable only through `pushSender`, which is itself
`@ConditionalOnBean(VapidSigner.class)`, and that reachability is behaviour rather than accident: a
deployment that is not sending has not been asked the question.

**The diagnostics survive the move, or the move is wrong.** Three of the four refusals — both
properties unset with no bean, every set property empty with no bean, and a malformed entry named by
property and index — move into the policy's factory unchanged. The fourth, a non-empty allowlist
property beside an application-supplied bean, cannot: when the application's bean wins,
`@ConditionalOnMissingBean` means the factory is never called. It stays where it is, in `pushSender`,
asked as "a property is non-empty and the context's policy is not the one this starter contributed".
Its message names the conflicting bean, and that message is the reason the check exists.

**Which bean is whose is answered by name**, declared as a constant next to the factory rather than
inferred from the method name. The cost is one case: an application naming its own bean
`push2uEndpointPolicy` loses the conflict message. It does not lose the control — its policy is the
one in the context and the one the sender uses — so what degrades is a diagnostic, not a decision. A
marker type wrapping the policy would answer precisely, and is refused for what it costs everywhere
else: a type on the starter's surface and a delegation on every send, bought for a case nobody meets.

**One price is paid knowingly.** `@ConditionalOnMissingBean` is reliable against beans from the
application's own configuration, which is processed before auto-configurations; a policy contributed
by *another* auto-configuration ordered after this one would now lose, where the `ObjectProvider`
resolved inside the sender's factory would have seen it. That case is rare enough to accept and
specific enough to state.

Nothing about the properties changes: `push2u.allowed-origins` and `push2u.allowed-domains` are two
halves of one statement, unioned into one allowlist, and the exclusivity is between the properties
and a bean. The bean this starter contributes is built only from those properties, so no
configuration-only path to unrestricted egress appears — `EndpointPolicies.unrestricted()` is still
reachable only as application code someone reviews.

## Checking at registration does not make the send's check redundant

The policy is a deployment decision, and deployment decisions change: an allowlist edited between
two releases makes a row accepted last month refusable today. A registration check therefore does
not make a stored row permanently acceptable, and `send` does not trust that a row once passed —
for the same reason ADR-023 refuses a `send` that trusts an earlier size assessment. What checking
at registration buys is that a row whose answer is already known does not enter the store at all.

The application decides what a refusal means at each point, because only it knows: a `400` and no
row where the subscription is offered, and at send the `EndpointRejected` value — a `NotAttempted`
outcome, not an exception (ADR-021) — where a fan-out flags or removes the row and carries on.

## What this does not touch

ADR-016 stands in every part: the policy remains a required argument of both factory methods, the
library still ships no allowlist, a policy is still not derived by resolving the endpoint, and there
is still no configuration-only path to unrestricted egress under Spring. ADR-017's rule kinds and
their matching are untouched. No ADR is superseded, in whole or in clause: this record adds where
the decision applies and how it is represented, to a decision that stays exactly as it was.

For a deployment that builds its sender by hand, nothing changes at all — it holds its policy today,
and the second call site was available to it before this record existed.

## What this rules out

- An endpoint policy a deployment cannot reach at the boundary where it accepts subscriptions.
- A second policy instance, built by the application from properties another module owns, as the
  supported way to check at that boundary.
- An accessor for the policy on `PushSender`.
- A second method on `EndpointPolicy` — a predicate, an overload taking a `Subscription`, or any
  other second way to ask the one question the seam exists to answer.
- A core factory joining subscription parsing to the deployment's admission decision, or a
  library-owned registration boundary — ADR-004 unchanged.
- A policy built inside the sender's factory method in an auto-configuration and left unrepresented
  in the context that owns it.
- An application-supplied policy bean winning silently over a non-empty allowlist property: the
  conflict diagnostic, naming the bean, survives the move.
- A policy bean that exists in a deployment which configured no signer, and with it a startup
  failure demanding an allowlist from a deployment that is not sending.
- A registration check a later send trusts, or one offered as a replacement for the send's check.
- A configuration-only path to unrestricted egress, in any spelling the new bean might have made
  available — ADR-016 unchanged in that respect.
