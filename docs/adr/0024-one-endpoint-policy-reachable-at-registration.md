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
life: where a subscription is accepted, and before every send.** One rule, from one definition — not
two kept in agreement by whoever remembers to.

Three things follow, and only one of them is code:

- the core gains no API, and that is a decision rather than an absence of work;
- the core describes the policy by both application points rather than by the send alone;
- under Spring the policy exists as a bean, and the sender takes it as an ordinary dependency.

**"One" is about the definition, not about object identity.** A deployment building its sender by
hand holds one object because it constructed one; under Spring the default singleton scope makes the
bean one object as well. Neither is what this record pins: an application declaring its policy bean
with another scope has not broken the decision, because what may not be duplicated is the rule and
the place it is stated, not the instance. A second definition of the same rule is the defect, and it
is a defect whether or not the two objects happen to behave alike today.

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
report two unrelated refusals through one call — an `IllegalArgumentException` for a malformed
subscription, an `EndpointRejectedException` for an inadmissible host — and it would take the moment
of acceptance into the library, which is the one thing ADR-004 keeps outside.

The library does not perform the registration check itself for that same settled reason: ADR-004
keeps subscription storage and lifecycle outside the library, so there is no boundary here at which
a subscription appears. The library owns the rule and the call; the application owns the moment.

**The order at that boundary is fixed, and by the seam's own contract rather than by preference.**
`validate` documents its argument as an endpoint that already satisfies `Endpoints.requireSecure` —
an absolute `https` URL with a host — so the boundary builds the `Subscription` first, which applies
that check together with the key-material and length rules; applies the policy to the endpoint it
carries second; and stores the row only once both have passed. What the application chooses is what
each refusal answers to its client, not which of the two runs first.

## Two definitions that agree is not the decision

A deployment can already read `push2u.allowed-origins` out of the environment and build a second
policy from it, without registering it as a bean. It works, and it is what the reporting deployment
does today. It is not what this record chooses, because a rule stated in two places is a rule that
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
@Conditional(OnAllowlistExpressed.class)  // at least one of the two properties has an entry
EndpointPolicy push2uEndpointPolicy(Push2uProperties properties) { … }
```

**The condition is the allowlist, not the signer.** Gating the bean on `VapidSigner` was the first
form of this decision, and it is wrong in the direction that matters most: a service that accepts
subscriptions and leaves the sending to another service has no signer, and it is exactly the
deployment this record exists for — it would have been denied the policy its own `push2u.allowed-*`
configuration states. Gating on nothing is wrong the other way: a deployment carrying the starter on
its classpath without having configured web push would start failing at startup for want of an
allowlist nobody asked it for.

The allowlist itself separates the cases without either mistake. The bean exists when at least one
of `push2u.allowed-origins` / `push2u.allowed-domains` has an entry — a deployment that stated the
rule holds it as a value, whether or not it sends. Nothing stated means no bean, and a context that
also has no sender starts exactly as it does today. The *obligation* to state it stays where ADR-016
put it, on the sender: a deployment that sends and has stated nothing still fails at startup, with
the message it fails with now.

**No diagnostic moves, which is the second thing that condition buys.** `pushSender` keeps resolving
the policy through an `ObjectProvider`, exactly as it does now, so the three refusals it owns stay
where they are and say what they say: both properties unset with no bean, every set property empty
with no bean, and a non-empty property beside an application-supplied bean. What moves into the
policy's factory is the construction of the rules, and with it the refusal naming a malformed entry
by property and index. The sender stops *building* the policy; it goes on deciding whether the
deployment expressed one.

**Which bean is whose is answered by where its definition came from, not by its name.** The
definition registered under the starter's name carries the metadata of the factory method that
declared it, so "this is the policy this starter contributed" is a question about the declaring
class rather than about a string an application is equally free to choose. Deciding it by name would
leave one silent hole — an application naming its own bean `push2uEndpointPolicy` would be taken for
the starter's, and its non-empty allowlist property would then be ignored without a word, which is
the outcome the last section of this record forbids. Where the origin cannot be established, the
bean counts as the application's: that errs towards a startup failure naming the conflicting bean
rather than towards silently dropping a stated allowlist.

**One price is paid knowingly.** `@ConditionalOnMissingBean` is reliable against beans from the
application's own configuration, which is processed before auto-configurations. A policy contributed
by *another* auto-configuration ordered after this one arrives too late for the condition, so the
context holds two `EndpointPolicy` beans and fails on the ambiguity instead of with this starter's
own message. It fails loudly either way, and the case is rare enough to accept and specific enough
to write down.

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
is still no configuration-only path to unrestricted egress under Spring. A policy bean in a context
that builds no sender is not an exception to any of that: what ADR-016 refuses is a `PushSender`
without an egress decision, not an egress decision without a sender. ADR-017's rule kinds and their
matching are untouched. No ADR is superseded, in whole or in clause: this record adds where the
decision applies and how it is represented, to a decision that stays exactly as it was.

For a deployment that builds its sender by hand, nothing changes at all — it holds its policy today,
and the second call site was available to it before this record existed.

## What this rules out

- An endpoint policy a deployment cannot reach at the boundary where it accepts subscriptions.
- A policy withheld from a deployment that stated an allowlist and does not send — a service that
  accepts subscriptions and leaves the sending to another one is the case this exists for.
- A second definition of the same rule, built by the application from properties another module
  owns, as the supported way to check at that boundary.
- An accessor for the policy on `PushSender`.
- A second method on `EndpointPolicy` — a predicate, an overload taking a `Subscription`, or any
  other second way to ask the one question the seam exists to answer.
- A core factory joining subscription parsing to the deployment's admission decision, or a
  library-owned registration boundary — ADR-004 unchanged.
- A policy built inside the sender's factory method in an auto-configuration and left unrepresented
  in the context that owns it.
- An application-supplied policy bean winning silently over a non-empty allowlist property: the
  conflict diagnostic, naming the bean, survives the move.
- The starter's own bean recognised by its name, which an application is equally free to choose,
  rather than by the definition it came from.
- A startup failure demanding an allowlist from a deployment that configured no sender.
- A registration check a later send trusts, or one offered as a replacement for the send's check.
- A boundary applying the policy to an endpoint the `Subscription` contract has not vetted first —
  the order is the seam's, not the application's.
- A configuration-only path to unrestricted egress, in any spelling the new bean might have made
  available — ADR-016 unchanged in that respect.
