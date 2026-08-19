# ADR-024 — One endpoint policy, reachable where subscriptions are accepted

**Status:** Accepted

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

**And "one" reaches as far as one process, which is as far as a library can reach.** Within a
context there is a single definition and every point that applies the policy reads that one. Across
processes — a service that accepts subscriptions and a service that sends, each with its own context
— what this record guarantees is one *interpretation*, not one *value*: both read the same two
properties through the same code, so the rules they end up with can differ only where the configured
values differ. Keeping those in step is configuration delivery, the same problem a deployment
already solves for every other setting two of its services share, and it is deliberately outside
this record. The drift this record removes is the second *interpretation* — a boundary that decides
for itself what an allowlist means — because that is the one that changes under the deployment
without anything being edited, as the next section shows it already has.

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
does today. It is not what this record chooses, because a boundary that decides for itself what an
allowlist means is a boundary that means something different at the next rule kind — and it already
does. ADR-017 added `push2u.allowed-domains`; a
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

`ENDPOINT_POLICY_BEAN_NAME` is not published. It is a spelling this starter has to keep consistent
with itself and nothing more; publishing it would offer an application a constant to match on, which
is the identification *Which bean is whose is answered by where its definition came from* refuses
below — a bean is the starter's because of the definition it came from, never because of the string
it was registered under.

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

**The four refusals split by what they are about, and one of them stops belonging to the sender.**
Two are about an *obligation*: both properties unset with no bean, and every set property empty with
no bean. The obligation is the sender's — ADR-016 asks the question of a deployment that sends — so
those two stay in `pushSender`, which keeps resolving the policy through an `ObjectProvider` exactly
as it does now, and keeps saying what it says. One is about a *malformed value*, and it goes with
the construction of the rules, naming the entry by property and index.

**That third one is raised by a startup check rather than by the factory method that builds the
policy**, and the reason is about ordering rather than about the check itself. A `@Bean` method runs
at singleton pre-instantiation, behind every bean-factory post-processor in the context, so a
malformed entry left there is reported only after any post-processor that refuses the context for a
broader reason — and a deployment holding both reads the broader message about a value it has not
corrected yet. So the check performs the same rule construction, discards it, and refuses at its own
declared position; the factory method goes on building through the one implementation of the rule,
and constructing a handful of rules twice at startup is the whole of the price. The positions of
this and every neighbouring startup refusal are one list, and it is
[ADR-025](0025-delivery-is-off-by-statement.md)'s to carry, since that record is where the general
refusal they are ordered against is introduced.

The fourth is about a *contradiction* — a non-empty allowlist property beside an application-supplied
bean — and a contradiction does not become acceptable because this context happens not to send. Left
in `pushSender`, it would be unreachable exactly where it now matters most: a registration-only
service has no sender, so an application bean would suppress the starter's policy under
`@ConditionalOnMissingBean` while the stated allowlist was ignored without a word, and the boundary
would validate against a rule its operator did not think was in force. So the exclusivity check
becomes a startup check of the context itself, independent of whether a sender exists — it reads bean
*definitions* rather than instances, so it forces nothing into existence, and its message is
unchanged, naming the property and the bean.

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
context ends up holding two `EndpointPolicy` beans. It fails at startup either way — on the
contradiction check where an allowlist was also stated, and on the ambiguity where the sender
resolves first — and which message arrives is not worth pinning for a case this rare. What matters
is that it is loud, and it is.

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

## Documents

`docs/SPRING.md` carries the bean, its condition and the registration recipe a consumer writes
against it — the `Subscription` first, the policy second, the row third, and what each refusal
answers to a client. `README.md` gains the second application point in the sentence that introduces
the endpoint policy, since a plain-Java deployment has it available already and does not know.
`docs/DESIGN.md` §5 and §8 describe where the policy is applied and where it now lives in the
context. `EndpointPolicy`'s own Javadoc states both application points, in its own words: it ships in
a `sources.jar` to readers who have neither this record nor that document.

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
  conflict diagnostic, naming the property and the bean, survives the move.
- That diagnostic reachable only through the sender, so that a context building none accepts the
  contradiction in silence — a contradiction is not excused by a deployment that does not send.
- A claim that one rule spans processes. Within a context the definition is one; across services the
  guarantee is one interpretation of the same properties, and the values are configuration delivery,
  which this record does not undertake.
- The starter's own bean recognised by its name, which an application is equally free to choose,
  rather than by the definition it came from — and that name published as a constant, which offers
  the identification this record refuses.
- The malformed-entry refusal left in the policy's factory method, where singleton
  pre-instantiation puts it behind every broader refusal in the context.
- A startup failure demanding an allowlist from a deployment that configured no sender.
- A registration check a later send trusts, or one offered as a replacement for the send's check.
- A boundary applying the policy to an endpoint the `Subscription` contract has not vetted first —
  the order is the seam's, not the application's.
- A configuration-only path to unrestricted egress, in any spelling the new bean might have made
  available — ADR-016 unchanged in that respect.
