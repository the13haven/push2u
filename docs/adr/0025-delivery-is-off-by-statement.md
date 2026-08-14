# ADR-025 — Delivery is off by statement, never by omission

**Status:** Proposed

Under the Spring starter a `PushSender` bean exists when a `VapidSigner` bean exists, and a signer
exists when one of two property sets is complete: `push2u.vapid.public-key` with `.private-key` for
the in-JVM signer, `push2u.signer.vault.address`, `.key-name` and `.token` for the Vault Transit
one. With none of them the context starts, holds no sender, logs nothing, and fails nothing.

That silence answers two different questions with one state. A deployment that never configured web
push and a deployment whose configuration failed to reach the container are indistinguishable — from
inside the application, from the outside, and afterwards.
https://github.com/the13haven/push2u/issues/88 reports what a consumer writes to tell them apart:
roughly fifty lines that restate this starter's activation rules in application code, key on a
Spring profile to decide whether the absence is tolerable, and carry a comment explaining that a
YAML default of `${PUSH2U_VAPID_PUBLIC_KEY:}` turns the clean back-off into a startup failure,
because to Spring an empty property is a present one.

None of the knowledge in that copy is the application's to hold: which prefixes activate which
signer, which starter owns each, and what "set" means. It is also wrong on the day a third signer
starter exists, and nothing will report that it has become wrong.

**The starter already refuses to let a decision go unstated — just not this one.** ADR-016 made the
endpoint policy required, and the starter fails at startup when neither the properties nor a bean
express it, with a message naming every way to answer. `push2u.vapid.subject` fails the same way.
Both of those checks run only *after* a signer has been found: up to that line the starter insists
that decisions be stated, and past it the largest decision of all — whether this deployment sends at
all — is answered by omission.

The two ways of getting that decision wrong do not cost the same. A deployment that mistypes a
property prefix binds nothing, validates nothing, boots green and never sends; no part of the
process can tell it from a correctly configured deployment that has had nothing to send yet. The
first symptom is a notification a user did not receive, which nobody reports. For a library whose
whole subject is delivery, "silently does not deliver" is the state it should be least able to
enter.

## The decision

**A deployment states that it does not send, or the autoconfigured delivery path is present and
usable.** `push2u.enabled` is that statement, it defaults to on, and the third state — on, with no
signer resolvable from anything — fails the context at startup.

The invariant is one sentence, and it is the point of the record: *under an active
auto-configuration, the absence of a sender is incompatible with `push2u.enabled` other than
`false`.* It is deliberately narrower than "no sender means the deployment said no". An application
that excludes the auto-configuration, or supplies its own `PushSender`, or does not carry the
starter at all, has left this decision outside the starter's reach, and a record that claimed
otherwise would be claiming something the starter cannot enforce.

**The switch is an activation switch for delivery, not a master switch over `push2u.*`.** Off, it
removes the signer, the transport, the sender, the health indicator and every diagnostic this record
adds — including the Vault signer, whose construction reads from Vault, so that "off" costs no
network call to a custodian a deployment has decided not to use. It does not remove an
application's own `PushSender`, which is not this starter's to withdraw, and it does not reach the
endpoint policy.

## What the switch does not reach, and why

ADR-024 makes the endpoint policy a value the deployment owns and the starter publishes, precisely
so that a service which accepts subscriptions and leaves the sending to another one can apply it at
registration. That deployment has no signer and wants none. Gating the policy on this switch would
withhold it from exactly the deployment ADR-024 exists for, which that record already rules out —
and it would do so through a property whose name says nothing about endpoint policies.

So the reach of `push2u.enabled` stops at the delivery path. A deployment with the switch off and a
stated allowlist still gets its policy; a malformed entry in that allowlist still fails at startup;
an allowlist stated beside an application-supplied policy bean still fails as the contradiction it
is. What the switch suspends is the validation of *delivery and signer* configuration, because
those are the values it declares unused.

Two orders of implementation are possible and the boundary holds under both. Today the policy is
built inside the sender's factory method and is unreachable without a sender, so the switch gates
what exists. When ADR-024's bean arrives it must arrive outside the switch's reach — which means
outside the auto-configuration the switch gates — rather than inside it with an exception carved
for it later.

## Why the default is on, and why the third state is fatal

**A warning was the first shape of this, and it leaves the reported problem in place.** One WARN at
startup naming what was found is strictly better than silence, and it is still a line in a log
aggregator that a deployment discovers after the notifications it lost. It also makes the switch
decorative: with a warning as the only consequence, `push2u.enabled=false` changes nothing a running
process can observe, and a setting whose whole effect is the absence of a log line is not a
statement anybody can rely on.

**A three-valued switch was the second shape** — unset warns, `true` refuses, `false` is off — and
it buys compatibility by moving the decision back to the operator who has already demonstrated they
cannot see the state. The deployments that would set `true` are the ones that were never at risk.

**A mode property was the third** — `push2u.on-missing-signer: warn|fail`. It is two settings for
one decision, the second of which exists to soften the first. The asymmetry this repository already
argues from decides it: a property can be added later without breaking anyone and cannot be removed
after a release, so the one that is not yet needed is not shipped. If a deployment appears for which
the refusal is genuinely wrong and `false` is genuinely wrong, that property is still available.

**A sender that exists and refuses to send was the fourth**, and it is refused on what the library
is. A null-object `PushSender` puts "configured, running, delivering nothing" into the type the
whole API is built around, and every consumer that injects one would have to ask, at run time, which
kind it got. The consumer in the reported issue does write such a type — for its own domain, at its
own boundary, where it can decide what a disabled channel means to a caller. That decision is theirs
and stays theirs.

The refusal breaks deployments that boot without web push today and do not know it, which is the
population this record is about. `0.x` was declared, when the first release was cut, as the window
in which this kind of revision is honest rather than breaking, and this is the revision it was
declared for.

## Blank is unset, for the properties that activate a signer

`@ConditionalOnProperty` treats an empty value as present, so `public-key: ${PUSH2U_VAPID_PUBLIC_KEY:}`
activates the local signer and fails on a base64url decode — the trap the reporting consumer
documented in their own YAML because nothing else documents it. The same holds for the Vault token.

For the properties that *activate* a signer — the two local keys, the three Vault values — a blank
value counts as unset. Nothing is lost: no blank value of any of them could have produced a signer,
so the only outcomes traded are two failures, and the one this chooses names the missing
configuration instead of the shape of an empty string. It is a deliberate divergence from the
framework's own reading of "set", and it belongs to activation only: it says nothing about the
allowlist properties, where explicitly empty is a statement with a meaning of its own (ADR-024).

## The diagnostic belongs to the module whose properties it reads

The reported issue asks for a message naming which half of which property set was found, and it is
right that no consumer can produce that message. It is equally true that no single module can: a
starter that named another module's prefixes would have rebuilt, inside the library, the copy the
consumer was asked to delete.

So the diagnostic is split the way ownership is. Each starter that contributes a signer answers for
its own properties — a partially stated set is its finding, in its words, naming its keys — and the
general refusal answers only for the fact that no signer bean exists, listing the ways to supply one
in terms of the seam rather than of anyone's prefixes: the switch, an application `VapidSigner` or
`PushSender` bean, this starter's two key properties, the Vault starter's three, and the framework's
own condition report for the rest. A future signer starter is covered by the seam-level clause
without this module learning anything about it, and covers itself by owning its own diagnostic.

**A specific finding outranks the general one, and neither is aggregated.** When a starter has a
partially stated set, its message is what the operator sees; the general refusal is what remains
when no starter has anything specific to say. Ordering the two is enough to guarantee that, and it
is bought with the ordering the starters already declare between themselves. What is refused is the
next step: a mechanism by which one module's finding is collected into another module's message.
That is a cross-module contract, published for the life of the API, in exchange for one better
sentence in a failure that already names both.

Each such diagnostic also stands down when a `VapidSigner` or a `PushSender` bean exists, from
anywhere. A deployment sending through its local signer with a forgotten half-written Vault block
has a stale property, not a broken deployment, and a startup failure over configuration nothing
reads would be the same mistake in the opposite direction.

## Where the refusal is raised, and what it may point at

**The refusal must precede the consumer's own failure.** An application bean that requires a
`PushSender` is instantiated before anything an auto-configuration contributes, so a refusal raised
as an ordinary bean would lose the race and the operator would read the framework's "required a bean
that could not be found" instead. Raising it from a post-processor of the bean factory puts it ahead
of every application singleton while leaving the condition that decides whether to raise it where it
belongs — evaluated against the bean definitions, after every signer contributor has registered
theirs.

**The message may not send the operator somewhere a failed context cannot serve.** The condition
report is the right place to look and `/actuator/conditions` is the wrong way to name it here: there
is no running application to ask. The refusal names the startup flag that prints the same report.

**And it may not be assembled by reading the framework's own report.** Quoting the condition
outcomes of other modules' conditions would produce the best message available and would tie a
published failure to diagnostic text the framework does not version, filtered from a structure whose
keys are equally not a contract. The stable enumeration above says the same thing and keeps saying
it after the framework rewords itself.

The case the refusal cannot reach — an application that requires a `PushSender` from a context where
this starter's check never ran — is answered separately, by an analyzer of the framework's own
missing-bean failure. It has to distinguish three causes and give three answers: the deployment
stated `false` and something still required a sender, which is a contradiction in the application
rather than a missing signer; the check itself is absent, because the auto-configuration was
excluded; and everything else, which is the enumeration above. An analyzer that answered "configure
a signer" in all three would reintroduce this record's own subject one layer down — a deliberate
"off" reported as a defect.

## What this does not touch

The core is untouched: no type, no method, no behaviour of `PushSender` changes, and a deployment
that builds its sender by hand is unaffected in every respect, since it never had an activation
question to answer — it wrote the constructor call or it did not.

ADR-016 stands whole. The obligation to state an egress decision still belongs to the sender, and a
deployment that sends without stating one still fails. This record adds an obligation *before* that
one, and removes none of it.

ADR-024 stands whole, and is not superseded in any clause. This record settles only which
auto-configuration may carry its bean, so that a switch introduced afterwards cannot take the policy
away from the deployment ADR-024 wrote it for.

ADR-005 is not engaged: nothing here is a seam. The switch is a property, the diagnostics are
startup checks inside the modules that own the configuration they read, and the ways to supply a
signer are the ones that already exist.

## What this rules out

- A context that starts with the auto-configuration active, no sender, and no statement that this
  deployment does not send.
- A warning as the whole answer to that state, or any shape in which `push2u.enabled=false` changes
  nothing a running process can observe.
- A three-valued activation switch, and a second property whose subject is how strictly the first
  one is enforced.
- A `PushSender` that exists and declines to send — a disabled channel is the application's type to
  write, at its own boundary.
- `push2u.enabled` reaching the endpoint policy: the policy of a deployment that states an allowlist
  and does not send survives the switch, as does the refusal of a malformed allowlist and of an
  allowlist stated beside a policy bean.
- The endpoint policy bean declared inside an auto-configuration the delivery switch gates.
- A claim that a missing sender proves the deployment said no — the invariant holds under an active,
  non-excluded auto-configuration, and nowhere else.
- A blank activating property read as a configured one; and equally that reading applied to the
  allowlist properties, where explicitly empty carries a meaning of its own.
- One module's failure message naming another module's property prefixes, and equally a mechanism
  for one module to contribute its finding to another module's message.
- A partial-configuration diagnostic that fires while a `VapidSigner` or `PushSender` bean exists,
  and so refuses a deployment over configuration nothing reads.
- A general refusal that outranks a starter's specific finding, or an order between the two left to
  chance.
- A refusal an application's own missing-bean failure can precede.
- A startup failure pointing at an Actuator endpoint the failed context does not serve.
- A diagnostic assembled by reading the framework's condition report — its keys and its wording are
  diagnostics, not a contract.
- A missing-bean analyzer that answers "configure a signer" to a deployment that switched delivery
  off, or to a context whose auto-configuration was excluded.
- An activation switch reaching the core: nothing in this record is visible to a deployment that
  builds its sender by hand.
