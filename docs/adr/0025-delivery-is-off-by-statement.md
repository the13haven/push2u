# ADR-025 — Delivery is off by statement, never by omission

**Status:** Proposed

Under the Spring starter a `PushSender` bean exists when a `VapidSigner` bean does, and a signer
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
usable.** `push2u.enabled` is that statement, it defaults to on, and the third state — on, with
neither a sender nor a signer in the context — fails the context at startup.

The invariant is one sentence, and it is the point of the record: *under an active
auto-configuration, the absence of a sender is incompatible with `push2u.enabled` other than
`false`.* It is deliberately narrower than "no sender means the deployment said no". An application
that excludes the auto-configuration, or supplies its own `PushSender`, or does not carry the
starter at all, has left this decision outside the starter's reach, and a record that claimed
otherwise would be claiming something the starter cannot enforce.

**Only `true` and `false` are values of it.** This is the one key where a typo would be free to mean
the opposite of what was typed, so a value that is neither fails the context naming the property
instead of being read as one of them. The framework's own reading of an `enabled` key — anything not
literally `false` is on — is the safer of the two directions and still not good enough here: it turns
`flase` into a deployment that sends although it said not to, which is this record's subject with the
sign reversed. Absent is not a value: it is the default, and the default is on.

**The switch is a condition every auto-configuration on the delivery path honours, and not a master
switch over `push2u.*`.** Off, the core starter contributes no signer, no transport and no sender;
the health indicator, which lives in its own auto-configuration so the starter stays usable without
Actuator on the classpath, honours the same condition and is gone too; and every signer starter
honours it, so the Vault signer is never constructed — which in its fetched mode means a read from
Vault during startup, a call no deployment that has declared the custodian unused should pay for.
The delivery path is not only what a starter contributes: a signer starter's own diagnostic is gated
with it too, for the reason the table further down gives. A signer starter that does not honour the
condition contributes its signer anyway, and the refusal below is then correctly silent: that
starter is outside this one's reach in the same way an excluded auto-configuration is. The switch
does not remove an application's own `PushSender`, which is not this starter's to withdraw, and it
does not reach the endpoint policy.

**A signer starter therefore reads a key another module owns, and that is not the coupling this
record forbids elsewhere.** Naming another module's prefixes inside a message copies that module's
activation rules and goes stale when they change. Honouring a switch copies nothing: it is one fact
about the namespace, stated once, whose meaning cannot drift — and the Vault starter already orders
itself against the core starter by name without depending on it, so the condition costs no
dependency either. The health indicator keeps an opt-out of its own, whatever that key comes to be
called: this switch sits upstream of it and the two stay independent, since a deployment that has
turned delivery off has no indicator left to opt out of, while one that is sending may still decline
to have its health tied to a signer. Which key spells that second decision is not this record's to
fix.

**Withdrawing the contributor is not the same as rewriting the operator's health groups, and the
switch does only the first.** The framework validates the membership of every health group declared
in properties, on the `exclude` side as well as the `include` side, and refuses a context that names
a contributor which does not exist. A deployment whose group names `push2u` — most often to keep a
signer probe out of a container health check — therefore edits that group in the same change that
removes the indicator, by whichever route it removes it: the indicator's own key removes it, so does
the absence of a signer bean, and both of those reach a released version before this switch does, so
the switch is one route of several rather than the one that introduces the problem. The trap is the
framework's, the deployment that meets it is the one
https://github.com/the13haven/push2u/issues/89 is about, and none of the answers to it are this
library's to take. It does not register a contributor that reports delivery being off, which would
put a new observable state into every deployment that does not send in order to keep a name
registered for a check performed on the operator's own configuration; and it does not
switch that validation off on the deployment's behalf, which is global and would stop catching a
mistyped contributor name anywhere in it. What it owes is the recipe, in the Spring guide, given
with the presence requirement attached rather than as a bare `exclude`.

## What the switch does not reach, and why

ADR-024 makes the endpoint policy a value the deployment owns and the starter publishes, precisely
so that a service which accepts subscriptions and leaves the sending to another one can apply it at
registration. That deployment has no signer and wants none. Gating the policy on this switch would
withhold it from exactly the deployment ADR-024 exists for, which that record already rules out —
and it would do so through a property whose name says nothing about endpoint policies.

So the reach of `push2u.enabled` stops at the delivery path, and the policy is declared where the
switch's condition is not applied. **Being outside the auto-configuration that carries the sender is
not what makes it safe**: the health indicator is outside it too and is gated all the same. What
makes it safe is that the policy's own auto-configuration does not carry the condition, and that is
the constraint this record places on ADR-024's bean.

**The switch and that bean reach a consumer together, so the constraint is on the release and not on
the order of the work.** Today the allowlist is parsed inside the sender's factory method and has no
reader outside it, so a switch shipped over that arrangement would suspend the allowlist's own
validation along with the delivery path it currently sits in — which is exactly why no released
version carries one without the other. What a deployment receives is the whole of it: with the
switch off and a stated allowlist it still holds its policy, a malformed entry in that allowlist
still fails at startup, and an allowlist stated beside an application-supplied policy bean still
fails as the contradiction it is. Between two merges on the way there the tree may hold less than
that; an artifact anyone can depend on may not.

**The deployment ADR-024 exists for states `push2u.enabled: false`.** It accepts subscriptions,
holds a policy and sends nothing, so the statement this record asks of everything that does not send
is one it can make truthfully — and what it keeps by making it is the policy its allowlist states.
ADR-024, written before this switch existed, has that deployment holding the rule as a value whether
or not it sends; after this record it holds it and says so. Neither record revises the other: what
changes is one line of that deployment's configuration.

## Which startup checks the switch reaches

The section above settles one question of this kind, the endpoint policy's. It is a row or two of a
table, and leaving the other rows to be decided by where each check happens to be implemented is how
a deployment that stated it does not send ends up refused over a property nothing reads.

**Most of this starter family's refusals need no row, and saying which is what makes the table
exhaustive rather than illustrative.** A refusal raised *while a bean the switch withdraws is being
constructed* is on the delivery-path side by construction and cannot be anywhere else: with that
bean unbuilt it is unreachable, and nothing about its position was ever a choice. That covers the
signer's own key material, every builder value the sender translates from a property, and every
per-property translation in a signer starter. What needs deciding is the rest — the checks raised
outside any such construction, which is exactly the six that take a declared position below, and
they are the whole of this table. Its rows are not in running order; that is the section *One
declared order over every startup check*, and it sorts them differently.

| Startup check | `push2u.enabled: false` | `true`, or unset |
|---|---|---|
| The value of `push2u.enabled` itself | runs | runs |
| A malformed allowlist entry | runs | runs |
| An allowlist stated beside an application policy bean | runs | runs |
| A signer starter's partial-configuration diagnostic | skipped | runs |
| The general refusal over a missing signer | skipped | runs |
| A tombstone over a property a release removed | runs, while the tombstone lives | the same |

**What decides a row is what the check is about, never where it is implemented.** The first three
are about a *value*: an allowlist entry that is not an origin is not an origin in a context that
sends nothing either, and a stated allowlist beside a bean is a contradiction whoever ends up
reading it. Those are ADR-024's, and this record narrows none of them. The next two are about the
*delivery path*: each asks, in its own words, whether this deployment can sign — and a deployment
that has said it does not send has answered that already.

**A signer starter's diagnostic is therefore gated by the switch although it is not a
contribution.** Its stand-down is over an existing `VapidSigner` or `PushSender` bean, and the
switch is precisely what keeps those from existing, so the stand-down cannot reach the case: a
deployment that switched delivery off with half a `push2u.signer.vault.*` block left over would be
refused over configuration nothing reads. That is the mistake the stand-down exists to prevent, with
the sign reversed.

**`push2u.signer.vault.public-key-fetch` is the case worth naming out of the unrowed ones**, because
ADR-026 asks the question directly and a reader will look for it here. Its readings are decided
while the Vault signer is built, so the switch removes them with the signer, and that is the right
answer for the right reason: they are about the delivery path, and a deployment that has answered
that question is owed no opinion about when a read it will never perform would have happened.

The tombstone row is not an exception to that line but sits outside it: a removed key names a
setting that exists in neither state, and the refusal is about what the operator believes is in
force rather than about what this deployment does. It is also the one row with an end date — the
tombstone is carried for one minor release after the one that removed the property, and the release
that adds it opens the work item that removes it. Naming that release here would be naming a version
that does not exist yet, which is the one thing this repository refuses to write down in advance.

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
population this record is about. The remedy is one line, `push2u.enabled: false`, and the
deployments that need it are precisely the ones that could not tell, before it existed, whether they
were sending at all. The first release's note declared `0.x` the window for revisiting names and
constructor shapes once real integrations existed; this revision is behavioural rather than one of
those, so that sentence does not cover it by its own words. It is taken under the same reasoning:
one release old, nothing promised beyond it, and a starter's activation behaviour is at least as
revisable under `0.x` as the shape of a constructor.

## Blank is unset, for the properties that activate a signer

`@ConditionalOnProperty` treats an empty value as present, and the local signer's condition is over
the pair of keys, so `public-key: ${PUSH2U_VAPID_PUBLIC_KEY:}` beside a private key defaulted the
same way activates the signer and is then refused — not for its encoding, since an empty string is
valid base64url and decodes to nothing, but for the length of the point it did not carry. The Vault
token is activated the same way and refused as empty. Each
failure describes a shape rather than what the operator did, which is why the trap is written down
in the reporting consumer's own YAML: nothing else writes it down anywhere.

For the properties that *activate* a signer — the two keys this starter owns, and each signer
starter's own activating set — a blank value counts as unset. Nothing is lost: no blank value of any of them could have produced a signer,
so the only outcomes traded are two failures, and the one this chooses names the missing
configuration instead of the shape of an empty string. It is a deliberate divergence from the
framework's own reading of "set", and it belongs to activation only: it says nothing about the
allowlist properties, where explicitly empty is a statement with a meaning of its own (ADR-024).

## The diagnostic belongs to the module whose properties it reads

The reported issue asks for a message naming which half of which property set was found, and it is
right that no consumer can produce that message. It is equally true that no single module can: a
starter that named another module's prefixes would have rebuilt, inside the library, the copy the
consumer was asked to delete — and would have frozen another module's activation set into a document
that cannot be edited afterwards.

So the diagnostic is split the way ownership is. Each starter that contributes a signer answers for
its own properties — a partially stated set is its finding, in its words, naming its keys — and the
general refusal answers only for the fact that no signer bean exists, listing what the deployment may
do about it: the switch, an application `VapidSigner` or `PushSender` bean, the two key properties
the module raising it owns, any signer starter's own configuration, and the framework's condition
report for the rest. Two of those supply no signer and are on the list all the same — the refusal is
about an unanswered question, not about a missing bean. A future signer starter is named by the clause about
signer starters rather than by anything this module had to learn about it, and it names its own keys
itself.

**A starter's diagnostic is not its contribution, and the two cannot sit at the same point.** A
signer starter is ordered ahead of the sender's auto-configuration so that the signer it contributes
is there to be found; a diagnostic has to be ordered behind *every* contribution, the local signer's
included, or it cannot see whether any signer was contributed at all. One class cannot be in both
places, so a signer starter that carries a diagnostic carries two auto-configurations: the
contribution before, the diagnostic after, and both ahead of the general refusal. Without that split
the stand-down below is unreachable — a deployment sending through the local signer with a forgotten
`push2u.signer.vault.address` would be refused by a check that could not yet see the signer it was
about to be told to stand down for.

**Each diagnostic stands down when a `VapidSigner` or a `PushSender` bean exists, from anywhere.** A
deployment sending through its local signer with a half-written Vault block left over has a stale
property, not a broken deployment, and a startup failure over configuration nothing reads would be
the same mistake in the opposite direction. That stand-down is not the only one: the switch gates
these diagnostics as well, because with delivery off there is no bean for the stand-down to find and
the very case it exists for would go unanswered — the table above is where that is settled.

**A specific finding outranks the general one, and neither is aggregated.** Two different orders
carry that, and conflating them is how it gets lost. One is the order of the auto-configurations,
which decides what each check's condition can see, and it is the order the starters already declare
between themselves. The other is the order in which the raised checks run, and it is not the first
one restated: the framework sorts post-processors into buckets by the kind of precedence they
declare and orders what remains by a registration sequence it promises only as far as it can. So the
running order is declared on both checks, and a test pins the result. Testing an undeclared order is
not the same answer and does not substitute for it — a green test over a sequence nothing guarantees
records what this version happens to do, and the next one is free to do otherwise without failing
anything. Declaring it on one check and not on the other is refused for a different reason: which of
the two then runs first depends on which of them declared, and a reader who has to work that out
from the buckets a framework sorts into is a reader this record has failed.

These two checks are not the whole of it. By the time this record is implemented six of them declare
a position, and the reasoning just given applies to every one; the section *One declared order over
every startup check* below is where they are put in one line.

What is refused is the step after that: a mechanism by which one module's finding is collected into
another module's message. That is a cross-module contract, published for the life of the API, in
exchange for one better sentence in a failure that already names both.

## Where the refusal is raised, and what it may point at

**The refusal must precede the application's own failure.** A bean that requires a `PushSender` is
instantiated before any ordinary bean an auto-configuration contributes, so a refusal raised as one
would lose the race, and the operator would read the framework's "required a bean that could not be
found" instead. Raising it from a post-processor of the bean factory puts it ahead of every
application singleton while leaving the condition that decides whether to raise it where it belongs:
decided while the auto-configurations are being processed, against the bean definitions registered
by then rather than against instances, so nothing is forced into existence to answer it.

**One price is paid knowingly, and it is the price ADR-024 pays in the other direction.** That
condition sees the application's own configuration, which is processed first, and every signer
starter ordered ahead of the one raising the refusal — which is the order the Vault starter already
declares, and the order any signer starter has to declare in any case, since the sender's own
condition would not see it either. A signer starter that declares no order is placed by a fallback,
and where that puts it after the refusal has been decided, the context fails demanding a signer it
holds. The alternative is a refusal raised late enough to see everything, which is a refusal raised
after the application beans it exists to precede. The order is one line to declare, and a starter
that omits it is relying on the same fallback for the sender's own condition.

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

**And it has to win.** The framework ships an analyzer for a missing bean of its own, both recognise
the same failure, and what the operator reads is whichever of them answers first in a sorted list. So
this one declares its precedence over that list rather than taking the position the list happens to
give it, and a test pins that its text is the one that arrives. Losing that race leaves no mark: the
startup output is still correct, still generic, and looks exactly like the output that existed before
this record did.

## One declared order over every startup check

The rule above was stated for two checks, and by the time this record is implemented there are six.
ADR-023 leaves a tombstone behind a removed property; ADR-024 raises two refusals about the
allowlist; this record adds three of its own. They are not alternatives — one context can earn
several at once, and the operator reads whichever arrives first. So there is one list, and this is
it:

1. **the value of `push2u.enabled`**, because a deployment that mistyped the one key deciding
   whether any of this applies is owed that sentence and not a consequence of it;
2. **a tombstone over a removed property**, because a key that no longer exists makes every reading
   under it a reading of something the operator did not mean to write;
3. **a malformed allowlist entry**;
4. **an allowlist stated beside an application policy bean**;
5. **a signer starter's partial-configuration diagnostic**;
6. **the general refusal over a missing signer**;
7. everything else, which is ordinary bean creation — every refusal raised while a bean is being
   built, including the `public-key-fetch` readings and what `pushSender` refuses on its own. They
   are reachable there because steps 5 and 6, the two that are about whether a signer exists, stand
   down once its definition does. Steps 1 to 4 have no such stand-down and must not grow one: none
   of them is about a signer.

Steps 3 through 6 are the rule above generalised: specific before general, a value before the path.
Steps 1 and 2 sit ahead of all of it because they decide whether the configuration underneath them
can be read at face value at all. The order is about which message an operator holding several
faults reads first; it is not a claim that a later step's *condition* is decided by an earlier
step's outcome, and no such claim would be true — a condition on an auto-configuration is evaluated
while the configuration classes are parsed, long before any of these checks runs.

**Each of 1 to 6 declares its position, and none of them is left as validation inside an ordinary
bean's factory method.** That is the half that is easy to get wrong and invisible afterwards: an
ordinary `@Bean` is created at singleton pre-instantiation, which is step 7, so a refusal left there
loses to every post-processor above it however specific it is. (A `@Bean` method whose *product* is
a post-processor is not that case — the framework fetches those in the earlier phase, which is
precisely how these six are contributed from an auto-configuration at all. What that method has to
look like is *One mechanism, or the numbers do not compare* below, and it is not obvious.) The
refusal ADR-024 raises over a malformed entry is the worked example: it went with the construction
of the rules, inside the policy's factory method, and this order is what made that position
unreachable. It is now raised at step 3 by a check that performs the same construction and discards
it, while the factory goes on building through the one implementation of the rule — an amendment
that record carries in its own words. Constructing a handful of rules twice at startup is what buys
the operator a message naming the entry rather than one about a signer they had not reached yet.

**A check runs when its row says it runs, and nothing the row does not mention may suppress it.**
Stated for ADR-024's policy bean as "declared where the switch's condition is not applied", and that
is necessary rather than sufficient: a class-level condition on Actuator's presence, a condition on
a bean, an allowlist condition hoisted from a method to the class that ends up hosting the check —
each of them silently narrows a row without going anywhere near the switch. Issue #89 records that
exact trap for this exact tombstone mechanism, where gating the refusal on the health classes being
present would let a dead key through in a context that dropped Actuator. So the constraint is about
the whole of what stands between the check and the context, not about the one suppressor that
prompted it. The tombstone is where it bites hardest: its natural home is the core starter's own
auto-configuration, which is the one the switch turns off.

**One mechanism, or the numbers do not compare — and the mechanism is narrower than it sounds.** The
framework sorts post-processors of the bean factory into buckets by the *kind* of precedence they
declare and orders only within each bucket, so two checks in different buckets run in bucket order
whatever integers they carry. Three ways to fall out of the intended bucket, all silent:

- **A post-processor of the bean definition registry is a different phase**, and the whole of it
  completes before any plain bucket. Such a check precedes every position in this list whatever it
  declares.
- **A check over the environment as it is being prepared precedes the context itself**, so it
  precedes all of them too. This is why the tombstone reads the environment *at refresh*, which is
  what ADR-023 asks for in any case.
- **The bucket is chosen from the declared return type of the `@Bean` method, not from the object
  it returns.** The framework must not instantiate a candidate to find out where it belongs, so it
  asks the definition, and a factory method declaring the post-processor *interface* as its return
  type lands in the bucket that is never sorted — carrying an order the framework will not look at.
  A position declared by an annotation on the method rather than on the class is invisible for the
  same reason.

So a check of this family declares its position **on its class**, and the `@Bean` method that
contributes it declares **that class** as its return type; and the method is `static`, which the
framework instructs for one producing a post-processor without enforcing — a non-static one is
noted in the log and otherwise tolerated, while it instantiates the auto-configuration that declares
it before the phase these checks run in. A check that cannot be built that way has left this list
rather than taken a position in it, and then the list is what has to be revisited.

**The numbers cannot live in one place, and this list is what keeps them in step.** A signer starter
deliberately does not depend on the core starter — the Vault one orders itself against it by name —
so no constant is visible to both, and step 5 is declared in a different module from steps 1, 2, 3,
4 and 6. Each module keeps its own positions as package-private constants in a single class and
reads them against this list. A position taken from the registration sequence rather than declared
is refused here for the reason it is refused above: the framework promises that sequence only as far
as it can, and a green test over it records what this version happens to do.

**What pins the order is the message that arrives, not the value of a constant.** A test asserting
that a constant equals the number written here proves that someone typed the number twice, and stays
green while the module next door moves its own — which is the failure the split into two modules
introduces and the only one worth testing for. So the order is pinned by a context holding *every*
starter that declares a position, configured to earn several refusals at once, asserting which
message the operator gets. That context exists in exactly one place: the Vault starter's suite,
which is the only one with both starters on a classpath. A per-module test can pin the positions
that module owns; it cannot pin the thing this section exists to guarantee, and must not be offered
as though it had.

## What this does not touch

The core is untouched: no type, no method, no behaviour of `PushSender` changes, and a deployment
that builds its sender by hand is unaffected in every respect, since it never had an activation
question to answer — it wrote the constructor call or it did not.

ADR-016 stands whole. The obligation to state an egress decision still belongs to the sender, and a
deployment that sends without stating one still fails. This record adds an obligation *before* that
one, and removes none of it.

ADR-024 stands whole: no clause of its decision is displaced here. This record settles only which
auto-configuration may carry its bean, so that a switch introduced afterwards cannot take the policy
away from the deployment ADR-024 wrote it for.

ADR-022 is not reopened, and it saw this coming. That record names this very question as lying
outside itself, says nothing in it forecloses an explicit switch, and leaves the starters'
`IllegalStateException` meaning what it means — a context that could not be built from what was
configured. The refusals added here are exactly that: a required decision left unstated, a property
set stated in half. No type is minted for them, and no list in that record has to be reopened to
hold them.

ADR-005 is not engaged: nothing here is a seam. The switch is a property, the diagnostics are
startup checks inside the modules that own the configuration they read, and the ways to supply a
signer are the ones that already exist.

## Documents

`README.md` and `docs/SPRING.md` for the switch and for what the refusal says; `docs/DESIGN.md` §8
for the startup contract, since the table and the order above describe how the starters behave and
that description belongs in the document that may be rewritten. `docs/VAULT.md` gains nothing of its
own: what a signer starter owes is one condition and one diagnostic, and the operator-facing half of
it is the same sentence in `docs/SPRING.md`. The release notes name the transition — a context that
boots without web push today fails after this, `push2u.enabled: false` is the line that answers it,
and a health group naming `push2u` is edited in the same change, because the switch withdraws the
contributor that name refers to. That instruction reaches only a deployment that owns the file naming
it, so the note carries the other half as well: an application that distributes push2u inside an
image ships no health group naming the contributor, since the deployment stating the switch has
properties and an environment and no way to edit what the image carries.

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
  and does not send survives the switch, as do the refusal of a malformed allowlist and of an
  allowlist stated beside a policy bean.
- That policy declared where the switch's condition is applied — and equally the claim that being
  outside the auto-configuration carrying the sender is the test, when the health indicator is
  outside it and gated all the same.
- A placeholder health contributor registered in a deployment that does not send, so that a group
  naming `push2u` goes on validating; and equally that validation switched off on the deployment's
  behalf, which is global and reaches every other group and every other name in it.
- A group recipe published by this project that names `push2u` in an `include` or an `exclude`
  without saying that the name is a claim the contributor is registered.
- A released version carrying the switch while the allowlist is still read only inside the sender's
  own auto-configuration, which carries the switch's condition: the two arrive in one release or
  neither does.
- A Vault signer constructed, and its fetched mode's startup read performed, in a deployment that
  switched delivery off.
- A claim that a missing sender proves the deployment said no — the invariant holds under an active,
  non-excluded auto-configuration, and nowhere else.
- A blank activating property read as a configured one; and equally that reading applied to the
  allowlist properties, where explicitly empty carries a meaning of its own.
- One module's failure message naming another module's property prefixes or counting its keys, and
  equally a mechanism for one module to contribute its finding to another module's message.
- A partial-configuration diagnostic that fires while a `VapidSigner` or `PushSender` bean exists,
  and so refuses a deployment over configuration nothing reads — and equally one that fires in a
  deployment which switched delivery off, where the same configuration is read by nothing and the
  stand-down over a bean cannot reach the case because the switch is what removed the bean.
- A startup check whose side of the switch is decided by where it was implemented rather than by
  what it is about, in either direction: a value refusal suspended along with the delivery path, or
  a question about the delivery path asked of a deployment that has answered it.
- A general refusal that outranks a starter's specific finding; an order between the two taken from
  the registration sequence the framework promises only as far as it can; and a test over that
  sequence offered as the thing that pins it.
- A precedence declared on some of these checks and not on the others, which leaves which one runs
  first depending on which one declared; and any check of this family without a position in the one
  list, whichever module raises it.
- A refusal ordered below another by being left inside an ordinary bean's factory method, where
  singleton pre-instantiation puts it behind every post-processor however specific it is.
- A check of this family built on a mechanism that sorts into a different bucket, or that runs in an
  earlier phase than the rest — a post-processor of the bean definition registry, or one over the
  environment as it is being prepared — so that its declared number does not compare with theirs.
- A position declared where the framework will not read it: on the factory method rather than on
  the class, or behind a factory method whose declared return type is the post-processor interface,
  either of which puts the check in the bucket that is never sorted while it carries a number.
- A check the table has running with delivery off, suppressed by anything the row does not mention:
  the switch's condition, a condition on the presence of a class or a bean, or a condition hoisted
  to whatever class ends up hosting it.
- A table of what the switch reaches that claims to be exhaustive without saying which refusals need
  no row, and why they cannot be anywhere but where they are.
- The order pinned by asserting a constant's value, or by a test that can see only one module's
  checks: what has to be pinned is the message that arrives in a context holding every starter that
  declares a position.
- A tombstone over a removed property with no end to it, and equally an end written as a version
  number that does not exist yet.
- A starter's diagnostic sharing an auto-configuration with its contribution, and so deciding
  whether a signer exists from a point before the local one is registered.
- A value of `push2u.enabled` that is neither `true` nor `false` read as either of them.
- A refusal an application's own missing-bean failure can precede.
- A signer starter whose contribution the refusal's condition is assumed to see although that
  starter declares no order — the price is stated rather than designed away.
- A startup failure pointing at an Actuator endpoint the failed context does not serve.
- A diagnostic assembled by reading the framework's condition report — its keys and its wording are
  diagnostics, not a contract.
- A missing-bean analyzer that answers "configure a signer" to a deployment that switched delivery
  off, or to a context whose auto-configuration was excluded.
- That analyzer's precedence over the framework's own left to the position a factories list happens
  to give it, or its winning the race left unpinned.
- An activation switch reaching the core: nothing in this record is visible to a deployment that
  builds its sender by hand.
