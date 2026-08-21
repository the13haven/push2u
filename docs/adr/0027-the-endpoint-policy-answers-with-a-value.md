# ADR-027 — The endpoint policy answers with a value

**Status:** Proposed

Reported as https://github.com/the13haven/push2u/issues/179, by a deployment that had adopted the
registration-time check one release earlier and found the call awkward at exactly the boundary the
check was introduced for.

Two decisions moved out of the exception channel in the release before, and the argument was the
same both times: a condition the caller is expected to meet routinely is not an exceptional one, and
reporting it by throwing makes every caller write control flow around something that is not an
error. [ADR-021](0021-retry-belongs-to-the-caller.md) gave `send` a sealed `PushOutcome`;
[ADR-023](0023-one-size-limit-answerable-before-a-send.md) gave the size question a
`PayloadSizeAssessment`, answerable before a send.

`EndpointPolicy.validate` did not move, and it is the seam whose *new* purpose is a boundary where
refusal is routine. [ADR-024](0024-one-endpoint-policy-reachable-at-registration.md) made the policy
reachable where subscriptions are accepted; there, an inadmissible endpoint is an ordinary request
from an ordinary client, arriving as a `POST` that a web application answers with `400` and no
stored row. The refusal is the boundary working, not failing.

What the exception shape costs is not a matter of taste. The recipe this project prints in its own
Spring guide is a `try`/`catch` around a check whose failure is expected, and
[ADR-022](0022-one-type-per-programmatic-action.md)'s deliberate refusal to let
`EndpointRejectedException` extend `IllegalArgumentException` — so that no framework maps it to a
`400` echoing the message to whoever posted the subscription — guarantees that every consumer writes
the same catch-and-translate at its own boundary. That refusal is right, and it is precisely what
makes the exception-shaped answer expensive rather than merely unfashionable.

**This record owns the shape of the endpoint policy's answer**: what the seam's one method returns,
what the value carries, and what reaches a caller at each of the two application points. It does not
touch which endpoints are admissible (ADR-016, [ADR-017](0017-domain-rule-in-the-endpoint-allowlist.md)),
where the decision is applied or who owns it (ADR-024), or how a refusal is classified once `send`
holds it (ADR-021).

## The decision

**`EndpointPolicy` keeps exactly one method, and that method returns a value.**

```java
@FunctionalInterface
public interface EndpointPolicy {
    EndpointAssessment assess(URI endpoint);
}

public sealed interface EndpointAssessment {
    record Allowed() implements EndpointAssessment {}
    record Refused(String reason) implements EndpointAssessment {}
}
```

`validate` is removed, and `EndpointRejectedException` with it. The seam stays a functional
interface with a single abstract method, so a corporate egress rule is still one lambda — it returns
an answer now instead of falling off the end of a `void`.

## Replacing the method, rather than adding beside it

The reported shape was an `assess` added beside a `validate` kept as a `default`, so that nothing
breaks. It is refused, and for two reasons that point the same way.

**A `default validate` is a second way to ask the one question the seam exists to answer**, which is
what ADR-024 rules out in those words. That a derived default cannot *disagree* with the method it
derives from answers the consistency half of ADR-024's objection and not the other half: the seam
would publish two spellings of one question for the life of the API, and every reader would have to
learn which one their codebase settled on. Replacing keeps ADR-024's clause intact rather than
superseding it — after this record the policy still has exactly one way to be asked.

**And a retained `EndpointRejectedException` becomes a `catch` that never fires.** With the standard
allowlist answering by value, nothing in this library throws that type: it is constructed in exactly
three places today, all inside `EndpointPolicies`, and caught in exactly one, inside `PushSender`.
A published exception type that nothing throws is not harmless documentation — it is an invitation
to write `catch (EndpointRejectedException e)` around `assess`, compile cleanly, and never reject
anything. The type goes in the same change that removes the method that promised it.

The reason offered for keeping `validate` does not survive its own shape, and is recorded here so it
is not re-proposed: the report argues that an implementation which finds throwing natural should
keep that freedom. With `assess` abstract it does not have that freedom in either design — it must
return a value — so the `default` serves callers, not implementers, and what it offers them is
migration convenience for the life of the API.

## The name changes because the spelling decides who breaks silently

Keeping the name and changing only the return type — `EndpointAssessment validate(URI)` — is
available and is refused. The call site written against the published recipe keeps compiling:

```java
try {
    endpointPolicy.validate(URI.create(subscription.endpoint()));
} catch (EndpointRejectedException e) {
    return ResponseEntity.badRequest().build();
}
```

The call is still a legal statement expression, the returned value is discarded, and nothing is
thrown. `EndpointRejectedException` extends `RuntimeException`, so the `catch` is unreachable rather
than illegal and javac says nothing — the "exception is never thrown in body" error exists only for
checked types. A registration boundary upgraded across that change stops refusing anything and
starts storing every endpoint a client offers, silently, in the one control this seam exists to
enforce.

The scope is worth stating exactly, because it is what the rule-out below is written against. With
the exception type kept for compatibility — which is what the report proposes beside the kept name —
that recipe compiles with no diagnostic of any kind, `-Xlint:all` included. With the type removed as
this record removes it, a boundary that names it in a `catch` fails loudly at the `catch` and is
therefore safe. What stays silent under either is the other common shape: a boundary that calls the
method and lets the unchecked refusal travel to a framework's handler, naming the type nowhere. One
of the two hazards needs the exception to survive; the other does not need anything.

So the spelling has to differ, and the choice among the spellings that do is `assess` — the verb
this project already uses for the same move, one release earlier, on `PushSender.assessPayloadSize`
answering a `PayloadSizeAssessment`. A reader who has met one of the two guesses the other. `probe`
was considered and refused: in this project's vocabulary a probe goes and touches something — it is
what the health indicator does, once per cache interval, to a custodian — and a name promising that
would describe every implementation of this seam by the habits of the rare one. The standard
allowlist reads a `URI` and reaches nothing; an implementation *may* resolve, and the seam's own
Javadoc offers a custom DNS check as one reason it stays an interface, which is exactly why the
method's name may not decide the question for all of them. `decide` was considered and refused
because "decision" already names the allowlist itself in ADR-016 and ADR-024, and a per-endpoint
verdict under the same word would collide with the vocabulary those records established.

## `Refused` carries a reason, and deliberately not the endpoint

The report proposes `Refused(String redactedEndpoint, String reason)`, mirroring
`PushOutcome.EndpointRejected` component for component so that one refusal is described in one
vocabulary. The symmetry is real and it is not taken, because of what it moves.

Today `send` renders the redacted endpoint itself, from the subscription it holds, whatever the
policy wrote:

```java
return new PushOutcome.EndpointRejected(Endpoints.redact(subscription.endpoint()), reason);
```

Of the two components on that outcome, one is a structural guarantee of this library and the other
rests on the seam's contract. A `redactedEndpoint` supplied by the implementation would move the
first into the second, and a policy that put the raw capability URL there would publish it through
an outcome and into whatever logs the outcome reaches — for a seam whose whole subject is what an
attacker-influenced endpoint may do.

**The component is also unnecessary, which is what settles it.** Both callers hold the endpoint at
the moment they ask: `send` has the subscription, and a registration boundary has the URI it just
passed in. `Endpoints.redact` is public. Nobody needs the policy to hand back the thing they gave
it, and no component may be added later without a breaking change, so this is decided now rather
than deferred.

`reason` keeps the obligation the exception message carried — the raw URI does not go in it, and an
implementation renders the endpoint with `Endpoints.redact` where it wants to name it, as the
standard allowlist does. Its compact constructor enforces what the name asserts, as `ExceedsLimit`
does for its numbers: a `null` reason is a `NullPointerException` and a blank one an
`IllegalArgumentException`, because a refusal nobody can read is a defect in the policy rather than
a refusal.

**One defensive branch disappears with the exception, and it is worth naming.**
`EndpointRejectedException` is a public non-final class, so a consumer may subclass it and override
`getMessage()` — which is why `send` reads that message inside a `try`/`catch` today, with a
fixed-text fallback, on the reasoning that a hostile or defective accessor must not turn a
classified refusal into the accessor's own complaint. `Refused` is a record: final, with an accessor
this library generates and nobody can replace. The failure mode does not need guarding because it
cannot occur.

## `Allowed` carries nothing, and one instance says it

The permitting branch has no components, for the reason ADR-023 gives for `WithinLimit`: an endpoint
that is admissible needs no number or string to act on, and a component added to a record later
changes its canonical constructor, its accessors and every pattern written against it — a breaking
change where a method would have been a compatible addition. Deciding it now is what makes the empty
shape a commitment instead of an omission.

The type is not a singleton — its canonical constructor is public and a caller may build as many as
it likes — and the library's own implementations still hand out one shared instance, as
`assessPayloadSize` does for `WithinLimit`. Identity is not part of what the answer means; not
allocating to say a thing with one thing to say is an implementation property, and pinning it in a
test does not publish it.

## What `send` does with the answer

The pipeline is unchanged in order and in outcome. `send` asks the policy before encrypting, before
signing and before any network I/O, and a `Refused` becomes `PushOutcome.EndpointRejected` carrying
this library's own redaction of the endpoint beside the policy's reason — the same value, in the
same position of ADR-021's sorting, that a caller reads today. A fan-out still flags or drops one
hostile row and carries on.

Two failure modes of the new shape are settled here rather than discovered:

- **A policy returning `null`** is a defect, and it arrives as a `NullPointerException` from the
  sender's own check. The `void` method had no such case; the value-returning one does, and the
  answer is the one ADR-022's table already gives for a violated non-null contract.
- **A policy throwing anything at all** is a defect and propagates unchanged. This is not a new rule
  but the removal of the exception from the one list it was on: the facade converted three seam
  types and now converts two, and everything else out of a consumer seam is read as a defect in that
  implementation rather than as an operational condition.

## Which records move

**ADR-022 takes the narrow status line.** It owns the exception taxonomy entirely — which types
exist, what each promises, and what leaves each seam — and one of its three seam signals ceases to
exist. Its table row for a refused endpoint, and the clause naming three converted types, are what
this record supersedes; every other part of that ADR stands, including the reasoning that put
`EndpointRejectedException` outside `IllegalArgumentException`, which is half of why the exception
shape had to go.

**ADR-024 is untouched, and that is a claim worth making explicitly** because this record looks at
first like the thing that ADR forbids. What it rules out is a *second* method on `EndpointPolicy` —
a predicate, an overload, "or any other second way to ask the one question the seam exists to
answer". After this record there is exactly one way to ask. Everything else that ADR decided holds
unchanged: one definition of the rule, applied at both points; the policy as a bean under Spring;
the order at a registration boundary — the `Subscription` first, the policy on the endpoint it
carries second, the row third; no accessor for the policy on `PushSender`; and no configuration-only
path to unrestricted egress.

One sentence of that record deserves naming rather than passing over, since a later reader will find
it: *the core gains no API, and that is a decision rather than an absence of work*. This record does
add a type to the core. That sentence answers ADR-024's own question — what the core needed in order
to make the policy reachable where subscriptions are accepted — and the four additions it refused
are an accessor on `PushSender`, a predicate beside `validate`, an overload taking a `Subscription`,
and a factory joining subscription parsing to the admission decision. None of them is the shape of
the one method's answer, none appears here, and ADR-024's durable list rules out no core API in
general. So the clause is answered rather than superseded.

ADR-016 and ADR-017 are untouched: the seam is still a required argument of every `PushSender`
factory, the library still ships no allowlist, and the rule kinds and their matching are unchanged.
ADR-021 is untouched: `EndpointRejected` is still a `NotAttempted` outcome and still means what it
meant.

## What this breaks, and how a reader finds out

Every implementation of `EndpointPolicy` breaks, and every call to `validate` breaks, and both break
at compile time: the abstract method's signature changed and the removed method is gone. A lambda
policy stops compiling because a `void` body cannot satisfy a value-returning method; a class
implementing the seam stops compiling because `assess` is unimplemented; a caller stops compiling
because `validate` does not resolve, and `catch (EndpointRejectedException e)` stops compiling
because the type does not exist.

**The one shape that would have broken silently is the one this record refused** — the same spelling
with a new return type — and that is why the name changed rather than a preference among words.
`docs/MIGRATION.md` states the move from the version that has `validate`, and says both halves: the
mechanical translation, and that a reader who finds their build still green has not finished the
migration but has some other `EndpointPolicy` on the classpath.

This is a breaking change to published API, made inside the revision window the first release note
declared, and its pull request carries the marker that puts it in the release notes as one.

## Documents

`README.md` for the seam's shape and the two application points; `docs/SPRING.md` for the
registration recipe, which stops being a `try`/`catch` and becomes a `switch`; `docs/DESIGN.md` §4
and §5 for the pipeline step and where the policy is applied; `docs/MIGRATION.md` for the move
itself. `EndpointPolicy`'s own Javadoc states the value contract in its own words, since it ships in
a `sources.jar` to readers who have neither this record nor those documents — and `CLAUDE.md`'s
architecture summary names the three converting seam signals, which becomes two.

## What this rules out

- An endpoint policy that answers by throwing, in any shape: a seam whose refusal is control flow at
  a boundary where refusal is the ordinary case.
- A second way to ask it — a retained `validate`, a predicate, an overload — whether or not the
  second is derived from the first and so cannot disagree with it.
- A published exception type that nothing in this library throws, offered as compatibility, whose
  only remaining use is a `catch` that never fires.
- The same method name kept across the change from `void` to a value, which leaves a call site that
  does not name the exception compiling unchanged, and silently admitting every endpoint.
- A method name promising that the seam goes and touches what the endpoint names, when the
  ordinary implementation reads a `URI` and reaches nothing — whatever an unusual one is free to do
  inside it.
- A refused endpoint rendered by the policy rather than by this library: the redaction of a
  capability URL is not delegated to an implementation, and `Refused` therefore carries no endpoint
  component in any spelling.
- Components on the permitting branch, now or later — `Allowed` gains them only by a breaking
  change, which is the same commitment ADR-023 made for `WithinLimit`.
- A published singleton for that branch: a non-public canonical constructor, or an `INSTANCE`
  constant offering identity as something a caller may read.
- A `Refused` carrying no reason, or one carrying the raw endpoint in the reason it does carry.
- A `send` that treats a `null` assessment, or any exception out of the seam, as an operational
  outcome rather than as the defect it is.
- A change to where the policy is applied, to who owns the rule, or to how the refusal is classified
  once the sender holds it — those are ADR-024's, ADR-016's and ADR-021's, and this record leaves
  all three where they are.
