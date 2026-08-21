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

    record Refused(String reason) implements EndpointAssessment {

        /** Takes a null reason and stores "" for it: the component is non-null, the parameter is not. */
        public Refused(@Nullable String reason) {
            this.reason = Objects.requireNonNullElse(reason, "");
        }
    }
}
```

`validate` is removed, and `EndpointRejectedException` with it. The seam stays a functional
interface with a single abstract method, so a corporate egress rule is still one lambda — it returns
an answer now instead of falling off the end of a `void`.

**`Refused`'s constructor is written out because its nullness is part of the decision and not an
implementation detail.** Every package here is `@NullMarked`, so a plain canonical constructor would
declare the parameter non-null and a policy passing `null` would be violating the contract rather
than exercising it — which is the opposite of what the section below decides. The explicit canonical
constructor is what makes "accepts null, stores `""`" machine-readable: the parameter carries
`@Nullable`, the component and its accessor stay non-null, and the compact form cannot express it,
since it has no parameter list to annotate.

## Doing nothing is the alternative to refuse first

Every alternative below is a way of making the change; this one is not making it, and it is the
plainest reading of the cost. Breaking a published seam falls on every implementation and every call
site a consumer has, and what it buys them is that one `try`/`catch` per registration boundary
becomes a `switch`. Consistency with two decisions of the release before is not, by itself, a
licence to spend that.

What decides it is a premise about *when*, and it is the argument this record rests on rather than
the aesthetic one. The second application point is one release old: before it, the only caller of
this method in existence was `send` itself, and a consumer had no reason to hold a policy at all.
The population of `validate` call sites and of hand-written implementations is therefore at its
historical minimum right now and grows with every release that ships without this change — the guide
that tells applications to inject the bean and apply it at registration is the same age as the
problem. Deferring does not avoid the cost; it buys the same cost later at a higher price, paid by
more people.

**The shape the report offers as the compatible one is not compatible**: with `assess` abstract,
every existing lambda and every implementing class stops compiling exactly as it does under this
record, because the single abstract method's signature is what moved. Its `default` buys callers and
nobody else. A genuinely compatible shape does exist, though — the mirror of it — and it is compared
and refused in the next section rather than denied here, because the choice this record makes is
between breaking now and breaking later, and a reader is owed the reason that is so.

The timing has one more thing in it, and it cuts the same way. This would be the second consecutive
release to break the deployment that reported it, which migrated to the current version days before
filing. That is a real cost and it is named rather than hidden: it is also the deployment that asked
for the change, and the alternative on offer is to make it pay the same migration later, when its
own codebase and everyone else's holds more of the calls that break.

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

## The compatible shape, and why it is the expensive one

Turn the report's proposal around and it stops breaking anything:

```java
@FunctionalInterface
public interface EndpointPolicy {

    void validate(URI endpoint);                      // still the single abstract method

    default EndpointAssessment assess(URI endpoint) { // the library catches on the caller's behalf
        try {
            validate(endpoint);
            return new EndpointAssessment.Allowed();
        } catch (EndpointRejectedException e) {
            return new EndpointAssessment.Refused(e.getMessage());
        }
    }
}
```

Every lambda, every call site and — with one exception worth naming, since a compatibility claim
that overstates is worth nothing — every implementing class in existence keeps compiling, and the
binary contract is untouched. The exception is a class that already declares an `assess(URI)` of its
own with an incompatible return type: its recompilation fails on the clash, though the binary it
already produced goes on running. A registration boundary gets its `switch`. This is the alternative
the record has to beat, and beating it takes four things rather than one.

**It does not remove the exception; it hides it.** Every refusal is still constructed and thrown, on
every request a boundary refuses, and a client posting junk to a public registration endpoint is the
ordinary source of those. What the caller stops doing is *writing* the catch; the runtime goes on
performing the throw, with the stack-trace fill-in the value shape avoids. The premise this record
rests on — that a condition met routinely is not an exceptional one — is answered for the caller's
source code and left standing everywhere else.

**It makes the seam two methods where ADR-024 left one, and puts the split in the worse place.**
Under the report's shape an implementation writes `assess` and a caller may spell the question two
ways; under this one an implementation must still write `validate` — so the seam is asked one way
and implemented another, and no implementation can ever answer with a value. A policy that would
rather return `Refused` is not allowed to.

**It writes the lossy conversion into the library and freezes it.** `Refused`'s reason becomes
`getMessage()` by construction, so the structured answer is permanently a rendering of a message —
including the `null` message this record has to normalise, now normalised by us on the policy's
behalf, for good. Nothing built on top of it can ever be more than prose.

**And it settles into one of two futures, neither of which is free.** If the two methods are
permanent, then it is not a step towards this record's decision but a refusal of it, and the three
paragraphs above are the whole of its price — paid on every request a boundary refuses, for the life
of the API. If it is a way station, the arithmetic of arriving later is worse than arriving now, and
the shape of the later break is worth stating exactly rather than rounding up: `validate` is removed
and `assess` loses its `default`, so every implementation must write the method none of them had to
write before — from a population larger than today's, with `EndpointRejectedException` retired in
the same change.

Stating both is the honest form, because the second reading presumes the destination and the first
does not — and the two do not share a condition. Under the permanent reading there is no later break
to weigh at all; under the way-station reading a larger later break argues for deciding now rather
than for postponing, so neither future turns the cost of a future migration into a reason to take
the compatible shape.

What would justify taking it is one thing and it is about the installed base: a population for which
migrating today costs more than carrying a second method and an exception channel does — for a while
if the break comes later, indefinitely if it never does. That is a judgement about how many
implementations and call sites exist, and this seam gained its second application point one release
ago, which is the section above's answer to exactly that question.

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

**What the change moves, and what it does not, is worth stating in the same breath.** After it,
`policy.assess(uri);` as a bare statement compiles with no diagnostic of any kind and admits every
endpoint — where `policy.validate(uri);` as a bare statement was correct. The unsafe spelling and
the terse one change places, permanently and not only across the migration, and no compiler help is
available for it: the annotation that would mark the return value as one a caller may not discard
lives in a dependency the core may not take. The trade is accepted with its name said out loud —
implementations become safer, since falling off the end of a `void` stops being a way to admit
everything and a policy must now positively return `Allowed`, while call sites become riskier by
exactly the shape a discarded value has. `send` re-checks, so no send escapes the control; the
registration boundary is the point where nothing re-checks, which is why ADR-024 put the policy
there, and the seam's own Javadoc has to say so where a consumer reads it.

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
standard allowlist does.

**It validates nothing, and that is a decision rather than an oversight.** The obvious shape is the
one `ExceedsLimit` uses — refuse what the name contradicts — and here it would be a defect. A policy
translating its own failure writes `new Refused(e.getMessage())` in one line, and `getMessage()` is
`null` for every exception built without a message; today that is legal, because
`EndpointRejectedException`'s constructor checks nothing, and `send` renders it as `""` on an
outcome whose Javadoc keeps that rendering deliberately distinguishable from the fixed text it
substitutes elsewhere. A compact constructor throwing on `null` or blank would send that one-line
slip out of the seam as a defect, by this record's own rule, and a defect propagates: a synchronous
fan-out over a subscription store stops on the first row whose policy took that shortcut. That is
the self-inflicted denial of service the whole value shape exists to prevent, and it is reachable by
an endpoint an attacker chose. So `Refused` normalises a `null` reason to `""` and permits a blank
one, which is exactly what `PushOutcome.EndpointRejected` permits — one refusal may not be legal in
one of the two types describing it and illegal in the other. `ExceedsLimit` is not the precedent it
looks like: its check guards a relation a caller branches on, and a blank reason breaks nothing
anybody branches on.

**One defensive branch disappears with the exception, and it is worth naming.**
`EndpointRejectedException` is a public non-final class, so a consumer may subclass it and override
`getMessage()` — which is why `send` reads that message inside a `try`/`catch` today, with a
fixed-text fallback, on the reasoning that a hostile or defective accessor must not turn a
classified refusal into the accessor's own complaint. `Refused` is a record: final, with an accessor
this library generates and nobody can replace. The failure mode does not need guarding because it
cannot occur.

## The reason is a log line, not a switch

`Refused` carries prose, and the affirmative reason for that decides it: the component exists for
observability. **This library writes no log lines.** It holds no logger and takes no logging
dependency — the zero-dependency core could not take one — so every diagnostic it produces is a
value handed to a caller who renders it, and `PushOutcome` already describes its own components in
exactly those terms: a diagnostic for the log line and the metric, safe to log and enough to find
the row. An operator wanting to know why a subscription was turned away at registration reads a
sentence somebody wrote for them to read. A string is the shape of that.

**Read that way, ADR-022's rule is not engaged.** What it forbids is message-text matching *as the
supported way to tell two conditions apart* — "anywhere a consumer must do that, a type is missing".
Rendering a message is not telling two conditions apart; it is what a message is for. The rule fires
where a program branches, and nothing here asks one to.

**A code would be the wrong shape for the purpose, not merely an unnecessary one.** A code carries
no text, so somewhere a table has to map it to a sentence — and the somewhere would be each
consumer, reconstructing in its own words what the policy knew at the moment it refused, from an
enumeration that cannot say which rule was involved or what the endpoint looked like. The
observability the component exists for would get worse, not better, and every consumer would rebuild
the same table.

A second reason stands behind that one and would refuse a code even if the first did not: the seam
is open. A code this library defines can enumerate only the reasons `EndpointPolicies` produces, and
a corporate egress rule — the reason the seam is an interface at all — would reach for a general
"other" and put its real answer back in the prose, publishing a property of one implementation as a
property of the seam.

The disclosure argument is *not* what refuses a code, and is recorded as insufficient so it is not
reached for later: the standard allowlist declines to report which rule came closest because that
describes the allowlist to whoever supplied the endpoint, and a coarse code — userinfo present, no
host, no rule matched — tells that client only things about what it just posted, or what the `400`
already told it.

What stays live is the obligation ADR-022 places on whoever *does* find a consumer needing to branch
on the kind of refusal: that reader is looking at a missing type, and where it goes is a decision of
its own rather than a component added to this one. The prose is not a substitute for it and is not
offered as one.

## Structure through a subclass, also refused

`EndpointRejectedException` is a public non-final class, so a consumer's policy may today throw
`class EgressDenied extends EndpointRejectedException` carrying whatever its own boundary wants to
read — a rule, a zone, a ticket reference — catch that type where it accepts subscriptions, and
still have `send` classify it as `EndpointRejected` because the base type is what the facade
converts. `EndpointAssessment` is sealed and `Refused` is final, so that channel closes and a
`String` is what remains.

It closes on purpose. The subclass hatch is the same hatch that made `send` read `getMessage()`
defensively, and it works only for a consumer that owns both ends — its own policy and its own
boundary — which is a consumer that can as easily carry its structure beside the assessment, in the
class that produced it. What it cannot do is travel through this library, and it does not need to:
the sender's business with a refusal is to report it, and the two components of the outcome are what
that report is made of.

## `Allowed` carries nothing, and one instance says it

The permitting branch has no components, for the reason ADR-023 gives for `WithinLimit`: an endpoint
that is admissible needs no number or string to act on, and a component added to a record later
changes its canonical constructor, its accessors and every pattern written against it — a breaking
change where a method would have been a compatible addition. Deciding it now is what makes the empty
shape a commitment instead of an omission.

Unlike the size assessment, this case does have a candidate on offer, and it is named rather than
waved past: a policy that resolves could hand back the address it vetted, for a transport to pin and
connect to. It is refused because the pinning belongs to the transport that opens the socket, not to
the value a policy returns — the seam's own Javadoc sends a deployment wanting that guarantee to the
transport layer, and an address `PushSender` never reads would be a component published for a
consumer to carry between two of its own components. A policy needing it holds it already, in the
implementation that resolved.

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
  sender's own check — which stops the fan-out, where a blank reason above deliberately does not.
  The two are not treated differently by temperament: a missing reason has a rendering that keeps
  the refusal's meaning intact, and a missing answer has none. Reading `null` as `Allowed` fails
  open on the one control this seam is, and reading it as `Refused` invents a decision the
  deployment never made. So the only honest reading is the one ADR-022's table already gives for a
  violated non-null contract, and the `void` method's freedom from this case is a real thing the
  change costs.
- **A policy throwing anything at all** is a defect and propagates unchanged. This is not a new rule
  but the removal of the exception from the one list it was on: the facade converted three seam
  types and now converts two, and everything else out of a consumer seam is read as a defect in that
  implementation rather than as an operational condition.

## Which records move

**Two records take the narrow status line, and ADR-022 divides the halves itself.** It says that it
owns the taxonomy — which types exist, what each promises, what each carries — and that it owns "the
contracts and not the sorting"; that classification is ADR-021's, "and so is which failure leaves a
seam wearing which of these types; a type is the channel and that record decides what goes down it",
along with "the line between an outcome and an exception". It says why the division is written down:
so that whoever supersedes either knows which half they are replacing. This record replaces one
clause of each.

**ADR-022** loses a type. `EndpointRejectedException` ceases to exist, and with it that record's
table row for a refused endpoint and its last row's count — "the facade converts three types and no
others" is two after this. Every other part of it stands, including the reasoning that put the type
outside `IllegalArgumentException` — which is half of why the exception shape had to go, so the
clause that survives is the one that argued this change into being.

**ADR-021** loses the seam's channel. That record states, in its own words, that "the seams keep
signalling as they do now — `PushHttpClient` throws `PushDeliveryException`, `EndpointPolicy` throws
`EndpointRejectedException`, and a signer that cannot sign now throws
`VapidSignerUnavailableException`", and that "those three types convert and no others". After this
record the endpoint policy signals by returning, the enumeration is two, and for this one seam the
line between an outcome and an exception has moved. What ADR-021 keeps is everything it is chiefly
about: the retry removal, the sealed `PushOutcome`, both status matrices, the surfacing of
`Retry-After`, and the classification itself — a refused endpoint is still `EndpointRejected`, still
a `NotAttempted`, still meaning exactly what that record made it mean. Only the channel the seam
uses to say so is gone, and a caller of `send` cannot tell the difference.

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

One argument inside ADR-024 does get weaker without any of its decisions moving, and it is named
here so that a later reader who notices does not read the weakening as an opening. That record
refuses a core `Subscriptions.accept(policy, …)` factory partly because it would report two
unrelated refusals through one call, an `IllegalArgumentException` for a malformed subscription
beside an `EndpointRejectedException` for an inadmissible host. After this record the second is a
value and that leg is gone. The refusal stands on the other one, which is ADR-004's and untouched:
the moment a subscription is accepted is outside this library.

ADR-016 and ADR-017 are untouched: the seam is still a required argument of every `PushSender`
factory, the library still ships no allowlist, and the rule kinds and their matching are unchanged.

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
declared. The pull request that carries it — the implementation, not this record — takes the marker
that files it in the release notes as one; this one changes no code and is filed as documentation.

## Documents

`README.md` for the seam's shape and the two application points; `docs/SPRING.md` for the
registration recipe, which stops being a `try`/`catch` and becomes a `switch`; `docs/DESIGN.md` §4
and §5 for the pipeline step and where the policy is applied; `docs/MIGRATION.md` for the move
itself. `EndpointPolicy`'s own Javadoc states the value contract in its own words, since it ships in
a `sources.jar` to readers who have neither this record nor those documents, and it is where the
discarded-answer trade above has to be said to the person who can walk into it — and `CLAUDE.md`'s
architecture summary names the three converting seam signals, which becomes two.

Two documents are owed an edit that is easy to miss because neither is about this change.
`docs/MIGRATION-FROM-WEB-PUSH.md` twice tells a reader arriving from the other library that
`EndpointRejectedException` is what the policy seam throws and what to catch at a registration
boundary; both sentences become false. `docs/MIGRATION.md`'s existing section for the `0.1.0` move
says in its table that the type still exists and is still what `validate` throws. That section is
**not** edited: it records one transition, its columns ask what a `catch` clause caught in `0.1.0`
and what it catches after that move, and rewriting it to match a later API would destroy the account
of the move it describes. The file accumulates newest first, so the new section is inserted directly
under the index and the `0.1.0` one sits below it. Which of the two a reader crossing both versions
meets first depends on whether they are scanning the file or working through the hops in the order
they have to apply them, and neither needs to be guessed at: every section names the version it
moves *from*, and that label is what tells a reader which claims belong to which hop.

## What this rules out

- An endpoint policy that answers by throwing, in any shape: a seam whose refusal is control flow at
  a boundary where refusal is the ordinary case.
- A second way to ask it — a retained `validate`, a predicate, an overload — whether or not the
  second is derived from the first and so cannot disagree with it.
- The compatible mirror of that shape, `validate` abstract with `assess` derived from it: it keeps
  the exception thrown on every routine refusal, lets no implementation answer with a value, freezes
  the reason as a rendering of a message, and buys a delay it repays with a larger break later.
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
- A `Refused` carrying the raw endpoint in the reason it does carry; and equally a `Refused` that
  refuses to be constructed — a policy's blank or absent reason is rendered, never thrown, because a
  refusal that throws out of the seam is a defect and a defect stops the fan-out this value exists to
  keep running.
- A reason a program branches on, in this type: a code, an enum or a second component, in place of
  the sentence an operator reads — the component is this library's contribution to a log line it does
  not write itself, and a code moves the writing of that line into every consumer. Equally: the
  disclosure argument offered as what refuses a code, and the prose offered as an answer to a
  consumer that genuinely needs to branch, which is a missing type and a decision of its own.
- Structured refusal data travelling through this library on a consumer's own subtype, which the
  sealed hierarchy closes deliberately.
- A component on `Allowed` carrying an address a policy resolved, for a transport to pin: the pinning
  belongs to the seam that opens the socket.
- A `send` that treats a `null` assessment, or any exception out of the seam, as an operational
  outcome rather than as the defect it is.
- A change to where the policy is applied, to who owns the rule, or to how the refusal is classified
  once the sender holds it: the first two are ADR-024's and ADR-016's and are untouched, and the
  third is ADR-021's and survives — what moves there is the channel the seam signals through, never
  the outcome the caller reads.
