# Migrating between push2u versions

This is the guide for an application already on push2u that is moving to a newer version of it. The
document beside it, [`MIGRATION-FROM-WEB-PUSH.md`](MIGRATION-FROM-WEB-PUSH.md), is the other
journey — arriving from `nl.martijndwars:web-push`, a different library with a different API. If you
are already calling `PushSender`, this is your document.

One section per migration, **newest first**, so an application skipping several versions reads
upwards from the release it is on. No section names the version it moves *to*: a release has no
number until its tag is cut, and each section is written while the release it describes is still
being prepared. Each one does name the version it moves *from*, which has a tag and cannot move.
Where you need a coordinate to paste into a build file, take it from
[README's *Installation*](../README.md#installation) — the released version is written there and
nowhere else in this tree.

**Adding a migration:** the new section goes directly under [Migrations](#migrations), above the one
that was newest, and its row goes at the top of that index. Every heading inside it must be unique
across the whole file, and by construction rather than by care: GitHub derives a heading's `id` from
its text alone — the level it sits at and the section it sits under are not part of it — and
numbers a repeat by the order it appears in, so a second *Checklist* added at the top would take the
clean anchor and silently push the older one to `checklist-1`, breaking nothing visibly while
sending that section's own links into the new one. A heading naming a type, a method or a property
key is unique on its own; one naming a role in the document carries its source version, the way
*Checklist for the `0.1.0` move* does.

## Migrations

| Moving from | What that release changed |
|---|---|
| [`0.2.0`](#from-020) | The endpoint policy answers with a value: `EndpointPolicy.validate` becomes `assess`, returning an `EndpointAssessment`, and `EndpointRejectedException` is removed. Separately, the published signer conformance contract runs one more check, and the Spring Boot starters stop publishing Spring Boot's BOM. |
| [`0.1.0`](#from-010) | The result type, the retry loop, the exception taxonomy, one of the two size knobs, six Spring keys, and a bound on the subscription endpoint. |

## From `0.2.0`

`0.2.0` is where this upgrade starts. It is the version this section is written against, and the one
it names throughout; the release it lands in is deliberately unnamed, for the reason above.

One seam changed shape, and only one. `EndpointPolicy` — a deployment's rule for which push
endpoints it will contact — used to answer by throwing; it answers with a value now. `validate` is
replaced by `assess`, which returns an `EndpointAssessment`, and `EndpointRejectedException` no
longer exists. The reason is the second place the policy is applied: since `0.2.0` an application
can hold the policy where it accepts subscriptions, and there a refusal is an ordinary request from
an ordinary client rather than an error — the boundary working, not failing.

Everything that moves breaks your compilation, which is the cheap kind, and this section's second
half is about the reader for whom nothing broke.

One further change travels with this release and has nothing to do with the policy: the published
conformance contract for `VapidSigner` runs an extra check, so a project maintaining a signer of its
own can find its test suite red on an upgrade that changed nothing it wrote. That has a subsection
of its own below, and no bearing on an application that only sends.

- [What stops compiling on the way from `0.2.0`](#what-stops-compiling-on-the-way-from-020)
  - [`EndpointPolicy.validate` is now `EndpointPolicy.assess`](#endpointpolicyvalidate-is-now-endpointpolicyassess)
  - [`EndpointRejectedException` is gone, subtypes included](#endpointrejectedexception-is-gone-subtypes-included)
  - [At a registration boundary, `EndpointAssessment` replaces the `catch`](#at-a-registration-boundary-endpointassessment-replaces-the-catch)
- [A green build does not finish the `0.2.0` move](#a-green-build-does-not-finish-the-020-move)
  - [`policy.assess(uri);` as a bare statement admits every endpoint](#policyassessuri-as-a-bare-statement-admits-every-endpoint)
- [`VapidSignerContractTest` now signs from several threads at once](#vapidsignercontracttest-now-signs-from-several-threads-at-once)
- [The starters stop exporting Spring Boot's BOM](#the-starters-stop-exporting-spring-boots-bom)
  - [Which Spring Boot you end up with, before and after](#which-spring-boot-you-end-up-with-before-and-after)
- [What the `0.2.0` move does not change](#what-the-020-move-does-not-change)
- [Checklist for the `0.2.0` move](#checklist-for-the-020-move)

### What stops compiling on the way from `0.2.0`

#### `EndpointPolicy.validate` is now `EndpointPolicy.assess`

The seam keeps exactly one method and stays a functional interface, so a corporate egress rule is
still one lambda — it returns an answer now instead of falling off the end of a `void`:

```java
// 0.2.0
EndpointPolicy policy = endpoint -> {
    if (!egress.permits(endpoint.getHost())) {
        throw new EndpointRejectedException(
                "egress rule denies " + Endpoints.redact(endpoint.toString()));
    }
};
```

```java
// now
EndpointPolicy policy = endpoint -> egress.permits(endpoint.getHost())
        ? new EndpointAssessment.Allowed()
        : new EndpointAssessment.Refused(
                "egress rule denies " + Endpoints.redact(endpoint.toString()));
```

A class implementing the seam takes the same edit at its declaration: `public void validate(URI
endpoint)` becomes `public EndpointAssessment assess(URI endpoint)`, and every path through the body
ends in a `return`.

`EndpointAssessment` is a sealed interface with two record variants:

- **`Allowed()`** — no components, deliberately and permanently: an admissible endpoint needs no
  number or string to act on. Its canonical constructor is public, so build one wherever you need
  it; all instances are equal and identity says nothing.
- **`Refused(String reason)`** — the reason is the prose an operator reads in a log line, and it
  carries exactly the obligation the exception message carried before it: **the raw endpoint does
  not go in it**, so an implementation that wants to name the endpoint renders it with
  `Endpoints.redact` first. `null` is stored as `""` and a blank reason is permitted, so a policy
  translating its own failure may write `new EndpointAssessment.Refused(e.getMessage())` in one line
  without that line becoming a defect.

Three rules of the new contract are worth reading once rather than meeting:

- **A policy must positively return `Allowed`.** Under `void`, doing nothing was how an
  implementation admitted an endpoint; there is no such path now, which is the one way this change
  makes implementations safer rather than riskier.
- **Returning `null` is a defect**, not an admission and not a refusal: `send` reports it as a
  `NullPointerException` naming the policy, and that stops a fan-out where a refusal would not.
- **Throwing anything at all out of `assess` is still a defect** and still propagates unchanged.
  That rule has not moved; what moved is the list of seam signals `send` converts, which was three
  and is two — `VapidSignerUnavailableException` and `PushDeliveryException`.

#### `EndpointRejectedException` is gone, subtypes included

The type is removed, so `catch (EndpointRejectedException e)` no longer compiles anywhere: around a
`send`, where it had already stopped catching anything in the release before, and around the policy
call itself, where it was still doing its job. Nothing in the library throws it and nothing converts
it; a `catch` kept "for compatibility" would have been one that never fires, which is why the type
went in the same change as the method that promised it.

If a policy of yours threw its own subtype — `class EgressDenied extends EndpointRejectedException`
carrying a rule, a zone, a ticket reference — caught at your own boundary while `send` still
classified it as `EndpointRejected` on the base type, that channel is closed on purpose.
`EndpointAssessment` is sealed and `Refused` is a final record carrying prose, so nothing of yours
travels through this library. Nothing needs to: that pattern works only for a consumer that owns
both ends, its own policy and its own boundary, and such a consumer keeps the structure beside the
assessment, in the class that produced it — the sentence is what the library carries, and
`PushOutcome.EndpointRejected` is what a send reports.

One consequence travels with that closure. `send` used to read a refusal's `getMessage()` inside its
own `try`/`catch` and substitute a fixed text where the accessor threw, because a public non-final
exception class could be subclassed by anyone. `Refused` is a final record whose accessor this
library generates and nobody can replace, so that failure mode cannot occur: the fallback is gone
and `EndpointRejected.reason()` is now exactly the string the policy's `Refused` carried.

#### At a registration boundary, `EndpointAssessment` replaces the `catch`

The recipe published in `0.2.0` applied the policy where subscriptions are accepted, and its middle
step was a `try`/`catch` around a check whose failure is expected:

```java
// 0.2.0 — step 2 of: build the Subscription, apply the policy, store the row
try {
    endpointPolicy.validate(URI.create(subscription.endpoint()));
} catch (EndpointRejectedException e) {
    return ResponseEntity.badRequest().build();   // policy refuses — store nothing
}
store.save(subscription);
```

```java
// now — the same three steps, with the second one reading an answer
switch (endpointPolicy.assess(URI.create(subscription.endpoint()))) {
    case EndpointAssessment.Refused refused -> {
        log.info("subscription refused at registration: {}", refused.reason());
        return ResponseEntity.badRequest().build();   // policy refuses — store nothing
    }
    case EndpointAssessment.Allowed() -> store.save(subscription);   // both passed — store it
}
```

The hierarchy is sealed, so that `switch` is exhaustive and needs no `default`, and a variant added
in a later release fails your compilation instead of falling into a branch written for something
else. An `if (… instanceof EndpointAssessment.Refused refused)` guard is the shorter spelling and is
fine where the permitting branch is a fall-through — but note which way it fails: a third variant
would miss the guard and be stored. Where both branches do work, take the `switch`; `send` takes it
over the same value for the same reason.

**The order around it is unchanged**, and it is the seam's contract rather than a preference: build
the `Subscription` first — its own `IllegalArgumentException` is what a malformed one raises, and it
is what establishes the precondition `assess` documents — apply the policy to the endpoint it
carries second, store the row third. What each refusal answers to the client is still yours to
decide, and the reason still does not belong in that answer: echoing it would describe your
allowlist, or the refused endpoint, to whoever posted the subscription. The one thing the exception
bought you here — that no framework mapped it to a `400` echoing its message, because it
deliberately did not extend `IllegalArgumentException` — a value cannot lose.
[`SPRING.md` → Endpoint policy](SPRING.md#endpoint-policy) carries the recipe in full.

**Whichever spelling you take, the answer has to be read.** `endpointPolicy.assess(uri);` on a line
of its own compiles, discards the assessment and stores every row a client offers — the one hazard
of this release no compiler reports, and this is the boundary it is about:
[`policy.assess(uri);` as a bare statement](#policyassessuri-as-a-bare-statement-admits-every-endpoint).

### A green build does not finish the `0.2.0` move

First, who this is about: code that *implements* the seam or *calls* it. An application that only
hands an `EndpointPolicies.…` allowlist to `PushSender.builder` and lets `send` do the asking names
neither the method nor the exception anywhere, so a green build is the whole truth for it and this
release asks nothing of it.

**For everyone else: if you rebuilt against the new version and nothing failed, you have not
finished the migration — you have another `EndpointPolicy` on the classpath.** An older push2u jar
ahead of the new one, a shaded copy, a version that resolved to what you thought you had replaced:
something is answering `validate` for you, and the code that will run is not the code you believe
you compiled. A module of your own that was not rebuilt is the same diagnosis with a different
symptom — it holds a class compiled against `validate`, so nothing answers `assess` for it at all
and the first call raises `AbstractMethodError` at run time, or `NoSuchMethodError` where the stale
class was the caller rather than the policy. Loud, late, and in production if that module is not
covered by a test.

Everything this release moves breaks at compile time wherever the code is actually recompiled, by
construction and not by luck. The seam's single abstract method changed its signature, so no lambda
and no implementing class survives it; `validate` does not resolve at any call site; and
`EndpointRejectedException` does not exist to be named in a `catch`. There is no shape of `0.2.0`
policy code that keeps compiling and quietly means something else.

That property was bought rather than found. Keeping the name and changing only the return type was
the cheaper change, and it was refused precisely here: `endpointPolicy.validate(uri);` inside a
`try` with a now-unreachable `catch` would have gone on compiling with no diagnostic of any kind —
the `catch` is unreachable rather than illegal, since the type was unchecked — and a registration
boundary upgraded across it would have stopped refusing anything and started storing every endpoint
a client offered. The name moved so that no reader can arrive there.

**This is not a promise that the release has no silent half.** It has one, it is below, and it is
permanent rather than something the migration passes through.

#### `policy.assess(uri);` as a bare statement admits every endpoint

The safe spelling and the terse one changed places. In `0.2.0`, `policy.validate(uri);` on a line of
its own was the whole correct call — the refusal arrived by itself. The same shape now compiles with
no diagnostic of any kind, `-Xlint:all` included, discards the answer and admits everything. No
compiler help is available for it: the annotation that would mark the return value as one a caller
may not discard lives in a dependency the zero-dependency core may not take.

Where that matters is not everywhere. Inside a send the slip cannot open the network: `PushSender`
performs the assessment itself, on every send, and acts on the value, whatever your own code did
with an earlier one. **The registration boundary is the point where nothing re-checks** — which is
why the policy is reachable there at all — and it is the one place a discarded answer stores a row
the policy refused.

So the last step of this migration is a grep rather than a build: search your sources for `assess(`
and check that every hit either feeds a `switch` or an `instanceof`, or lands in a variable
something reads. It costs one command and it is the only check there is.

### `VapidSignerContractTest` now signs from several threads at once

A different reader again: not an application that sends, but a project holding a `VapidSigner` of
its own — over an HSM, a KMS or a remote custodian — whose test suite extends the published
conformance contract. Nothing you wrote stops compiling and nothing you configure changes. What
changes is that the contract runs one more check than it did in `0.2.0`, and your build inherits it
the moment the test-scoped kit is upgraded.

**The check.** Several threads are inside `sign` at the same moment, each signing a *different*
input, and every signature that comes back must verify against the input its own call handed in,
under a key read once, on one thread, before any of them start. The signatures are never compared
with one another — ES256 is randomized. A call answering `VapidSignerUnavailableException` counts as
neither a pass nor a failure, a custodian rate-limiting a burst being exactly what that type is for;
if fewer than two calls come back with a signature, or the check runs out of its budget, it is
reported as skipped rather than passed. So a custodian that meters a burst hard enough may show this
check as skipped in your report, and that is the honest answer rather than a green one: one
signature overlaps nothing, and there is nothing for the check to have read. One thing outranks
that, though — a signature that did come back and does not verify fails the check however few of
them there were, since nothing about a quota explains bytes that verify against nothing your signer
was asked to sign.

**If your build goes red on it, the finding is real and it is not new.** `VapidSigner` has always
required implementations to be thread-safe, and has always named the mistake this catches: a
`java.security.Signature` held in a field. One `PushSender` is shared across threads and `sendAsync`
makes concurrent signing ordinary, so a signer weaving one signing object through several callers
has been corrupting signatures under load all along — silently, because a bad signature is not an
error anywhere in this library. It leaves as an opaque `401` or `403` from the push service,
attributed to nothing. What changed is that your own suite can now see it; what it reports was
already true of the version you are upgrading from.

**The fix is at the seam, not in the kit.** Obtain a per-call `Signature` — `getInstance` costs
little beside the ECDSA itself, let alone a network round trip — or confine one to a thread with a
`ThreadLocal`. The same goes for any other per-call state kept in a field: a reused output buffer, a
digest, a cached signing context. A signer that merely borrows a shared, already thread-safe client
per call has nothing to do.

**Passing it does not establish that your signer is thread-safe**, and the kit says as much of
itself. No schedule is forced, so a signer that shares state can go a great many runs without two
threads colliding inside it. A red run is a real defect every time; a green one means only that the
check did not catch you. The requirement is the sentence in `VapidSigner`'s own contract, as it has
been all along.

### The starters stop exporting Spring Boot's BOM

A third reader, and the one least likely to be looking: an application that uses either Spring Boot
starter and does not manage Spring Boot's version itself. Gradle or Maven — both are here, moving
in opposite directions. Nothing in your source changes. What changes is what resolves.

Until this release both starters declared Spring Boot's BOM on `api`, so it was published — as an
imported BOM in the POM and as a dependency in the Gradle module metadata. For a Gradle consumer
that made Spring Boot's entire version manifest a live input to their own resolution, and Gradle
takes the higher of two requirements: a build that said Spring Boot 4.0.0 throughout resolved
`spring-boot` 4.1.1, `spring-core` 7.0.9, `jackson-databind` 3.1.5 and `micrometer` 1.17.1 —
because it had added a Web Push starter. Nothing warned about it.

The starters now publish one Spring Boot dependency, `spring-boot-autoconfigure`, at the minimum
version they support; the number is in
[`README.md` → Requirements](../README.md#requirements) and what it does and does not enforce is in
[`SPRING.md` → The minimum Spring Boot](SPRING.md#the-minimum-spring-boot). Everything the BOM used
to manage that the starters do not themselves depend on — Jackson, Netty, Tomcat, the rest of the
manifest — is no longer spoken about at all. What the starters still bring is that one dependency's
own transitives: `spring-boot`, `spring-core`, `spring-context`, `spring-beans`, `spring-aop`,
`spring-expression`, `commons-logging` and Micrometer's `micrometer-observation` and
`micrometer-commons`. A Gradle build below the minimum is raised on those and one at or above it
keeps its own; a Maven build that manages no Spring Boot of its own simply receives them at the
minimum, which is the paragraph after next.

**Who sees nothing here.** An application that manages Spring Boot itself — a Maven build on
`spring-boot-starter-parent` or importing Boot's BOM, or a Gradle build applying
`io.spring.dependency-management` — was never on the receiving end of this. Its own management
outranks a version reached through a dependency, in both the old shape and the new one. Read on
only for the floor: you are asked for a minimum Spring Boot that your build does not enforce and
this library cannot make it.

**Maven builds that do *not* manage Spring Boot themselves were affected, and in the opposite
direction.** A `dependencyManagement` section reached through a dependency supplies versions to
*that dependency's* own dependencies — and the starters' own `spring-boot-autoconfigure` was
declared with no version, resolved by the BOM they imported. So an application that simply added a
starter got Boot at whatever version this project built against. Measured, resolving both published
shapes with Maven: the old one handed such a consumer `spring-boot-autoconfigure` 4.1.1, the new one
hands it 4.0.8. That is a **downgrade across a minor line** — the direction that surfaces at run
time rather than at compile time. What it is *not* is push2u letting go of the decision: a POM
carries no minimum, so the starter's declaration is simply the version, and taking that decision
back means managing Spring Boot yourself. The next section says how, ecosystem by ecosystem.

#### Which Spring Boot you end up with, before and after

Here is the half no compiler reports on its own, and the two ecosystems do not move together. What
changed for **everyone** is the version push2u names. What changed only for a **Gradle** build is
whether your own declaration wins.

**Gradle, declaring a Spring Boot of your own.** This is the case the change is for. Your
declaration used to lose — the exported BOM entered a higher requirement and Gradle took it — and
now it wins outright as long as it is at or above the minimum. push2u genuinely stops choosing your
Spring Boot.

**Gradle, declaring no Spring Boot of your own.** push2u still supplies one, as it did before: the
starter's `spring-boot-autoconfigure` requirement is the only requirement in play. It is a lower
number now, that is all.

**Maven, without `spring-boot-starter-parent` and without Boot's BOM imported.** *push2u still
decides your Spring Boot version, before and after.* The old shape decided it through the BOM the
starters imported, which resolved their own versionless `spring-boot-autoconfigure`; the new shape
decides it by declaring `spring-boot-autoconfigure:4.0.8` outright. Nothing about that is a floor —
a POM cannot express one — so it is a version handed to you rather than a minimum you may exceed,
and your Spring Boot moves from whatever this project last built against down to the published
minimum unless you say otherwise.

Saying otherwise is ordinary Maven, and there are two ways of different quality. A **direct**
dependency on `spring-boot-autoconfigure` in your own POM sits nearer the root than the starter's
transitive one and wins by nearest-definition — one coordinate, one version, and it does work. What
it does not do is govern the rest: `spring-boot`, `spring-core`, `spring-context` and the others
still arrive at whatever the winning `spring-boot-autoconfigure` drags, and you are pinning one
artifact of a set that is meant to move together. **The way to own the decision rather than one
coordinate of it is to manage Spring Boot yourself** — `spring-boot-starter-parent` as your parent,
or Boot's BOM imported into your `dependencyManagement`. Then every Boot and Spring version in your
graph is yours, push2u's number stops mattering, and this release is a good moment to do it.

Two things follow from a version that moved, and only the first is loud:

- **Your own code may have used an API from the version you were being given.** It is gone with
  it. Where your module recompiles, this is a compile error and the cheap kind. Where it does not —
  a module you did not rebuild, a jar you assemble separately — it is a `NoSuchMethodError` or a
  `NoClassDefFoundError` the first time that line runs. This is the shape a *downgrade* takes, and
  both the Maven cohort above and a Gradle build that was declaring less than it was being given
  are in it.
- **A Gradle build's graph also moves outside Spring's coordinates — a Maven build's does not.**
  The BOM managed the whole Spring Boot manifest and only a Gradle consumer ever received it, so
  Jackson, Netty, Tomcat and the rest were being raised there and now stop moving entirely. Values
  can also *drop* with no Spring coordinate changing: `commons-logging` resolves 1.3.5 through the
  floor's own graph where the exported BOM raised it to 1.3.6. A Maven consumer sees none of this;
  what moves for them is `spring-boot-autoconfigure` and what it drags transitively —
  `spring-boot`, `spring-core`, `spring-context`, `spring-beans`, `spring-aop`, `spring-expression`,
  `commons-logging` and Micrometer's two — all together, to the minimum.

So the check is a resolution diff rather than a rebuild: resolve once before the upgrade and once
after — `./gradlew :your-app:dependencies --configuration runtimeClasspath`, or
`mvn dependency:tree` — and read what moved. If a version dropped, decide where you want it and say
so in your own build: a declaration in Gradle, your own Boot parent or imported BOM in Maven. That
is the point of the exercise; there is nothing to do here beyond it.

One direction can still raise you, in Gradle and under ordinary conflict resolution: a build asking
for a Spring Boot **below** the declared minimum is raised to that minimum, the same way any
dependency's requirement raises another. A build that *forces* versions is not raised — nor is
Maven, where the number is a plain version and your own `dependencyManagement` settles it. Either
way that bound is far lower than the version you were previously being pulled to.

### What the `0.2.0` move does not change

Nothing about the decision moved — only the shape of its answer. Specifically:

- **Where the policy is applied.** Before encrypting, before signing and before any network I/O on
  every send, and at a registration boundary if your application applies it there. The send-time
  assessment is not replaced by the registration one: the policy is configuration and can change
  after a row was stored.
- **Who owns the rule.** The deployment, as before. A policy is still a required argument of both
  `PushSender.builder` overloads, and `EndpointPolicies.allowedEndpoints`, `allowedOrigins`,
  `allowedDomains` and `unrestricted()` keep their names and their signatures.
- **How a refusal is classified once `send` holds it.** `PushOutcome.EndpointRejected`, carrying the
  same two strings — this library's own redaction of the endpoint, and the policy's reason — still a
  `NotAttempted`, still meaning that no POST was made. **A caller that only calls `send` or
  `sendAsync` and switches on the outcome has nothing to change in this release.**
- **What the standard allowlist says when it refuses**, word for word: an endpoint carrying
  userinfo, an endpoint with no scheme or host, and an endpoint no origin or domain rule matches.
  Which rule came closest is still deliberately not reported.
- **Spring.** `push2u.allowed-origins` and `push2u.allowed-domains`, their union, the
  `EndpointPolicy` bean and an application-supplied bean superseding it, the exclusivity between the
  properties and the bean, the startup refusals that guard them, and the continued absence of a
  property for the unrestricted mode. A Spring deployment that never names `EndpointPolicy` in its
  own source has nothing to do for this release.

### Checklist for the `0.2.0` move

- [ ] Rebuild. If your own code implements or calls the policy and nothing failed to compile, stop
      and find the other `EndpointPolicy` on your classpath before going further.
- [ ] Change every policy you implement — lambda and class alike — to return `EndpointAssessment`,
      with a `Refused` on every path that used to throw and an `Allowed` on every path that used to
      fall off the end.
- [ ] Replace every `validate(...)` call with `assess(...)`, and read the answer at each one.
- [ ] Delete every `catch (EndpointRejectedException ...)`, and answer the client from the `Refused`
      branch instead.
- [ ] If a policy of yours threw a subtype of that exception to carry structure, keep the structure
      in your own code beside the assessment.
- [ ] Grep for `assess(` and confirm no hit is a bare statement, at a registration boundary above
      all.
- [ ] If you maintain a `VapidSigner` of your own, rerun its suite against the upgraded kit. The
      contract signs from several threads now, and a failure there is a defect that was already
      corrupting signatures under load rather than a new rule to satisfy.
- [ ] **Gradle**, if you use either Spring Boot starter and do not apply
      `io.spring.dependency-management`: diff your resolved runtime classpath before and after.
      Jackson, Netty, Tomcat and the rest of Boot's manifest stop being managed by the starters
      altogether, and Spring's own coordinates now follow your declaration where you have one — so
      a version you were relying on can drop. Declare it yourself if you want it back.
- [ ] **Maven**, if you use either Spring Boot starter and are not on `spring-boot-starter-parent`
      and do not import Boot's BOM: your Spring Boot moves *down* to the published minimum, and
      push2u still decides it — a POM has no way to express a floor. `mvn dependency:tree` before
      and after shows the move. To take the decision back for the whole Boot graph rather than one
      coordinate of it, add the Boot parent or import its BOM; a direct dependency on
      `spring-boot-autoconfigure` also outranks the starter's transitive one, and leaves the rest
      of Spring following it.

## From `0.1.0`

`0.1.0` is where this upgrade starts. It is the version this section is written against, and the
one it names throughout; the release it lands in is deliberately unnamed, for the reason above.

This release is the largest break the library has taken, and by design: `0.1.0`'s own release note
declared `0.x` the window in which names and constructor shapes are revised once real integrations
exist. Most of what landed stops your code compiling, which is the cheap kind. Some of it does not,
and that has a chapter of its own.

- [Do these first when coming from `0.1.0`](#do-these-first-when-coming-from-010)
- [What stops compiling on the way from `0.1.0`](#what-stops-compiling-on-the-way-from-010)
  - [`PushResult` is now `PushOutcome`](#pushresult-is-now-pushoutcome)
  - [Retry left the library](#retry-left-the-library)
  - [`recordSize` left the builder](#recordsize-left-the-builder)
  - [`PayloadSizeAssessment`, `EndpointRule` and the other new types](#payloadsizeassessment-endpointrule-and-the-other-new-types)
- [What changes without a compiler error, coming from `0.1.0`](#what-changes-without-a-compiler-error-coming-from-010)
  - [`PushCryptoException` narrows, and three `catch` clauses stop catching](#pushcryptoexception-narrows-and-three-catch-clauses-stop-catching)
  - [If you wrote your own `VapidSigner`: an outage changes type](#if-you-wrote-your-own-vapidsigner-an-outage-changes-type)
  - [An eager Vault `build()` raises a different type when Vault is down](#an-eager-vault-build-raises-a-different-type-when-vault-is-down)
  - [`Subscription` now bounds the endpoint's length](#subscription-now-bounds-the-endpoints-length)
  - [VAPID tokens are reused by default](#vapid-tokens-are-reused-by-default)
- [Spring Boot, coming from `0.1.0`](#spring-boot-coming-from-010)
  - [The `push2u.*` keys that `0.1.0` had and this release refuses](#the-push2u-keys-that-010-had-and-this-release-refuses)
  - [`push2u.enabled`: a context that boots without web push now fails](#push2uenabled-a-context-that-boots-without-web-push-now-fails)
  - [The health probe moved under `management.health.push2u`](#the-health-probe-moved-under-managementhealthpush2u)
  - [The endpoint policy is a bean, and its refusals moved](#the-endpoint-policy-is-a-bean-and-its-refusals-moved)
  - [`Push2uProperties` and `VaultSignerProperties` changed shape](#push2uproperties-and-vaultsignerproperties-changed-shape)
  - [Vault: a third construction mode](#vault-a-third-construction-mode)
- [Checklist for the `0.1.0` move](#checklist-for-the-010-move)

### Do these first when coming from `0.1.0`

Five steps, in this order, before you read the rest:

1. **Rebuild against the new version and read every compiler error.** They are the map: `PushResult`,
   `RetryPolicy`, `Sleeper` and `recordSize(int)` are gone, so nothing that used them survives the
   compilation. Fixing them is most of the work.
2. **Grep your own sources for `catch (PushCryptoException`, `catch (PushDeliveryException` and
   `catch (EndpointRejectedException`.** Each of those still compiles and each now catches strictly
   less than it did — two of them catch nothing at all from a send. See
   [`PushCryptoException` narrows](#pushcryptoexception-narrows-and-three-catch-clauses-stop-catching).
3. **If you implement `VapidSigner` yourself** — over an HSM, a KMS, or any remote custodian — read
   [an outage changes type](#if-you-wrote-your-own-vapidsigner-an-outage-changes-type) before
   anything else. That implementation keeps compiling and its outages change meaning, and the
   conformance kit does not catch it.
4. **If you build `VaultTransitVapidSigner` by hand** — outside the Vault starter — the same
   narrowing reaches the `build()` that reads Vault, and a `catch` written to retry a sealed Vault
   at startup stops catching one:
   [an eager Vault `build()`](#an-eager-vault-build-raises-a-different-type-when-vault-is-down).
5. **If you run the Spring starters, do not upgrade the jar without recompiling and re-reading your
   YAML.** Six `push2u.*` keys now fail the context at startup rather than being ignored, the health
   probe answers to different keys, and a deployment that quietly holds no signer now refuses to
   start. All of it is in [Spring Boot](#spring-boot-coming-from-010).

### What stops compiling on the way from `0.1.0`

#### `PushResult` is now `PushOutcome`

`send` and `sendAsync` used to answer `PushResult` — a record of a `Status` enum, a status code and
an attempt count. They now answer `PushOutcome`, a sealed hierarchy. The type is not a rename: the
enum sorted three cases and the hierarchy sorts eight, because the old shape had no way to report a
send that never happened, and no way to say whether a repeat would be safe or merely useful.

The mapping from the old `Status` values, with what the old shape could not express:

| `PushResult` in `0.1.0` | `PushOutcome` now |
|---|---|
| `Status.DELIVERED` (a `2xx`) | `Accepted(statusCode)` — accepted for delivery, which is not a receipt |
| `Status.SUBSCRIPTION_EXPIRED` (`404`/`410`) | `SubscriptionExpired(statusCode)` — unchanged in meaning: delete the row |
| `Status.FAILED`, where the service answered about its own moment | `RetryableFailure(statusCode, retryAfter)` |
| `Status.FAILED`, where the service answered about the request | `NonRetryableFailure(statusCode)` |
| a thrown `PushDeliveryException` — the POST went out unanswered | `Indeterminate`, carrying the transport's `cause()` |
| a thrown `EndpointRejectedException` | `EndpointRejected(redactedEndpoint, reason)` |
| a thrown `IllegalArgumentException` over an oversized payload | `PayloadRejected(payloadBytes, maximumPayloadBytes)` |
| a thrown `PushCryptoException`, where the custodian was merely down | `SignerUnavailable`, carrying the custodian's `status()` and `retryAfter()` |

The last four rows are the ones to read twice: each was an *exception* in `0.1.0` and is a *value*
now. That is the whole of the change
[`PushCryptoException` narrows](#pushcryptoexception-narrows-and-three-catch-clauses-stop-catching)
describes, seen from the other side.

The three `NotAttempted` leaves — `SignerUnavailable`, `PayloadRejected`, `EndpointRejected` —
implement a shared marker interface, so one `switch` picks its own grain:
`case PushOutcome.NotAttempted n` takes all three at once where the only thing your code needs to
know is that no POST was made and no repeat can duplicate anything.

Two accessors have no replacement, deliberately:

- **`isDelivered()`** described a `2xx` as a delivery. RFC 8030 §5 has the push service answer that
  it accepted the message for delivery, which is why the variant is `Accepted` and not `Delivered`.
  A `switch` on the sealed type replaces the predicate.
- **`attempts()`** counted POSTs inside one `send`. There is exactly one now, always, so the number
  had nothing left to say — and the count that does matter is the one your own retrier keeps.

`isSubscriptionExpired()` maps to `case PushOutcome.SubscriptionExpired`, and means what it always
meant.

Because the hierarchy is sealed, a `switch` over it needs no `default`, and a variant added in a
later release fails your compilation instead of falling into a branch written for something else.
Take the exhaustive `switch` rather than a chain of `instanceof` with a fallback: the fallback is
precisely what forfeits that warning.

#### Retry left the library

`RetryPolicy`, `Sleeper` and `PushSender.Builder.retryPolicy(...)` are removed, and nothing replaces
them. **`send` performs exactly one POST.** There is no configuration that restores the loop, and
there deliberately is no retrying wrapper shipped from this repository either.

This is the largest change in the release, and it is a transfer of work rather than a removal of it.
A `0.1.0` sender built with the default policy made up to three POSTs, sleeping one second before
the first retry and doubling to a ceiling of sixty. If you configured nothing, you had that; after
the upgrade the same code makes one POST and hands you back a classification.

What the library kept is the part it can decide correctly: which statuses mean the service answered
about its own moment (`RetryableFailure`) and which mean it answered about the request
(`NonRetryableFailure`), and whatever `Retry-After` arrived, parsed and **reported with no ceiling
applied**. What it gave up is the schedule, because a loop inside `send` can see none of what your
retrier knows — the budget, the dead-letter path, what survives a restart, whether a duplicate
notification costs anything.

A caller that relied on the built-in retry looked like this:

```java
PushSender sender = PushSender.builder(keys, "mailto:ops@example.com", pushServices)
    .retryPolicy(new RetryPolicy(3, Duration.ofSeconds(1), Duration.ofSeconds(60)))
    .build();

PushResult result = sender.send(subscription, message);
if (result.isSubscriptionExpired()) {
    subscriptionStore.delete(subscription);
} else if (!result.isDelivered()) {
    log.warn("push failed after {} attempts: HTTP {}", result.attempts(), result.statusCode());
}
```

and now looks like this — the sender loses a builder step, and the call site gains the decision the
sleeping loop used to make on its behalf:

```java
PushSender sender = PushSender.builder(keys, "mailto:ops@example.com", pushServices).build();

switch (sender.send(subscription, message)) {
    case PushOutcome.Accepted a -> log.debug("accepted: HTTP {}", a.statusCode());
    case PushOutcome.SubscriptionExpired e -> subscriptionStore.delete(subscription);
    case PushOutcome.RetryableFailure f ->
        // The service answered about its own moment, so a repeat may be *useful*. Whether it is
        // *safe* is yours to price: this POST may have been applied. f.retryAfter() is the
        // service's own floor where it named one, and it arrives with no ceiling but yours.
        retrier.scheduleIfAllowed(subscription, message, f.retryAfter().orElse(backoff.next()));
    case PushOutcome.NonRetryableFailure f -> log.warn("refused: HTTP {}", f.statusCode());
    case PushOutcome.SignerUnavailable s ->
        // Nothing was signed and nothing was sent, so a repeat duplicates nothing — but stop
        // submitting: every further row makes its own round trip to a custodian that is down.
        pauseFanOut(s.retryAfter());
    case PushOutcome.PayloadRejected p ->
        log.warn("payload {} bytes, this sender carries {}", p.payloadBytes(), p.maximumPayloadBytes());
    case PushOutcome.EndpointRejected r ->
        log.warn("endpoint refused by policy: {} — {}", r.redactedEndpoint(), r.reason());
    case PushOutcome.Indeterminate i ->
        // The POST went out and nothing answered. Repeating may duplicate, not repeating may lose;
        // only the application can price that.
        retrier.scheduleIfADuplicateIsAcceptable(subscription, message);
}
```

Four rules the removed loop never applied, and a scheduler now has to:

- **A repeat re-bases the message's lifetime.** RFC 8030 §5.2 counts `TTL` from the moment the push
  service receives the message, so an attempt scheduled hours later carries a fresh lifetime unless
  you decrement the `TTL` you pass by the time already spent. The in-process loop retried within
  seconds and never had to care.
- **`RetryableFailure` says a repeat may be useful, never that it is safe.** A push POST is not
  idempotent, and the old loop repeated regardless.
- **`Indeterminate` is not a failure.** The old code reported an unanswered POST by throwing
  `PushDeliveryException`; a repeat there is a duplicate notification weighed against a lost one,
  which is exactly the pricing the library refuses to do on your behalf.
- **A `507` is the one status whose own specification restricts the repeat.** RFC 4918 §11.5 has a
  refused request that came from a user action not repeated until a separate user action asks again
  — a condition on what produced the send, which no scheduler can see and only the application can.

If your deployment already runs sends through a job engine, a queue with redelivery or a resilience
library, this is a subtraction: delete the `retryPolicy(...)` line, drop the double retry you were
probably running, and branch on the outcome. If it does not, this release is where you write the
loop, and [README's send reference](../README.md#what-a-send-reports-and-what-it-still-throws) is
the status matrix to write it against.

#### `recordSize` left the builder

`PushSender.Builder.recordSize(int)` is removed. The `aes128gcm` record size (RFC 8188 `rs`) is now
**derived** from `maxEncryptedBodyBytes`, which is the one size knob left. There were two, they
constrained the same thing from opposite ends, and a deployment could set them into disagreement and
find out one payload at a time.

Delete the call. If you raised `recordSize` in order to carry larger payloads, raise
`maxEncryptedBodyBytes` instead and the derived record size follows it; if you lowered it, there is
nothing to do, because the record-size rule can no longer be the bound that refuses a send.

The plaintext a sender carries is `maxEncryptedBodyBytes` less the fixed **103** octets of
`aes128gcm` framing — 3993 octets at the default ceiling of 4096, which is the figure RFC 8291 §4
derives. That is the number `PayloadRejected.maximumPayloadBytes()` reports, and the number
`assessPayloadSize` compares against.

#### `PayloadSizeAssessment`, `EndpointRule` and the other new types

None of these break anything; they are what the sections above hand the work to.

- **`PushSender.assessPayloadSize(byte[])`** answers the size question *before* a send, returning
  `PayloadSizeAssessment.WithinLimit` or `ExceedsLimit(payloadBytes, maximumPayloadBytes)`. Useful
  where a notification is rendered and can still be shortened. `send` runs its own check regardless
  and never trusts an earlier assessment.
- **`PushInterruptedException`** — what `send` throws when the sending thread is interrupted, with
  the interrupt status re-set before the throw. On `sendAsync` the future completes exceptionally
  with it and is **not** cancelled: `isCancelled()` answers `false`.
- **`VapidSignerUnavailableException`** — the type a signer raises for a custodian that cannot sign
  *now*. See the two signer sections below.
- **`EndpointRule`, `EndpointPolicies.allowedDomains(...)` and `EndpointPolicies.allowedEndpoints(...)`**
  — a domain rule covers a zone's apex and every subdomain at a label boundary, `https` and the
  default port only. `allowedEndpoints` takes a mixed list of origin and domain rules and is the
  ordinary cross-browser call; `allowedOrigins` is unchanged and still matches one origin exactly.
  Two of the four browser push services publish a zone rather than a fixed set of origins, so an
  allowlist written in `0.1.0` against `allowedOrigins` alone may be narrower than the services it
  names — [`PUSH-SERVICES.md`](PUSH-SERVICES.md) is the per-service list.
- **`VapidKeys.encodePublicKey(byte[])`** and the `VapidSigner.publicKeyBase64Url()` default method,
  which is what lets a custodian holding a pre-encoded key advertise it without a round trip through
  bytes.

### What changes without a compiler error, coming from `0.1.0`

This chapter is the reason this document exists. Nothing in your build fails; the behaviour under it
moves. Two of the five below are a narrowed exception type reaching code that still catches the old
one, and they are one seam apart: the first is what `send` no longer throws, the second what a
hand-wired Vault signer's `build()` throws instead.

#### `PushCryptoException` narrows, and three `catch` clauses stop catching

`send`'s failure surface was re-sorted: an operational condition is now a **value**, and only a
defect or a condition that recurs is an **exception**. Three `catch` clauses survive that unchanged
and mean less than they did.

| The clause | What it caught in `0.1.0` | What it catches now |
|---|---|---|
| `catch (PushCryptoException e)` | a cryptographic defect, an unusable provider, **and a remote key service that was unreachable, timed out or refused** | only the first two, plus a custodian misconfiguration that recurs. **A custodian that is merely down no longer arrives here** — it is the `SignerUnavailable` outcome |
| `catch (PushDeliveryException e)` | a POST that went out and was never answered | **nothing from `send`.** That condition is the `Indeterminate` outcome now; the type still exists as the transport seam's own signal |
| `catch (EndpointRejectedException e)` | the endpoint policy refusing this subscription's endpoint | **nothing from `send`.** It is the `EndpointRejected` outcome. The type still exists and is still what `EndpointPolicy.validate` throws, which is what lets you apply the same policy where you accept subscriptions |

The first row is the one that bites. `PushCryptoException` kept its name through the narrowing — the
name is still true of everything it retains — so there is no rename to trip over and no warning
anywhere. A `catch` block that logged "key service unavailable, will retry" now logs nothing,
because the condition arrives as a value your `switch` may have no branch for. The
[`PushOutcome` table above](#pushresult-is-now-pushoutcome) is the mapping; the exhaustive `switch`
is what makes the compiler point at each site.

One more clause changes without being about a library type: `send` used to throw
`IllegalArgumentException` for a payload that did not fit. It returns `PayloadRejected` now. If you
were catching that — and some callers were, since it was how an oversized notification announced
itself — the clause still compiles and now catches only genuinely illegal arguments.

What still leaves `send` as an exception: `PushCryptoException` for a reason that recurs,
`PushInterruptedException` for an interrupt, and `IllegalArgumentException` / `NullPointerException`
for an argument that is not a legal value. **And exactly three seam signals convert to outcomes and
no others** — `EndpointRejectedException`, `VapidSignerUnavailableException`,
`PushDeliveryException`. Any other `RuntimeException` out of a seam you wrote is read as a defect in
that implementation and propagates unchanged.

#### If you wrote your own `VapidSigner`: an outage changes type

**Read this even if nothing in your build broke — especially then.** If your VAPID key lives in an
HSM, a KMS or any remote custodian, you implemented `VapidSigner` against a contract that changed
underneath the same method signatures.

`0.1.0`'s contract told an implementation to raise `PushCryptoException` when its key service was
unreachable, timed out or refused the operation. That sentence is gone. An outage is now
`VapidSignerUnavailableException`, and it is the only thing that becomes the `SignerUnavailable`
outcome.

So a signer written against the old sentence:

- **compiles unchanged** — same interface, same two abstract methods, nothing added that an
  implementation must supply;
- **passes the conformance kit unchanged** — `VapidSignerContractTest` asserts no exception types,
  on purpose, so it cannot catch this;
- **turns every outage into a permanent defect.** The custodian goes down, the signer raises
  `PushCryptoException` as it always did, and `send` propagates it as a condition that recurs —
  because the facade will not sniff a cause chain to guess otherwise. A fan-out stops with a defect
  where it should have paused and resumed.

The fix is one type at one throw site: raise `VapidSignerUnavailableException` where the failure is
a *state of the custodian* that ends on its own terms — unreachable, sealed, not yet initialized,
still catching up, rate-limited — and carry the status where it answered a number and the delay
where it declared one. Keep `PushCryptoException` for what waiting cannot clear: a wrong key type, a
missing mount, a token without the capability.

[`SIGNER.md`](SIGNER.md) is the reference for the whole contract — the two shape checks every
signature and key pass, the split above stated in full, why the advertised key may never change for
a signer's lifetime, and what the conformance kit holds an implementation to. Do not re-derive it
from this page.

Three smaller things, and the first two are worth keeping apart, because only one of them is
something an implementation *does*.

**What the implementation gains:** `publicKeyBase64Url()` has a `default` implementation, so
overriding it is worth it only for a custodian holding a pre-encoded key.

**What the implementation owes, on an interruption:** not the sorting. An implementation is never
asked to tell an interrupted exchange apart from any other exchange that produced no answer — both
raise `VapidSignerUnavailableException`. What it owes is what any code catching an
`InterruptedException` owes: re-set the interrupt status on its own thread, and keep that exception
in the cause chain of what it raises. The *caller* is what tests for the interruption before it
reads the exception's type — `PushSender.send` does it on every send, and a startup supervisor
around a signer that reads its key in `build()` must do it there — and an interruption swallowed
without the flag is the one defect that leaves that test unable to see a cancellation at all.

**And if you wrote your own `VaultHttpTransport`** — the Vault module's transport seam, not
`PushHttpClient` — `VaultHttpResponse` gained a third component, `retryAfter`, while keeping its
two-argument constructor. Your transport therefore compiles and works exactly as before, and never
fills the hint: `PushOutcome.SignerUnavailable.retryAfter()` is permanently empty for that
deployment, because the header stops at the transport unless the transport hands it on. Read
`Retry-After` and pass it to the three-argument constructor if the deployment schedules anything on
that value. The same record also prints differently now: `toString()` describes the body — its
length — instead of reproducing it, so a transport that logged the response object whole logs a
description of the answer from this version on, and a log parser reading the body out of that line
stops finding it.

#### An eager Vault `build()` raises a different type when Vault is down

The same narrowing, met outside a send, by a deployment that wires `VaultTransitVapidSigner` by hand
rather than through the starter. In `0.1.0`, `builderWithFetchedPublicKey(...).build()` documented
exactly one failure type for the Vault read it performs: `PushCryptoException`, "if the key read
fails or the key is not a usable P-256 key". A
sealed Vault, a refused connection and a token without the capability all arrived as that one type,
which is why the natural thing to write around it was one `catch` that scheduled a retry:

```java
try {
    signer = VaultTransitVapidSigner.builderWithFetchedPublicKey(address, keyName, token).build();
} catch (PushCryptoException e) {
    scheduleAnotherAttempt(e);           // in 0.1.0 this caught a sealed Vault
}
```

That `catch` compiles unchanged and no longer catches the case it was written for. A Vault that
cannot serve the read *now* — unreachable, sealed, not initialized, standing by, not caught up,
rate-limited — is `VapidSignerUnavailableException`, and `PushCryptoException` is left with the
half that recurs until a person changes something: a token without the capability, a mount or key
that is not there, a key that is not on P-256, an answer Vault could not have meant. The block above
now lets a sealed Vault through, and the process dies at startup where it used to wait and try
again.

**Nothing converts it for you here, because no send is involved.** The three seam-signal conversions
in the [chapter's first section](#pushcryptoexception-narrows-and-three-catch-clauses-stop-catching)
happen inside `PushSender.send`; a `build()` is outside the sender entirely, so what it raises is
what your code catches. The same holds for a direct `publicKey()` or `publicKeyBase64Url()` call —
the ordinary way an application publishes its `applicationServerKey` to a frontend. On an eager
signer that call answers from what `build()` already read and raises nothing, which is why the
`catch` above is the whole of the exposure today; adopt the deferred mode below and it becomes the
call that performs the read, with the same two types and the same order to test them in.

Catch both, and in the order the contract fixes: the interruption first (the thread's interrupt
status set, *or* an `InterruptedException` in the cause chain), then
`VapidSignerUnavailableException` as a boot worth retrying with backoff and not before any moment
its `retryAfter()` names, then `PushCryptoException` as a deployment to fail and a person to fetch.
[`VAULT.md` → What the signer throws](VAULT.md#what-the-signer-throws) is the reference, with the
Vault status codes that decide which of the two a response becomes.

#### `Subscription` now bounds the endpoint's length

`Subscription` refuses an endpoint longer than **2048 characters**, with an
`IllegalArgumentException` naming the limit and the actual length — and not the endpoint, not even
redacted, because the redaction's origin half carries the host, which is the very part of an
oversized endpoint that is oversized. Every construction path runs the canonical constructor,
`fromBase64` included, so nothing evades it.

**This one appears in no generated release note.** It reached this release through a branch that
merged into a feature branch rather than into `main`, so the notes built from pull requests do not
list it. This paragraph is where it is written down.

Why it matters on an upgrade: a stored subscription is data your application already holds, and the
check runs when you rebuild the `Subscription` from that row — not when the row was written. If your
registration endpoint accepted whatever a client offered, a row above the bound now throws at
construction, in the fan-out, where `0.1.0` would have sent to it. The bound is structural rather
than a vendor's number: RFC 1035 §2.3.4 caps a domain name at 255 octets, 253 as a presentation-form
hostname, so beyond the longest resolvable host only the capability path and query legitimately
vary, and a capability needs only enough characters to be unguessable — 43 base64url characters for
a 256-bit token. That leaves roughly 1780 characters of headroom, two orders of magnitude above what
a capability needs. No claim is made about any named push service's endpoint lengths; no vendor
documents one.

If you would rather know before the upgrade than during it, run one query against your subscription
store for rows whose endpoint exceeds 2048 characters. A row that fails it was expensive already:
the endpoint's origin is embedded in the `Authorization` header of every POST, so an oversized one
was being paid for on every send.

#### VAPID tokens are reused by default

A signed VAPID token is now held per push-service origin and reused for later sends to that origin
until it nears its `exp` — `jwtReuse` defaults to `true`, with a 5-minute renewal margin
(`jwtRenewBefore`) and a bound of 64 entries (`jwtCacheSize`), evicting least-recently-used. In
`0.1.0` every send built and signed its own token.

Nothing about a token is per-message — its claims are the origin, the contact and the expiry — and
RFC 8292 §5 encourages application servers to reuse them. Two consequences are worth knowing before
meeting them:

- **A remote signer signs far less often.** For a Vault- or KMS-backed key that is the point: one
  signature per origin per token lifetime instead of one per notification. It also changes the shape
  of that custodian's audit log, its quota and its bill.
- **A misconfigured signer surfaces later.** A signer whose *signing* key rotates under an unchanged
  *advertised* key produced a bad header on the very next send in `0.1.0`; now it can take up to
  `jwtExpiry` to show. `jwtReuse(false)` — or `push2u.jwt-reuse: false` — restores the old behaviour
  exactly, and is also the remedy if a push service ever refuses a token it has seen before (the
  shape of that failure: `401` or `403` on every send to an origin after the first, with a signature
  that verifies).

A deployment that treats process memory as reachable should also know that a cached entry is a
bearer credential resident in the heap, and that nothing sweeps the cache — an entry leaves it when
a later send to that origin finds it stale, or when the bound evicts it.

### Spring Boot, coming from `0.1.0`

Everything above applies to a Spring deployment too; this section is what the starters add on top of
it. [`SPRING.md`](SPRING.md) is the reference for every property as it stands now, and
[`HEALTH.md`](HEALTH.md) for the probe.

#### The `push2u.*` keys that `0.1.0` had and this release refuses

Six keys are gone, and none of them is ignored. Each fails the context at startup with a message
naming the key, saying it configures nothing now, and saying what to write instead — because a
removed key left in a YAML file is a setting the operator believes is in force, and every one of
these costs in the same direction if it is merely dropped.

| The key | What it did | What to write instead |
|---|---|---|
| `push2u.record-size` | the `aes128gcm` record size | nothing — raise `push2u.max-encrypted-body-bytes` if the point was larger payloads |
| `push2u.retry.max-attempts` | POSTs per send, including the first | nothing: a send performs exactly one POST, and whether to repeat it is the caller's |
| `push2u.retry.initial-backoff` | the wait before the first retry | nothing: with no second attempt there is no wait to configure. What a repeat should wait for comes from the service's own `Retry-After` on a `RetryableFailure` |
| `push2u.retry.max-backoff` | the ceiling on that wait, and on an honoured `Retry-After` | nothing here — but note that the `Retry-After` an outcome carries is reported exactly as the push service sent it, **with no ceiling applied**, so a bound is now applied where the repeat is scheduled |
| `push2u.health.enabled` | whether the health indicator is registered | `management.health.push2u.enabled` |
| `push2u.health.cache-ttl` | how long a probe result is cached | `management.health.push2u.cache-ttl`, same value, same meaning |

The three retry keys are the ones whose silent removal would have changed *delivery* rather than a
diagnostic: a deployment that configured three attempts would have started clean and then sent once
per message, with nothing at startup or at run time saying so, and the messages a push service
dropped under load simply gone. That is why they refuse the context rather than being ignored.

These refusals are **tombstones**, not permanent validation: each is carried for one minor release
after the release that removed its key, and then deleted. They exist to catch configuration written
against the previous release, not to accumulate for the life of the library — which is another way
of saying that skipping this step now and returning to it two releases later is a state nothing will
warn you about.

#### `push2u.enabled`: a context that boots without web push now fails

`push2u.enabled` is the statement a deployment makes about whether it sends. It defaults to `true`
and takes only `true` or `false` — an unrecognised value, blank included, fails the context naming
the key, because this is the one key where a typo would otherwise be free to mean the opposite of
what was typed.

**The upgrade consequence: a context that is on while holding neither a `VapidSigner` nor a
`PushSender` bean now fails at startup.** In `0.1.0` that context started, sent nothing, and said
nothing about it — which is exactly the state the refusal exists to make impossible. If your
application carries the starter on its classpath without configuring a signer, this is where the
upgrade stops.

Two answers, and which one is yours depends on the truth:

```yaml
push2u:
  enabled: false          # this deployment deliberately sends nothing
```

or configure a signer — this starter's `push2u.vapid.*` keys, a signer starter's own configuration,
or an application bean of either type. The refusal's own message names every route.

`false` withdraws the signer, the transport, the sender and the health indicator, plus every signer
starter and its diagnostic. It does **not** reach the endpoint policy: a service that accepts
subscriptions and leaves the sending to another one keeps the policy its allowlist states, and every
startup refusal guarding those properties keeps running. That deployment is the reason the switch
stops where it does.

**And there is a second half to `push2u.enabled: false` which the line itself does not tell you.**
Withdrawing the indicator is not the same as rewriting your health groups. Spring Boot validates the
membership of every health group declared in properties — on the `exclude` side as well as the
`include` side — and refuses a context that names a contributor which does not exist:

```
Health contributor 'push2u' defined in 'management.endpoint.health.group.container.exclude' does not exist
```

A deployment that keeps the `push2u` probe out of its container health check has exactly such a
group, and that is the common case rather than an exotic one. So `push2u.enabled: false` — typed in
the middle of a failed start, in a change nobody planned — buys a second failed start seconds later,
this time with the framework's message and nothing in it pointing back at what was just edited.
**Edit the group in the same change.** The edit is the right one on its own terms: the exclusion was
there to keep a signer probe out of the check, and there is no probe left to keep out.

That assumes one party owns both the properties and the group, and an application *distributing*
push2u inside an image is where it stops being true. A health group shipped in an image is a build
artifact; the deployment that states `push2u.enabled: false` has properties and environment
variables and no way to edit it. So the rule for anyone shipping a group is the stronger one: **do
not name `push2u` in a group you distribute** — that is a claim someone else will be refused for, in
a message naming neither of you. A deployment already holding such an image is often not stuck,
since the group's key can be overridden from the environment like any other and an explicitly empty
value clears the list (`MANAGEMENT_ENDPOINT_HEALTH_GROUP_CONTAINER_EXCLUDE=`) — often, because that
spelling reaches only a single-word group name. It is a repair, and the deployment did not choose
its conditions.

[`HEALTH.md` → Keeping the probe out of a container health check](HEALTH.md#keeping-the-probe-out-of-a-container-health-check)
carries the routes in full, including the wildcard's effect on that validation and the separate
refusal that meets a group named after a contributor.

#### The health probe moved under `management.health.push2u`

Beyond the two renamed keys in the table above, one behaviour is new:
**`management.health.defaults.enabled` now reaches this indicator.** It never did before —
`push2u.health.enabled` was the library's own switch and answered to nothing else. A deployment that
turns contributors off wholesale and names back the ones it wants will therefore lose this probe
silently unless it names this one back too. That is a probe disappearing with nothing failing, which
is why it is worth checking rather than discovering.

[`HEALTH.md`](HEALTH.md) is the reference: what the probe asserts about the signer, what it
deliberately does not, and its two keys.

#### The endpoint policy is a bean, and its refusals moved

The allowlist expressed by `push2u.allowed-origins` and `push2u.allowed-domains` is now published as
an `EndpointPolicy` bean, so the code that accepts subscriptions can inject it and validate each
offered endpoint against the same rule every send will enforce. One definition, applied at both
points of a subscription's life. In `0.1.0` the policy was built inside the sender's factory method
and nothing else in the context could reach it — so a policy refusal could only ever be discovered
at send time, on a stored row that no `410` will ever expire and no later send will ever satisfy.

Two upgrade consequences follow from *where* the checks now live rather than from the bean itself.
The refusals that guard those properties — a malformed entry, and an allowlist stated beside an
application-supplied `EndpointPolicy` bean — moved out of the sender's factory method into startup
checks that run whether or not a sender is built. **A context that carries these properties without
building a sender now meets them**, where in `0.1.0` the check was never reached: a malformed entry
sat unreported, and the contradiction between a stated allowlist and an application's own policy
bean was never raised.

If your application declares its own `EndpointPolicy` bean it still wins — the starter's bean is
suppressed by an application-supplied one. What is refused is stating *both*: a bean beside an
allowlist with an entry is a second definition of the same rule, and the refusal names the bean. An
explicitly empty allowlist beside a bean is not a contradiction and still cedes to the bean.

There is still deliberately no property for the unrestricted mode: under Spring it is an application
`@Bean EndpointPolicy` returning `EndpointPolicies.unrestricted()`, so that turning the control off
is a code change someone reviews rather than a line copied between profiles.
[`SPRING.md` → Endpoint policy](SPRING.md#endpoint-policy) carries the registration recipe written
against the bean.

#### `Push2uProperties` and `VaultSignerProperties` changed shape

`Push2uProperties`' canonical constructor changed several times in this release and
`VaultSignerProperties`' once. **Application code that names either record — constructing one,
holding one, or binding it in a test — and is run against these starters without being recompiled
fails with `NoSuchMethodError`**, because the constructor it was compiled against no longer exists.
Most applications never name these types: they are the starters' binding surface, not API anyone was
meant to hold, and code that only injects a `PushSender` or an `EndpointPolicy` is untouched by
this. But swapping the jars underneath classes you did not rebuild is not an upgrade path in either
case; recompile, and this stops being a question.

Concretely, on `Push2uProperties`: `recordSize`, `retry` and `health` are gone as components, the
nested `Push2uProperties.Retry` and `Push2uProperties.Health` records are gone as types, and
`jwtRenewBefore`, `jwtReuse`, `jwtCacheSize` and `allowedDomains` are new. The health settings live
in their own `Push2uHealthProperties`, bound from `management.health.push2u`. On
`VaultSignerProperties`, one component was inserted: `publicKeyFetch`.

#### Vault: a third construction mode

`VaultTransitVapidSigner` gains `builderWithDeferredPublicKeyFetch(address, keyName, token)` beside
the two it had, selected under Spring by `push2u.signer.vault.public-key-fetch: deferred`. The two
existing builders keep their names and their parameters, and `eager` remains what an unset or blank
value means, so nothing here has to be edited to keep working — but the eager builder's `build()`
did change what it *throws*, which is the silent half and is
[in the chapter above](#an-eager-vault-build-raises-a-different-type-when-vault-is-down).

The eager fetched builder reads Vault inside `build()`, which under Spring is during context
refresh: a Vault that is sealed or not yet reachable fails the boot. The deferred builder performs
every check that does not need a Vault response and contacts nothing, moving the metadata read to
the signer's first `sign`, `publicKey` or `publicKeyBase64Url`. An application that must start while
Vault is still coming up wants the third mode.

One thing that does not change with it: the advertised key still never moves for a signer's
lifetime. A successful pair is retained, there is no TTL, no second read after a success, and no
`refresh()`. Replacing a VAPID identity is a migration and not a mutation —
[`VAPID-KEY-ROTATION.md`](VAPID-KEY-ROTATION.md) is the runbook, and it is worth reading before a
rotate rather than during one, because an eager signer takes `latest_version` every time one is
built and the next restart after a rotate is where that is discovered.
[`VAULT.md` → When boot must not depend on Vault](VAULT.md#when-boot-must-not-depend-on-vault)
covers the deferred mode itself.

### Checklist for the `0.1.0` move

- [ ] Rebuild; replace `PushResult` with an exhaustive `switch` over `PushOutcome`.
- [ ] Delete `retryPolicy(...)`, and `push2u.retry.*` from every YAML file and profile.
- [ ] Decide the repeat schedule yourself, honouring the reported `Retry-After` where one arrived,
      bounding it, and decrementing `TTL` on a delayed repeat.
- [ ] Delete `recordSize(...)` and `push2u.record-size`; raise `maxEncryptedBodyBytes` if the record
      size was what you had raised.
- [ ] Re-read every `catch` clause around `send`, and add the branches the converted conditions now
      need.
- [ ] If you implement `VapidSigner`: raise `VapidSignerUnavailableException` for an outage, and
      re-read [`SIGNER.md`](SIGNER.md).
- [ ] If you implement `VaultHttpTransport`: read `Retry-After` and pass it to `VaultHttpResponse`'s
      three-argument constructor, or accept a permanently empty hint.
- [ ] If you build `VaultTransitVapidSigner` by hand: catch the interruption, then
      `VapidSignerUnavailableException`, then `PushCryptoException` — in that order, around the
      eager `build()`, and around the first `publicKey()` too if you adopt the deferred mode.
- [ ] Check the subscription store for endpoints above 2048 characters.
- [ ] Decide whether VAPID token reuse is what you want; `jwtReuse(false)` restores per-send
      signing.
- [ ] Rename `push2u.health.*` to `management.health.push2u.*`, and check
      `management.health.defaults.enabled`.
- [ ] State `push2u.enabled` where this deployment does not send — and edit any health group naming
      `push2u` in the same change.
- [ ] Recompile every artifact that binds the starters' properties records.
- [ ] Start the application and read the startup refusals; they are the last mile of this list.
