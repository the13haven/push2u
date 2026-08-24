# ADR-032 — The starters declare a minimum Spring Boot, never impose one

**Status:** Proposed

[ADR-002](0002-zero-dependency-core.md) settled what the core may carry: nothing, so that a consumer
inherits no foreign surface and no foreign CVE by depending on this library. It says in one clause
where the rest goes — "framework and remote-system integrations live in optional modules that depend
on the core" — and stops there, because a module a consumer opts into is a module whose dependencies
they asked for. **This record is that clause's neighbour and not its successor.** ADR-002 is about
what an artifact drags in; this one is about what an artifact *says about the versions* of things the
consumer already has. The core has no dependency to have an opinion about. The starters sit on top of
Spring Boot, which the consumer owns, chose, pins and upgrades on a schedule this library knows
nothing about — and today the published metadata of those starters has an opinion about it anyway.

## What the starters publish today, and what it does

Both starters declare `api(platform(libs.spring.boot.dependencies))`. That is a dependency like any
other, so it lands in the published Gradle Module Metadata under `apiElements` and `runtimeElements`,
and in the POM as a `<dependency>` with `<scope>import</scope>` inside `<dependencyManagement>`. Next
to it, `spring-boot-autoconfigure` is published **without a `<version>` at all**: the catalog alias
carries no version because the imported BOM supplies one, and the publication reproduces exactly that
— a versionless dependency plus the BOM that resolves it.

The result is that these starters ship Spring Boot's entire version manifest to every consumer, as a
live input to their resolution. Measured, by publishing eight variants into `mavenLocal` and
resolving them from real consumer projects:

| Consumer | What they asked for | What they got |
|---|---|---|
| Gradle, `platform(spring-boot-dependencies)` at 4.0.0 | Boot 4.0.0 | `spring-boot-autoconfigure` **4.1.1**, `spring-boot` 4.1.1, `spring-core` 7.0.9, `jackson-databind` 3.1.5, `micrometer` 1.17.1 |
| Gradle, Spring Boot plugin, no `io.spring.dependency-management` | Boot 4.0.0 | the same upgrade |
| Gradle, `io.spring.dependency-management` applied | Boot 4.0.0 | Boot 4.0.0 — the plugin forces its managed versions and the import loses |
| Maven, `dependencyManagement` at 4.0.0 | Boot 4.0.0 | Boot 4.0.0 |

Two things in that table matter more than the rest. The first is that the upgrade is **silent**: a
consumer who pinned Boot 4.0.0 deliberately, and who has an application-wide statement to that effect
in their build, gets a different Spring, a different Jackson and a different Micrometer because they
added a Web Push starter. Nothing warns them; the build succeeds. The second is that **the official
Spring Boot Gradle plugin does not prevent it.** What prevents it is `io.spring.dependency-management`,
a separate plugin that is no longer applied by default, and whose forcing behaviour happens to
outrank an imported BOM. So the defect is real for roughly half of Gradle consumers and invisible for
the other half, which is the worst distribution available: it will be reported once, by someone whose
neighbour cannot reproduce it.

Maven is untouched in every variant measured, and for a structural reason rather than by luck: a
consumer's own `dependencyManagement` always wins over `dependencyManagement` reached through a
transitive dependency. That fact returns wherever this record measures what a Maven consumer
actually gets.

**Publishing that manifest was never a decision.** `api(platform(...))` is the idiom for getting
version alignment inside a build, and it works; the part nobody weighed is that on `api` it is also a
statement to everyone downstream. This record weighs it.

## The decision

**A published starter declares the *minimum* Spring Boot version it supports, and nothing else about
which version the consumer runs.** Concretely:

- `api(platform(libs.spring.boot.dependencies))` leaves every publishable configuration of both
  starters. The platform stays on `compileOnly`, `annotationProcessor` and `testImplementation`,
  which are not published and where alignment is exactly what is wanted — this build compiling and
  testing against one coherent Spring Boot.
- `spring-boot-autoconfigure` is published **with an ordinary `require` version**, which is a floor
  and not a pin: inside Gradle's own conflict resolution it is raised by anything asking for more and
  is never lowered. That is a claim about resolution, not about the world — a build that *forces*
  versions overrules it in either direction, and the third row of the table above is that case
  measured: `io.spring.dependency-management` holds a consumer at 4.0.0 while this library's own
  published metadata asks for 4.1.1.
- The catalog key `springBoot` **changes meaning**. It stops being "the Spring Boot this build
  happens to use" and becomes "the minimum Spring Boot these starters support" — and, by the same
  number, the version the **default build** compiles against and therefore the version the published
  artifacts are built from.
- **The oldest supported minor is 4.0**, and the declared value is a released patch of that line —
  **4.0.8** when this record was written, moved inside the line by the rule under *When the floor
  moves*.

The starters keep saying what a starter must say — that they need Spring Boot, and how old a Spring
Boot is too old. They stop saying which one the consumer should be running.

## The catalog number has to *be* the floor, and one measurement is why

The tempting half-move is to drop the platform from `api` and leave `springBoot = "4.1.1"` alone. It
was measured, and it is wrong. With the platform still on `compileClasspath` at 4.1.1 and the
published requirement at the floor, the compile classpath resolves `4.0.8 -> 4.1.1`, because that is
what Gradle does with two requirements: it takes the higher. The starters would compile against 4.1.1
while telling consumers the floor is enough, and the first use of anything 4.1 added would ship as a
`NoSuchMethodError` in someone else's process.

So there is **one number in one place**, and in the default build the promise is checked by the
compiler: a starter cannot use an API newer than the floor it advertises, because the floor is the
classpath it sees. Runs against a newer Spring Boot are worth having, and the next section says both
what they are worth and what they may not do — but the tree has none of them today, and this record's
implementation is where they would arrive: named runs that report and publish nothing. That property
is the reason this is a decision and not a build tweak.

## A floor nothing checks is not a promise

The claim "these starters work on the minimum we advertise" survives exactly as long as something
re-checks it, and the scheme that does has parts that will change with Spring's release cadence and
parts that must not. Only the second kind is decided here.

- **The floor is the classpath of the default build.** A bare `./gradlew build` resolves Spring Boot
  at the declared minimum, and the artifacts that are published are built from that same resolution.
  Nothing has to be remembered for the check to happen: the ordinary path is the checked path.
- **Exactly one merge-blocking check covers the floor, and it is one that exists already.** `main`
  requires three, and the other two analyse the sources without building them, so `quality` is the
  only one that can witness anything about a classpath. Once the catalog key means the floor,
  `quality` compiles and tests both starters against it — no fourth required check, and nothing new
  for anyone to remember. A floor guarded by a job somebody has to remember to read is not guarded.
- **Any run above the floor is informative and publishes nothing.** Building and testing against a
  newer Spring Boot is worth doing — it is how the next floor move is discovered before a consumer
  discovers it — but such a run reports rather than decides, and no artifact leaves it.

How many such runs there are, which versions they name and what the jobs are called are liable to
change with every Spring Boot line, and they belong in `docs/DESIGN.md` and `CONTRIBUTING.md`. A
record fixing the matrix would need superseding by the next release train, which is precisely the
kind of ADR this repository does not write.

## Why the oldest supported minor is 4.0, and why the declared value is 4.0.8

Two questions, and they have different answers.

**The minor is measured.** With the floor on the 4.0 line both starters compile, their tests pass and
the quality gate is green. With `3.5.9` the build does not resolve at all, and exactly one dependency
causes it: `spring-boot-health` is a module Boot 4 split out of actuator, and it does not exist in the
3.5 BOM. The health indicator's four imports —
`org.springframework.boot.health.contributor.{HealthIndicator, Health, Status}` and
`…health.autoconfigure.contributor.ConditionalOnEnabledHealthIndicator` — are the whole of the
obstacle.

Everything else these starters touch exists in 3.x as well: `AutoConfiguration`, the `ConditionalOn*`
family, `Binder`/`Bindable`/`BindResult`, `SpringBootCondition`, `ConditionOutcome`,
`AbstractInjectionFailureAnalyzer`, `FailureAnalysis`, `Ordered`. Nothing from 4.1 is used anywhere.

The floor was also checked from the other side, by standing up real application contexts: starters
built against the 4.0 line run on 4.0, on 4.1.1 and on 4.2.0-M1; starters built against 4.1.1 run on
4.0. In the surface these modules actually touch there is no binary incompatibility in either
direction — which is what makes the floor honest rather than defensive.

**The patch inside that line is chosen by the rule under *When the floor moves*, and 4.0.0 fails
it.** The graph a floor of 4.0.0 actually produces was resolved rather than assumed —
`spring-boot-autoconfigure` 4.0.0, `spring-boot` 4.0.0, and `spring-core`, `spring-context`,
`spring-beans`, `spring-aop` and `spring-expression` all at 7.0.1 — and checked against the GitHub
Advisory Database. It carries **seven** published advisories:

| Artifact at a 4.0.0 floor | Advisory | Severity |
|---|---|---|
| `spring-boot` 4.0.0 | [GHSA-8v8j-3hxp-93wr](https://github.com/advisories/GHSA-8v8j-3hxp-93wr) — CVE-2026-40976, `>=4.0.0, <4.0.6`, fixed 4.0.6 | **critical** |
| `spring-boot` 4.0.0 | [GHSA-wwpq-f5c3-7hvx](https://github.com/advisories/GHSA-wwpq-f5c3-7hvx) — CVE-2026-40973, `>=4.0.0, <4.0.6`, fixed 4.0.6 | **high** |
| `spring-boot-autoconfigure` 4.0.0 | [GHSA-ggg2-9786-hwc8](https://github.com/advisories/GHSA-ggg2-9786-hwc8) — CVE-2026-41001, `>=4.0.0, <=4.0.6`, fixed 4.0.7 | moderate |
| `spring-expression` 7.0.1 | [GHSA-r5w3-xv2f-j59q](https://github.com/advisories/GHSA-r5w3-xv2f-j59q) — CVE-2026-41850, `>=7.0.0, <=7.0.7`, fixed 7.0.8 | **high** |
| `spring-expression` 7.0.1 | [GHSA-wxpp-56q6-5pcg](https://github.com/advisories/GHSA-wxpp-56q6-5pcg) — CVE-2026-41851, same range, fixed 7.0.8 | moderate |
| `spring-expression` 7.0.1 | [GHSA-9f52-rjqv-25qv](https://github.com/advisories/GHSA-9f52-rjqv-25qv) — CVE-2026-41852, same range, fixed 7.0.8 | low |
| `spring-core` 7.0.1 | [GHSA-659m-px2c-25wj](https://github.com/advisories/GHSA-659m-px2c-25wj) — CVE-2026-41848, `>=7.0.0, <=7.0.7`, fixed 7.0.8 | low |

One critical, two high, two moderate, two low. **Only three of the seven are Spring Boot's own
coordinates**, and one of those three is `spring-boot-autoconfigure` — the artifact this record
decides to publish a version of. The other four arrive through what Boot's BOM manages, which is
precisely why the rule under *When the floor moves* is written over the graph the floor produces
rather than over the floor's own artifact.

The same graph at 4.0.8 resolves `spring-boot` and `spring-boot-autoconfigure` 4.0.8 with the whole
framework at 7.0.9 — above every fixed version in the table — so it carries none of the seven, as
4.1.1 carries none. The 4.0 line's BOM at 4.0.8 manages `spring-framework` 7.0.9, `micrometer`
1.16.7 and `jackson-bom` 3.1.5.

Declaring the *minor* as the decision and the *patch* as a value moved by rule is what keeps this
record from needing a successor every time Spring publishes a security patch. Where this leaves 3.x
is a separate question with an answer already on record: the catalog's own comment says these modules
target 4.x because push2u is new and its adopters build on the current Boot. Lowering the floor to
3.x is not ruled out by this record — it is ruled out by `spring-boot-health`, and a later record
wanting 3.x support has to say what happens to the health indicator first.

## When the floor moves, and the only two reasons that move it

A floor that drifts upward with each release is a pin wearing a different word. It moves for two
reasons and no others.

1. **A starter needs an API the floor does not have.** Then raising the floor is part of that work
   and is argued with it — the feature and the narrowing arrive together, and the compiler is what
   forced the question.
2. **A published vulnerability sits in the graph the floor produces — in Spring Boot itself or in
   anything its BOM manages into that graph — and a patch of the same line fixes it.** Then raising
   to that patch is **obligatory, not discretionary**: the floor is what a consumer's resolution may
   be raised *to*, so leaving it on a known-vulnerable patch hands that version to every consumer
   whose build honours it. This is the ordinary public path a vulnerable dependency takes in this
   repository, advisory named and all, and not the private one that belongs to a defect in this
   library's own code.

   **The graph and not the artifact is the trigger, and the seven advisories are why.** Four of the
   seven that ruled 4.0.0 out are against `spring-core` and `spring-expression`, which this library
   declares nowhere: they arrive because Boot's BOM manages them, and a patch of Boot's line is what
   moves them. A rule reading "the floor's own artifact" would have left the
   floor at 4.0.0 in the very case that produced this record.

**A new Spring Boot existing is not a reason.** Neither is a wish to use a newer API that nothing
needs.

The two reasons narrow different things. Under (2) the move stays inside the supported line and
narrows nothing: a consumer above the floor is unaffected, and one below it was running a version
with a published defect. Under (1) the *minor* moves, which drops deployments this library previously
supported — so it is made by a record of its own and a note in `docs/MIGRATION.md`, whose silent-break
section exists for exactly this shape of change, and never by editing a number in the catalog in
passing.

## What each mechanism actually publishes

Gradle's rich versions are four declarations — `require`, `prefer`, `strictly` and `reject` — and
only some of them survive into a POM. The fifth row below is not one of them: `constraints {}` is a
different mechanism reached for the same purpose, and it is measured here beside them because it is
the alternative a reader will ask about. The serialisations were read out of published metadata
(Gradle 9.7.1) rather than quoted from documentation, and the asymmetry is the reason the decision is
`require` and nothing stronger:

| Declared | Gradle Module Metadata | POM |
|---|---|---|
| `require` | `{"requires":"4.0.8"}` | `<version>4.0.8</version>` |
| `prefer` | `{"prefers":"4.0.8"}` | `<version>4.0.8</version>` — indistinguishable from `require` |
| `strictly` | `{"strictly":"4.0.8","requires":"4.0.8"}` | `<version>4.0.8</version>` — the strictness is lost entirely |
| `reject` | `{"requires":"4.0.8","rejects":["[,4.0.8)"]}` | `<version>4.0.8</version>` — the dependency is there, the *rejection* is absent |
| `constraints {}` | a constraint node | `<dependencyManagement>` without `scope=import`, plus a versionless dependency |

A Gradle consumer reads the module metadata and sees whichever of these was declared. A Maven
consumer reads the POM, where `prefer` and `strictly` become indistinguishable from `require`, and
`reject` keeps its dependency while losing the restriction that was its entire point. Any decision
that leans on a mechanism the POM cannot carry is a decision that behaves differently for half the
ecosystem while looking uniform in the source.

## The alternatives, and what each one cost when it was measured

**`strictly`.** A Gradle consumer on Boot 4.1.1 gets `BUILD FAILED` — `Cannot find a version of
org.springframework.boot:spring-boot-autoconfigure that satisfies the version constraints …
{strictly …}` — while the same consumer on Maven builds and runs, because the POM does not carry
strictness. That is imposition in its purest form, and asymmetric imposition at that: this library
would be dictating a version to Gradle users and merely suggesting one to Maven users, from a single
line of build script. Refused.

**A Maven range, `[4.0.8,)`.** It is the only spelling of "not below X" that a POM has, and its price
is measured: a consumer with no BOM of their own resolved `spring-boot-autoconfigure:4.2.0-M1` and
`spring-core:7.1.0-M1`. What selects the milestone is the open right end, so the result is the same
whatever the floor on the left is; the measurement was taken with the floor of the day on it. The
library would be pulling *pre-release milestones* into applications, and what an application resolves
would change with every Spring publication while not a line of anyone's code changed. A floor that
drags a consumer forward is not a floor. Refused.

**`compileOnly` for `spring-boot-autoconfigure`.** It publishes nothing at all — no version, and no
record that Spring Boot is required. A consumer who does not also depend on a `spring-boot-starter`
fails to compile, and a consumer on Boot 3.x learns about the mismatch as a `NoClassDefFoundError` at
runtime. A floor that says nothing cannot be violated, and cannot be relied on either. Refused.

**`reject("[,4.0.8)")`.** Its appeal is that it expresses the actual intent — not below the floor, no
opinion above, the bound moving with the floor so that it never admits a patch the floor exists to
exclude. It is absent from the POM, so Maven never sees it; and under
`io.spring.dependency-management` it was measured to be **silently ignored**, a consumer on Boot 3.5.9
resolving 3.5.9 with no complaint. A guard that is invisible to some consumers and inert for others
is worse than no guard, because it reads in our source like protection. Refused.

**`prefer`.** Weaker than `require` — a preference yields to any other requirement, in either
direction — and indistinguishable from it in the POM. It buys nothing anywhere. Refused.

**`constraints {}` with a versionless dependency.** Measured to be behaviourally identical to
`require` in every consumer cell tested. It is refused on two smaller grounds rather than a
behavioural one: it states the version one level of indirection away from the dependency it governs,
for no gain; and it publishes a POM whose dependency has no `<version>` element, which SBOM
generators and IDEs read inconsistently. Where two spellings behave the same, the one that puts the
number where a reader looks for it wins. Refused.

## The floor is not enforceable everywhere, and this record says so rather than implying otherwise

Measured, per consumer:

| Consumer | Does the floor hold? |
|---|---|
| Gradle with `platform(spring-boot-dependencies)` | **Yes** — a consumer pinned to 3.5.9 resolves 4.0.8, and `spring-core` with it |
| Gradle with `io.spring.dependency-management` | **No** — the plugin's managed version wins, in either direction |
| Maven | **No** — the consumer's `dependencyManagement` wins over a transitive one |

There is no mechanism that expresses "not below X" in a POM. The only candidate is a range, and the
section above measured what a range costs. So for Maven consumers and for Gradle consumers under the
dependency-management plugin, **the minimum supported version is documentation and nothing else** —
a sentence in `docs/SPRING.md` and a POM value that resolution is free to overrule.

**This is not a regression.** Today there is no floor for anyone; after this change there is a floor
for some and a documented statement for the rest, and the silent upgrade stops for everyone. What
would be a defect is a record that quietly let a reader believe the enforcement is uniform, so it is
stated here in the form a later reader can check.

## No runtime version check, and that is a choice

The obvious closing move is to have a starter read Spring Boot's version at startup and refuse a
context below the floor. It is declined.

The refusal it would add is a *startup* refusal, and startup refusals in this tree are not free: they
belong to one ordered list spanning both starters ([ADR-025](0025-delivery-is-off-by-statement.md)),
each with a declared position, a message and tests over the order that arrives. Adding a member to
that list buys a diagnostic in exactly the case where the application has already failed to
resolve — a Gradle consumer under the plugin, or a Maven consumer, on a Boot too old — and where the
symptom is a missing class with the class's own name in it. Against that, it makes the library's
behaviour depend on a version string it reads out of the framework rather than on what it was
compiled against, and it is the kind of check that outlives the reason it was added.

**The decision is that metadata and documentation carry the floor, and the process carries no
opinion about the framework's version.** The hole this leaves is the one named in the previous
section, and resolution does not close it either.

## Documents

`docs/SPRING.md` gains the statement of the minimum supported Spring Boot and what it means — that
the consumer chooses the version, that this library raises it only where resolution permits, and that
on Maven and under `io.spring.dependency-management` the floor is a statement rather than a
constraint. README names Spring Boot 4 in its feature list, in *Requirements*, and in the *Spring
Boot* section where both starters are said to require 4.x and Boot 3.x is ruled out by name; its
module table carries no version and needs none. `docs/DESIGN.md` describes the module layout and is
where the verification matrix's changeable half belongs, with `CONTRIBUTING.md` for what a
contributor runs; `gradle/libs.versions.toml` carries the comment that fixes what `springBoot` now
means. All of that belongs with the implementation, together with this record's move to `Accepted`;
while it is `Proposed` those documents are accurate, because the tree still publishes the platform.

Sources for the mechanism claims, where a wrong one would cost a consumer a build:
[Gradle rich versions](https://docs.gradle.org/current/userguide/dependency_versions.html#sec:rich-version-constraints),
[Gradle's mapping of dependency metadata into a POM](https://docs.gradle.org/current/userguide/publishing_maven.html),
[Maven dependency management](https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html#Dependency_Management)
and the
[`io.spring.dependency-management` plugin](https://docs.spring.io/dependency-management-plugin/docs/current/reference/html/).
The measured behaviours above are this repository's own observations and are not claims any of those
documents makes.

## What this rules out

- Spring Boot's BOM on `api` or `implementation` in either starter, or in any other configuration
  that is published — it belongs on `compileOnly`, `annotationProcessor` and test configurations,
  which do not travel.
- `spring-boot-autoconfigure`, or any other Spring Boot artifact, published from a starter without a
  version, whatever supplies that version inside this build.
- `strictly`, `reject` or a version range on a Spring Boot dependency published from a starter — the
  first two because the POM discards them while Gradle enforces them, so one ecosystem gets a hard
  failure the other never sees; the third because a floor that admits milestones is not a floor.
- A published Spring Boot requirement this library expects the consumer's build to *lower*, which an
  ordinary requirement cannot express and a strict one can only express by breaking.
- A `springBoot` catalog value raised because a newer Spring Boot exists, or because this build would
  like to test against one. The two reasons that do move it are a starter needing an API the floor
  lacks, and a published vulnerability anywhere in the graph the floor produces — Spring Boot's own
  artifacts or anything its BOM manages into that graph — fixed by a patch of the same line; the
  second obligatory rather than discretionary, since the floor is a version consumers may be raised
  to.
- A move to a newer *minor* made by editing the catalog number: that narrows the deployments this
  library supports, and is owed a record of its own and a note in `docs/MIGRATION.md`.
- The two meanings split apart: a second catalog key so that the starters compile against one Spring
  Boot and advertise another, in either direction. Temporarily substituting the single key for a
  named run is not that, and the criterion separating them is checkable — the version lives in
  exactly one place in the tree, and no published artifact is built with a substituted value.
- Compiling a starter against a Spring Boot above its declared floor **in the default build, or in
  the build that publishes artifacts** — by a platform on `compileClasspath`, by a test fixture, or
  by any other path that raises it. A named run above the floor that publishes nothing is not this.
- More than one merge-blocking check over the floor, or a floor whose verification lives in a run
  that publishes artifacts.
- An upper bound on Spring Boot, published in any spelling — a range with a closed right end, a
  `reject` over future versions, or a documented "tested up to" presented as a supported ceiling.
- A runtime or startup check of the framework's version, and a member of the startup-refusal list
  whose subject is which Spring Boot is present.
- A claim, in this repository or its published metadata, that the minimum version is enforced for
  every consumer — it is enforced where the consumer's resolution lets it be, and the three consumers
  named under *The floor is not enforceable everywhere* are the whole of what was measured.
- Spring Boot's version manifest reaching a consumer as a live input to their resolution by any other
  route: a BOM published from this project, a `pom` variant, or a starter re-exporting managed
  versions under another name.
