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

The result is that this library ships Spring Boot's entire version manifest to every consumer of a
starter, as a live input to their resolution. Measured, by publishing eight variants into
`mavenLocal` and resolving them from real consumer projects:

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
transitive dependency. That fact is load-bearing twice below.

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
  and not a pin: Gradle raises it when something else asks for more, and never lowers it.
- The catalog key `springBoot` **changes meaning**. It stops being "the Spring Boot this build
  happens to use" and becomes "the minimum Spring Boot these starters support" — and, by the same
  number, the version they are compiled against.
- **The declared floor is 4.0.0.**

The starters keep saying what a starter must say — that they need Spring Boot, and how old a Spring
Boot is too old. They stop saying which one the consumer should be running.

## The catalog number has to *be* the floor, and one measurement is why

The tempting half-move is to drop the platform from `api` and leave `springBoot = "4.1.1"` alone. It
was measured, and it is wrong. With the platform still on `compileClasspath` at 4.1.1 and the
published requirement at 4.0.0, the compile classpath resolves `4.0.0 -> 4.1.1`, because that is what
Gradle does with two requirements: it takes the higher. The starters would compile against 4.1.1
while telling consumers 4.0.0 is enough, and the first use of anything 4.1 added would ship as a
`NoSuchMethodError` in someone else's process.

So there is **one number in one place**, and the promise is checked by the compiler on every build:
a starter cannot use an API newer than the floor it advertises, because the floor is the classpath it
sees. That property is the reason this is a decision and not a build tweak.

## Why the floor is 4.0.0

Measured, not reasoned. With `springBoot = "4.0.0"` both starters compile, every test passes and
`qualityCheckCi` is green. With `3.5.9` the build does not resolve at all, and exactly one dependency
causes it: `spring-boot-health` is a module Boot 4 split out of actuator, and it does not exist in the
3.5 BOM. The health indicator's four imports —
`org.springframework.boot.health.contributor.{HealthIndicator, Health, Status}` and
`…health.autoconfigure.contributor.ConditionalOnEnabledHealthIndicator` — are the whole of the
obstacle.

Everything else these starters touch exists in 3.x as well: `AutoConfiguration`, the `ConditionalOn*`
family, `Binder`/`Bindable`/`BindResult`, `SpringBootCondition`, `ConditionOutcome`,
`AbstractInjectionFailureAnalyzer`, `FailureAnalysis`, `Ordered`. Nothing from 4.1 is used anywhere.

The floor was also checked from the other side, by standing up real application contexts: starters
built against 4.0.0 run on 4.0.0, 4.1.1 and 4.2.0-M1; starters built against 4.1.1 run on 4.0.0. In
the surface these modules actually touch there is no binary incompatibility in either direction —
which is what makes the floor honest rather than defensive.

Where this leaves 3.x is a separate question with its own answer already on record: the catalog's own
comment says these modules target 4.x because push2u is new and its adopters build on the current
Boot. Lowering the floor to 3.x is not ruled out by this record — it is ruled out by
`spring-boot-health`, and a later record wanting 3.x support has to say what happens to the health
indicator first.

## What each mechanism actually publishes

Gradle's rich versions are four different statements, and only some of them survive into a POM. The
serialisations below were read out of published metadata rather than quoted from documentation, and
the asymmetry is the reason the decision is `require` and not something stronger:

| Declared | Gradle Module Metadata | POM |
|---|---|---|
| `require` | `{"requires":"4.0.0"}` | `<version>4.0.0</version>` |
| `prefer` | `{"prefers":"4.0.0"}` | `<version>4.0.0</version>` — indistinguishable from `require` |
| `strictly` | `{"strictly":"4.0.0"}` | `<version>4.0.0</version>` — the strictness is lost entirely |
| `reject` | `{"rejects":[…]}` | absent |
| `constraints {}` | a constraint node | `<dependencyManagement>` without `scope=import`, plus a versionless dependency |

A Gradle consumer reads the module metadata and sees whichever of these was declared; a Maven
consumer reads the POM, where three of the five spellings collapse into the fourth or vanish. Any
decision that leans on a mechanism POM cannot carry is a decision that behaves differently for half
the ecosystem while looking uniform in the source.

## The alternatives, and what each one cost when it was measured

**`strictly("4.0.0")`.** A Gradle consumer on Boot 4.1.1 gets `BUILD FAILED` —
`Cannot find a version of org.springframework.boot:spring-boot-autoconfigure that satisfies the
version constraints … {strictly 4.0.0}` — while the same consumer on Maven builds and runs, because
the POM does not carry strictness. That is imposition in its purest form, and asymmetric imposition
at that: this library would be dictating a version to Gradle users and merely suggesting one to Maven
users, from a single line of build script. Refused.

**A Maven range, `[4.0.0,)`.** It is the only spelling of "not below X" that a POM has, and its price
is measured: a consumer with no BOM of their own resolved `spring-boot-autoconfigure:4.2.0-M1` and
`spring-core:7.1.0-M1`. The library would be pulling *pre-release milestones* into applications, and
what an application resolves would change with every Spring publication while not a line of anyone's
code changed. A floor that drags a consumer forward is not a floor. Refused.

**`compileOnly` for `spring-boot-autoconfigure`.** It publishes nothing at all — no version, and no
record that Spring Boot is required. A consumer who does not also depend on a `spring-boot-starter`
fails to compile, and a consumer on Boot 3.x learns about the mismatch as a `NoClassDefFoundError` at
runtime. A floor that says nothing cannot be violated, and cannot be relied on either. Refused.

**`reject("[,4.0.0)")`.** Its appeal is that it expresses the actual intent — not below 4.0.0, no
opinion above. It is absent from the POM, so Maven never sees it; and under
`io.spring.dependency-management` it was measured to be **silently ignored**, a consumer on Boot 3.5.9
resolving 3.5.9 with no complaint. A guard that is invisible to some consumers and inert for others
is worse than no guard, because it reads in our source like protection. Refused.

**`prefer("4.0.0")`.** Weaker than `require` — a preference yields to any other requirement, in either
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
| Gradle with `platform(spring-boot-dependencies)` | **Yes** — a consumer on 3.5.9 is raised to 4.0.0 |
| Gradle with `io.spring.dependency-management` | **No** — the plugin's managed version wins |
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
constraint. README's module table describes the starters in one line each and names Boot 4;
`docs/DESIGN.md` describes the module layout; `CLAUDE.md` names Boot 4 where it describes the
starter's dependencies; `gradle/libs.versions.toml` carries the comment that fixes what `springBoot`
now means. All of that belongs with the implementation, together with this record's move to
`Accepted`; while it is `Proposed` those documents are accurate, because the tree still publishes the
platform.

Sources for the mechanism claims, where a wrong one would cost a consumer a build:
[Gradle rich versions](https://docs.gradle.org/current/userguide/dependency_versions.html#sec:rich-version-constraints),
[Gradle's mapping of dependency metadata into a POM](https://docs.gradle.org/current/userguide/publishing_maven.html),
[Maven dependency management](https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html#dependency-management)
and the
[`io.spring.dependency-management` plugin](https://docs.spring.io/dependency-management-plugin/docs/current/reference/html/).
The measured behaviours above are this repository's own observations and are not claims any of those
documents makes.

## What this rules out

- `api(platform(...))` or `implementation(platform(...))` in any publishable configuration of any
  published module, for Spring Boot or for any other BOM — the platform belongs on `compileOnly`,
  `annotationProcessor` and test configurations, which do not travel.
- A dependency published without a version, in any module, whatever supplies the version inside this
  build.
- `strictly`, `reject` or a version range on a published dependency — the first two because the POM
  discards them and Gradle enforces them, so one ecosystem gets a hard failure the other never sees;
  the third because a floor that admits milestones is not a floor.
- A published dependency whose version this library expects the consumer's build to *lower*, which an
  ordinary requirement cannot express and a strict one can only express by breaking.
- A `springBoot` catalog value raised because a newer Spring Boot exists, or because this build wants
  to test against one — the key is the minimum supported version and the compile classpath both, and
  raising it is a decision about what the starters support.
- The two meanings split apart: a second catalog key so that the starters compile against one Spring
  Boot and advertise another, in either direction. What makes the advertised floor true is that the
  compiler cannot see anything above it.
- Compiling a starter against a Spring Boot above its declared floor, by a platform on
  `compileClasspath`, by a test fixture, or by any other path that raises the compile classpath.
- An upper bound on Spring Boot, published in any spelling — a range with a closed right end, a
  `reject` over future versions, or a documented "tested up to" presented as a supported ceiling.
- A runtime or startup check of the framework's version, and a member of the startup-refusal list
  whose subject is which Spring Boot is present.
- A claim, in this repository or its published metadata, that the minimum version is enforced for
  every consumer — it is enforced where the consumer's resolution lets it be, and the three cells
  above are the whole of what was measured.
- Spring Boot's version manifest reaching a consumer as a live input to their resolution by any other
  route: a BOM published from this project, a `pom` variant, or a starter re-exporting managed
  versions under another name.
