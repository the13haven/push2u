# Contributing to push2u

Thanks for taking the time. This document covers what the build expects and what a reviewer will
look for, so that neither is a surprise at pull-request time.

**Found a security problem? Do not open an issue — and do not open a pull request either.** Follow
[`SECURITY.md`](SECURITY.md); the report stays private until a fix is released. That holds when you
ran into the problem while working on something else, and when your branch already carries the fix:
a released version stays exposed until a fixed one is out, so a pull request describing the defect
is the disclosure whether or not it also repairs it. An ordinary bug is not this, and neither is
pinning a vulnerable dependency of ours — that constraint names its advisory in public on purpose,
below.

Questions and half-formed ideas belong in
[Discussions](https://github.com/the13haven/push2u/discussions); the issue tracker is for defects
and accepted work. Participation is covered by the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

Read [`DESIGN.md`](docs/DESIGN.md) for the architecture as it stands, and
[`docs/adr/`](docs/adr/README.md) for the decisions that are already settled — one file per
decision, indexed there. Two of them shape most contributions:

- **[ADR-002](docs/adr/0002-zero-dependency-core.md), zero-dependency core.** `push2u-core` declares
  exactly one non-test dependency: JSpecify, an annotation-only jar. A change that adds a runtime
  dependency to the core will not be accepted — the library exists to replace one that leaked a
  heavy transitive surface into its API. Framework and remote-system integrations live in the
  optional modules.
- **[ADR-005](docs/adr/0005-public-spis-in-the-core.md), three public SPIs in the core**
  (`VapidSigner`, `PushHttpClient`, `EndpointPolicy`). New extension points need an articulable
  reason the library cannot decide the behaviour for the deployment. Protocol steps stay concrete.

If a change contradicts an ADR, that is not automatically wrong — but it has to say so, in the
pull request and in the documents, rather than leave them describing a design the code no longer
follows.

**An ADR is immutable once its decision is implemented.** Do not edit one to match a change: a
decision that moves gets a *new* ADR with the next free number, and the old one keeps its number,
its title and its body while its status line becomes `Superseded by ADR-NNN`. A decision that moves
only in part takes the same status-line edit in a narrower form, `Accepted; one clause superseded
by ADR-NNN`, beside the full form rather than in place of it — and that form accumulates: a later
record taking a second clause extends the same line rather than replacing it, `Accepted; one clause
superseded by ADR-NNN, another by ADR-MMM`, each record named in the order it arrived. Which clause
each one took stays out of the superseded ADR and lives in the record that took it. Descriptions of
how the code works now belong in `docs/DESIGN.md`, which is meant to be rewritten as the
architecture moves.
[`docs/adr/README.md`](docs/adr/README.md) has the full procedure and the house style.

The [non-goals](docs/DESIGN.md#non-goals) are equally settled: subscription persistence,
browser-side code, legacy `aesgcm`, general JSON parsing.

## Building

You need a JDK able to run Gradle, and Docker for the Vault integration test. The build itself
uses a Java 26 toolchain and compiles with `--release 21`; Gradle resolves the toolchain for you.

```bash
./gradlew build          # compile + test
./gradlew qualityCheck   # the full local gate — auto-formats, then runs every analyser
./gradlew javadoc        # the published API documentation
```

`build` deliberately does **not** run the analysers, so ordinary compile-test cycles stay fast.
Run `qualityCheck` before pushing: it is what CI runs (as `qualityCheckCi`, which verifies
formatting instead of applying it), and it is the only way to see Checkstyle, PMD, SpotBugs,
Error Prone, NullAway and the coverage threshold.

Javadoc is the exception, and worth knowing before it surprises you: `build` fails on any javadoc
warning, because `assemble` builds the published `-javadoc` jar and that task runs with `-Xwerror`.
See [What the build enforces](#what-the-build-enforces).

Useful narrower runs:

```bash
./gradlew :push2u-core:test --tests "com.the13haven.push2u.HkdfTest"
./gradlew :push2u-core:fipsTest        # BC-FIPS suite, isolated source set
./gradlew :push2u-signer-vault:test    # requires Docker
./gradlew spotlessApply                # after a formatting failure
./gradlew aggregateTestResults         # every module's JUnit XML in one directory
```

Reports land in `<module>/build/reports/` (HTML and XML); aggregated coverage in
`build/reports/jacoco/testCodeCoverageReport/`. `aggregateTestResults` collects every module's
JUnit XML — `push2u-core`'s `fipsTest` suite included — into `build/test-results-aggregated/`; CI
runs it after the quality check and hands that directory, plus the aggregated JaCoCo XML, to
Codecov.

### Developing against unpublished changes

Nothing between releases is published — no snapshots. To build against changes that have not been
released yet, include this repository as a Gradle composite build:

```kotlin
// settings.gradle.kts
includeBuild("../push2u")
```

The dependency declarations stay exactly as they are in
[`README.md` → Installation](README.md#installation) — Gradle substitutes the included build for
the published Maven Central artifact.

### Building against a newer Spring Boot

`gradle/libs.versions.toml`'s `springBoot` is not "the Spring Boot this build uses". It is the
**minimum** Spring Boot the two starters support and publish as a floor, and by the same number the
version everything above compiles against — one key, so a starter cannot use an API newer than the
floor it advertises. Do not raise it to pick up a newer Spring Boot: it moves only when a starter
needs an API the floor lacks, or when a published vulnerability sits in the graph the floor
resolves and a patch of the same line fixes it. Either move narrows what the project supports and
is written up in `docs/MIGRATION.md`.

To build against a newer Spring Boot without touching that number:

```bash
./gradlew -Ppush2u.springBoot=4.1.1 \
    :push2u-spring-boot-starter:build :push2u-signer-vault-spring-boot-starter:build
```

The property substitutes the catalog key for that invocation alone. A publishing task named
alongside it fails the build, so a substituted run cannot leave an artifact behind that was built
against something other than the floor it declares. CI runs exactly this, once per released Spring
Boot minor line at or above the floor's own — informative jobs, not required checks. Read a red one
as a floor move that may be due; it does not block a merge.

Why the two meanings are one number, why nothing published names an upper bound, and where the
floor is a constraint rather than a statement:
[ADR-032](docs/adr/0032-starters-declare-a-minimum-spring-boot.md).

### Upgrading Gradle

`gradle/wrapper/gradle-wrapper.properties` carries a `distributionSha256Sum`, so the wrapper
verifies the distribution zip it downloads instead of trusting TLS alone. CI's
`gradle/actions/wrapper-validation` checks the wrapper *jar* committed here; the checksum checks
the distribution that jar goes and fetches, which nothing else does.

**The version and the checksum move together, and neither the tooling nor the build lets them
drift apart.**

- Dependabot's `gradle` ecosystem — already configured in `.github/dependabot.yml` for `/`, which
  is where this wrapper lives — updates `gradle-wrapper.properties`, and updates
  `distributionSha256Sum` too whenever the file already has one. So the ordinary Gradle bump
  arrives as a pull request with both lines changed and needs nothing from you.
- Upgrading by hand goes through the `wrapper` task, and it will not let you drop the sum:

  ```bash
  ./gradlew wrapper --gradle-version <X.Y.Z> \
      --gradle-distribution-sha256-sum "$(curl -sSL \
        https://services.gradle.org/distributions/gradle-<X.Y.Z>-bin.zip.sha256)"
  ```

  Without the second option the task fails with *"gradle-wrapper.properties contains
  distributionSha256Sum property, but the wrapper configuration does not have one"*. That is the
  guard against the tempting fix: a stale checksum makes the build fail loudly, and the way out is
  the correct sum, not deleting the line.

Take the checksum from Gradle itself — `<distributionUrl>.sha256`, or the
[release checksums page](https://gradle.org/release-checksums/) — never from a mirror, a blog, or
a value copied out of another repository.

## What the build enforces

Formatting (Spotless/Palantir), naming and the presence of Javadoc on the public API (Checkstyle),
bug patterns (PMD, SpotBugs, Error Prone), the nullness contract (NullAway) and every warning the
`javadoc` tool itself emits all fail the build rather than warn. Aggregated instruction coverage
must stay at or above 80 %.

| Tool                 | What it enforces                                            | Configuration                                |
|----------------------|-------------------------------------------------------------|----------------------------------------------|
| Spotless             | Palantir Java Format, import order                           | `build-logic/.../push2u-quality.gradle.kts`  |
| Checkstyle           | Naming, Javadoc on the public API, import grouping, the licence header, no repository references in published sources | `config/quality/checkstyle/`                 |
| PMD                  | Best practices, design, error-prone patterns, performance    | `config/quality/pmd/ruleset.xml`             |
| SpotBugs             | Bytecode-level bug patterns                                  | `config/quality/spotbugs/exclusions.xml`     |
| Error Prone + NullAway | Compiler-attached checks; a named set and the nullness contract fail the build | `build-logic/.../push2u-quality.gradle.kts` |
| JaCoCo               | Aggregated coverage, minimum 80% of instructions             | `build.gradle.kts`                           |
| Javadoc              | Every javadoc warning, through `-Xwerror` — including on a plain `./gradlew build` | `build-logic/.../push2u-quality.gradle.kts`  |

Checkstyle, PMD, SpotBugs and `javadoc` run on `main` sources only — test code is exempt. Error
Prone covers the test compilations as well, since its checks are about defects rather than style;
NullAway runs on `main` and on `testFixtures`, which share `main`'s packages and so its nullness
contract. Practical consequences:

- **A javadoc warning is a build failure, and it is the one check that does not wait for
  `qualityCheck`.** The `javadoc` task runs with `-Xwerror`, so a `@param` that names no parameter,
  a `{@link}` that resolves to nothing, a missing `@return` or a stale `@throws` stops the build
  instead of scrolling past in the log. It catches you on a plain `./gradlew build` too, because
  `javadoc` is not an analyser hooked to `check` — it is the task that produces the published
  `-javadoc` jar, which `assemble` pulls in, so the strictness applies unconditionally and
  `./gradlew javadoc` on its own tells you exactly what the gate will. Fix the finding rather than
  the option: a JDK toolchain bump can surface a fresh warning on sources nobody touched, and that
  is a finding like any other.
- A new package needs a `package-info.java` carrying JSpecify's `@NullMarked`; forgetting it is a
  build failure, not a lint warning.
- Every `.java` file carries the Apache-2.0 SPDX licence header. You do not have to type it:
  `./gradlew qualityCheck` writes it into any file that lacks one, with the current year, and the
  year is never rewritten afterwards. The exceptions are `package-info.java` and `module-info.java`
  — Spotless leaves those alone so it cannot eat their Javadoc, so copy the header into them by
  hand:

  ```java
  /*
   * Copyright <the year you create the file> The 13 Haven
   *
   * SPDX-License-Identifier: Apache-2.0
   */
  ```

  Copy the year from a file you are adding alongside it rather than from this example — the check
  accepts any four digits, so a stale year copied from documentation would pass unnoticed.
- **Published code and Javadoc explain themselves, without pointing at this repository.** Every
  module ships a `sources.jar`, so a comment in a `main` source set is read by people who have only
  the artifact: `(ADR-014)` or "see `DESIGN.md`" sends them nowhere. Write the reason into the
  sentence instead of citing where it is recorded. Checkstyle enforces it — `ADR`, any `*.md`
  filename and the word `readme` in any case fail the build anywhere in a `main` source set, through
  the `checkstyleReferences` task, which reads source lines rather than a parsed AST so that
  `module-info.java` and `package-info.java` are covered too. A URL is fine — `http://` or
  `https://`, `#readme` anchor or `?q=README.md` query included — because a consumer can open it;
  the exemption is the link itself, not the rest of the line it sits on. Test sources are exempt;
  nothing ships them.
- A rule exclusion carries a comment saying why. A per-file exception is a
  `@SuppressWarnings("PMD.<Rule>")` at the narrowest scope that covers it, next to its reason.
- **Boolean methods are named by what they are, in three kinds.** Checkstyle does not enforce this
  and cannot; the point of writing it down is that one type should not end up with two habits.

  1. **A record's component accessor** keeps the component's name — a `record Feature(boolean
     enabled)` has an accessor called `enabled()`. That is the language, not a preference: the
     component names the method, and there is nothing to decide. The example is deliberately not a
     type from this tree: a rule illustrated by one is wrong the day that type's component is
     renamed or removed, and the rule itself never was.
  2. **A question about state** is a predicate: `is…` for what something *is*
     (`Es256Verifier.isSupported()`, and the cached VAPID token entry answering `isFresh(...)`),
     `has…` for what it holds, `can…` for what it is able to do. Whether the answer is stored,
     computed, or cached does not enter into it — `String.isEmpty()` computes, `isSupported()`
     caches, both are `is`.
  3. **An action or a relation keeps its verb**, with no prefix: `Es256Verifier.verify(...)`
     performs a check and reports the outcome, `endsMember(json, end)` reads as its own sentence,
     and a two-argument comparison like `sameCurve(actual, expected)` states a relation the way
     `Objects.equals` does. `isVerify` would be nonsense, and that is the tell.

  The failure this exists to prevent is 1 against 2 — a derived predicate wearing a component
  accessor's name, so that a judgement reads as one more stored value. `isFresh(...)` above is the
  worked example: it sits beside the three quantities a cache entry actually holds, and calling it
  `fresh(...)` would read as a fourth. The same trap is one step away from any record —
  `VaultHttpResponse` carries `statusCode()`, `body()` and `retryAfter()`, and a question derived
  from them would be `isRateLimited()`, never `rateLimited()`. The pair that takes judgement to
  apply is 2 against 3: one subject and a question about it is a predicate; two subjects, or
  something performed, is a verb.

  A name fixed by an interface or superclass is not ours to choose — `getBody()` in
  `JdkVaultHttpTransport` overrides the JDK's `BodySubscriber` and stays as the JDK named it.
- **Required parameters go into the factory method, optional ones become builder steps.** That is a
  firm rule, not a preference, and its firm consequence is this: `build()` must not be able to
  refuse over a missing required value — making an incomplete object inexpressible is the
  compiler's job, not the runtime's. `PushMessage.builder(payload)` takes the payload because there
  is no message without one; `PushSender.builder(keys, contact, endpointPolicy)` takes the key
  source, the contact and the egress rule for the same reason; and everything either builder still
  exposes is genuinely optional.
  What remains legitimate at the factory is rejecting a value that is present but *invalid* — a
  blank contact, a malformed key — with an `IllegalArgumentException`. What is never acceptable is
  an optional value smuggled into the factory method.

  When several required values are of the same type, what makes the positional list safe is types,
  not argument order: `VaultTransitVapidSigner`'s factory takes a `TransitKeyName` and a
  `VaultToken`, and swapping them does not compile. A value type earns its existence when it also
  carries the value's validation or redaction — `VaultToken` carries the token's character-set
  validation and a `toString()` that never prints the token, so every holder of one gets both for
  free.

  A staged builder — each required step its own type, `build()` reachable only on the last — is the
  answer when the required values are genuinely many, roughly four or five up. Its step types must
  be public and exported: hiding them in a non-exported package breaks every module-path consumer,
  whose chained calls fail to compile with "package … is not exported" (verified by experiment, not
  assumed). `sealed` is the right tool there instead — it forbids foreign implementations of the
  steps without hiding anything.

  When a type has one way to be assembled, the method is `builder()`. When it has several and they
  differ in *contract* rather than only in their parameters, each is named
  `builderWith<what exactly>()`, in one consistent form, and a bare `builder()` is not offered — it
  would silently promote one of several equal ways to the default. The example is the Vault signer:
  `builderWithFetchedPublicKey(…)` reads Vault inside `build()` and can fail there, while
  `builderWithSuppliedPublicKey(…)` does nothing over the network — different contracts, so
  different names. Entry points that differ only in a required parameter are overloads of one
  `builder(…)` instead: `PushSender.builder(keys, contact, endpointPolicy)` and
  `PushSender.builder(signer, contact, endpointPolicy)` share one contract, so they share one name.
- Vulnerable transitive dependencies are pinned with dependency **constraints**, never
  `resolutionStrategy.force` — force also records the originally requested version in the
  submitted dependency graph, and Dependabot then alerts on that phantom node. Each pin names its
  advisory.
- A pin goes where the dependency actually resolves, and never in a bucket that is published.
  `api` and `implementation` are inherited by `apiElements`/`runtimeElements`, so a constraint
  there is published — as `dependencyConstraints` in the module metadata and `dependencyManagement`
  in the POM — and Gradle applies it to every consumer's graph, which is the transitive surface
  ADR-002 exists to keep out. `push2u-testkit`'s `api` is published too — the kit reaches every
  consumer that puts it on a test classpath. Pin in `testImplementation`, `fipsTestImplementation`,
  `push2u-core`'s `testFixtures` buckets (whose variants are skipped from its publication), a
  tool configuration, or the buildscript instead, and check the result: no variant of any module
  should carry `dependencyConstraints` (`./gradlew generateMetadataFileForMavenPublication`, then
  read `<module>/build/publications/maven/module.json`).

## Tests

The suite is the RFC vectors, the sender's status matrix and seam-signal conversions, the Spring
Boot auto-configuration tests and a Vault Transit integration contract run against a Testcontainers
Vault.

The RFC vectors are the specification, not a snapshot of current behaviour: RFC 5869 for HKDF,
the RFC 8291 worked example for encryption, RFC 8292 for VAPID structure. If a change makes a
vector fail, the change is wrong until proven otherwise.

Every `VapidSigner` implementation extends the published conformance kit
`com.the13haven.push2u.testkit.VapidSignerContractTest`, every `EndpointPolicy` this build ships
extends `EndpointPolicyContractTest` beside it
([ADR-029](docs/adr/0029-the-kit-states-what-an-endpoint-policy-owes.md)), and `JdkPushHttpClient`
is the subject of `PushHttpClientContractTest`
([ADR-030](docs/adr/0030-the-kit-states-what-a-transport-owes.md)), whose loopback TLS harness is
the kit's own package-private machinery — the in-tree subjects are what keeps a published contract
from drifting away from what the library actually requires. Those contracts are one side of the
`push2u-testkit` module; the other is the
fixtures a *sending* application tests with — a generated VAPID pair, a coherent browser
subscription and a scripted, recording `PushHttpClient`, each carrying knowledge that is the
library's own and moves with it, which is what admits anything there
([ADR-028](docs/adr/0028-the-test-kit-publishes-contracts-not-conveniences.md), and
[`docs/TESTKIT.md`](docs/TESTKIT.md) for what it publishes and what it refuses to). The whole module
is a `main` source set, so the full analyser set applies to all of it — treat it as published API,
because it is.

The plumbing the suites share — the RFC vectors, the in-process mock push receiver, its loopback
TLS identity — lives in `push2u-core`'s `src/testFixtures`, in `main`'s package because it needs
package-private access. Those fixtures are internal: their variants are skipped from the
publication, and they must stay free of both BouncyCastle flavours, because `test` and `fipsTest`
load them on deliberately disjoint classpaths. `push2u-core` has a separate `fipsTest` source set
on a bcprov-free classpath — `bc-fips` and stock `bcprov` ship incompatible
`org.bouncycastle.crypto` classes and can never share one. Add BC-FIPS tests there, never to
`test`.

New behaviour needs a test that fails without the change. Security-relevant behaviour needs a test
that demonstrates the bad outcome is now impossible, not merely that the good path still works.

## Pull requests

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) — `feat:`,
`fix(vault):`, `test:`, `docs:`, `ci:`, `chore(deps):` — matching the existing log.

**If your change closes an issue, write `Closes #N` in the pull request description.** Put it there
rather than only in a commit message: a closing keyword in a commit does close the issue, but the
pull request is then not listed as a linked one, and the person who filed the issue loses the link
that would have carried them from it to the release your fix shipped in. If your change advances an
issue without finishing it, write `Refs #N` instead — a plain mention in the issue's timeline, which
carries the trail without closing anything or claiming to. Do not name the
release your change will appear in — that version is decided when the tag is cut, and the release
notes are generated then from the pull request labels below.

**Label your pull request.** The release notes are generated from PR labels
(`.github/release.yml`), so an unlabeled PR lands in "Other Changes" instead of the section it
belongs to:

| Label | Section |
|---|---|
| `breaking-change` | Breaking Changes |
| `security` | Security |
| `enhancement` | New Features |
| `bug` | Bug Fixes |
| `dependencies` | Dependencies |
| `documentation` | Documentation |
| `ignore-for-release` | omitted from the notes |

Categories are matched in that order and a PR appears in exactly one of them, so a PR that is both
breaking and a feature belongs under `breaking-change`. `security` sits above `bug` because the
same mechanism runs the other way there: a security fix is `fix:` by Conventional Commit, so unless
`security` was already on it when it was opened the labelling workflow gives it `bug` as well — and
anywhere below `bug` would be enough to keep it out of the Security section altogether.

Before merging, `main` requires the `quality` check and CodeQL analysis to pass. A change to prose
skips the heavy jobs automatically (`.github/workflows/detect-changes.yml`) and still reports
success — with one exception, `docs/VAPID.md`. Its key-generation snippet is executed by
`VapidGuideKeyGenerationTest`, straight out of the file, so editing that file runs the full quality
gate (about three and a half minutes rather than ten seconds), even for a typo fix. CodeQL still
skips: the snippet is executed, not compiled, and the tree it scans is unchanged.

One more thing gates a merge, and no check reports it: **nothing merges into `main` while the
Release workflow is running.** A release works from the commit it checked out, and a merge landing
underneath it breaks the run at its most expensive point. If *Actions → Release* shows a run in
progress, wait for it — it is a matter of tens of minutes. See
[`RELEASING.md`](docs/RELEASING.md#freeze-main-while-a-release-runs).

Also update, when your change touches them:

- `README.md` — the consumer-facing documentation. Keep Maven coordinates in the literal form
  `com.the13haven:<module>:X.Y.Z`; a release hook rewrites every such coordinate to the released
  version, matching any `X.Y.Z` — so do not write one to name a historical version.
- `docs/DESIGN.md` — the architecture, whenever the change moves it.
- **The reference document that owns the subject**, which is where most of a change's prose belongs:
  `docs/SPRING.md` for a `push2u.*` property, `docs/HEALTH.md` for the health indicator,
  `docs/VAULT.md` for the Vault Transit signer, `docs/SIGNER.md` for the `VapidSigner` contract and
  the conformance kit that checks one, `docs/TESTKIT.md` for the kit's other half — the fixtures and
  the transport fake a sending application tests with, so a change to what `ScriptedPushHttpClient`
  answers or what `SubscriptionFixture` publishes lands there — `docs/VAPID.md` for key generation,
  `docs/VAPID-KEY-ROTATION.md` for replacing a live VAPID identity, `docs/PUSH-SERVICES.md` for a
  browser push service's allowlist entry, `docs/OBSERVABILITY.md` for anything a deployment's
  instrumentation reads — an outcome variant added or renamed, a seam's signature, what a signer
  call costs, or a Spring bean condition that decides whether a wrapper can be installed at all —
  and `docs/MIGRATION-FROM-WEB-PUSH.md` for anything a reader arriving from
  `nl.martijndwars:web-push` compares against — that document states the other
  library's API and dependency set as verified facts, so an addition there is checked against the
  published artifact.
- `docs/MIGRATION.md` — whenever the change breaks a consumer upgrading from the previous release,
  and *especially* when it breaks one without breaking their compilation. A narrowed exception, a
  changed default, a value that used to be an exception, a stricter constructor: each of those
  compiles unchanged at the call site, so this document is the only warning anyone gets. Say what to
  do, not only what moved. The release notes are generated from pull request labels and cannot carry
  this. It holds one section per migration, newest first; the document's own introduction carries
  how a new one is added and why every heading in it has to be unique across the whole file.
- **A new file under `docs/`** — plus its row in the *Documentation* table of `README.md`, right
  after *Installation*. That table is the index of everything under `docs/`, and an index that skips
  one document is worse than no index.
- `docs/adr/` — a *new* file, plus its row in `docs/adr/README.md`, when the change settles
  something the existing ADRs do not cover or replaces a decision one of them records. Never an edit
  to an ADR that is already implemented, beyond the two the procedure there allows: the status line
  of a superseded one, and a link to a document that has been renamed.

## Public API

This is a published library, so anything `public` is a commitment: it appears on Maven Central and
cannot be removed without a breaking release. New public types and methods need Javadoc (enforced),
must stay compilable against Java 21, and should be as narrow as the use case allows. If you are
unsure whether something belongs in the API, open an issue before writing it.

## Licensing

Contributions are accepted under the [Apache License 2.0](LICENSE), the license the project is
released under. There is no separate CLA; opening a pull request means you agree your contribution
is licensed that way and that you have the right to submit it.
