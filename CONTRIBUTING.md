# Contributing to push2u

Thanks for taking the time. This document covers what the build expects and what a reviewer will
look for, so that neither is a surprise at pull-request time.

**Found a security problem? Do not open an issue.** Follow [`SECURITY.md`](SECURITY.md) — the
report stays private until a fix is released.

Questions and half-formed ideas belong in
[Discussions](https://github.com/the13haven/push2u/discussions); the issue tracker is for defects
and accepted work. Participation is covered by the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

Read [`DESIGN.md`](DESIGN.md) for the architecture, and its ADRs (§9) for the decisions that are
already settled. Two of them shape most contributions:

- **ADR-002, zero-dependency core.** `push2u-core` declares exactly one non-test dependency:
  JSpecify, an annotation-only jar. A change that adds a runtime dependency to the core will not
  be accepted — the library exists to replace one that leaked a heavy transitive surface into its
  API. Framework and remote-system integrations live in the optional modules.
- **ADR-005, two SPIs in the core** (plus `EndpointPolicy`, added later under the same test). New
  extension points need an articulable reason the library cannot decide the behaviour for the
  deployment. Protocol steps stay concrete.

If a change contradicts an ADR, that is not automatically wrong — but it has to amend the ADR in
the same pull request, with the reasoning, rather than leave the document describing a design the
code no longer follows.

The [non-goals](DESIGN.md#non-goals) are equally settled: subscription persistence, browser-side
code, legacy `aesgcm`, general JSON parsing.

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

Formatting (Spotless/Palantir), naming and Javadoc on the public API (Checkstyle), bug patterns
(PMD, SpotBugs, Error Prone) and the nullness contract (NullAway) all fail the build rather than
warn. Aggregated instruction coverage must stay at or above 80 %.

| Tool                 | What it enforces                                            | Configuration                                |
|----------------------|-------------------------------------------------------------|----------------------------------------------|
| Spotless             | Palantir Java Format, import order                           | `build-logic/.../push2u-quality.gradle.kts`  |
| Checkstyle           | Naming, Javadoc on the public API, import grouping           | `config/quality/checkstyle/checkstyle.xml`   |
| PMD                  | Best practices, design, error-prone patterns, performance    | `config/quality/pmd/ruleset.xml`             |
| SpotBugs             | Bytecode-level bug patterns                                  | `config/quality/spotbugs/exclusions.xml`     |
| Error Prone + NullAway | Compiler-attached checks; a named set and the nullness contract fail the build | `build-logic/.../push2u-quality.gradle.kts` |
| JaCoCo               | Aggregated coverage, minimum 80% of instructions             | `build.gradle.kts`                           |

Checkstyle, PMD and SpotBugs run on `main` sources only — test code is exempt. Error Prone covers
the test compilations as well, since its checks are about defects rather than style; NullAway runs
on `main` and on `testFixtures`, which share `main`'s packages and so its nullness contract.
Practical consequences:

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
- A rule exclusion carries a comment saying why. A per-file exception is a
  `@SuppressWarnings("PMD.<Rule>")` at the narrowest scope that covers it, next to its reason.
- **Boolean methods are named by what they are, in three kinds.** Checkstyle does not enforce this
  and cannot; the point of writing it down is that one type should not end up with two habits, as
  `PushResult` did before `delivered()` became `isDelivered()`.

  1. **A record's component accessor** keeps the component's name — `Push2uProperties.Health`
     holds a `boolean enabled`, so its accessor is `enabled()`. That is the language, not a
     preference: the component names the method, and there is nothing to decide.
  2. **A question about state** is a predicate: `is…` for what something *is*
     (`PushResult.isDelivered()`, `Es256Verifier.isSupported()`), `has…` for what it holds,
     `can…` for what it is able to do. Whether the answer is stored, computed, or cached does not
     enter into it — `String.isEmpty()` computes, `isSupported()` caches, both are `is`.
  3. **An action or a relation keeps its verb**, with no prefix: `Es256Verifier.verify(...)`
     performs a check and reports the outcome, `endsMember(json, end)` reads as its own sentence,
     and a two-argument comparison like `sameCurve(actual, expected)` states a relation the way
     `Objects.equals` does. `isVerify` would be nonsense, and that is the tell.

  The failure this exists to prevent is 1 against 2 — a derived predicate wearing a component
  accessor's name, which is what `delivered()` did next to `status()` and `attempts()` until it
  became `isDelivered()`. The pair that takes judgement to apply is 2 against 3: one subject and a
  question about it is a predicate; two subjects, or something performed, is a verb.

  A name fixed by an interface or superclass is not ours to choose — `getBody()` in
  `JdkVaultHttpTransport` overrides the JDK's `BodySubscriber` and stays as the JDK named it.
- **Required parameters go into the factory method, optional ones become builder steps.** That is a
  firm rule, not a preference, and its firm consequence is this: `build()` must not be able to
  refuse over a missing required value — making an incomplete object inexpressible is the
  compiler's job, not the runtime's. `PushMessage.builder(payload)` takes the payload because there
  is no message without one; `PushSender.builder(keys, contact)` takes the key source and the
  contact for the same reason; and everything either builder still exposes is genuinely optional.
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
  `builder(…)` instead: `PushSender.builder(keys, contact)` and `PushSender.builder(signer,
  contact)` share one contract, so they share one name.
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

The suite is the RFC vectors, the sender and retry tests, the Spring Boot auto-configuration tests
and a Vault Transit integration contract run against a Testcontainers Vault.

The RFC vectors are the specification, not a snapshot of current behaviour: RFC 5869 for HKDF,
the RFC 8291 worked example for encryption, RFC 8292 for VAPID structure. If a change makes a
vector fail, the change is wrong until proven otherwise.

Every `VapidSigner` implementation extends the published conformance kit
`com.the13haven.push2u.testkit.VapidSignerContractTest`, the whole of the `push2u-testkit` module.
It is a module's `main` source set, so the full analyser set applies to it — treat it as published
API, because it is.

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

**Label your pull request.** The release notes are generated from PR labels
(`.github/release.yml`), so an unlabeled PR lands in "Other Changes" instead of the section it
belongs to:

| Label | Section |
|---|---|
| `breaking-change` | Breaking Changes |
| `enhancement` | New Features |
| `bug` | Bug Fixes |
| `security` | Security |
| `dependencies` | Dependencies |
| `documentation` | Documentation |
| `ignore-for-release` | omitted from the notes |

Categories are matched in that order, so a PR that is both breaking and a feature belongs under
`breaking-change`.

Before merging, `main` requires the `quality` check and CodeQL analysis to pass. A change to prose
skips the heavy jobs automatically (`.github/workflows/detect-changes.yml`) and still reports
success — with one exception, `README.md`. Its VAPID key-generation snippet is executed by
`ReadmeVapidKeyGenerationTest`, straight out of the file, so editing that file runs the full quality
gate (about three and a half minutes rather than ten seconds), even for a typo fix. CodeQL still
skips: the snippet is executed, not compiled, and the tree it scans is unchanged.

One more thing gates a merge, and no check reports it: **nothing merges into `main` while the
Release workflow is running.** A release works from the commit it checked out, and a merge landing
underneath it breaks the run at its most expensive point. If *Actions → Release* shows a run in
progress, wait for it — it is a matter of tens of minutes. See
[`RELEASING.md`](RELEASING.md#freeze-main-while-a-release-runs).

Also update, when your change touches them:

- `README.md` — the consumer-facing documentation. Keep Maven coordinates in the literal form
  `com.the13haven:<module>:X.Y.Z`; a release hook rewrites every such coordinate to the released
  version, matching any `X.Y.Z` — so do not write one to name a historical version.
- `DESIGN.md` — the architecture and its ADRs.

## Public API

This is a published library, so anything `public` is a commitment: it appears on Maven Central and
cannot be removed without a breaking release. New public types and methods need Javadoc (enforced),
must stay compilable against Java 21, and should be as narrow as the use case allows. If you are
unsure whether something belongs in the API, open an issue before writing it.

## Licensing

Contributions are accepted under the [Apache License 2.0](LICENSE), the license the project is
released under. There is no separate CLA; opening a pull request means you agree your contribution
is licensed that way and that you have the right to submit it.
