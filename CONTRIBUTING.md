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
```

Reports land in `<module>/build/reports/`; aggregated coverage in
`build/reports/jacoco/testCodeCoverageReport/`.

## What the build enforces

Formatting (Spotless/Palantir), naming and Javadoc on the public API (Checkstyle), bug patterns
(PMD, SpotBugs, Error Prone) and the nullness contract (NullAway) all fail the build rather than
warn. Aggregated instruction coverage must stay at or above 80 %. Practical consequences:

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

  1. **A record's component accessor** keeps the component's name — `status()`, `statusCode()`.
     That is the language, not a preference: a `boolean delivered` component would have to be
     `delivered()`, and there is nothing to decide.
  2. **A question about state** is a predicate: `is…` for what something *is*
     (`PushResult.isDelivered()`, `Es256Verifier.isSupported()`), `has…` for what it holds,
     `can…` for what it is able to do. Whether the answer is stored, computed, or cached does not
     enter into it — `String.isEmpty()` computes, `isSupported()` caches, both are `is`.
  3. **An action or a relation keeps its verb**, with no prefix: `Es256Verifier.verify(...)`
     performs a check and reports the outcome, `endsMember(json, end)` reads as its own sentence,
     and a two-argument comparison like `sameCurve(actual, expected)` states a relation the way
     `Objects.equals` does. `isVerify` would be nonsense, and that is the tell.

  The distinction to get right is 2 against 3: a predicate answers *"is it so?"* about one thing,
  while a verb *does* something or relates two things.
- Vulnerable transitive dependencies are pinned with dependency **constraints**, never
  `resolutionStrategy.force` — force also records the originally requested version in the
  submitted dependency graph, and Dependabot then alerts on that phantom node. Each pin names its
  advisory.
- A pin goes where the dependency actually resolves, and never in a bucket that is published.
  `api` and `implementation` are inherited by `apiElements`/`runtimeElements`, so a constraint
  there is published — as `dependencyConstraints` in the module metadata and `dependencyManagement`
  in the POM — and Gradle applies it to every consumer's graph, which is the transitive surface
  ADR-002 exists to keep out. `push2u-core`'s `testFixturesApi`/`testFixturesImplementation` are
  published too, as the conformance kit. Pin in `testImplementation`, `fipsTestImplementation`, a
  tool configuration, or the buildscript instead, and check the result: no variant of any module
  should carry `dependencyConstraints` (`./gradlew generateMetadataFileForMavenPublication`, then
  read `<module>/build/publications/maven/module.json`).

## Tests

The RFC vectors are the specification, not a snapshot of current behaviour: RFC 5869 for HKDF,
the RFC 8291 worked example for encryption, RFC 8292 for VAPID structure. If a change makes a
vector fail, the change is wrong until proven otherwise.

Every `VapidSigner` implementation extends the published conformance kit
`com.the13haven.push2u.testkit.VapidSignerContractTest`, from `push2u-core`'s test fixtures. `push2u-core` also has a separate `fipsTest` source set on
a bcprov-free classpath — `bc-fips` and stock `bcprov` ship incompatible `org.bouncycastle.crypto`
classes and can never share one. Add BC-FIPS tests there, never to `test`.

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

Before merging, `main` requires the `quality` check and CodeQL analysis to pass. A
documentation-only change skips the heavy jobs automatically (`.github/workflows/detect-changes.yml`)
and still reports success.

Also update, when your change touches them:

- `README.md` — the consumer-facing documentation. Keep Maven coordinates in the literal form
  `com.the13haven:<module>:X.Y.Z`; a release hook rewrites exactly that string.
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
