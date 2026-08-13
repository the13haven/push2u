# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

push2u is a JVM Web Push library (RFC 8030/8188/8291/8292/5869): VAPID-authenticated,
`aes128gcm`-encrypted push delivery from a Java server to browser push services. Java 21 baseline,
Gradle multi-project build, published to Maven Central as `com.the13haven:*`.

Every reference document lives under `docs/`; the repository root keeps only what a newcomer or
GitHub's community profile looks for there — `README.md`, `CONTRIBUTING.md`, `SECURITY.md`,
`CODE_OF_CONDUCT.md`, `LICENSE` and this file.

`README.md` documents the public API for consumers; `docs/VAULT.md` and `docs/SPRING.md` carry the
reference for the two integrations, and `docs/VAPID.md` the one-time recipe for generating a VAPID
key pair — all three are what README introduces in a few lines and links to. `docs/VAPID.md` is the
one with a moving part: its `jshell` block sits between the `vapid-keygen:begin` /
`vapid-keygen:end` anchors and is executed by `VapidGuideKeyGenerationTest` out of the file itself,
so the anchors, the fenced block and the heredoc wrapper are load-bearing and
`.github/workflows/detect-changes.yml` treats an edit there as a build change — its `case` block
matches the path, so moving or renaming the file silently switches that off unless the pattern moves
with it. `docs/PUSH-SERVICES.md` is the operator-facing list of the four browser push services and
the allowlist entry each one needs, in both the Java and the YAML spelling — two origins, and two
domains for Apple's and Microsoft's zones, which both vendors publish as the thing an application
server should be allowed to reach. It also carries why no browser is missing from those four rows,
and a prose note on the pre-VAPID GCM host a stored subscription may still name. The library ships
none of them as a default and the document is there to be copied out of, so its names are a snapshot
of what the vendors publish rather than anything this repository verifies; it says so itself, and
names the two rows whose vendor page carries the host but not the last step to Web Push — those
clauses are load-bearing rather than caveats, and a citation swapped for a weaker one undoes them.
`docs/DESIGN.md` describes the architecture as it stands — why it is shaped this way, never
how to use it — and `docs/adr/` holds the decisions behind it, one file per ADR (ADR-001…022) with
`docs/adr/README.md` as the index. Read the relevant ADR before changing anything structural.
`docs/PERFORMANCE.md` records what one message costs step by step, per JCE provider, together with
the environment the numbers were taken on — a snapshot someone took, not an output the build
maintains, and README links consumers to it from the `cryptoProvider` section because the provider
choice turns out to be a throughput decision too. **The measurement suites are deliberately not in
this tree**: they live on the long-running `perf/hot-path-measurements` branch, because wiring a
measurement into `check` reports a shared runner's noise as a regression, and because a harness has
not earned a place in the build configuration of two published modules. A number in that document
that no longer holds is deleted rather than left to age.
`docs/MIGRATION.md` is the guide for consumers coming from `nl.martijndwars:web-push` — it states
the other library's API and dependency set as verified facts, so anything added there must be
checked against the published artifact. `docs/RELEASING.md` covers the release procedure,
`CONTRIBUTING.md` the contributor-facing form of the conventions below, and `SECURITY.md` the
vulnerability policy.

**An ADR is immutable once its decision is implemented.** It is not reworded, not brought up to date
with the code, and not amended. A decision that moves gets a *new* ADR with the next free number,
and the superseded one keeps its number, title and body while its status line becomes
`Superseded by ADR-NNN` — the only edit its body ever takes. A decision that moves only in part
takes the same one-line edit in a narrower form, `Accepted; one clause superseded by ADR-NNN`,
beside the full form rather than in place of it — ADR-004's status line, superseded in part by
ADR-019, is the worked example. The description of how things currently work belongs in
`docs/DESIGN.md`, which is the document that may be rewritten freely; `docs/adr/README.md` carries
the procedure.

**A `com.the13haven:<module>:X.Y.Z` coordinate in a living document belongs in `README.md` and
nowhere else.** The pre-release hook rewrites every one of them, in that file only, so the same
string written into `docs/VAULT.md`, `docs/SPRING.md`, `docs/VAPID.md`, `docs/MIGRATION.md` or
anywhere else freezes at whatever version it was written with and starts lying at the next release.
Those documents point at README's Installation section instead. The exception is a document that is
*about* one version and is never read as current: `.github/release-notes/vX.Y.Z.md` names its own
version on purpose, and a frozen coordinate there is correct.

`.claude/rules/workflow.md` carries the branch-implement-review-merge workflow, including who
approves a merge into `main` and how work that started from a tracker issue references it. It loads
automatically alongside this file.

Two skills hold the procedures that do not belong in this file:
`.claude/skills/push2u-implement/SKILL.md` for how recurring multi-file changes are made here, and
`.claude/skills/push2u-review/SKILL.md` for what a review of a change checks. A subagent inherits
this file but not the skill list, so read the matching one directly when the task calls for it.

**A vulnerability never goes in a public issue, pull request or commit message.** It is reported
through GitHub's private advisory channel (`SECURITY.md`), because the repository is public and a
description of a defect in the encryption, the VAPID signature or the endpoint policy discloses it
before a fix exists. This applies to anything you would file on the user's behalf. When one is
reported here and has to be fixed, `.claude/skills/push2u-advisory/SKILL.md` carries the procedure —
the ordinary branch-push-PR habit publishes the defect and cannot be undone.

## Commands

```bash
./gradlew build                  # compile + test only — quality tools are OFF in this path
./gradlew qualityCheck           # local gate: auto-formats (spotlessApply), then every analyser
./gradlew qualityCheckCi         # CI gate: verifies formatting instead of applying it
./gradlew javadoc
./gradlew currentVersion         # version derived from git tags (axion), not stored in the build
```

Targeted runs:

```bash
./gradlew :push2u-core:test --tests "com.the13haven.push2u.HkdfTest"
./gradlew :push2u-core:test --tests "*PushSender*"
./gradlew :push2u-core:fipsTest                 # BC-FIPS suite, separate source set (see below)
./gradlew :push2u-signer-vault:test             # needs Docker: Testcontainers Vault dev container
./gradlew spotlessApply                         # after a formatting failure
./gradlew aggregateTestResults                  # all modules' JUnit XML into build/test-results-aggregated/
```

Reports: `<module>/build/reports/` (HTML + XML); aggregated coverage in
`build/reports/jacoco/testCodeCoverageReport/`.

Notes that matter in practice:

- **`build` will not catch quality violations.** Checkstyle, PMD, SpotBugs, Spotless, Error Prone
  and NullAway are disabled unless `qualityCheck`/`qualityCheckCi` is in the task graph (or the tool
  task is named explicitly on the command line). Run `qualityCheck` before considering a change done.
  This was already incomplete before `-Xwerror` existed: `javadoc` sits in `build`'s graph regardless
  of that discipline — `assemble` pulls in `javadocJar`, which pulls in `javadoc` — because it is not
  a quality tool hooked to `check` but the task that produces a published artifact, and the
  discipline above disables only what rides along with `check`; there is nothing about `javadoc` for
  it to disable. A doclint error has therefore always failed a plain `build`; `-Xwerror` only widens
  what a plain `build` catches from doclint errors to any javadoc warning, on the same always-on
  task.
- Checkstyle/PMD/SpotBugs analyse `main` sources only. Error Prone also covers test compilations
  (defects, not style); NullAway covers `main` and `testFixtures`.
- Aggregated JaCoCo threshold is 80 % of instructions, enforced by `testCodeCoverageVerification`,
  which both quality lifecycle tasks depend on.
- The Vault integration test needs a Docker daemon. `TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE` defaults
  to `/var/run/docker.sock` (set in the root build for Colima); export it for rootless/remote Docker.
- CI runs `qualityCheckCi --no-build-cache` — a cached test result from a Docker-less environment
  would silently turn the Vault test into a skip.

## Module structure

```
push2u-core                                  no runtime implementation dependencies (JSpecify only)
  ├── push2u-testkit                         api(push2u-core) + JUnit/AssertJ — the published
  │                                          conformance kit, for a consumer's TEST classpath
  ├── push2u-signer-vault                    api(push2u-core)
  │     └── push2u-signer-vault-spring-boot-starter
  └── push2u-spring-boot-starter             api(push2u-core) + Spring Boot 4 autoconfigure
```

Packages are `com.the13haven.push2u` plus `.signer.vault`, `.spring`, `.signer.vault.spring`, and
`.testkit` for the published conformance kit, which is the whole of `push2u-testkit`.

`push2u-core` and `push2u-signer-vault` are explicit JPMS modules named after their package
(ADR-014); the starters and the test kit are automatic modules with a fixed `Automatic-Module-Name`.

**The core's zero-dependency constraint is load-bearing (ADR-002).** `push2u-core` declares exactly
one non-test dependency: JSpecify (annotations, no code, `api` so the nullness contract travels to
consumers). The library exists to replace `nl.martijndwars:web-push`, which leaked a heavy
transitive surface into its API — do not add a runtime dependency to the core, and do not let Spring
or Vault types reach it.

## Architecture

`PushSender` is the facade; `send`/`sendAsync` run one pipeline (docs/DESIGN.md §4):

size preconditions → `EndpointPolicy` → decode subscription key → ephemeral P-256 + salt → ECDH +
HKDF-SHA-256 → one AES-128-GCM RFC 8188 record → VAPID JWT → **one** POST via `PushHttpClient` →
`PushOutcome`.

**The library does not retry (ADR-021).** `send` performs exactly one POST and publishes the
classification a repeat decision needs; the schedule is the caller's. `PushOutcome` is sealed:
`Accepted` (`2xx`) · `SubscriptionExpired` (`404`/`410`, a value and not an exception — ADR-007) ·
`RetryableFailure(statusCode, retryAfter)` (`408`, `421`, `429`, a `413` carrying a parseable
`Retry-After`, and the 5xx class except `501`, `505`, `506`, `508`, `511`) · `NonRetryableFailure`
(everything else answered) · `Indeterminate` (the POST went out, nothing answered) · and the
`NotAttempted` marker over `SignerUnavailable`, `PayloadRejected` and `EndpointRejected`. The
`Retry-After` is reported with no ceiling applied.

Exactly three seam signals convert (ADR-022's taxonomy, ADR-021's sorting):
`EndpointRejectedException` → `EndpointRejected`; `VapidSignerUnavailableException` →
`SignerUnavailable`; `PushDeliveryException` → `Indeterminate`. Any other `RuntimeException` from a
consumer seam is a defect and propagates. `send` itself throws `PushCryptoException` (a defect, an
unusable substrate, a misconfiguration that recurs), `PushInterruptedException` (recognised by the
facade's disjunction — an `InterruptedException` in the chain *or* the thread's interrupt flag —
never by a seam), and `IllegalArgumentException`/`NullPointerException`.

Three SPIs, and only three (ADR-005):

- `VapidSigner` — key custody. Contract: raw 64-byte `r||s` ES256 signature, 65-byte uncompressed
  P-256 public point, both returned as fresh arrays the caller owns (the kit checks that by array
  identity). Implementations: `LocalEcVapidSigner`, `VaultTransitVapidSigner`.
- `PushHttpClient` — push transport. Response bodies are never read (untrusted capability URLs).
- `EndpointPolicy` — deployment egress policy (SSRF control). A required argument of both
  `PushSender.builder` overloads, so no sender exists without one (ADR-016). The standard
  implementation is an allowlist of `EndpointRule` values (ADR-017): `allowedEndpoints` takes a
  mixed list and is the primary cross-browser call, `allowedOrigins`/`allowedDomains` are the
  single-kind convenience over it, and `EndpointPolicies.unrestricted()` is the named opt-out.
  `EndpointRule` is sealed, its two implementations private and its match package-private — a
  closed enumeration of kinds, not a fourth SPI. An origin rule matches one origin exactly; a
  domain rule covers the apex and every subdomain at a label boundary, `https` and the default
  port only. Under Spring the allowlist comes from `push2u.allowed-origins` and
  `push2u.allowed-domains`, which are unioned rather than exclusive, or from an `EndpointPolicy`
  bean; the exclusivity is between the properties and the bean, neither present fails the context,
  and there is deliberately no property for the unrestricted mode.

The encryptor, HKDF and origin serialization are deliberately concrete — an alternative
implementation would only add a silent wrong-ciphertext failure mode (ADR-003).

`push2u-signer-vault` has its own `VaultHttpTransport` seam rather than reusing `PushHttpClient`:
the two face opposite trust domains — Vault responses must be read (bounded, timed out), push
responses must not be.

The Spring starters bind `push2u.*` / `push2u.signer.vault.*` and fail at startup with the YAML
property name in the message rather than surfacing the builder's camelCase parameter. The Vault
starter is ordered before the core starter and outranks the local signer.

## Conventions

- **Nullness:** every package's `package-info.java` carries JSpecify `@NullMarked`. NullAway plus
  `RequireExplicitNullMarking` fail the build on a violation or a new unmarked package — a new
  package needs its `package-info.java` with the mark. Both checks cover `main` **and
  `testFixtures`**, and stop before `test`/`fipsTest`. NullAway runs in `OnlyNullMarked` mode, so
  coverage follows the `@NullMarked` scope rather than the source set: both modules' fixtures
  deliberately share `main`'s package and inherit its mark from the classpath, so they need no
  `package-info.java` of their own and cost nothing to keep covered. `test`/`fipsTest` are left out
  because that is where a nullness complaint is least likely to be a defect — not for lack of a
  mark, which they also inherit.
- **A new public package in `push2u-core` or `push2u-signer-vault` needs an `exports` line** in that
  module's `module-info.java` (ADR-014). Nothing fails without it — tests run on the class path —
  but every module-path consumer gets "package … is not visible" once the version is published.
- **Formatting:** Palantir Java Format via Spotless is authoritative. Import order is
  static imports, `java`, everything else, `com.the13haven.push2u` (Checkstyle verifies the same
  grouping).
  Checkstyle requires Javadoc on the public API.
- **Boolean naming** (CONTRIBUTING.md carries the full form, nothing enforces it): a record's
  component accessor keeps the component's name (`Health.enabled()`) because the language says so;
  a question about state is `is…`/`has…`/`can…` regardless of whether the answer is stored or
  computed (`isSupported()`, the token cache entry's `isFresh(...)`); an action or a two-argument
  relation keeps its verb (`verify(...)`, `sameCurve(a, b)`). The failure it prevents is a derived
  predicate wearing a component accessor's name, so that a judgement reads as one more stored value
  — `VaultHttpResponse` carries `statusCode()`, `body()` and `retryAfter()`, so a question derived
  from them is `isRateLimited()` and never `rateLimited()` — and the pair that takes judgement is
  predicate against verb. A name an interface fixes (`getBody()`, from the JDK) is not ours.
- **Builders** (CONTRIBUTING.md carries the full form): required parameters go into the factory
  method, optional ones become builder steps — `PushMessage.builder(payload)`,
  `PushSender.builder(keys, contact, endpointPolicy)`. The firm rule is that `build()` must not be
  able to refuse over a missing required value: that is the compiler's job, not the runtime's (an
  invalid-but-present value still gets an `IllegalArgumentException` at the factory). Several
  same-typed required values are made swap-proof by value types, not by argument order —
  `TransitKeyName` and `VaultToken` cannot be transposed, and a value type earns its place by also
  carrying validation or redaction, as `VaultToken` carries its character-set validation and a
  redacting `toString()`. A staged builder (one type per required step) is for genuinely many
  required values, four-five up; its steps must be public and exported, with `sealed` — not
  package-hiding — keeping them closed.
  One way to assemble a type means `builder()`; several ways that differ in *contract* get one
  `builderWith<what exactly>()` each and no bare `builder()` (`builderWithFetchedPublicKey(…)`
  reads Vault inside `build()`, `builderWithSuppliedPublicKey(…)` does nothing over the network).
  Entry points differing only in a required parameter are overloads: `PushSender.builder(keys,
  contact, endpointPolicy)` / `builder(signer, contact, endpointPolicy)`.
- **Licence header:** every `.java` file in every source set opens with the Apache-2.0 SPDX header
  from `config/quality/license/header.txt` (ADR-008), and the build fails without it. Spotless
  writes it into a new file on `qualityCheck` and verifies it on `qualityCheckCi`. Two file kinds
  are the exception: `package-info.java` and `module-info.java`, which `LicenseHeaderStep` skips by
  name because their leading Javadoc would be mistaken for an old header and replaced — write the
  header by hand there. Checkstyle's `RegexpHeader` is what catches its absence, on `main` through
  `checkstyle.xml` and on every other source set through `checkstyle-header.xml` and the
  `checkstyleLicenseHeader` task — the split exists because `checkstyleMain` cannot parse `main`'s
  `module-info.java`. **The year is the year the file was created and is never updated
  afterwards**, so the tree holds a spread of years on purpose; a new file gets the current one
  automatically. `LICENSE` itself keeps the canonical Apache appendix with its `[yyyy]` placeholder
  — the notice belongs in the files, and each published jar carries the licence as
  `META-INF/LICENSE`.
- **Published code explains itself.** Every module ships a `sources.jar`, so a comment or Javadoc in
  a `main` source set is read by consumers who have no clone of this repository: "ADR-014" or "see
  `DESIGN.md`" is a dead end for them. State the reason in the text instead — `// ADR-002's
  zero-dependency claim` becomes a sentence saying what this code keeps true. Checkstyle's
  `checkstyleReferences` task fails the build on `ADR`, a `*.md` filename or `readme` in any case,
  anywhere in `main`. A URL is exempt — any whitespace-delimited token containing `://`, whatever
  `#`, `?` or `%` it carries — because a link the consumer can open is not a dangling pointer; the
  exemption covers that token and not the rest of the line. Test sources are free to cite whatever
  they like. The rule reads lines rather than an AST, which is what lets it cover `module-info.java`
  and `package-info.java`.
- **Suppressions:** a rule exclusion carries a comment stating why; a per-file exception is a
  `@SuppressWarnings("PMD.<Rule>")` at the narrowest scope, next to the reason.
- **Gradle 10 readiness:** the build avoids removed idioms on purpose — `register<Type>(name)` not
  `by registering`, `project(":path")`/`testFixtures(project(":path"))` not the `Project` object,
  `sourceSets.create(...)` not `by sourceSets.creating`. Keep new build code in the same style.
- **Versions:** never hardcode a version. `libs.versions.toml` holds every dependency and tool
  version; the project version comes from `vX.Y.Z` git tags via axion. The README's Maven
  coordinates must stay in the literal form `com.the13haven:<module>:X.Y.Z` — a pre-release hook
  rewrites every one of them to the released version, matching any `X.Y.Z` — so a coordinate written
  to name a *historical* version (in a migration note, say) would be silently bumped; put such a
  version somewhere other than a `com.the13haven:<module>:` coordinate. Some versions cannot live in
  the catalog and are not violations of this rule: the JDK toolchain (the root build plus each of
  the five workflows that set up a JDK) and `--release 21` (the root build only); GitHub Action
  versions, major-tag pinned and Dependabot-managed; the Testcontainers image tag in the Vault test;
  and **Gradle's own version**, in `gradle/wrapper/gradle-wrapper.properties` beside a
  `distributionSha256Sum` — which makes bumping it a procedure, CONTRIBUTING.md, *Upgrading Gradle*.
  The `wrapper` task refuses to drop the checksum silently, so a wrong move there fails loudly
  rather than weakening the build. Those are the *declaration* sites; a JDK bump also stales the
  prose in `README.md` and `CONTRIBUTING.md` that names the toolchain.
- **Security pins:** vulnerable transitives are pinned with dependency *constraints*, never
  `resolutionStrategy.force` (force leaks the originally requested version into the submitted
  dependency graph and Dependabot alerts on that phantom node). Each pin names its advisory.
- **Commits/PRs:** Conventional Commits (`feat:`, `fix(vault):`, `ci:`, `test:`, `docs:`). The
  release notes are generated from PR *labels* (`.github/release.yml`), and
  `.github/workflows/label-pull-request.yml` derives them from the title — `feat:` →
  `enhancement`, `fix:` → `bug`, `docs:` → `documentation`, a `!` marker → `breaking-change`. It
  never overrides a label already set. Everything else is manual: `security` in particular is a
  judgement about impact that no title prefix carries, and `test`/`ci`/`chore`/`refactor` are left
  to fall into "Other Changes" rather than guessed at. Merges into `main` are squash-only, and
  `main` requires `quality` plus both CodeQL analyses.

## Testing notes

- `push2u-core` has a hand-rolled `fipsTest` source set on a **bcprov-free** classpath: `bc-fips`
  and stock `bcprov` both ship `org.bouncycastle.crypto` with incompatible
  `CryptoServicesRegistrar` classes and can never share a classpath. `fipsTest` covers the ES256
  DER-fallback path; the regular `test` set carries bcprov for the raw-`r||s` path. It is wired into
  `check`, and its `jacoco/fipsTest.exec` is added to the aggregated coverage report explicitly.
- **The shared test plumbing lives in `push2u-core`'s `testFixtures`** — `TestVectors`,
  `MockPushReceiver`, `LoopbackTls`, `PushTestSupport`, in `main`'s package because they need
  package-private access to `EcKeys`/`Jca`. `test` and `fipsTest` each depend on it as ordinary
  consumers, which is what keeps the two BouncyCastle flavours apart; the fixtures themselves name
  neither provider. They are **not** published: the variants are skipped from the publication, as
  `push2u-signer-vault` does with its internal `RecordingHttpClient`.
- `push2u-testkit` is the published `VapidSignerContractTest` conformance kit and nothing else —
  every signer implementation extends it, from this build or outside it. Its package
  `com.the13haven.push2u.testkit` is separate from the core's because the core is an explicit JPMS
  module and cannot share a package with a second artifact on the module path (ADR-014). Being a
  module's `main`, the kit is under the full analyser set.
- Conformance is pinned by published RFC vectors (RFC 5869 HKDF, the RFC 8291 worked example,
  RFC 8292 structure). When touching crypto, the vectors are the specification — not the current
  output.
