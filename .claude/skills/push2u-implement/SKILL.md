---
name: push2u-implement
description: How to make a change in the push2u Web Push library — the procedures and constraints that are not visible from the code being edited. Consult it before writing or changing any library or build code here, including a change that looks local or one-line, because most changes here have required companions elsewhere — a builder option also needs a Spring property, startup validation, docs and tests; a protocol or crypto fix has an RFC clause and a published vector that decide what is correct; a new public member is permanent once released; a vulnerable transitive is pinned by constraint rather than force; a BC-FIPS test belongs in its own source set. Use it for fixing a bug in the encryption, VAPID, endpoint, outcome-classification or Vault code, adding or changing a configuration option, writing a new VapidSigner or transport, avoiding a new dependency in the zero-dependency core, pinning an advisory, and working out everything a change touches.
---

# Implementing a change in push2u

This is how work gets done in this repository — the procedures that span more than one file and are
easy to complete only halfway. It does not restate what is already written elsewhere: `CLAUDE.md`
carries the facts that are always true, `docs/DESIGN.md` the architecture as it stands, `docs/adr/`
the settled decisions, and `.claude/skills/push2u-review/SKILL.md` what a reviewer will check when
you are finished.

If you delegate part of the work to a subagent, note that it starts fresh and does not inherit this
skill — only the repository's `CLAUDE.md` reaches it. Put the relevant recipe in the delegation
prompt, or tell it to read this file first; otherwise the half of the work that spans other files is
exactly the half that gets left out.

## The working loop

`./gradlew build` compiles and tests; it does **not** run the analysers. The real gate is
`./gradlew qualityCheck`, which also formats your code. Run it before you commit, not after — then
the formatter's changes are part of your commit instead of a follow-up that muddies the diff.

While iterating, run the narrowest thing that answers your question:

```bash
./gradlew :push2u-core:test --tests "com.the13haven.push2u.WebPushEncryptorTest"
./gradlew :push2u-core:fipsTest
./gradlew :push2u-signer-vault:test        # needs Docker — Testcontainers starts a Vault
```

Because the gate will catch formatting, import order, missing Javadoc on public API, an unmarked new
package in a checked source set and unused imports, do not spend attention hand-checking them. Write
the code, run the gate.

NullAway and `RequireExplicitNullMarking` run over `main` **and `testFixtures`**, and stop before
`test`/`fipsTest`. NullAway is in `OnlyNullMarked` mode, so coverage follows the `@NullMarked` scope
rather than the source set, and the scope comes from a `package-info.java` — wherever it lives.

Every fixtures package that exists today sits in the package of its own `main` and inherits the
mark from its `package-info.class` on the compile classpath, so **do not add a `package-info.java`
beside them**: it would be a second class file for a package `main` already marks, which javac
compiles silently rather than refusing. If you put a fixtures class in a package `main` does *not*
have, `RequireExplicitNullMarking` will fire — and then the fix is the ordinary one, a
`package-info.java` for that new package. Move the class into `main`'s package only if it actually
needs package-private access to internals, which is the sole reason the current fixtures live
there; doing it to satisfy the check would deepen a split package across two jars for nothing.

One thing the gate does **not** catch: a new public package in `push2u-core` or
`push2u-signer-vault` needs an `exports` line in that module's `module-info.java`. The tests run on
the class path, so a missing one stays invisible until a module-path consumer hits "package … is not
visible" after the release.

The same goes for the Apache-2.0 SPDX licence header every `.java` file carries: `qualityCheck`
writes it into a new file with the current year, and leaves the year alone from then on. The one
thing the gate cannot do for you is `package-info.java` and `module-info.java` — Spotless skips both
by name so it cannot swallow their Javadoc, so a new package means copying the header in by hand.
Checkstyle fails the build if you forget.

**A comment or Javadoc in a `main` source set may not point at this repository.** Every module ships
a `sources.jar`, so those lines are read by people holding the artifact and nothing else: `(ADR-014)`
or "see `DESIGN.md`" is a dead end for them. Write the reason into the sentence — what this code
keeps true, not where the decision is filed. The `checkstyleReferences` task fails the build on
`ADR`, any `*.md` filename and the word `readme` in any case, anywhere in `main` —
`module-info.java` and `package-info.java` included, since it reads lines rather than an AST. A URL
is exempt — any whitespace-delimited token containing `://`, anchors and query strings included,
because a consumer can follow it — and test sources may cite whatever they like.

## Changing encryption, VAPID or protocol behaviour

**Start from the clause, not from the code.** Find the RFC paragraph that governs what you are
changing and cite it in the code comment or the test name. Every existing rule here does this, and
it is what makes the next reader able to tell a deliberate choice from an accident.

**Then start from the vector.** `TestVectors` (in `push2u-core`'s `testFixtures`, package
`com.the13haven.push2u`) holds the published vectors transcribed verbatim — the RFC 8291 §5 worked
example, the RFC 8292 §2.4 example, RFC 5869 HKDF. They are the specification: if your change alters
output, the vectors are what decide whether the new output is right. Extend them when you cover a
new case; never adjust one to match what the code now produces. A vector that moves because code
moved has stopped being evidence of anything.

Write the failing test before the fix — specifically the test that would have caught the bug. For
security-relevant behaviour, aim the test at the bad outcome being impossible, not at the good path
still working; the second passes for reasons that have nothing to do with your change.

Two habits particular to this code:

- **One rule, one implementation.** The RFC 8291 §4 record-size rule lives once, as the inverse
  pair `WebPushEncryptor.maxPlaintextForRecordSize` / `recordSizeForMaxPlaintext`: the encryptor's
  `checkRecordSize` refusal reads one direction, and the sender's `build()`-time derivation of `rs`
  from the body ceiling reads the other — one place decides the rule whichever way it is asked.
  When you find yourself writing a second copy of a protocol rule, put it where the first one
  lives.
- **Size arithmetic in `long`.** A payload above `Integer.MAX_VALUE - 103` wraps negative in `int`
  and passes any limit check. If you touch the size path, keep the sums wide and keep the boundary
  test.

## Adding a configuration option

This is the procedure most often left half-finished, because the useful part works after step 1.

1. **Core builder.** Add the setter on `PushSender.Builder`, validate the value where it is set (not
   at send time), and document the unit and the default in Javadoc. Validation belongs here because
   this is where the constraint is known — the builder rejects a `maxEncryptedBodyBytes` below the
   fixed 103-octet `aes128gcm` overhead regardless of who is calling.

2. **Starter property.** Add the component to `Push2uProperties`. Leave it nullable and let `null`
   mean "keep the builder default" — that is the pattern `jwt-expiry`, `default-ttl` and
   `max-encrypted-body-bytes` all follow, and it keeps the default in one place
   instead of two.

3. **Wire it, and translate the error.** In `Push2uAutoConfiguration`, forward the value through
   `applyIfPresent`, which skips a `null` and re-throws a rejection with the YAML property name in
   front:

   ```java
   applyIfPresent(properties.maxEncryptedBodyBytes(), builder::maxEncryptedBodyBytes, "push2u.max-encrypted-body-bytes");
   ```

   The builder's own message names its camelCase parameter, which is not what the operator wrote in
   their YAML. The helper keeps the cause — the original message carries the actual constraint.
   Use it rather than writing the try/catch inline: four inline copies is what pushed
   `pushSender(...)` past PMD's complexity thresholds, and a fifth would do it again.

   `applyIfPresent` is the only helper there is now, and it works because every property the starter
   forwards reaches a *setter* that validates that one value. A property group that instead reached
   a constructor validating several at once could not be attributed this way — one constructor call
   rejects on behalf of any of its arguments — and would need a probe per key, offering the
   constructor one real value and filling the rest with values it accepts regardless. The starter
   had exactly one such group, `push2u.retry.*`, and it went with the retry loop; if a change ever
   introduces another, that shape is what it needs, along with a test sampling the invariant the
   attribution rests on — that the filler values stay acceptable beside any value of the key being
   probed.

4. **Document it.** The README property table, and the protocol-limits section if the option changes
   a limit. `docs/DESIGN.md` too if it changes the pipeline's contract rather than a number.

5. **Test all three levels.** The builder's validation in `push2u-core`, the binding in
   `Push2uPropertiesTest`, and the wiring in `Push2uAutoConfigurationTest` — including the failure
   case, asserting that the message names the YAML property. That assertion is the only thing
   keeping step 3 from silently regressing.

## Writing a new VapidSigner

The contract is narrow and unforgiving: `sign` returns a raw 64-byte P-256 `r || s` ES256 signature,
`publicKey` returns the 65-byte uncompressed point. A signer that returns DER, or a compressed
point, will produce a JWT that push services reject with no useful diagnostic.

- Extend `VapidSignerContractTest` from the published `push2u-testkit` module (package
  `com.the13haven.push2u.testkit`). That is what the kit is published for, and it is the cheapest
  way to find out you got the encoding wrong.
- If the signer talks to a network service, give it **its own transport seam**. Do not reuse
  `PushHttpClient`: it exists for a domain where response bodies are never read, and a key service's
  responses must be read. Bound them by streamed byte count, fail closed rather than truncating, and
  put a timeout on the request itself, not just the connection — a service that accepts a connection
  and never answers would otherwise hang application startup.
- A remote signer belongs in its own optional module (`api(project(":push2u-core"))`), never in the
  core.
- If the module has test fixtures, skip their variants from the publication the way
  `push2u-signer-vault` and `push2u-core` both do — otherwise an internal helper becomes frozen API
  on the next release. Every set of fixtures in this build is internal scaffolding; a test artifact
  meant for consumers is a published module of its own, which is what `push2u-testkit` is.

## Solving it without a new dependency

`push2u-core` has no runtime implementation dependency and that is a design constraint, not an
accident (ADR-002) — the library exists to replace one that dragged a heavy transitive surface into
its public API. Work through the options in this order:

1. **A JDK API.** Most of what this library needs is already in `java.net.http`, `java.security`,
   `javax.crypto` and `java.util.Base64`.
2. **A minimal, purpose-built implementation, with the reason in a comment.** The precedent is the
   Vault module's targeted extraction of `data.signature` from a JSON response: it is not a JSON
   parser and does not try to be, it is bounded, and it fails closed. Narrow beats general here
   because the failure mode of general parsing is a surprise, and the surprise is in a security
   path.
3. **A real library** — then it goes in an optional module and never in the core, and that is an
   ADR-level decision to argue in the pull request (a *new* file in `docs/adr/`, since ADR-002
   itself is immutable), not a dependency line to slip in.

Test-scoped dependencies and `compileOnly` in the starters are not exceptions to this: neither
reaches a consumer's runtime classpath. Framework artifacts in the starters stay BOM-managed so
their versions are governed in one place.

## Pinning a vulnerable dependency

The advisory usually lands on a transitive that no manifest here declares, so the fix is a
dependency **constraint**, never `resolutionStrategy.force` — force also records the originally
requested version in the submitted dependency graph, and Dependabot then alerts on that phantom node
forever.

```kotlin
constraints {
    add("checkstyle", "org.apache.commons:commons-lang3:3.18.0") {
        because("CVE-2025-48924")
    }
}
```

Where it goes depends on whose classpath it is: build tooling that runs the build lives in the
`buildscript` block of the root `build.gradle.kts`; analyser tool classpaths live with the tool in
the `push2u-quality` convention plugin; anything on a module's own classpath goes in the
`subprojects` constraint block. Name the advisory, and say in a comment whether the vulnerable path
is one this project actually takes — that is what tells the next maintainer whether the pin can be
dropped when the tool upgrades.

## Provider-specific and BC-FIPS tests

The ES256 path has two shapes: providers that offer native `SHA256withECDSAinP1363Format`, and
providers that offer only DER-format `SHA256withECDSA` and need strict conversion. Both need
covering, and the two providers cannot share a classpath — `bc-fips` and stock `bcprov` both ship
`org.bouncycastle.crypto` with incompatible `CryptoServicesRegistrar` classes, and the non-FIPS one
shadows the FIPS one.

So: a test needing stock BouncyCastle goes in `src/test`, a test needing BC-FIPS goes in
`src/fipsTest`, and neither jar is ever added to the other's configuration. The helpers both need —
vectors, mock receiver, loopback TLS — are `push2u-core`'s test fixtures, and each source set
depends on them separately, so no dependency of one set can reach the other. Shared plumbing
therefore names no provider at all; a BouncyCastle import in `src/testFixtures` breaks one of the
two by construction. `fipsTest` also fails on discovering zero tests, so a suite that silently stops
compiling into that source set is a build failure rather than a green run.

## Before you call it done

Run `./gradlew qualityCheck` — it formats, analyses, tests and checks the aggregated coverage floor
in one pass. Then check the things no tool can see: is the documentation that describes this
behaviour still true, does the change move something `docs/DESIGN.md` describes, and does a new
public member deserve to be permanent, since it ships to Maven Central and cannot be withdrawn.

If the change settles something the ADRs do not cover, or replaces a decision one of them records,
write a **new** file in `docs/adr/` and add its row to `docs/adr/README.md`. Do not edit an ADR
whose decision is implemented — a superseded one keeps its body and takes a status-line spelling
that depends on how much moved: `Superseded by ADR-NNN` when the whole decision did, or the narrower
`Accepted; one clause superseded by ADR-NNN` when only one clause did, which accumulates where a
later record takes a second clause — `Accepted; one clause superseded by ADR-NNN, another by
ADR-MMM`, each record named in the order it arrived, and so on for a third — and
`docs/adr/README.md` carries the procedure for all of them. `docs/DESIGN.md` is the document that tracks
the code; the ADRs are the record of what was decided and when.

**Before you push, one question about what this change is.** Does the branch, the commit message
or the pull request body describe a way for a remote peer — a push service, whatever answers on
the Vault address, an endpoint arriving in a subscription — to reach a secret or a key, forge or
evade the VAPID signature, get past the endpoint policy to the network, write into a log some other
system trusts, or exhaust memory or time? And does this library's own code, in a version already
released, complete that path? Then each of those three texts discloses it, whether or not the fix
travels with them, and a defect you found yourself halfway through unrelated work discloses exactly
as much as one somebody reported. Take `.claude/skills/push2u-advisory/SKILL.md` instead of the
branch-push-PR path — nothing about a push can be undone afterwards, and this is the last point at
which asking costs nothing. An ordinary bug in released code is not this; neither is a vulnerable
third-party dependency, which is the ordinary change above and whose constraint names its advisory
in public on purpose; and neither is hardening that closes a path no released code completes.

Commit in Conventional Commit form (`feat:`, `fix(vault):`, `test:`, `docs:`), and label the pull
request — the release notes are generated from labels, and an unlabeled pull request lands in "Other
Changes" without anything failing to warn you.
