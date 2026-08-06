# ADR-013 — Release and publication process

**Status:** Accepted

## The version comes from a git tag

The version is derived from git tags of the form `vX.Y.Z` by the axion-release plugin rather than
written into a build file. A tag records the release where releases actually happen — in git
history — so the build cannot disagree with it, and between releases every checkout identifies
itself as the next `X.Y.Z-SNAPSHOT` without anyone editing a version line.

The rejected alternative, a hard-coded version bumped by a "release commit", turns every release
into a source change, invites merge conflicts on that line, and lets the tag and the declared
version drift apart.

## Publication goes through the Central Portal, on `maven-publish`

Publication goes to Maven Central through the Central Portal, with the nmcp plugin layered on top
of the standard `maven-publish` and `signing` plugins: nmcp only aggregates what `maven-publish`
produces and uploads the bundle to the Portal (`publishAggregationToCentralPortal`, publishing
mode AUTOMATIC — after the Portal's validation passes, the deployment proceeds to Central without
a manual step).

The rejected alternative, an all-in-one publishing plugin such as vanniktech's
gradle-maven-publish-plugin, generates the publications and POM from its own conventions; keeping
them in the build's `maven-publish` configuration leaves the POM content, the artifact set (jar,
`-sources`, `-javadoc`) and the signing step explicit and under the build's control.

## The group ID and the packages are anchored on an owned domain

The Maven group ID is `com.the13haven` and the Java packages are `com.the13haven.push2u.*`. Both
are anchored on `the13haven.com`, the domain the project actually owns, and each has its own
reason to be. Central verifies namespace ownership with a DNS TXT record on the exact domain the
group ID reverses to, and `push2u.io` does not belong to the project. The package name is a
separate matter — the JLS recommends a reversed domain name one owns, for the same purpose of
guaranteed uniqueness — but the original `io.push2u.*` was anchored on that same unowned domain,
which is the part that made it a squat rather than a convention.

Two alternatives were rejected. Registering `push2u.io` solely to legitimise the shorter name ties
a permanent, immutable namespace to a recurring registration fee and an expiry risk. Keeping
`io.push2u.*` alongside a `com.the13haven` group ID would also have been defensible — nothing
requires the two to match, and Guava (`com.google.guava` → `com.google.common`) and OkHttp
(`com.squareup.okhttp3` → `okhttp3`) both diverge — but it leaves the package name resting on a
domain someone else may register, and the only moment to change a package name for free is before
the first release: afterwards it is a breaking change for every adopter.

## A release is a deliberate human action

Releases are triggered manually through `workflow_dispatch`, never by a push to `main`. A
published Maven Central version is immutable — it cannot be deleted or replaced — so the decision
"this state becomes a release" deserves an explicit human action rather than being implied by a
merge.

The rejected alternative, releasing on every merge to `main`, couples review cadence to release
cadence and turns any accidental merge into a permanent artifact.

`RELEASING.md` is the operational companion to this decision: it carries the procedure, the
required secrets and the one-time publishing setup.
