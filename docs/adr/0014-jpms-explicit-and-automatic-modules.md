# ADR-014 — JPMS: explicit modules for the library, automatic for the starters

**Status:** Accepted

A JPMS module name is as permanent as a package name: free to choose before the first release, a
breaking change for every adopter afterwards. Without a descriptor or an `Automatic-Module-Name`,
a module's name is derived from the jar file name, which is neither stable nor ours to keep. That
timing is the whole reason this was settled while the repository carried no release tag.

## Explicit modules for the library, automatic for the starters and the kit

`push2u-core` and `push2u-signer-vault` carry a `module-info.java`, and the module name is the
package name — `com.the13haven.push2u` and `com.the13haven.push2u.signer.vault`. A descriptor is
cheap to keep accurate here precisely because of ADR-002: with no runtime dependencies there is
almost nothing to declare, and the descriptor turns the zero-dependency posture into something a
consumer's module resolution checks rather than something the documentation asserts.

The two Spring Boot starters and `push2u-testkit` stay **automatic** modules with a fixed
`Automatic-Module-Name`. Boot's own artifacts are automatic modules, and auto-configuration works
by reflecting over classes named in `META-INF/spring/*.imports` — a relationship no descriptor can
express and one that `requires` would misrepresent as a compile-time dependency. The kit's API
carries JUnit and AssertJ, themselves automatic modules, so a descriptor there would `requires`
names derived from jar files. What the manifest attribute buys in both cases is that the module
name stops following the jar file name.

## The conformance kit is its own artifact, in its own package

A package split across two artifacts cannot be resolved from the module path. With the kit still
in the core's package, a consumer putting both on the module path gets `ResolutionException:
Module … contains package com.the13haven.push2u, module com.the13haven.push2u exports package
com.the13haven.push2u to …` — reproduced before the move, not assumed. The kit's package is
therefore `com.the13haven.push2u.testkit`.

The kit is also an artifact of its own rather than `push2u-core`'s published test fixtures. That
source set carried two things that cannot travel together: the kit, meant for a consumer's test
classpath, and the plumbing the core's own suites share — an in-process mock push service, a
self-signed loopback certificate factory, the RFC vectors — which has no business on Maven
Central. A source set cannot be half published, so the split had to be an artifact boundary.
`push2u-core`'s fixtures now skip their variants from the publication, the mechanism
`push2u-signer-vault` already used for its internal `RecordingHttpClient`.

Both halves had the same deadline. A consumer would otherwise have reached the kit through a
`test-fixtures` classifier on `push2u-core`, and its coordinates, like its package and every
module name here, stop being free the moment the first version is published.
