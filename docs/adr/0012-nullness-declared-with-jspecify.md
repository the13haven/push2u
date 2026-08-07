# ADR-012 — Nullness declared with JSpecify

**Status:** Accepted

A published API's nullness contract stated only in prose is a contract nothing checks — neither
the library's own build nor a consumer's analyser. The alternatives were a project-local
annotation (free of any dependency, but meaningful to nothing outside this build), one of the
framework-specific annotation sets, or JSpecify.

Every package therefore carries JSpecify's `@NullMarked`: a reference type is non-null unless it
is annotated `@Nullable`.

JSpecify is declared as an `api` dependency rather than `compileOnly`, so the contract travels to
consumers — NullAway, IntelliJ and the Kotlin compiler all read the same annotations. It carries
annotations and no code, so the dependency posture of ADR-002 is unaffected in substance: a
published contract that tools can check is worth more than an absolute artefact count.

The build enforces both halves rather than trusting the convention: NullAway fails on a contract
violation, and Error Prone's `RequireExplicitNullMarking` fails on a package that forgets the
mark. That second check is not theoretical — moving the conformance kit into its own package
(ADR-014) left it outside any `@NullMarked` scope, and nothing else would have said so, because a
`package-info.java` carrying no annotation does not compile to a class file at all.

NullAway's full `JSpecifyMode` (generic nullness) is deliberately not enabled: its authors still
describe it as evolving. Enabling it is a later decision, not part of this one.
