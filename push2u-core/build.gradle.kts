plugins {
    `java-library`
    // Hosts the shared test plumbing (src/testFixtures): the RFC vectors, the in-process mock push
    // receiver and its loopback TLS identity, used by both `test` and `fipsTest`. Internal to this
    // build — the published conformance kit lives in push2u-testkit.
    `java-test-fixtures`
}

description = "push2u-core — JVM Web Push library core with no runtime implementation dependencies " +
    "(RFC 8030/8291/8292/8188): VAPID-authenticated, end-to-end-encrypted push delivery " +
    "from a Java application server to browser push services."

// The BC-FIPS provider tests run in their own source set with their own classpath: bc-fips and
// stock bcprov both ship the org.bouncycastle.crypto package with incompatible
// CryptoServicesRegistrar classes, so the two jars can never coexist on one classpath — the
// non-FIPS class shadows the FIPS one and BC-FIPS fails with NoSuchMethodError
// (isInApprovedOnlyMode). The regular `test` set carries bcprov only; `fipsTest` carries bc-fips
// only. Both reach the shared plumbing (mock receiver, vectors, subscription helpers) through an
// ordinary testFixtures(project) dependency, declared per source set below — no classpath surgery,
// so neither set can drag the other's BouncyCastle across.
//
// `sourceSets.create("fipsTest")`, not the `by sourceSets.creating` delegate: the Kotlin DSL
// delegated-property syntax is deprecated and scheduled for removal in Gradle 10.
val fipsTest: SourceSet = sourceSets.create("fipsTest")

// Toolchain (JDK 26) + `--release 21` + JUnit Platform are configured for every module in the
// composite-build root build.gradle.kts. Zero runtime IMPLEMENTATION dependencies is a deliberate design
// constraint of the core (JSpecify, the lone `api` entry below, ships annotations and no code) —
// the library replaces nl.martijndwars:web-push precisely because it
// dragged a heavy transitive surface (EOL Apache HttpClient 4.x, plus jose4j and BouncyCastle)
// and leaked it into its public API. The only declared deps are the test stack (JUnit + AssertJ)
// from the version catalog.
dependencies {
    // JSpecify: annotations only, no code. `api` so the nullness contract travels with the
    // published API — consumers' analysers read the same @NullMarked/@Nullable the core is built
    // against. This is the single non-test dependency the core carries.
    api(libs.jspecify)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    // The shared plumbing. testFixtures(project(":push2u-core")), not testFixtures(project):
    // passing the Project object itself as a dependency notation is deprecated and fails in
    // Gradle 10.
    testImplementation(testFixtures(project(":push2u-core")))
    // The published conformance kit — LocalEcVapidSigner's contract tests extend it, on the same
    // terms as any other signer implementation.
    testImplementation(project(":push2u-testkit"))
    testRuntimeOnly(libs.junit.platform.launcher)

    // Stock BouncyCastle for the ES256 provider-matrix tests: it registers raw-format ECDSA
    // (SHA256withECDSAinP1363Format) and exercises the direct r||s path. Test-scoped only — the
    // library core keeps no runtime implementation dependencies. bc-fips must NOT be added here (see the
    // fipsTest source set above).
    testImplementation(libs.bouncycastle.bcprov)

    // BC-FIPS for the DER-fallback tests (registers only DER-format SHA256withECDSA) — isolated
    // in the fipsTest source set, never on the same classpath as bcprov. Everything else is the
    // same set of dependencies `test` takes, declared rather than borrowed.
    "fipsTestImplementation"(platform(libs.junit.bom))
    "fipsTestImplementation"(libs.junit.jupiter)
    "fipsTestImplementation"(libs.assertj.core)
    "fipsTestImplementation"(testFixtures(project(":push2u-core")))
    "fipsTestImplementation"(project(":push2u-testkit"))
    "fipsTestImplementation"(libs.bouncycastle.bcfips)
    "fipsTestRuntimeOnly"(libs.junit.platform.launcher)

    // The test fixtures declare nothing of their own. They are the shared plumbing of the two test
    // source sets — mock receiver, loopback TLS identity, RFC vectors — and java-test-fixtures
    // already puts this module's main classes and its `api` dependencies on their classpath, which
    // is all they use. That second half is load-bearing and easy to miss: the fixtures import
    // JSpecify's @Nullable, and it reaches them only because the core declares `api(libs.jspecify)`
    // (ADR-002). Demoting that to `implementation` would stop compileTestFixturesJava, so the
    // fixtures would need their own declaration.
    //
    // No JUnit and no assertion library: they are plain helpers, not tests. Above all no
    // BouncyCastle, in either flavour, because `test` and `fipsTest` load them on deliberately
    // disjoint classpaths.
}

val fipsTestTask = tasks.register<Test>("fipsTest") {
    description = "Runs the BC-FIPS provider tests (ES256 DER fallback) on a bcprov-free classpath."
    group = "verification"
    testClassesDirs = fipsTest.output.classesDirs
    classpath = fipsTest.runtimeClasspath
    shouldRunAfter(tasks.test)
    // A run that discovers zero tests is a false green (e.g. the FIPS classes silently stopped
    // compiling into this source set) — fail instead of passing empty.
    failOnNoDiscoveredTests = true
}

// Part of `check`, so the FIPS suite runs in every full build — it must not silently drop out.
tasks.named("check") {
    dependsOn(fipsTestTask)
}

// java-test-fixtures wires the fixture variants into the `java` component, so the publication (see
// build-logic's push2u-publish convention plugin) would ship them by default. That default was
// right while these fixtures WERE the published conformance kit; the kit is now push2u-testkit, and
// what is left here is internal plumbing — an in-process mock push service and a self-signed
// certificate factory, which have no business in an artifact on Maven Central. Skip the variants
// via the documented AdhocComponentWithVariants mechanism, exactly as push2u-signer-vault does;
// this removes them from the PUBLICATION only — the testFixtures(...) dependencies above keep
// working unchanged.
(components["java"] as AdhocComponentWithVariants).apply {
    withVariantsFromConfiguration(configurations["testFixturesApiElements"]) { skip() }
    withVariantsFromConfiguration(configurations["testFixturesRuntimeElements"]) { skip() }
}
