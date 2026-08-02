plugins {
    `java-library`
    // Hosts the shared VapidSigner conformance contract (src/testFixtures), extended by the local
    // signer's test here and by each remote signer module (e.g. push2u-signer-vault).
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
// only. fipsTest reuses the compiled helpers of `test` (mock receiver, vectors, subscription
// helpers) by putting the test OUTPUT — classes only, not the test dependency configurations —
// on its classpath, so bcprov cannot leak across. The main classes and the testFixtures
// contract are NOT added here: they arrive once via the testFixtures(project) dependency below
// (adding sourceSets.main output too would duplicate every main class on the classpath).
//
// `sourceSets.create("fipsTest")`, not the `by sourceSets.creating` delegate: the Kotlin DSL
// delegated-property syntax is deprecated and scheduled for removal in Gradle 10.
val fipsTest: SourceSet = sourceSets.create("fipsTest") {
    compileClasspath += sourceSets.test.get().output
    runtimeClasspath += sourceSets.test.get().output
}

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
    testRuntimeOnly(libs.junit.platform.launcher)

    // Stock BouncyCastle for the ES256 provider-matrix tests: it registers raw-format ECDSA
    // (SHA256withECDSAinP1363Format) and exercises the direct r||s path. Test-scoped only — the
    // library core keeps no runtime implementation dependencies. bc-fips must NOT be added here (see the
    // fipsTest source set above).
    testImplementation(libs.bouncycastle.bcprov)

    // BC-FIPS for the DER-fallback tests (registers only DER-format SHA256withECDSA) — isolated
    // in the fipsTest source set, never on the same classpath as bcprov.
    "fipsTestImplementation"(platform(libs.junit.bom))
    "fipsTestImplementation"(libs.junit.jupiter)
    "fipsTestImplementation"(libs.assertj.core)
    // testFixtures(project(":push2u-core")), not testFixtures(project): passing the Project object
    // itself as a dependency notation is deprecated and fails in Gradle 10.
    "fipsTestImplementation"(testFixtures(project(":push2u-core")))
    "fipsTestImplementation"(libs.bouncycastle.bcfips)
    "fipsTestRuntimeOnly"(libs.junit.platform.launcher)

    // Test fixtures = the shared VapidSigner conformance contract, published with the module so
    // downstream signer implementations can extend it.
    testFixturesApi(platform(libs.junit.bom))
    testFixturesApi(libs.junit.jupiter)
    testFixturesApi(libs.assertj.core)
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
