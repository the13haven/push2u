plugins {
    `java-library`
}

description = "push2u-testkit — the published conformance kit for push2u extension points: the contract every " +
    "VapidSigner implementation extends to prove it produces a raw r||s ES256 signature and a 65-byte " +
    "uncompressed P-256 public point."

// The kit is a MODULE rather than push2u-core's test fixtures, and the reason is that one source set
// cannot be half published. The core's fixtures now hold internal plumbing (the mock push receiver,
// the self-signed loopback TLS certificate, the RFC vectors) that must never leave this build, while
// the kit is meant to be on a consumer's test classpath. Splitting them along the artifact boundary
// is what lets the core's fixtures be skipped from its publication and this one be published whole.
//
// Everything here is `api`: a consumer extends VapidSignerContractTest, so the JUnit annotations it
// carries, the AssertJ assertions its methods run, and the VapidSigner its abstract method returns
// are all part of what compiling against this kit requires.
dependencies {
    api(project(":push2u-core"))
    // Declared directly, not leaned on transitively through the core: this module annotates its own
    // package with @NullMarked.
    api(libs.jspecify)

    api(platform(libs.junit.bom))
    api(libs.junit.jupiter)
    api(libs.assertj.core)

    // The kit's own tests: they check that the contract passes a conforming signer and fails a
    // non-conforming one, so they need a runnable JUnit platform of their own.
    testRuntimeOnly(libs.junit.platform.launcher)
}

// An automatic module, not an explicit one. The kit is test scaffolding a consumer puts on the test
// classpath and it carries JUnit and AssertJ — themselves automatic modules — through `api`, so a
// module-info.java here would name modules whose own names are derived from their jar files.
// Fixing the Automatic-Module-Name keeps the name off the jar file name, which would otherwise
// derive `push2u.testkit`. The package stays com.the13haven.push2u.testkit, deliberately not
// com.the13haven.push2u: the core is an explicit module and would refuse to share its package with
// a second artifact on the module path (ADR-014).
tasks.named<Jar>("jar") {
    manifest { attributes("Automatic-Module-Name" to "com.the13haven.push2u.testkit") }
}
