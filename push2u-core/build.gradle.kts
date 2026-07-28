plugins {
    `java-library`
    // Hosts the shared VapidSigner conformance contract (src/testFixtures), extended by the local
    // signer's test here and by remote signer modules.
    `java-test-fixtures`
}

description = "push2u-core — zero-dependency JVM Web Push library core " +
    "(RFC 8030/8291/8292/8188)."

// Toolchain (JDK 26) + `--release 21` + JUnit Platform are configured for every module in the
// composite-build root build.gradle.kts. Zero runtime dependencies (ADR-002): the only declared
// deps are the test stack (JUnit + AssertJ) from the version catalog.
dependencies {
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    testRuntimeOnly(libs.junit.platform.launcher)

    // Test fixtures = the shared VapidSigner conformance contract, published with the module so
    // downstream signer implementations can extend it.
    testFixturesApi(platform(libs.junit.bom))
    testFixturesApi(libs.junit.jupiter)
    testFixturesApi(libs.assertj.core)
}
