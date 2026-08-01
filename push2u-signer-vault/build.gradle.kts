plugins {
    `java-library`
}

description = "push2u-signer-vault — a VapidSigner backed by HashiCorp Vault Transit: the private " +
    "key never leaves Vault. Opt-in module on top of push2u-core; not zero-dep " +
    "(it calls Vault over HTTP, reusing push2u-core's PushHttpClient transport)."

// Toolchain + `--release 21` + JUnit Platform come from the composite-build root build.gradle.kts.
// This module is NOT zero-dep — it depends on push2u-core; the Vault call itself goes through
// push2u-core's JDK HttpClient with hand-built/parsed JSON, so it adds no runtime dependency.
dependencies {
    api(project(":push2u-core"))

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    // The shared VapidSigner conformance contract (published from push2u-core's test fixtures).
    testImplementation(testFixtures(project(":push2u-core")))
    // A real Vault (dev mode) with a Transit mount for the integration test.
    testImplementation(libs.testcontainers.vault)
    testRuntimeOnly(libs.junit.platform.launcher)
}
