plugins {
    `java-library`
    // Hosts the RecordingHttpClient test fixture, shared with the Vault starter's tests.
    `java-test-fixtures`
}

description = "push2u-signer-vault — a VapidSigner backed by HashiCorp Vault Transit: the private " +
    "key never leaves Vault. Opt-in module on top of push2u-core; it calls the Vault API over " +
    "its own VaultHttpTransport seam (default: the JDK HttpClient)."

// Toolchain + `--release 21` + JUnit Platform come from the composite-build root build.gradle.kts.
// This module is NOT zero-dep — it depends on push2u-core; the Vault calls go through the module's
// own VaultHttpTransport over the JDK HttpClient with hand-built/parsed JSON, so it adds no
// third-party runtime dependency.
dependencies {
    api(project(":push2u-core"))

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    // The shared VapidSigner conformance contract (published from push2u-core's test fixtures).
    testImplementation(testFixtures(project(":push2u-core")))
    // This module's own fixture (RecordingHttpClient) for the transport tests. Named explicitly:
    // passing the Project object as a dependency notation is deprecated and fails in Gradle 10.
    testImplementation(testFixtures(project(":push2u-signer-vault")))
    // A real Vault (dev mode) with a Transit mount for the integration test.
    testImplementation(libs.testcontainers.vault)
    testRuntimeOnly(libs.junit.platform.launcher)
}
