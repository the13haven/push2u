plugins {
    `java-library`
    // Hosts the RecordingHttpClient test fixture, shared with the Vault starter's tests.
    `java-test-fixtures`
}

description = "push2u-signer-vault — a VapidSigner backed by HashiCorp Vault Transit: the private " +
    "key never leaves Vault. Opt-in module on top of push2u-core; it calls the Vault API over " +
    "its own VaultHttpTransport seam (default: the JDK HttpClient)."

// Toolchain + `--release 21` + JUnit Platform come from the composite-build root build.gradle.kts.
// This module depends on push2u-core; the Vault calls go through the module's
// own VaultHttpTransport over the JDK HttpClient with hand-built/parsed JSON, so it adds no
// third-party runtime dependency.
dependencies {
    api(project(":push2u-core"))
    // Declared directly, not leaned on transitively: this module annotates its own API.
    api(libs.jspecify)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    // The published VapidSigner conformance kit, consumed exactly as an outside implementation
    // would consume it.
    testImplementation(project(":push2u-testkit"))
    // This module's own fixture (RecordingHttpClient) for the transport tests. Named explicitly:
    // passing the Project object as a dependency notation is deprecated and fails in Gradle 10.
    testImplementation(testFixtures(project(":push2u-signer-vault")))
    // A real Vault (dev mode) with a Transit mount for the integration test.
    testImplementation(libs.testcontainers.vault)
    testRuntimeOnly(libs.junit.platform.launcher)
}

// java-test-fixtures wires the fixture variants into the `java` component, so the publication
// (see build-logic's push2u-publish convention plugin) would ship them by default. No module here
// wants that: the conformance kit is its own published module (push2u-testkit), and push2u-core
// skips its fixture variants for the same reason this one does. This module's fixture
// (RecordingHttpClient) is internal test scaffolding shared with the Vault starter inside this
// build only, and publishing it would freeze an accidental API. Skip the
// variants via the documented AdhocComponentWithVariants mechanism; this removes them from the
// PUBLICATION only — the testFixtures(...) dependencies above keep working unchanged.
(components["java"] as AdhocComponentWithVariants).apply {
    withVariantsFromConfiguration(configurations["testFixturesApiElements"]) { skip() }
    withVariantsFromConfiguration(configurations["testFixturesRuntimeElements"]) { skip() }
}
