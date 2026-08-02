plugins {
    `java-library`
}

description = "push2u-signer-vault-spring-boot-starter — Spring Boot auto-configuration that binds " +
    "push2u.signer.vault.* to a VaultTransitVapidSigner. With the core push2u-spring-boot-starter " +
    "present, this remote signer backs the auto-configured PushSender. Opt-in module."

// Toolchain + `--release 21` + JUnit Platform come from the composite-build root build.gradle.kts.
dependencies {
    api(platform(libs.spring.boot.dependencies))
    api(project(":push2u-signer-vault"))
    api(libs.jspecify)
    api(libs.spring.boot.autoconfigure)
    annotationProcessor(platform(libs.spring.boot.dependencies))
    annotationProcessor(libs.spring.boot.configuration.processor)

    testImplementation(platform(libs.spring.boot.dependencies))
    testImplementation(libs.spring.boot.test)
    // The core starter, so the composition test can prove the Vault signer outranks the local one.
    testImplementation(project(":push2u-spring-boot-starter"))
    // RecordingHttpClient, shared from the signer module's test fixtures — proves which HttpClient
    // instance actually carries the Vault requests.
    testImplementation(testFixtures(project(":push2u-signer-vault")))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    testRuntimeOnly(libs.junit.platform.launcher)
}
