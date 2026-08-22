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
    // Health lives in Boot 4's optional spring-boot-health module, and the core starter has it as
    // compileOnly — so it has to be declared again here for the composition test that proves the
    // health indicator still appears when the signer is the Vault one. That test exists because the
    // indicator's @ConditionalOnBean(VapidSigner) only holds if this autoconfiguration is ordered
    // ahead of the core starter's; a wrong order makes the indicator vanish silently.
    testImplementation(libs.spring.boot.health)
    // RecordingHttpClient, shared from the signer module's test fixtures — proves which HttpClient
    // instance actually carries the Vault requests.
    testImplementation(testFixtures(project(":push2u-signer-vault")))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    // The published kit, for the generated VAPID pair the push2u.vapid.* and
    // push2u.signer.vault.public-key properties bind — key material valid against whatever the
    // library's current input contract is, rather than a shape these tests froze once.
    //
    // It brings the JUnit platform with it: the kit carries the BOM on `api`, because a consumer
    // extending its contract test compiles against those annotations. So the kit's constraint lands
    // beside the one Boot already manages here, and resolution takes the higher — which today is
    // the catalog's, so the version in this module moved up to the one the rest of the build
    // already runs. That is the state worth having, one JUnit across every module, and it is
    // stated rather than left to be discovered in a resolution report.
    testImplementation(project(":push2u-testkit"))
    testRuntimeOnly(libs.junit.platform.launcher)
}

// An automatic module, for the reason ADR-014 gives for the core starter: Boot's own artifacts are
// automatic modules and its auto-configuration is reflective. The name is fixed here so it does not
// follow the jar file name.
tasks.named<Jar>("jar") {
    manifest { attributes("Automatic-Module-Name" to "com.the13haven.push2u.signer.vault.spring") }
}
