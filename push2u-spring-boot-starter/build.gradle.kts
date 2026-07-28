plugins {
    `java-library`
}

description = "push2u-spring-boot-starter — Spring Boot auto-configuration for push2u: binds " +
    "push2u.* properties to a ready PushSender bean (in-JVM VAPID signer), with an optional " +
    "actuator health indicator. Opt-in module on top of push2u-core."

// Toolchain + `--release 21` + JUnit Platform come from the composite-build root build.gradle.kts.
// This module is NOT zero-dep — it pulls Spring Boot autoconfigure (the core stays Spring-free).
dependencies {
    api(platform(libs.spring.boot.dependencies))
    api(project(":push2u-core"))
    api(libs.spring.boot.autoconfigure)
    // Health lives in the optional spring-boot-health module (Boot 4 split it out of actuator);
    // the indicator is conditional on it being on the classpath.
    compileOnly(libs.spring.boot.health)
    // Health carries Jackson's @JsonInclude — keep the annotation jar on the compile classpath so
    // javac resolves the enum (no runtime dependency added).
    compileOnly(libs.jackson.annotations)
    annotationProcessor(platform(libs.spring.boot.dependencies))
    annotationProcessor(libs.spring.boot.configuration.processor)

    testImplementation(platform(libs.spring.boot.dependencies))
    testImplementation(libs.spring.boot.test)
    testImplementation(libs.spring.boot.health)
    testImplementation(libs.jackson.annotations)
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    testRuntimeOnly(libs.junit.platform.launcher)
}
