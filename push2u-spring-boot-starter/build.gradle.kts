plugins {
    `java-library`
}

description = "push2u-spring-boot-starter — Spring Boot auto-configuration for push2u: binds " +
    "push2u.* properties to a ready PushSender bean (in-JVM VAPID signer), with an optional " +
    "actuator health indicator. Opt-in module on top of push2u-core."

// Toolchain + `--release 21` + JUnit Platform come from the composite-build root build.gradle.kts.
// This module pulls Spring Boot autoconfigure as a real dependency (the core stays Spring-free).
dependencies {
    api(platform(libs.spring.boot.dependencies))
    api(project(":push2u-core"))
    api(libs.jspecify)
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
    // Actuator's endpoint types back spring-boot-health's HealthEndpointGroups machinery, which
    // the liveness-group test drives for real — proving Boot never places the push2u indicator in
    // the liveness group. Test classpath only; the starter itself never needs actuator.
    testImplementation(libs.spring.boot.actuator)
    testImplementation(libs.jackson.annotations)
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    testRuntimeOnly(libs.junit.platform.launcher)
}

// An automatic module, not an explicit one (ADR-014): Spring Boot's own artifacts are automatic
// modules themselves, and auto-configuration works by reflection over classes named in
// META-INF/spring — a dependency graph a module descriptor cannot express. What the name buys is
// stability: without it the module name is derived from the jar file name, which would make it
// `push2u.spring.boot.starter` and tie it to an artifact name.
tasks.named<Jar>("jar") { manifest { attributes("Automatic-Module-Name" to "com.the13haven.push2u.spring") } }
