plugins {
    `java-library`
}

description = "push2u-spring-boot-starter — Spring Boot auto-configuration for push2u: binds " +
    "push2u.* properties to a ready PushSender bean (in-JVM VAPID signer), with an optional " +
    "actuator health indicator. Opt-in module on top of push2u-core."

// Toolchain + `--release 21` + JUnit Platform come from the composite-build root build.gradle.kts.
// This module pulls Spring Boot autoconfigure as a real dependency (the core stays Spring-free).
dependencies {
    // Spring Boot's BOM aligns THIS build and stops at its edge (ADR-032). On `api` it was
    // published too — as an imported BOM in the POM and a dependency in the module metadata — and
    // a Gradle consumer resolving it took Spring Boot's whole version manifest as a live input to
    // their own resolution, silently raising their Spring, Jackson and Micrometer to whatever
    // version this build happened to use. compileOnly reaches compileClasspath and travels
    // nowhere; the published Spring Boot requirement is spring-boot-autoconfigure's own version,
    // which the catalog now carries.
    compileOnly(platform(libs.spring.boot.dependencies))
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
    // The published kit, used here exactly as a consumer uses it: a generated VAPID pair for the
    // push2u.vapid.* properties to bind and a coherent subscription for a send. Standing those up
    // by hand is what let this module's tests encode key material the library later stopped
    // accepting — the same drift the kit exists to absorb for applications.
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

// An automatic module, not an explicit one (ADR-014): Spring Boot's own artifacts are automatic
// modules themselves, and auto-configuration works by reflection over classes named in
// META-INF/spring — a dependency graph a module descriptor cannot express. What the name buys is
// stability: without it the module name is derived from the jar file name, which would make it
// `push2u.spring.boot.starter` and tie it to an artifact name.
// The configuration-metadata processor merges META-INF/additional-spring-configuration-metadata.json
// — the hand-written half, for keys no properties record binds — only if it can find that file on
// the classpath it runs with. Gradle gives it no reason to: compileJava and processResources are
// independent, so the annotation processor runs against a resources directory that may not exist
// yet, silently produces metadata without the hand-written entries, and every one of them
// disappears from the published jar with no error anywhere. Declaring the resources as an input
// both orders the two tasks and puts the file where the processor looks.
tasks.named<JavaCompile>("compileJava") { inputs.files(tasks.named("processResources")) }

tasks.named<Jar>("jar") { manifest { attributes("Automatic-Module-Name" to "com.the13haven.push2u.spring") } }
