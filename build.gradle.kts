import java.math.BigDecimal
import org.gradle.api.plugins.JavaPluginExtension
import pl.allegro.tech.build.axion.release.domain.hooks.HookContext
import pl.allegro.tech.build.axion.release.domain.preRelease

// Shared configuration for every push2u module. It lives at the standalone build root rather than
// being duplicated per module.

plugins {
    // Convention plugins from the build-logic included build; applied to the modules below.
    id("push2u-quality") apply false
    id("push2u-publish") apply false
    // `base` gives the root the lifecycle tasks without pulling in the Java plugin; the
    // aggregation plugin hosts the cross-module coverage report on top of it.
    base
    id("jacoco-report-aggregation")
    // Versioning from git tags (axion) + the Central Portal upload (nmcp aggregation) are
    // whole-build concerns and live at the root only; the per-module publishing half is the
    // push2u-publish convention plugin above.
    alias(libs.plugins.axion.release)
    alias(libs.plugins.nmcp.aggregation)
}

// ---------------------------------------------------------------------------------------------
// Versioning — the git tag is the single source of truth; there is no version constant to bump
// (and forget) in this file. On a `vX.Y.Z` tag axion reports X.Y.Z; on any commit past the last
// tag it reports the next patch as X.Y.Z-SNAPSHOT. `./gradlew currentVersion` prints it,
// `./gradlew release` tags (and pushes) the next one.
// ---------------------------------------------------------------------------------------------
scmVersion {
    // Consult the remote, don't trust the local clone alone: a release must not mint a version
    // that ignores tags pushed from elsewhere (another machine, the CI runner).
    localOnly.set(false)
    // Highest tag overall, not the nearest reachable one — keeps the version monotonic even if
    // release and maintenance branches diverge.
    useHighestVersion.set(true)
    versionIncrementer("incrementPatch")
    releaseOnlyOnReleaseBranches = true

    tag {
        prefix.set("v")
        // The version RELEASED first, not a base the incrementer starts from. With no tags at
        // all the build reports 0.0.0-SNAPSHOT and `release` creates the tag v0.0.0;
        // incrementPatch only takes effect once a tag exists (v0.0.0 -> 0.0.1-SNAPSHOT ->
        // v0.0.1). Verified by simulating an empty repository against this configuration.
        //
        // So the first release is not 0.1.0 by itself: run the Setup Next Version workflow with
        // 0.1.0 before the first Release. See RELEASING.md, "Setting the next version".
        initialVersion { _, _ -> "0.0.0" }
    }

    repository {
        type.set("git")
    }

    nextVersion {
        suffix.set("SNAPSHOT")
        separator.set("-")
    }

    // All three release preconditions on: a dirty tree, an unpushed branch or a SNAPSHOT
    // dependency each abort `release` before a tag is created.
    checks {
        uncommittedChanges.set(true)
        aheadOfRemote.set(true)
        snapshotDependencies.set(true)
    }

    hooks {
        preRelease {
            // Keep the Maven coordinates in the README's examples on the released version. The
            // README states them strictly as `com.the13haven:<module>:X.Y.Z`. axion's fileUpdate
            // pattern is a regex (multiline), but capture groups in the replacement are not a
            // documented feature — so instead of one clever regex there is one fileUpdate hook
            // per module with a fully literal (Regex.escape'd) pattern. Boring and robust.
            listOf(
                "push2u-core",
                "push2u-signer-vault",
                "push2u-spring-boot-starter",
                "push2u-signer-vault-spring-boot-starter",
            ).forEach { module ->
                fileUpdate {
                    encoding = "utf-8"
                    file("README.md")
                    pattern = { previousVersion: String, _: HookContext ->
                        Regex.escape("com.the13haven:$module:$previousVersion")
                    }
                    replacement = { currentVersion: String, _: HookContext ->
                        "com.the13haven:$module:$currentVersion"
                    }
                }
            }
            // Commits whatever the fileUpdate hooks changed, before the tag is placed.
            commit { releaseVersion, _ -> "Release v${releaseVersion}" }
        }
    }
}

// Resolve the version ONCE here and hand the plain string to every project below: scmVersion is
// an extension of the root project only, so subprojects cannot query it themselves — and each
// query would re-run the git inspection anyway.
val scmDerivedVersion: String = scmVersion.version

allprojects {
    // Maven groupId (the verified Central namespace). The Java packages stay io.push2u.* on
    // purpose: Central namespace verification binds the groupId, not package names, and renaming
    // packages would break every early adopter for zero gain.
    group = "com.the13haven"
    version = scmDerivedVersion

    repositories {
        mavenCentral()
    }
}

subprojects {
    // Baseline = Java 21 LTS (DESIGN.md ADR-001): build with the JDK 26 toolchain but pin
    // `--release 21` so the bytecode + visible API stay 21-compatible.
    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "UTF-8"
        options.release.set(21)
        options.compilerArgs.add("-parameters")
    }
    tasks.withType<Test>().configureEach {
        useJUnitPlatform()

        // Ryuk bind-mounts the Docker socket into its own container. Docker clients on macOS
        // reach Colima through a host path such as ~/.colima/default/docker.sock, but that path
        // does not exist inside the Colima VM. Docker 29 rejects that mount, so Testcontainers
        // cannot start even though the daemon itself is reachable. The socket is available inside
        // Colima, Docker Desktop, and GitHub-hosted Linux runners at /var/run/docker.sock.
        //
        // Keep an explicit override for rootless/remote Docker installations.
        val dockerSocketOverride =
            System.getenv("TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE")?.takeIf { it.isNotBlank() }
                ?: "/var/run/docker.sock"
        environment("TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE", dockerSocketOverride)
    }
    plugins.withId("java") {
        this@subprojects.the<JavaPluginExtension>().toolchain {
            languageVersion = JavaLanguageVersion.of(26)
        }
        // Static analysis + coverage (see build-logic/src/main/kotlin/push2u-quality.gradle.kts).
        // Applied reactively: the modules declare `java-library` themselves, and the quality plugin
        // configures tasks the Java plugin must have created first.
        apply(plugin = "push2u-quality")
        // Maven Central publishing, same reactive pattern (see
        // build-logic/src/main/kotlin/push2u-publish.gradle.kts): every java module is published.
        apply(plugin = "push2u-publish")
    }
}

// Catalog handles for the BouncyCastle security pin, referenced by the constraints below.
// Jackson is not pinned: Spring Boot's managed jackson-2-bom governs it on the starter
// classpaths.
val bouncycastleBcpkix = libs.bouncycastle.bcpkix
val bouncycastleBcprov = libs.bouncycastle.bcprov

subprojects {

    plugins.withType<JavaPlugin> {

        // Pin BouncyCastle via dependency CONSTRAINTS rather than resolutionStrategy.force. Same
        // resolved classpath (1.85), but constraints report only the resolved version in the GitHub
        // dependency graph, whereas `force` also leaked the original requested version (1.82) as a
        // phantom node that Dependabot alerted on. Added to every declarable configuration for
        // consistent resolution across modules.
        configurations.configureEach {
            if (isCanBeDeclared && !isCanBeResolved && !isCanBeConsumed) {
                val bucket = name
                project.dependencies.constraints.apply {
                    add(bucket, bouncycastleBcpkix)
                    add(bucket, bouncycastleBcprov)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Aggregated coverage. Each module produces its own JaCoCo report; the aggregation below merges
// them so the threshold applies to the library as a whole (a module such as
// push2u-signer-vault-spring-boot-starter is mostly wiring and would skew a per-module rule).
// ---------------------------------------------------------------------------------------------
dependencies {
    // project(path), not the Project object: passing a Project as a dependency notation is
    // deprecated and fails in Gradle 10.
    subprojects.forEach { jacocoAggregation(project(it.path)) }
}

reporting {
    reports {
        register<JacocoCoverageReport>("testCodeCoverageReport") {
            testSuiteName = "test"
        }
    }
}

val aggregatedCoverageReport = tasks.named<JacocoReport>("testCodeCoverageReport")

// The aggregation plugin collects execution data per JVM Test Suite, and `test` is the only suite
// here — push2u-core's `fipsTest` is a hand-rolled source set with its own Test task (it needs a
// bcprov-free classpath, which a suite cannot express). Its coverage would therefore be missing
// from the aggregate, and the BC-FIPS paths would look untested. Add its execution data explicitly,
// and depend on every module's Test tasks so the report is never built from a partial set.
aggregatedCoverageReport {
    val extraExecutionData = files(subprojects.map { module ->
        module.layout.buildDirectory.file("jacoco/fipsTest.exec")
    }).filter { it.exists() }

    executionData(extraExecutionData)
    subprojects.forEach { dependsOn(it.tasks.withType<Test>()) }
}

// `register<Type>(name)`, not the `by registering` delegate: the delegated-property syntax is
// deprecated and scheduled for removal in Gradle 10.
val testCodeCoverageVerification = tasks.register<JacocoCoverageVerification>("testCodeCoverageVerification") {
    description = "Verifies aggregated code coverage meets the minimum threshold."
    group = "verification"

    dependsOn(aggregatedCoverageReport)

    sourceDirectories.from(aggregatedCoverageReport.map { it.sourceDirectories })
    classDirectories.from(aggregatedCoverageReport.map { it.classDirectories })
    executionData.from(aggregatedCoverageReport.map { it.executionData })

    violationRules {
        rule {
            limit {
                minimum = BigDecimal("0.80")
            }
        }
    }
}

// Gradle writes JUnit XML per module and per test task (push2u-core alone has `test` and
// `fipsTest`). Collect all of it under one directory so a consumer that takes a single path —
// Codecov's test-results upload, for one — sees every module's results instead of whichever one it
// was pointed at.
val aggregateTestResults = tasks.register<Sync>("aggregateTestResults") {
    description = "Collects the JUnit XML of every module's test tasks into one directory."
    group = "verification"

    into(layout.buildDirectory.dir("test-results-aggregated"))

    subprojects.forEach { module ->
        // `*/*.xml` keeps one directory per test task, so push2u-core's `test` and `fipsTest`
        // results stay apart; `into(module.name)` keeps the modules apart in turn.
        from(module.layout.buildDirectory.dir("test-results")) {
            include("*/*.xml")
            into(module.name)
        }
        // mustRunAfter, not dependsOn: this collects whatever the invoked lifecycle task already
        // ran, and stays usable when the build fails partway (CI calls it with `if: always()`)
        // instead of forcing the suite to run again.
        mustRunAfter(module.tasks.withType<Test>())
    }
}

// Local entry point: ./gradlew qualityCheck — auto-formats, then runs every analyser.
tasks.register("qualityCheck") {
    description = "Runs all quality checks locally (auto-formats code)."
    group = "verification"
    subprojects.forEach { dependsOn("${it.path}:qualityCheck") }
    dependsOn(testCodeCoverageVerification)
}

// CI entry point: ./gradlew qualityCheckCi --no-build-cache
// --no-build-cache because Gradle may replay test results cached from an environment without
// Docker, which would let the Testcontainers-backed Vault test show up as "skipped" instead of
// running. Docker availability is not part of the cache key, so a stale hit hides real failures.
tasks.register("qualityCheckCi") {
    description = "Runs all quality checks in CI (verifies formatting without modifying files)."
    group = "verification"
    subprojects.forEach { dependsOn("${it.path}:qualityCheckCi") }
    dependsOn(testCodeCoverageVerification)
}

// ---------------------------------------------------------------------------------------------
// Maven Central upload — the aggregation half of publishing (the per-module half is the
// push2u-publish convention plugin). nmcp gathers every module's publication and uploads ONE
// bundle to the Central Portal, which validates the whole set together — a half-published
// release cannot happen. Entry point: ./gradlew publishAggregationToCentralPortal.
// ---------------------------------------------------------------------------------------------
dependencies {
    // project(path), not the Project object: passing a Project as a dependency notation is
    // deprecated and fails in Gradle 10. All four subprojects are published modules; if one ever
    // stops applying nmcp, the aggregation simply ignores it.
    subprojects.forEach { nmcpAggregation(project(it.path)) }
}

nmcpAggregation {
    centralPortal {
        // Publisher API token from https://central.sonatype.com/account — injected by the release
        // workflow as secrets, never stored in the repository or in gradle.properties.
        username = providers.environmentVariable("MAVEN_CENTRAL_USERNAME")
        password = providers.environmentVariable("MAVEN_CENTRAL_PASSWORD")
        // AUTOMATIC: a bundle that passes Central's validation goes live without a manual click
        // in the portal UI — the release pipeline is hands-off end to end. The safety net is the
        // validation itself plus axion's pre-release checks, not a human in the loop.
        publishingType = "AUTOMATIC"
    }
}
