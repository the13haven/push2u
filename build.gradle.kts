import java.math.BigDecimal
import org.gradle.api.plugins.JavaPluginExtension
import pl.allegro.tech.build.axion.release.domain.hooks.HookContext
import pl.allegro.tech.build.axion.release.domain.preRelease

// Shared configuration for every push2u module. It lives at the standalone build root rather than
// being duplicated per module.

// BouncyCastle on the BUILDSCRIPT classpath — the plugins that build this library, not the library.
//
// axion-release reads the version from git tags through JGit, and JGit's optional
// org.eclipse.jgit.gpg.bc module (signed-tag support) depends on BouncyCastle 1.81, whose range
// dependencies then resolve bcprov to 1.82. That combination carries five open advisories, one of
// them critical (GHSA-574f-3g2m-x479, GOST 28147 CTR keystream reuse — not a code path this build
// takes, but the version is the version). axion-release 1.21.2 is the current release and still
// ships that JGit, so there is no upgrade to wait for.
//
// CONSTRAINTS rather than resolutionStrategy.force (the convention in CONTRIBUTING.md): force also
// records the originally requested version in the submitted dependency graph, and Dependabot alerts
// on that phantom node even though only the resolved version is ever used. This classpath is
// submitted, so the difference is the six alerts that prompted the pin in the first place.
//
// The repositories block is required — plugins arrive through settings.gradle.kts pluginManagement,
// so the buildscript itself declares none, and raising a version means fetching an artifact.
//
// The version is read from the catalog rather than repeated here: `libs` accessors do not exist yet
// inside buildscript {}, which is evaluated before the plugins block. A missing key fails the build
// at configuration time rather than silently dropping the pin.
buildscript {
    val bouncycastle = file("gradle/libs.versions.toml").readLines()
        .first { it.startsWith("bouncycastle = ") }
        .substringAfter('"')
        .substringBefore('"')

    repositories {
        gradlePluginPortal()
        mavenCentral()
    }

    dependencies {
        constraints {
            classpath("org.bouncycastle:bcpg-jdk18on:$bouncycastle") {
                because("GHSA-cj8j-37rh-8475")
            }
            classpath("org.bouncycastle:bcprov-jdk18on:$bouncycastle") {
                because("GHSA-574f-3g2m-x479, GHSA-p93r-85wp-75v3, GHSA-c3fc-8qff-9hwx")
            }
            classpath("org.bouncycastle:bcpkix-jdk18on:$bouncycastle") {
                because("GHSA-wg6q-6289-32hp")
            }
            // No advisory of its own; pinned so the four BouncyCastle artefacts stay version-aligned.
            classpath("org.bouncycastle:bcutil-jdk18on:$bouncycastle")
        }
    }
}

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
    // Release for real: push the release commit and tag to origin, and run the `aheadOfRemote`
    // precondition rather than skipping it. Note what this does NOT do — it is not what makes the
    // version resolution see tags pushed from elsewhere. `localOnly` is read only by the push and
    // by whether that precondition runs; tag visibility comes from the clone (`fetch-depth: 0` in
    // the workflows) plus axion's own unshallow on CI. `fetchTags` would be the setting for that,
    // and it is deliberately left at its default.
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
        // 0.1.0 before the first Release. See docs/RELEASING.md, "Setting the next version".
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
            // per module, each matching only its own coordinate. Boring and robust.
            //
            // The version part matches ANY X.Y.Z rather than the literal previousVersion axion
            // offers, and that is load-bearing at the first release: axion computes
            // previousVersion with ignoreNextVersionTags, so the `vX.Y.Z-SNAPSHOT` marker that
            // Setup Next Version pushes is skipped and previousVersion falls back to
            // initialVersion — 0.0.0, a string the README does not contain. A literal pattern
            // would therefore match nothing exactly once: on the release where getting the
            // coordinates right matters most, and silently.
            listOf(
                "push2u-core",
                "push2u-testkit",
                "push2u-signer-vault",
                "push2u-spring-boot-starter",
                "push2u-signer-vault-spring-boot-starter",
            ).forEach { module ->
                fileUpdate {
                    encoding = "utf-8"
                    file("README.md")
                    pattern = { _: String, _: HookContext ->
                        Regex.escape("com.the13haven:$module:") + """\d+\.\d+\.\d+"""
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
    // Maven groupId — the namespace verified on the Central Portal, and the same reversed domain
    // the Java packages are built on (com.the13haven.push2u.*). Nothing requires the two to match,
    // but both are meant to be anchored on a domain the project owns, and the13haven.com is it.
    group = "com.the13haven"
    version = scmDerivedVersion

    repositories {
        mavenCentral()
    }
}

subprojects {
    // Baseline = Java 21 LTS (docs/adr/0001-java-21-baseline.md): build with the JDK 26 toolchain but pin
    // `--release 21` so the bytecode + visible API stay 21-compatible.
    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "UTF-8"
        options.release.set(21)
        options.compilerArgs.add("-parameters")
    }
    tasks.withType<Test>().configureEach {
        useJUnitPlatform()

        // The measurement suites (docs/PERFORMANCE.md) are opt-in: they spend wall clock on
        // purpose and assert nothing, so CI must never run them. They are gated on this property
        // rather than on a JUnit tag because a tag has to be excluded everywhere it could run,
        // while a disabled-by-default condition is off unless someone asks for it. A -D on the
        // Gradle command line reaches Gradle's own JVM and not the forked test JVM, so it is
        // forwarded here explicitly.
        systemProperty("push2u.measure", providers.systemProperty("push2u.measure").getOrElse("false"))

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

// No module-level dependency constraints here, on purpose.
//
// A constraint declared in `api` or `implementation` is inherited by apiElements/runtimeElements,
// which are the configurations Gradle publishes — it lands in the module metadata as
// dependencyConstraints and in the POM as dependencyManagement, and Gradle applies it to every
// consumer's graph. That is the transitive surface ADR-002 exists to keep out, and published
// metadata cannot be taken back. The same holds for push2u-testkit's `api`: the kit is published,
// so a constraint declared there would reach every consumer that puts it on a test classpath.
//
// So a vulnerable transitive gets pinned where it actually resolves and where the pin stays private:
// a non-published bucket (testImplementation, fipsTestImplementation, and now push2u-core's
// testFixtures buckets, whose variants are skipped from its publication), a tool configuration (as
// push2u-quality.gradle.kts does for the Checkstyle classpath), or the buildscript. Each pin names
// its advisory — the convention in CONTRIBUTING.md.
//
// The buildscript pin above is exactly that and stays: JGit (inside axion-release) really does
// request 1.81/1.82, the pin really does raise it to 1.85, and it is the build's own classpath, so
// no artefact's metadata sees it.
//
// Jackson is not pinned: Spring Boot's managed jackson-2-bom governs it on the starter classpaths.

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
    // deprecated and fails in Gradle 10. Every subproject is a published module; if one ever
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
