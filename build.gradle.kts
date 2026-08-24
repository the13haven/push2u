import java.math.BigDecimal
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Element
import org.gradle.api.plugins.JavaPluginExtension
import pl.allegro.tech.build.axion.release.domain.hooks.HookContext
import pl.allegro.tech.build.axion.release.domain.preRelease

// Shared configuration for every push2u module. It lives at the standalone build root rather than
// being duplicated per module.

// No BouncyCastle pin on the BUILDSCRIPT classpath any more, and no buildscript block at all.
//
// There used to be one. axion-release reads the version from git tags through JGit, and JGit's
// optional org.eclipse.jgit.gpg.bc module (signed-tag support) used to request BouncyCastle 1.81
// through range dependencies that resolved bcprov to 1.82 — five advisories, one of them critical
// (GHSA-574f-3g2m-x479, GOST 28147 CTR keystream reuse; not a code path this build takes, but the
// version is the version). Four constraints raised the four BC artefacts to a clean release.
//
// axion-release 1.21.3 carries JGit 7.7.1, which manages all four at a flat 1.84 with no ranges,
// and axion itself declares bcprov 1.84 directly on top of that. Every one of those five advisories
// is patched in 1.84, so the constraints had nothing left to raise and were removed rather than
// left to look load-bearing. The repositories block went with them: plugins arrive through
// settings.gradle.kts pluginManagement, and nothing here fetches an artefact of its own any more.
//
// If a future advisory hits what JGit requests, the pin comes back in this shape — constraints
// rather than resolutionStrategy.force, per CONTRIBUTING.md, because force records the originally
// requested version in the submitted dependency graph and Dependabot alerts on that phantom node.

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
// The buildscript carried exactly such a pin until JGit stopped requesting a vulnerable
// BouncyCastle; the comment at the top of this file records what it was for and what it would take
// to need it again.
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
// A substituted Spring Boot version never reaches a published artifact.
//
// settings.gradle.kts lets -Ppush2u.springBoot=<version> substitute the catalog's `springBoot` key
// so that a named run can compile the starters against a NEWER Spring Boot than the floor they
// advertise. What that run must not do is publish. The catalog key is BOTH the version compiled
// against and the version published as the floor, so a substituted publish is internally
// consistent — it compiles against 4.1.1 and declares 4.1.1 — and wrong for the reason that
// consistency hides: the number it declares is not the minimum this project supports, tests and
// answers for. Nothing about the jar would say so.
//
// The check is on the task TYPE and runs when the task runs, which is what makes it hold. A name
// filter over the invoked tasks does not: Gradle accepts camelCase abbreviations, so `pTML` enters
// publishToMavenLocal without the word appearing anywhere, and the Central bundle reaches every
// module's publication through nmcpZipAggregation depending on tasks nobody named. Every path into
// publishing — local, Central, the aggregation, and any of them reached as a dependency — runs an
// AbstractPublishToMaven, and each one asks here first.
//
// Every module, and not only the two starters whose floor is at stake. That breadth is deliberate:
// the Central upload is one bundle validated as a whole, so a run that would publish push2u-core
// under a substituted invocation is the same run that would publish the starters. Refusing the
// invocation wherever it first reaches a publication is simpler than deciding which module's
// artifacts a substitution could have changed.
// ---------------------------------------------------------------------------------------------
val springBootSubstitute = providers.gradleProperty("push2u.springBoot")

allprojects {
    tasks.withType<AbstractPublishToMaven>().configureEach {
        val substitute = springBootSubstitute
        doFirst {
            require(!substitute.isPresent) {
                "-Ppush2u.springBoot=${substitute.get()} substitutes the Spring Boot version " +
                    "this build compiles against AND the floor the starters publish, and $path is " +
                    "a publishing task. A release built this way would declare a minimum this " +
                    "project does not support, with nothing about the artifacts to say so. The " +
                    "property is for a run above the floor, and such a run publishes nothing. " +
                    "Drop the property, or drop the publishing task."
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// What the starters publish about Spring Boot's version, asserted against the generated metadata.
//
// ADR-032 decided four things, and the build enforces one of them by construction: the floor is
// the compile classpath, so a starter cannot use an API newer than it advertises. The other three
// are properties of the published files and nothing else — no BOM leaves the project, the one
// Spring Boot dependency that does carries an ordinary `require` version, and no upper bound is
// published in any spelling. Undoing any of them compiles, tests green and is discovered by a
// consumer after a release that cannot be withdrawn, which is the failure shape the SPI contract
// tests exist for. So the same treatment: read the POM and the module metadata the publication
// tasks generate, and fail `check` on what they say.
// ---------------------------------------------------------------------------------------------
val springBootFloor = libs.versions.springBoot.get()

/** The direct child elements of [parent] with this tag — never a grandchild, which is the point. */
fun childElements(parent: Element, tag: String): List<Element> =
    (0 until parent.childNodes.length)
        .map { parent.childNodes.item(it) }
        .filterIsInstance<Element>()
        .filter { it.tagName == tag }

listOf(":push2u-spring-boot-starter", ":push2u-signer-vault-spring-boot-starter").forEach { path ->
    project(path) {
        val module = path
        val verifyPublishedSpringBoot = tasks.register("verifyPublishedSpringBootFloor") {
            group = "verification"
            description = "Fails if the published metadata says anything about Spring Boot's version " +
                "beyond the declared minimum."

            val pom = layout.buildDirectory.file("publications/maven/pom-default.xml")
            val moduleMetadata = layout.buildDirectory.file("publications/maven/module.json")
            dependsOn("generatePomFileForMavenPublication", "generateMetadataFileForMavenPublication")
            inputs.file(pom)
            inputs.file(moduleMetadata)
            inputs.property("floor", springBootFloor)
            val marker = layout.buildDirectory.file("reports/published-spring-boot-floor.txt")
            outputs.file(marker)

            val floor = springBootFloor
            doLast {
                // The POM is read as XML rather than matched as text, and the difference is not
                // fastidiousness: <groupId> is also the element an <exclusions> block uses, so any
                // pattern that finds this group inside a <dependency> window finds an exclusion
                // too and then reports the excluding artifact's version as a Spring Boot one.
                // Walking direct children cannot make that mistake.
                val pomRoot = DocumentBuilderFactory.newInstance().newDocumentBuilder()
                    .parse(pom.get().asFile)
                    .documentElement

                // Decision 1. An imported BOM is a <dependency> with <scope>import</scope> inside
                // <dependencyManagement>, and the element is absent from these POMs entirely — the
                // starters declare no constraints of any other kind either, so the stricter check
                // is also the simpler one.
                require(pomRoot.getElementsByTagName("dependencyManagement").length == 0) {
                    "$module publishes a <dependencyManagement> section. Spring Boot's BOM on a " +
                        "published configuration hands a Gradle consumer Spring Boot's whole " +
                        "version manifest as an input to their own resolution; it belongs on " +
                        "compileOnly, annotationProcessor and test configurations."
                }

                // Decision 2, WHICH artifact: exactly one Spring Boot artifact is published from
                // a starter, and it is spring-boot-autoconfigure. This is a rule about identity
                // and the version rules cannot stand in for it — spring-boot-dependencies declared
                // WITHOUT `platform()` is an ordinary dependency at the floor's own version, so it
                // leaves the dependencyManagement check and both version checks satisfied while
                // putting a second Spring Boot coordinate on every consumer's classpath, which is
                // a decision this library has not taken. What such a dependency does after that
                // varies by ecosystem and is deliberately not what this check reasons about.
                val bootDependencies = childElements(pomRoot, "dependencies")
                    .flatMap { childElements(it, "dependency") }
                    .filter { dependency ->
                        childElements(dependency, "groupId")
                            .any { it.textContent.trim() == "org.springframework.boot" }
                    }
                    .map { dependency ->
                        val artifact = childElements(dependency, "artifactId")
                            .map { it.textContent.trim() }
                            .firstOrNull()
                        val version = childElements(dependency, "version")
                            .map { it.textContent.trim() }
                            .firstOrNull()
                        artifact to version
                    }
                require(bootDependencies.map { it.first } == listOf("spring-boot-autoconfigure")) {
                    "$module publishes the Spring Boot artifacts " +
                        "${bootDependencies.map { it.first }} in its POM. Exactly one may leave a " +
                        "starter, and it is spring-boot-autoconfigure — every other Spring Boot " +
                        "coordinate here reaches a consumer's classpath through a decision this " +
                        "library has not taken. spring-boot-dependencies is the one to watch for: " +
                        "declared without platform() it is an ordinary dependency at the right " +
                        "version, and every other check in this task passes it."
                }

                // Decisions 2 and 4, WHICH version: it carries the floor literally. A missing
                // version and a range both fail here, the second being the only spelling of an
                // upper bound a POM can carry.
                val pomVersions = bootDependencies.map { it.second }
                require(pomVersions.all { it == floor }) {
                    "$module publishes Spring Boot versions $pomVersions in its POM; the floor is " +
                        "$floor. A versionless dependency leaves a Maven consumer with nothing to " +
                        "resolve, and a range admits milestones."
                }

                // Decisions 2 and 4, in the Gradle metadata, where the spellings a POM cannot carry
                // are visible: `strictly` fails a consumer's build outright, `rejects` is an upper
                // bound wherever it names one, and both are invisible to the POM check above.
                val gradleBootDependencies = Regex(
                        "\"group\": ?\"org\\.springframework\\.boot\",\\s*" +
                            "\"module\": ?\"([^\"]+)\",\\s*\"version\": ?\\{([^}]*)\\}",
                        RegexOption.DOT_MATCHES_ALL)
                    .findAll(moduleMetadata.get().asFile.readText())
                    .map { it.groupValues[1] to it.groupValues[2] }
                    .toList()
                require(gradleBootDependencies.map { it.first }.toSet() ==
                    setOf("spring-boot-autoconfigure")) {
                    "$module publishes the Spring Boot modules " +
                        "${gradleBootDependencies.map { it.first }.toSet()} in its module " +
                        "metadata. Exactly one leaves a starter, spring-boot-autoconfigure."
                }
                val gradleRequirements = gradleBootDependencies.map { it.second }
                // The same tolerance for optional whitespace the outer pattern allows — the two
                // read the same file and a writer that tightened its spacing must not make one
                // match and the other fail.
                val requiresFloor = Regex("\"requires\": ?\"" + Regex.escape(floor) + "\"")
                require(gradleRequirements.isNotEmpty() &&
                    gradleRequirements.all { requiresFloor.containsMatchIn(it) }) {
                    "$module publishes Spring Boot requirements $gradleRequirements in its module " +
                        "metadata; each must be an ordinary requires of $floor."
                }
                require(gradleRequirements.none {
                    it.contains("strictly") || it.contains("rejects") || it.contains("prefers")
                }) {
                    "$module publishes a strict, rejecting or preferred Spring Boot version " +
                        "$gradleRequirements. The POM carries none of the three, so a Gradle " +
                        "consumer would meet a constraint a Maven consumer never sees."
                }

                marker.get().asFile.writeText("published Spring Boot floor: $floor\n")
            }
        }
        // Reactively, for the reason the publishing convention plugin is applied reactively: the
        // module declares `java-library` itself, so `check` does not exist while the root is being
        // configured.
        plugins.withId("java") { tasks.named("check") { dependsOn(verifyPublishedSpringBoot) } }
    }
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
