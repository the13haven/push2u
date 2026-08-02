import com.github.spotbugs.snom.SpotBugsTask
import net.ltgt.gradle.errorprone.errorprone

// Convention plugin bundling every static-analysis tool push2u runs: Spotless (formatting),
// Checkstyle (style beyond formatting), PMD, SpotBugs, Error Prone + NullAway (compiler checks)
// and JaCoCo (coverage). Applied to every module from the root build.gradle.kts.
//
// The quality tools stay OUT of the plain `build` / `check` path — they are wired to the
// `qualityCheck` (local, auto-formats) and `qualityCheckCi` (CI, verifies formatting) lifecycle
// tasks instead, so an ordinary `./gradlew build` remains compile + test only.

plugins {
    id("checkstyle")
    id("pmd")
    id("jacoco")
    id("com.github.spotbugs")
    id("com.diffplug.spotless")
    id("net.ltgt.errorprone")
}

// The convention plugin lives in an included build, so the typed `libs` accessor is not available
// here — read the same catalog through the API instead.
val libs = extensions.getByType<VersionCatalogsExtension>().named("libs")

fun toolVersion(alias: String): String =
    libs.findVersion(alias).orElseThrow { IllegalStateException("missing catalog version: $alias") }
        .requiredVersion

fun toolLibrary(alias: String): Provider<MinimalExternalModuleDependency> =
    libs.findLibrary(alias).orElseThrow { IllegalStateException("missing catalog library: $alias") }

// Analysis runs on production code only — see the task-graph hook at the bottom. Test sources
// (including push2u-core's `fipsTest` source set and the published `testFixtures`) are exempt:
// Javadoc/naming rules, complexity limits and SpotBugs' mutability heuristics all fire constantly
// on test code without finding real defects.

// ---------------------------------------------------------------------------------------------
// Spotless — Palantir Java Format. Authoritative for everything layout-related.
// ---------------------------------------------------------------------------------------------
spotless {
    java {
        palantirJavaFormat(toolVersion("palantir"))
            .formatJavadoc(true)
            .style("PALANTIR")

        importOrder("java", "", "io.push2u")
        removeUnusedImports()
        targetExclude("build/**")
    }
}

// ---------------------------------------------------------------------------------------------
// Checkstyle — naming, Javadoc and import-order verification (never formatting; Spotless owns it).
// ---------------------------------------------------------------------------------------------
checkstyle {
    toolVersion = toolVersion("checkstyle")
    configFile = rootProject.file("config/quality/checkstyle/checkstyle.xml")
}

// Transitive override: Checkstyle 13.4.2 pulls in commons-lang3 3.8.1 via doxia-core, which is
// vulnerable to CVE-2025-48924 (uncontrolled recursion). The jar is loaded only by Gradle's
// checkstyle task to analyse our own source — no attacker-controlled input — but force the patched
// version anyway so the dependency graph stays clean. Remove once Checkstyle upstream depends on
// commons-lang3 >= 3.18.0.
dependencies {
    constraints {
        add("checkstyle", "org.apache.commons:commons-lang3:3.18.0") {
            because("CVE-2025-48924")
        }
    }
}

// ---------------------------------------------------------------------------------------------
// PMD
// ---------------------------------------------------------------------------------------------
pmd {
    toolVersion = toolVersion("pmd")
    ruleSetFiles = rootProject.files("config/quality/pmd/ruleset.xml")
    // Clear the default rule sets — ruleset.xml is the single source of truth.
    ruleSets = emptyList()
}

// ---------------------------------------------------------------------------------------------
// SpotBugs
// ---------------------------------------------------------------------------------------------
spotbugs {
    toolVersion = toolVersion("spotbugs")
    excludeFilter = rootProject.file("config/quality/spotbugs/exclusions.xml")
}

// Transitive override: SpotBugs pulls in a log4j-core build that Dependabot flags
// (CVE-2026-34478 / -34477 / -34480, CVE-2025-68161). The vulnerable layouts/appenders are not
// configured in this build, and the jar never reaches an application classpath — it is confined to
// the `spotbugs` configuration. Remove once SpotBugs depends on log4j-core >= 2.25.4 itself.
dependencies {
    constraints {
        add("spotbugs", "org.apache.logging.log4j:log4j-core:2.25.4") {
            because("CVE-2026-34478 / -34477 / -34480 / CVE-2025-68161")
        }
        add("spotbugs", "org.apache.logging.log4j:log4j-api:2.25.4") {
            because("aligned with log4j-core override")
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Reports — HTML for humans, XML for machines (CI artifacts, IDE and LLM-readable output).
// ---------------------------------------------------------------------------------------------
tasks.withType<Checkstyle>().configureEach {
    reports {
        html.required = true
        xml.required = true
    }
}

tasks.withType<Pmd>().configureEach {
    reports {
        html.required = true
        xml.required = true
    }
}

tasks.withType<SpotBugsTask>().configureEach {
    reports {
        create("html") { required = true }
        create("xml") { required = true }
    }
}

// ---------------------------------------------------------------------------------------------
// JaCoCo — per-module report; the aggregated report and the coverage threshold live in the root
// build.
// ---------------------------------------------------------------------------------------------
jacoco {
    toolVersion = toolVersion("jacoco")
}

tasks.named<JacocoReport>("jacocoTestReport") {
    reports {
        html.required = true
        xml.required = true
    }
}

// ---------------------------------------------------------------------------------------------
// Error Prone + NullAway — compiler-attached checks. Only active when a quality lifecycle task is
// in the graph, so a plain `./gradlew build` compiles at full speed.
// ---------------------------------------------------------------------------------------------
dependencies {
    add("errorprone", toolLibrary("errorprone-core"))
    add("errorprone", toolLibrary("nullaway"))
}

tasks.withType<JavaCompile>().configureEach {
    val analysedCompile = name == "compileJava"
    options.errorprone {
        enabled = provider {
            analysedCompile && (
                gradle.taskGraph.hasTask("${project.path}:qualityCheck") ||
                    gradle.taskGraph.hasTask("${project.path}:qualityCheckCi")
                )
        }
        // NullAway runs as a warning: push2u carries no nullability annotations yet (the core is
        // zero-dependency, so even an annotations-only jar is a deliberate decision). Promote to
        // error() once the public API is annotated.
        warn("NullAway")
        option("NullAway:AnnotatedPackages", "io.push2u")
    }
}

// ---------------------------------------------------------------------------------------------
// Lifecycle tasks
// ---------------------------------------------------------------------------------------------
val analysisTasks = listOf("checkstyleMain", "pmdMain", "spotbugsMain")

tasks.register("qualityCheck") {
    description = "Runs all quality checks locally (auto-formats code)."
    group = "verification"
    dependsOn("build")
    dependsOn("spotlessApply")
    dependsOn(analysisTasks)
    dependsOn("jacocoTestReport")
}

tasks.register("qualityCheckCi") {
    description = "Runs all quality checks in CI (verifies formatting without modifying files)."
    group = "verification"
    dependsOn("build")
    dependsOn("spotlessCheck")
    dependsOn(analysisTasks)
    dependsOn("jacocoTestReport")
}

// Ordering: format first, then style, then the heavier analysers — so the first failure a
// developer sees is the cheapest one to fix.
tasks.named("checkstyleMain") { mustRunAfter("spotlessApply", "spotlessCheck") }
tasks.named("pmdMain") { mustRunAfter("checkstyleMain") }
tasks.named("spotbugsMain") { mustRunAfter("pmdMain") }

// Quality tasks are disabled unless a quality lifecycle task is in the graph. That keeps
// `./gradlew build` (and the `check` task the tool plugins hook into) compile + test only, and it
// is what confines Checkstyle/PMD/SpotBugs to the `main` source set.
gradle.taskGraph.whenReady {
    val runQuality = hasTask("${project.path}:qualityCheck") || hasTask("${project.path}:qualityCheckCi")
    val mainOnly = { taskName: String -> runQuality && taskName.endsWith("Main") }

    tasks.withType<Checkstyle>().configureEach { enabled = mainOnly(name) }
    tasks.withType<Pmd>().configureEach { enabled = mainOnly(name) }
    tasks.withType<SpotBugsTask>().configureEach { enabled = mainOnly(name) }
    tasks.matching { it.name.startsWith("spotless") }.configureEach { enabled = runQuality }
}
