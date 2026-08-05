import com.github.spotbugs.snom.SpotBugsTask
import java.util.concurrent.Callable
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

// Checkstyle, PMD and SpotBugs analyse production code only — see the task-graph hook at the
// bottom. Measured on the tree of the day, running them over the test sources (`test`, `fipsTest`
// and `testFixtures`) reports 210 Checkstyle and 191 PMD violations — Javadoc, naming and
// complexity rules that test code is not written to satisfy — and 0 from SpotBugs, which alone
// costs ~17s of the ~37s CI run. Error Prone is the exception and does cover the test compilations;
// see its section below.

// ---------------------------------------------------------------------------------------------
// Spotless — Palantir Java Format. Authoritative for everything layout-related.
// ---------------------------------------------------------------------------------------------
spotless {
    java {
        // The Apache-2.0 SPDX header, on every Java file of every source set — Spotless both
        // applies it (qualityCheck) and verifies it (qualityCheckCi).
        //
        // $YEAR is resolved once, when the header is first written to a file, and preserved on
        // every later run (Spotless's PRESERVE year mode, the default without `ratchetFrom`): a
        // file keeps the year it was created in, and nothing rewrites every file each January.
        //
        // LicenseHeaderStep skips package-info.java and module-info.java by name — their leading
        // Javadoc would otherwise be treated as the old header and replaced. Those files carry the
        // header by hand, and Checkstyle's RegexpHeader is what verifies it there: checkstyle.xml
        // covers main's package-info.java, and the `checkstyleLicenseHeader` task below covers
        // every other source set plus main's module-info.java, which checkstyleMain cannot parse.
        licenseHeaderFile(rootProject.file("config/quality/license/header.txt"))

        palantirJavaFormat(toolVersion("palantir"))
            .formatJavadoc(true)
            .style("PALANTIR")

        // "java" matches by prefix, so javax.* lands in the first group with the JDK packages —
        // config/quality/checkstyle/checkstyle.xml verifies the same grouping.
        //
        // No targetExclude for build/**: Spotless targets the source sets, and nothing generated
        // under build/ is part of one (verified with a deliberately misformatted file there).
        importOrder("java", "", "com.the13haven.push2u")
        removeUnusedImports()
    }
}

// ---------------------------------------------------------------------------------------------
// Checkstyle — naming, Javadoc and import-order verification (never formatting; Spotless owns it).
// ---------------------------------------------------------------------------------------------
// The header-only Checkstyle task, named here because the exclusion below has to spare it.
val licenseHeaderTaskName = "checkstyleLicenseHeader"

// Checkstyle 13.9.0 cannot parse a module declaration: its TreeWalker grammar has no production for
// one, and `module foo {}` alone fails with "no viable alternative at input 'modulefoo{'". A single
// unparseable file fails the whole task, so the descriptor is excluded here rather than costing the
// module its Checkstyle coverage entirely. Nothing in checkstyle.xml applies to a module descriptor
// anyway — naming, Javadoc and import order are all about type declarations — except the licence
// header, which is why checkstyleLicenseHeader is exempt: its configuration has no TreeWalker, so
// it reads the file as lines and never parses it. Revisit when Checkstyle grows the grammar.
tasks.withType<Checkstyle>().configureEach {
    if (name != licenseHeaderTaskName) {
        exclude("module-info.java")
    }
}

checkstyle {
    toolVersion = toolVersion("checkstyle")
    configFile = rootProject.file("config/quality/checkstyle/checkstyle.xml")

    // `config/quality`, not the directory holding checkstyle.xml: this is what `${config_loc}`
    // resolves to inside the config, and both configurations read the header pattern from
    // `${config_loc}/license/header-regex.txt`. Gradle tracks the whole directory as a task input,
    // so editing the header pattern re-runs Checkstyle — a path escaping it with `..` would not
    // be tracked, and a changed pattern would silently replay a stale UP-TO-DATE result.
    //
    // An IDE Checkstyle plugin resolving `${config_loc}` on its own will point it at the directory
    // holding the config file; set it to `config/quality` there too, or the header pattern will
    // not be found.
    configDirectory = rootProject.layout.projectDirectory.dir("config/quality")
}

// Version bumps, not suppressions. Both artefacts reach the `checkstyle` configuration only — the
// tool classpath — and neither is a dependency of the published library.
//
// commons-lang3: Checkstyle 13.9.0 — the current release — still pulls 3.8.1 through doxia-core
// 1.12.0 (and 3.7 through commons-text 1.3), vulnerable to CVE-2025-48924 (uncontrolled recursion).
//
// plexus-utils: the same doxia-core chain, via plexus-container-default 2.1.0, resolves 3.3.0.
// GHSA-6fmv-xxpf-w3cw is fixed in 3.6.1, the last release of the 3.x line, so the pin stays within
// the major the tool was built against.
//
// Both come off the same unmaintained doxia 1.12.0 branch; remove each once Checkstyle upstream
// depends on a patched version.
dependencies {
    constraints {
        add("checkstyle", "org.apache.commons:commons-lang3:3.18.0") {
            because("CVE-2025-48924")
        }
        add("checkstyle", "org.codehaus.plexus:plexus-utils:3.6.1") {
            because("GHSA-6fmv-xxpf-w3cw")
        }
    }
}

// The one Checkstyle task that is not main-only. Checkstyle skips the test source sets because the
// full ruleset does not apply to them, and Spotless — which does cover every source set — skips
// package-info.java and module-info.java by name (LicenseHeaderStep would eat their leading
// Javadoc). The overlap of the two exclusions is a file nothing checks, and one of those files does
// ship to Maven Central: main's module-info.java, which checkstyleMain cannot even parse. This task
// closes that gap with a configuration holding RegexpHeader and nothing else, and it covers the
// test source sets in the same pass — ADR-008 puts the header on every file, published or not.
// Resolved here, against the project: inside the task-configuration lambda below, `extensions`
// would be the task's own and `SourceSetContainer` is not among them.
val javaSourceSets = extensions.getByType<SourceSetContainer>()

val checkstyleLicenseHeader = tasks.register<Checkstyle>(licenseHeaderTaskName) {
    description = "Verifies the licence header on the source sets checkstyleMain does not cover."
    group = "verification"

    configFile = rootProject.file("config/quality/checkstyle/checkstyle-header.xml")

    // A Callable, so the container is read when the task's inputs are resolved rather than when
    // this plugin is applied — push2u-core creates `fipsTest` in its own build script, which runs
    // later, and a list built here and now would miss it.
    //
    // `main` is here too, but only for module-info.java: checkstyleMain cannot read it at all.
    // Checkstyle 13.9.0's TreeWalker has no grammar for a module declaration — even `module foo {}`
    // fails with "no viable alternative at input 'modulefoo{'" — and one unparseable file aborts
    // the whole task, taking the other 32 main sources with it. So checkstyleMain excludes the
    // descriptor (see below) and it lands here instead, where the header-only configuration has no
    // TreeWalker and never parses anything.
    setSource(
        Callable {
            javaSourceSets.flatMap { sourceSet ->
                if (sourceSet.name == SourceSet.MAIN_SOURCE_SET_NAME) {
                    sourceSet.java.srcDirs.map { File(it, "module-info.java") }.filter { it.isFile }
                } else {
                    sourceSet.java.srcDirs
                }
            }
        })
    include("**/*.java")

    // Checkstyle parses source, not bytecode; the property is mandatory but nothing here reads it.
    classpath = files()
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

// No log4j constraint here: SpotBugs 4.10.3 already depends on log4j-core 2.26.1, past the versions
// CVE-2026-34478 / -34477 / -34480 and CVE-2025-68161 apply to.

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
//
// Unlike Checkstyle/PMD/SpotBugs, Error Prone runs on the test compilations too: its checks are
// about defects, not style, and they catch real ones there (a `return` inside a `finally`, a
// String.split call with surprising trailing-empty behaviour). NullAway is the exception — without
// annotations it reports every builder field, which on test sources is noise and nothing else.
// ---------------------------------------------------------------------------------------------
dependencies {
    add("errorprone", toolLibrary("errorprone-core"))
    add("errorprone", toolLibrary("nullaway"))
}

// Checks promoted to ERROR, so a quality run fails on them instead of printing a warning nobody
// reads. Two groups:
//   * the defects Error Prone actually caught in this codebase (Finally, StringSplitter,
//     AddressSelection, ArrayRecordComponent) — each one is fixed or explicitly suppressed at the
//     site, so a new occurrence is a regression;
//   * MissingOverride and ReferenceEquality, which config/quality/pmd/ruleset.xml excludes on the
//     grounds that Error Prone owns them. That claim only holds if they fail the build.
// Extend the list when a new check proves it earns a build failure here.
val blockingChecks = listOf(
    "AddressSelection",
    "ArrayRecordComponent",
    "Finally",
    "MissingOverride",
    "ReferenceEquality",
    "StringSplitter",
)

tasks.withType<JavaCompile>().configureEach {
    // `main` plus `testFixtures`; `test` and `fipsTest` stay out. NullAway runs in OnlyNullMarked
    // mode, so what decides coverage is whether the code sits in a @NullMarked scope, not which
    // source set it is in — and both modules' fixtures deliberately share the package of `main`,
    // whose package-info.java marks it. They inherit the mark from the classpath and need no
    // package-info.java of their own; covering them costs nothing and is not optional to keep,
    // because dropping it silently retires enforcement that already worked.
    //
    // `test` and `fipsTest` are excluded on their own merits, not for lack of a mark: they are
    // where a nullness complaint is least likely to be a defect and most likely to be scaffolding
    // written to fail. Whether they would pay for themselves has not been measured; if it ever is,
    // this is the line to change.
    //
    // The failure this catches is real and has happened once: moving the conformance kit into its
    // own package (ADR-014) left it outside any @NullMarked, and nothing said so — a
    // package-info.java carrying no annotation does not even compile to a class file, so the loss
    // is invisible in the jar. In push2u-testkit that check is now simply `compileJava`.
    val productionCompile = name == "compileJava" || name == "compileTestFixturesJava"
    options.errorprone {
        enabled = provider {
            gradle.taskGraph.hasTask("${project.path}:qualityCheck") ||
                gradle.taskGraph.hasTask("${project.path}:qualityCheckCi")
        }
        error(*blockingChecks.toTypedArray())

        // Style-only check: the Duration literals in the tests mirror protocol values (Retry-After
        // is specified in seconds), and restating them in minutes breaks that correspondence.
        disable("CanonicalDuration")

        if (productionCompile) {
            // The public API is annotated: every package carries JSpecify's @NullMarked, so a
            // reference type is non-null unless it says @Nullable. NullAway verifies that contract
            // and fails the build on a violation.
            //
            // OnlyNullMarked over the older AnnotatedPackages: the source of truth is the
            // @NullMarked annotation in package-info.java, not a package prefix repeated in the
            // build script — a new package is covered by marking it, not by editing this file.
            // RequireExplicitNullMarking then makes forgetting that mark a build failure.
            //
            // NullAway:JSpecifyMode (full generic nullness) is deliberately left off: its authors
            // still describe it as evolving and prone to false positives. It is the next step, not
            // this one.
            error("NullAway", "RequireExplicitNullMarking")
            option("NullAway:OnlyNullMarked", "true")
        } else {
            disable("NullAway")
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Lifecycle tasks
// ---------------------------------------------------------------------------------------------
val analysisTasks = listOf("checkstyleMain", checkstyleLicenseHeader.name, "pmdMain", "spotbugsMain")

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

// Ordering: cheapest failure first. Formatting is checked before anything is compiled, the
// analysers run before the test suites, and within the analysers it goes Checkstyle -> PMD ->
// SpotBugs. Without this, Gradle is free to schedule the whole build-and-test cycle ahead of
// spotlessCheck, and a misplaced brace surfaces minutes after the compiler already had the answer.
//
// Locally the same ordering is what makes spotlessApply rewrite the sources before javac reads
// them, rather than racing it.
val formattingTasks = listOf("spotlessApply", "spotlessCheck")

tasks.withType<JavaCompile>().configureEach { mustRunAfter(formattingTasks) }
// checkstyleLicenseHeader goes first among the analysers: one rule over the source lines, a
// fraction of a second, against SpotBugs' ~17s at the other end of the chain.
checkstyleLicenseHeader.configure { mustRunAfter(formattingTasks) }
tasks.named("checkstyleMain") { mustRunAfter(formattingTasks, checkstyleLicenseHeader) }
tasks.named("pmdMain") { mustRunAfter("checkstyleMain") }
tasks.named("spotbugsMain") { mustRunAfter("pmdMain") }
tasks.withType<Test>().configureEach { mustRunAfter(analysisTasks) }

// Quality tasks are disabled unless a quality lifecycle task is in the graph. That keeps
// `./gradlew build` (and the `check` task the tool plugins hook into) compile + test only, and it
// is what confines Checkstyle/PMD/SpotBugs to the `main` source set.
gradle.taskGraph.whenReady {
    val runQuality = hasTask("${project.path}:qualityCheck") || hasTask("${project.path}:qualityCheckCi")
    val mainOnly = { taskName: String -> runQuality && taskName.endsWith("Main") }

    // A tool task named on the command line runs regardless — `./gradlew spotlessApply` is what
    // Gradle itself tells you to do after a formatting failure, and `./gradlew checkstyleTest` is a
    // reasonable thing to ask for deliberately. Only the implicit path (a tool task pulled in by
    // `check`) is suppressed. Spotless is matched by prefix because spotlessApply/spotlessCheck
    // delegate to per-format tasks (spotlessJavaApply and friends) that carry different names.
    val requested = gradle.startParameter.taskNames.map { it.substringAfterLast(':') }.toSet()
    val spotlessRequested = requested.any { it.startsWith("spotless") }

    // checkstyleLicenseHeader is the exception to "main-only": it exists precisely for the source
    // sets the name-based rule excludes, so it is enabled by the quality gate on its own name.
    tasks.withType<Checkstyle>().configureEach {
        enabled = mainOnly(name) || (runQuality && name == checkstyleLicenseHeader.name) || name in requested
    }
    tasks.withType<Pmd>().configureEach { enabled = mainOnly(name) || name in requested }
    tasks.withType<SpotBugsTask>().configureEach { enabled = mainOnly(name) || name in requested }
    tasks.matching { it.name.startsWith("spotless") }.configureEach {
        enabled = runQuality || spotlessRequested
    }

    // The failure mode of resolving the source sets lazily is a rule that checks nothing, quietly.
    // Two shapes of it, and the second is the likely one:
    //
    //   * nothing at all resolves — Checkstyle reports NO-SOURCE and the build stays green;
    //   * something resolves, but not everything. Replace the Callable at the top of this file with
    //     a list built where it stands, and it evaluates while `plugins.withId("java")` is firing —
    //     before push2u-core applies java-test-fixtures and creates fipsTest. What you get is
    //     src/test alone: not empty, so a non-emptiness check passes, while src/testFixtures and
    //     src/fipsTest — two source sets this task is the only header check for — go unread.
    //
    // So the assertion is coverage, not non-emptiness: every non-main Java file the source sets
    // hold now must be one this task is about to read. `whenReady` is where that can be asked —
    // the graph is built and every build script has run, but nothing has executed, and
    // `SourceTask.getSource()` being @SkipWhenEmpty means a guard inside the task would itself be
    // skipped in the first case.
    val licenseHeaderTask = "${project.path}:${checkstyleLicenseHeader.name}"
    if (hasTask(licenseHeaderTask)) {
        // Read the container again here rather than reusing `javaSourceSets` from the top of the
        // file. An assertion computed from the same expression as the thing it asserts about is
        // not an assertion: factor the two into one shared val — the refactor this duplication
        // invites — and an eager read degrades both sides identically, `missing` comes back empty,
        // and the guard waves through exactly what it was written to catch. Keep the two reads
        // separate, and the guard fails independently of how the task's source was built.
        val sourceSetsNow = project.extensions.getByType<SourceSetContainer>()
        val nonMain =
            project
                .files(sourceSetsNow.filter { it.name != SourceSet.MAIN_SOURCE_SET_NAME }.flatMap { it.java.srcDirs })
                .asFileTree
                .matching { include("**/*.java") }
                .files
        // main's module descriptor belongs to the assertion too: checkstyleMain excludes it (the
        // parser cannot read it) and Spotless skips it by name, so this task is the only thing
        // checking its licence header. Leaving it out of `expected` would let the task quietly stop
        // reading the one file whose coverage depends entirely on it.
        val mainDescriptors =
            sourceSetsNow
                .filter { it.name == SourceSet.MAIN_SOURCE_SET_NAME }
                .flatMap { it.java.srcDirs }
                .map { File(it, "module-info.java") }
                .filter { it.isFile }
        val expected = nonMain + mainDescriptors
        val missing = expected - checkstyleLicenseHeader.get().source.files

        // `nonMain`, not `expected`: a module carrying a module-info.java has a non-empty `expected`
        // from that one file alone, so testing the union would leave this tripwire alive only in
        // the modules without a descriptor — and silent in push2u-core, which holds three non-main
        // source sets and most of the non-main sources.
        //
        // This plugin is applied reactively to `java` modules, so a java-platform BOM never gets
        // here and every module that does has test sources. Nothing to check therefore means
        // either the source-set read stopped being lazy, or a module was added before its tests —
        // both worth stopping for rather than passing silently.
        if (nonMain.isEmpty()) {
            error("$licenseHeaderTask found no non-main sources — module without tests, or a read that is no longer lazy?")
        }
        if (missing.isNotEmpty()) {
            // Capped: the total failure resolves to every non-main file in the module, and a
            // 43-path error message buries its own first line.
            val examples = missing.take(5).joinToString("\n  ") { it.relativeTo(project.projectDir).path }
            error(
                "$licenseHeaderTask does not cover everything it must read — ${missing.size} file(s) " +
                    "would go unchecked, among them:\n  $examples")
        }
    }
}
