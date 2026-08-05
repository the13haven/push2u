// Convention plugin for publishing a push2u module to Maven Central. Applied reactively from the
// root build.gradle.kts to every module that applies `java` — the same mechanism as
// push2u-quality, and for the same reason: the modules declare `java-library` themselves, and
// this plugin configures things (the `java` component, the javadoc task) that only exist once the
// Java plugin has created them.
//
// Split of responsibilities:
//   * this plugin — per module: the MavenPublication, the Central-mandated POM metadata, the
//     -sources/-javadoc jars, and the GPG signature;
//   * the root build — cross-module: the axion-derived version/group and the nmcp AGGREGATION,
//     which bundles every module's publication into the single upload the Central Portal expects.

plugins {
    `maven-publish`
    signing
    // Exposes this module's publication (jars, POM, module metadata, signatures) as an outgoing
    // variant the root's nmcp aggregation consumes. Purely a wiring plugin — the actual Central
    // upload task lives in the root project.
    id("com.gradleup.nmcp")
}

// Central mandates a -sources and a -javadoc jar next to every main artifact. The typed `java {}`
// accessor is not generated for this script because the convention plugin does not itself apply a
// Java plugin (the module does), so go through the extension API instead.
extensions.configure<JavaPluginExtension> {
    withJavadocJar()
    withSourcesJar()
}

// The licence travels inside every artifact, not only in the POM's `licenses` element. A jar that
// has been copied out of a repository — into a shaded bundle, an air-gapped mirror, a vendored
// lib/ directory — carries no POM with it, and META-INF/LICENSE is where every convention-following
// tool looks. This is the artifact-level counterpart of the per-file SPDX header of ADR-008.
//
// Deliberately not a NOTICE file: Apache-2.0 §4(d) would then oblige everyone redistributing a
// derivative work to reproduce its contents, which is a real obligation to place on consumers, and
// the attribution it would carry is already in the POM and in every source file.
//
// withType<Jar>, so the -sources and -javadoc jars carry it too — they are distributed artifacts
// like any other. It also reaches jars that are never published (the internal test fixtures of
// push2u-core and push2u-signer-vault), which is harmless: a licence in an artifact that stays
// inside the build costs
// nothing, and narrowing the rule would cost the guarantee that every jar leaving here has one.
tasks.withType<Jar>().configureEach { metaInf { from(rootProject.file("LICENSE")) } }

publishing {
    publications {
        // `register<Type>(name)`, not the `by registering` delegate: the delegated-property
        // syntax is deprecated and scheduled for removal in Gradle 10.
        register<MavenPublication>("maven") {
            // components["java"] carries the main jar plus the -sources/-javadoc variants added
            // above — and any testFixtures variants a module declares. Every set of fixtures in
            // this build is internal scaffolding, so push2u-core and push2u-signer-vault each skip
            // their variants in their own build.gradle.kts. That stays their decision rather than
            // an opt-in switch here: the published conformance kit used to be a set of fixtures,
            // and a module whose fixtures are meant to ship needs nothing from this plugin but the
            // default.
            from(components["java"])

            pom {
                // Everything below is what the Central Portal validates a POM for: name,
                // description, url, licenses, developers and scm. Missing any of them fails the
                // upload, not the build — so keep the list complete here.
                //
                // description is set LAZILY via provider: each module assigns
                // `description = "..."` in its own build script, which runs AFTER this plugin was
                // applied (plugins.withId in the root fires the moment `java-library` is applied,
                // before the rest of the module's script body). An eager read here would capture
                // null and fail Central validation.
                name = provider { project.name }
                description = provider { project.description }
                url = "https://github.com/the13haven/push2u"
                // No `packaging` element on purpose, though Central's example POM shows one: `jar`
                // is the Maven default, and Gradle drops the element whenever it matches that
                // default — assigning it here changes nothing in the generated file. Consumers
                // resolve the artifact identically, and Central validates the metadata above.

                licenses {
                    license {
                        name = "Apache License, Version 2.0"
                        url = "https://www.apache.org/licenses/LICENSE-2.0.txt"
                    }
                }

                developers {
                    developer {
                        // Central's requirements page names all four of these: name, email,
                        // organization and organizationUrl. They are also the only contact route
                        // a consumer has once the artifact is on Central, since a published
                        // version is immutable and can never be corrected.
                        id = "the13haven"
                        name = "Sergej Sidorov"
                        email = "ssidorov@the13haven.com"
                        organization = "the13haven"
                        organizationUrl = "https://github.com/the13haven"
                        url = "https://github.com/the13haven"
                    }
                }

                scm {
                    connection = "scm:git:https://github.com/the13haven/push2u.git"
                    developerConnection = "scm:git:ssh://git@github.com/the13haven/push2u.git"
                    url = "https://github.com/the13haven/push2u"
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// GPG signing — Central rejects unsigned artifacts. The armored private key and its passphrase
// come from the environment (CI: SIGNING_KEY / SIGNING_PASSWORD), falling back to Gradle
// properties (signing.key / signing.password, e.g. in ~/.gradle/gradle.properties) for a local
// release dry-run.
//
// Deliberately conditional: when no key is available, signing is not wired at all — no Sign task
// exists, so a contributor's plain `./gradlew build` or `publishToMavenLocal` works out of the
// box. The rejected alternative — always calling useInMemoryPgpKeys and only toggling isRequired
// — fails at configuration time, because the signing plugin does not accept a null in-memory key.
// Nothing is lost by skipping: the Central Portal is the enforcement point on the release path,
// and it rejects an unsigned bundle — a missing CI secret cannot slip a release through unsigned.
// ---------------------------------------------------------------------------------------------
val signingKey = providers.environmentVariable("SIGNING_KEY")
    .orElse(providers.gradleProperty("signing.key"))
val signingPassword = providers.environmentVariable("SIGNING_PASSWORD")
    .orElse(providers.gradleProperty("signing.password"))

if (signingKey.isPresent) {
    signing {
        useInMemoryPgpKeys(signingKey.get(), signingPassword.getOrElse(""))
        sign(publishing.publications["maven"])
        // With a key present the signature is mandatory: a corrupt key or wrong passphrase must
        // fail the build rather than quietly produce artifacts Central will bounce later.
        isRequired = true
    }
}
