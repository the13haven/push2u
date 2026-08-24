// push2u is a standalone multi-project Gradle build. Keeping its build conventions and version
// catalog local makes it usable directly or as an included build in a consuming application.
pluginManagement {
    // build-logic carries the push2u-quality convention plugin.
    includeBuild("build-logic")

    repositories {
        gradlePluginPortal()
    }
}

rootProject.name = "push2u"

include("push2u-core")
include("push2u-testkit")
include("push2u-signer-vault")
include("push2u-spring-boot-starter")
include("push2u-signer-vault-spring-boot-starter")

// One escape hatch on the version catalog, and only one: -Ppush2u.springBoot=<version> substitutes
// the `springBoot` key for this invocation.
//
// The catalog's `springBoot` is the MINIMUM Spring Boot the starters support, and by the same
// number the version the default build compiles against — one number, so that the floor is a
// promise the compiler keeps rather than a sentence in a document (ADR-032). Runs against a NEWER
// Spring Boot are still worth having: they are how the next floor move is found before a consumer
// finds it. This is how such a run asks for one, without a second key that would let the starters
// compile against one Spring Boot while advertising another.
//
// A substituted run publishes nothing — every publishing task in the build refuses to execute
// while this property is set, rather than leaving that to habit. `create("libs")` configures the catalog
// Gradle already built from gradle/libs.versions.toml; it does not declare a second one, which is
// why there is no `from(...)` call to go with it.
dependencyResolutionManagement {
    versionCatalogs {
        create("libs") {
            val substitute = providers.gradleProperty("push2u.springBoot").orNull
            if (substitute != null) {
                version("springBoot", substitute)
            }
        }
    }
}
