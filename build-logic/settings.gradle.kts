// build-logic is an included build that carries push2u's convention plugins (currently just the
// quality plugin). It is wired in from the root settings.gradle.kts via pluginManagement.
rootProject.name = "build-logic"

dependencyResolutionManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }

    // Reuse push2u's version catalog so quality tool versions live in exactly one file.
    versionCatalogs {
        create("libs") {
            from(files("../gradle/libs.versions.toml"))
        }
    }
}
