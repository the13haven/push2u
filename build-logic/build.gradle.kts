plugins {
    `kotlin-dsl`
}

dependencies {
    // The third-party quality plugins the convention plugin applies. Checkstyle, PMD, JaCoCo are
    // Gradle core plugins and need no dependency here.
    implementation(pluginMarker(libs.plugins.spotless))
    implementation(pluginMarker(libs.plugins.spotbugs))
    implementation(pluginMarker(libs.plugins.errorprone))
}

// Converts a version-catalog plugin alias into a dependency notation. Gradle publishes plugin
// marker artifacts as "{id}:{id}.gradle.plugin:{version}", which is what lets build-logic declare
// its plugin dependencies through the shared catalog instead of hard-coded coordinates.
fun pluginMarker(plugin: Provider<PluginDependency>): String {
    val id = plugin.get().pluginId
    val version = plugin.get().version
    return "$id:$id.gradle.plugin:$version"
}
