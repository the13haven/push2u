plugins {
    `kotlin-dsl`
}

dependencies {
    // The third-party quality plugins the convention plugin applies. Checkstyle, PMD, JaCoCo are
    // Gradle core plugins and need no dependency here.
    implementation(pluginMarker(libs.plugins.spotless))
    implementation(pluginMarker(libs.plugins.spotbugs))
    implementation(pluginMarker(libs.plugins.errorprone))
    // nmcp (per-module half of Central publishing) is applied by the push2u-publish convention
    // plugin. maven-publish and signing are Gradle core plugins and need no dependency here; the
    // nmcp AGGREGATION plugin is applied at the push2u root and resolves from the plugin portal.
    // asProvider(): the catalog alias `nmcp` is also the prefix of `nmcp-aggregation`, so the
    // generated accessor is a group and the plugin itself sits behind asProvider().
    implementation(pluginMarker(libs.plugins.nmcp.asProvider()))
}

// Converts a version-catalog plugin alias into a dependency notation. Gradle publishes plugin
// marker artifacts as "{id}:{id}.gradle.plugin:{version}", which is what lets build-logic declare
// its plugin dependencies through the shared catalog instead of hard-coded coordinates.
fun pluginMarker(plugin: Provider<PluginDependency>): String {
    val id = plugin.get().pluginId
    val version = plugin.get().version
    return "$id:$id.gradle.plugin:$version"
}
