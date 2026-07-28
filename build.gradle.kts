import org.gradle.api.plugins.JavaPluginExtension

// Shared configuration for every push2u module. Lives here (the composite build root) rather than
// being duplicated per module — and deliberately separate from hagit, so the library is built the
// same way standalone as it will be once extracted (DESIGN.md ADR-009).

allprojects {
    group = "io.push2u"
    version = "0.1.0-SNAPSHOT"

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
    }
}

// Catalog handles for the BouncyCastle security pin, referenced by the constraints below.
// (Jackson is not pinned: Spring Boot's managed jackson-2-bom governs it to 2.21.4 on every
// push2u classpath, and — unlike the hagit root build — no node-gradle plugin pulls a stale
// jackson onto the buildscript classpath here.)
val bouncycastleBcpkix = libs.bouncycastle.bcpkix
val bouncycastleBcprov = libs.bouncycastle.bcprov

subprojects {

    plugins.withType<JavaPlugin> {

        // Pin BouncyCastle via dependency CONSTRAINTS rather than resolutionStrategy.force. Same
        // resolved classpath (1.84), but constraints report only the resolved version in the GitHub
        // dependency graph, whereas `force` also leaked the original requested version (1.82) as a
        // phantom node that Dependabot alerted on. Mirrors the hagit root build; added to every
        // declarable configuration for global reach. See the root build.gradle.kts for full rationale.
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
