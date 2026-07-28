// push2u — a standalone Gradle build (composite), included by the hagit root settings via
// `includeBuild("backend/lib/push2u")`. Kept as its own build so the library carries none of
// hagit's build conventions and extraction to its own repository is a directory move
// (DESIGN.md ADR-009). Its own version catalog lives in gradle/libs.versions.toml.
rootProject.name = "push2u"

include("push2u-core")
include("push2u-signer-vault")
include("push2u-spring-boot-starter")
include("push2u-signer-vault-spring-boot-starter")
