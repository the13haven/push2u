// push2u is a standalone multi-project Gradle build. Keeping its build conventions and version
// catalog local makes it usable directly or as an included build in a consuming application.
rootProject.name = "push2u"

include("push2u-core")
include("push2u-signer-vault")
include("push2u-spring-boot-starter")
include("push2u-signer-vault-spring-boot-starter")
