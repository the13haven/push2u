# ADR-001 — Java 21 baseline

**Status:** Accepted

Java 21 provides every cryptographic and HTTP primitive this library needs — `java.net.http`,
`java.security`, `javax.crypto`, `java.util.Base64` — while remaining an LTS runtime that
enterprise deployments are willing to run.

The runtime baseline is therefore Java 21, and the build compiles against it with `--release 21`
rather than pinning the toolchain: a newer JDK builds the project, and the compiler refuses any
API that would not exist on 21. Raising the baseline is a breaking change for consumers and needs
a decision of its own.
