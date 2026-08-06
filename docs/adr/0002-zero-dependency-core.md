# ADR-002 — Zero-dependency core

**Status:** Accepted

The library exists to replace `nl.martijndwars:web-push`, the JVM's usual answer for Web Push,
whose resolved runtime graph is 26 artifacts — two complete HTTP stacks, Netty with its
platform-specific native transports, a JOSE library and a CLI argument parser — and whose public
API exposes BouncyCastle types and requires the consumer to register the BC provider. A consumer
adopting it inherits all of that, and every CVE filed against any of it.

`push2u-core` therefore implements the protocol on JDK APIs alone. Its single declared dependency
is JSpecify (ADR-012), an annotation-only jar with no code, exposed as `api` so the nullness
contract travels to consumers.

This rules out a runtime implementation dependency in the core, whatever the convenience — a JSON
parser, an HTTP client, a JOSE library, a crypto provider. Framework and remote-system
integrations live in optional modules that depend on the core, never the other way round, so a
consumer who wants none of them carries none of them. Test-scoped and `compileOnly` dependencies
are not exceptions: neither reaches a consumer's runtime classpath.
