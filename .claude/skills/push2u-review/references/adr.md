# ADRs: the index, and how to change one

Read this when a change touches architecture, a module boundary, an SPI, the dependency posture, the
nullness contract or the release process — or when a review needs to say whether a change is allowed
to do what it does.

The ADRs live in `DESIGN.md` §9. They are the settled decisions: not documentation of the code, but
the reasons the code is shaped the way it is. Their value is entirely in being trustworthy, so the
failure mode to guard against is a change that quietly contradicts one and leaves `DESIGN.md`
describing a design that no longer exists.

## Index

| ADR | Decision | What it rules out |
|---|---|---|
| 001 | Java 21 baseline, newer toolchain with `--release 21` | API or bytecode requiring a newer runtime |
| 002 | Zero-dependency core | Any runtime implementation dependency in `push2u-core`; JSpecify (annotations only) is the single exception |
| 003 | Concrete HKDF implementation | HKDF as an extension point |
| 004 | Stateless library | Subscription storage, deletion or lifecycle inside the library |
| 005 | Two public SPIs in the core (`VapidSigner`, `PushHttpClient`), plus `EndpointPolicy` added later under the same test | New seams without an articulable difference the library cannot decide for the deployment; reusing one transport seam for both trust domains |
| 006 | `aes128gcm` only | Legacy `aesgcm` support |
| 007 | Expired subscription is a result | `404`/`410` as exception-driven control flow |
| 008 | Apache License 2.0 | — |
| 009 | Standalone repository | Application-specific dependencies or configuration |
| 010 | Pluggable VAPID key custody | Hardwiring local signing into the pipeline |
| 011 | Size limit expressed on the encrypted body | A plaintext maximum as the configurable knob, or a hardcoded plaintext constant |
| 012 | Nullness declared with JSpecify | Unmarked packages; a nullness contract that exists only in prose |
| 013 | Release and publication process | A version constant in the build; a half-published release |

`RELEASING.md` is the operational companion to ADR-013.

## Reviewing against them

Ask two questions, in this order.

**Does the change contradict an ADR?** Not "does it feel unusual" — does it do the thing the ADR
rules out. Adding `com.fasterxml.jackson` to the core contradicts ADR-002. Adding a
`PayloadEncryptor` interface contradicts ADR-003 and ADR-005. Making `sendAsync` cache a
subscription contradicts ADR-004.

**If it does, does it say so?** A contradiction is not automatically wrong — the ADRs were written
by people who could not see every future requirement, and ADR-005 has already been amended once. The
requirement is that the change amends the ADR in the same pull request, with the reasoning. A silent
contradiction is a must-fix, because every later reader of `DESIGN.md` will be misled by it.

Watch for the quiet version of this: a change that does not violate the letter of an ADR but hollows
it out. A core that declares no dependency but requires one on the consumer's classpath to work still
breaks ADR-002.

## Amending an existing ADR

Keep the original decision readable and append the amendment beneath it, in the style ADR-005
already uses:

```markdown
*Amended:* a third seam, `EndpointPolicy` (deployment egress policy for push endpoints), was
added later under the same test — an articulable difference the library cannot decide for the
deployment. Which hosts an application may POST to is deployment security policy, not protocol;
see section 5.
```

Do not rewrite history so the ADR reads as though it always said the new thing. The record of what
was decided, and then what changed and why, is the artefact.

If the amendment invalidates the decision entirely rather than extending it, say that plainly in the
ADR and point to its replacement rather than deleting it — a numbered decision that vanishes leaves
dangling references in the code comments and the other ADRs.

## Writing a new one

Take the next free number and match the existing house style: a heading, then a short paragraph or
two. These ADRs state the decision and the reasoning that makes it non-obvious; they do not use a
Status/Context/Consequences template, and imitating one here would make the new entry read as
foreign.

A new ADR earns its place when the decision constrains future changes. "We use `HttpClient`" is not
an ADR; "the transport is replaceable but the encryptor is not, because an alternative encryptor
would only introduce a silent wrong-ciphertext failure mode" is.

After adding one, update the cross-references that carry the range: `DESIGN.md` §1 if it enumerates
scope, `CLAUDE.md` (which cites "ADR-001…013"), and `CONTRIBUTING.md` where it points contributors
at the settled decisions.
