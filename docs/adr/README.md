# Architectural decisions

One file per decision, `NNNN-slug.md` — the ADR's number zero-padded to four digits, so ADR-005 is
`0005-public-spis-in-the-core.md`. These record *why* the library is shaped the way it is — the
context at the time, the decision, and what it rules out. What the architecture looks like *now*
is [`DESIGN.md`](../DESIGN.md); how to use the library is [`README.md`](../../README.md).

| ADR | Decision | Status | What it rules out |
|---|---|---|---|
| [001](0001-java-21-baseline.md) | Java 21 baseline | Accepted | API or bytecode requiring a newer runtime |
| [002](0002-zero-dependency-core.md) | Zero-dependency core | Accepted | Any runtime implementation dependency in `push2u-core`; JSpecify (annotations only) is the single exception |
| [003](0003-concrete-hkdf-implementation.md) | Concrete HKDF implementation | Accepted | HKDF, the encryptor or the origin serialization as an extension point |
| [004](0004-stateless-library.md) | Stateless library | Accepted; one clause superseded by [019](0019-vapid-token-reused-until-it-nears-expiry.md) | Subscription storage, deletion or lifecycle inside the library |
| [005](0005-public-spis-in-the-core.md) | Public SPIs in the core | Accepted | A seam without an articulable difference the library cannot decide for the deployment; one transport seam serving both trust domains |
| [006](0006-aes128gcm-only.md) | `aes128gcm` only | Accepted | Legacy `aesgcm` support; a content-coding switch |
| [007](0007-expired-subscription-is-a-result.md) | Expired subscription is a result | Accepted | `404`/`410` as exception-driven control flow |
| [008](0008-apache-license-2-0.md) | Apache License 2.0, declared per file with an SPDX header | Accepted | A Java file without the header; a copyright year advanced after the file was created; a `NOTICE` file |
| [009](0009-standalone-repository.md) | Standalone repository | Accepted | Application-specific dependencies or configuration |
| [010](0010-pluggable-vapid-key-custody.md) | Pluggable VAPID key custody | Accepted | Hardwiring local signing into the send pipeline |
| [011](0011-size-limit-expressed-on-the-encrypted-body.md) | Size limit expressed on the encrypted body | Accepted | A plaintext maximum as the configurable knob; a hardcoded plaintext constant; `recordSize` following the body limit |
| [012](0012-nullness-declared-with-jspecify.md) | Nullness declared with JSpecify | Accepted | Unmarked packages; a nullness contract that exists only in prose |
| [013](0013-release-and-publication-process.md) | Release and publication process | Accepted | A version constant in the build; a release implied by a merge; a namespace on a domain the project does not own |
| [014](0014-jpms-explicit-and-automatic-modules.md) | JPMS: explicit modules for the library, automatic for the starters | Accepted | A module or package name changed after release; a package split across two artifacts; a descriptor on a starter |
| [015](0015-vault-address-scheme-policy.md) | Vault address scheme: https, or loopback/opted-in http | Accepted | A non-HTTP scheme; a loopback decision made by name resolution; a configuration-only path to plaintext transport of the Vault token |
| [016](0016-endpoint-policy-is-a-required-decision.md) | The endpoint policy is a required decision | Accepted | A `PushSender` without an egress decision; an allowlist shipped by the library; a policy derived by resolving the endpoint; a configuration-only path to unrestricted egress under Spring |
| [017](0017-domain-rule-in-the-endpoint-allowlist.md) | A domain rule in the endpoint allowlist | Accepted | A public `EndpointPolicy` combinator; a rule kind contributed from outside the library; a domain rule matching a non-`https` scheme or a non-default port; a wildcard syntax inside an origin entry; a public-suffix judgement made by the library; a push service's zone shipped as a default |
| [018](0018-encoded-vapid-public-key-on-the-signer.md) | The encoded VAPID public key is part of the signer contract | Accepted | An abstract addition to `VapidSigner`; a general-purpose base64url codec published from the core; an encoder for the private scalar; a padded or configurable encoding; an on-curve check inside the `default` method, and a merely structural one inside the static |
| [019](0019-vapid-token-reused-until-it-nears-expiry.md) | The VAPID token is reused until it nears expiry | Accepted | A token cache behind an SPI; a shared cache level in front of the in-process one; an unbounded or unevictable cache; a proportional safety margin; a second spelling of "sign every time"; a signature taken under the cache's lock; an entry whose life a backwards wall-clock step can extend past its monotonic bound, or staleness judged finer than the second the wire carries; a cache invalidated by an authentication status; an entry filed under a key read separately from the one its header carries; a signature and a public key delivered by one SPI call; a token bounded by the signing key's life or naming more than one origin in `aud`; a `byte[]` cache key; a claim about a named push service accepting a reused token |
| [020](0020-subscription-endpoint-length-bound.md) | The subscription endpoint is bounded in length | Accepted | An endpoint above 2048 characters inside a `Subscription`; a size or weight bound inside the token cache; a configurable endpoint-length limit; a bound derived by name resolution; the endpoint, raw or redacted, inside the refusal's message |

## An ADR is immutable once implemented

The record of what was decided, and when, is the whole artefact. So an ADR whose decision has been
implemented is not edited again — not to reword it, not to bring it up to date with the code, and
not to append an amendment.

**A decision that moves entirely gets a new ADR**, with the next free number, stating the new
decision and what it replaces. The superseded one keeps its number, its title and its body, and its
status line becomes:

```markdown
**Status:** Superseded by [ADR-NNN](NNNN-the-new-decision.md)
```

That line is the only edit its body ever takes. A superseded ADR is not deleted: its number is
referenced from other ADRs, from `docs/DESIGN.md` and from the review procedure, and a numbered
decision that vanishes leaves those references dangling.

**A decision that moves only in part — one clause superseded while the rest of the ADR still
stands — takes the same one-line edit, in a form beside the full one rather than in place of it:**

```markdown
**Status:** Accepted; one clause superseded by [ADR-NNN](NNNN-the-new-decision.md)
```

and the index's status cell follows, in the index's own link spelling:
`Accepted; one clause superseded by [NNN](NNNN-the-new-decision.md)`. That line is likewise the
only edit the superseded ADR's body ever takes — *which* clause it is stays out of it and lives in
the superseding ADR instead, because naming it in the old file's status line would put the new
decision's reasoning into a document that may not carry it. ADR-004 and ADR-019 are the worked
example: ADR-019 supersedes one sentence of ADR-004 and says which one; ADR-004's status line says
only that a clause was superseded and by what.

Before the decision is implemented, an ADR is still a draft and can be revised freely — the status
line says so (`Proposed`).

## Writing one

A new ADR earns its place when the decision constrains future changes. "We use `HttpClient`" is
not an ADR; "the transport is replaceable but the encryptor is not, because an alternative
encryptor would only introduce a silent wrong-ciphertext failure mode" is.

Match the house style: the heading `# ADR-NNN — Title`, a `**Status:**` line, then prose. State
the context as it was at the time, the decision, and what it rules out — including the
alternatives that were rejected and why, which is the part a later reader cannot reconstruct. Keep
the description of how things currently work in `docs/DESIGN.md`, where it can be updated; an ADR
that describes the present tense goes stale the moment the code moves, and it may not be edited to
catch up.

After adding one: the table above, and the cross-references that carry the range — `CLAUDE.md`,
`CONTRIBUTING.md` where it points contributors at the settled decisions, and `docs/DESIGN.md`
wherever the architecture it constrains is described.

Published sources are the one place an ADR is never cited: `push2u` ships a `sources.jar`, and a
consumer reading a comment there has no repository to follow the reference into. Code and Javadoc
carry the reasoning itself, in their own words — the build enforces this, see
[`CONTRIBUTING.md`](../../CONTRIBUTING.md#what-the-build-enforces).
