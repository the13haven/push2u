# Performance

What one message costs, step by step — so that sizing a deployment, choosing a JCE provider or
judging a change to the send path starts from a number instead of an argument. Read it as a
starting point for your own measurement rather than as a specification: the figures describe one
machine, one JVM and one moment, and your hardware will disagree.

This is not a benchmark suite and not a regression gate. The resolution it claims is an order of
magnitude — enough to answer "is this step worth optimising at all" and "is one provider in a
different class from another", not enough to defend a five-percent difference.

## What this means for a deployment

- **The library's own cost per message is well under a millisecond**, and almost all of it is
  elliptic-curve arithmetic that the Web Push protocol requires: an ECDH against the subscriber's
  key, an ES256 signature, and an ephemeral key pair. Parsing, validation, key decoding, HKDF and
  AES-GCM together are a rounding error.
- **The expensive steps are CPU-bound and independent per subscription**, so a fan-out scales with
  cores. `sendAsync` with an executor is what uses them; nothing in the per-message path benefits
  from being made cleverer.
- **The JCE provider is a throughput decision, not only a policy one.** Between the two measured
  here the whole local send differs by a factor of two, and it is worth confirming on your own
  hardware before assuming either way.
- **A remote signer moves the dominant cost off the CPU and onto the network.** With Vault Transit,
  one signature per message costs more than everything else the library does, so the sender's
  throughput becomes a property of the round trip to Vault rather than of its own cryptography.
- **None of this includes the POST to the push service**, which is not measured here and is normally
  the largest single term in wall-clock per message.

## How these numbers were produced

Each step is driven for a fixed wall-clock budget after a warm-up of the same shape, repeated five
times, and reported as the median; every result is summed into a sink that is printed, so no step
can be optimised away as dead code. Not JMH — no forks, no dead-code analysis beyond that sink, no
statistics past a median.

The suites that produce them are **not part of the build**. They live on the long-running
`perf/hot-path-measurements` branch, one per module (`push2u-core`'s inside the library's own
package, because half the steps it measures are package-private), gated so that even there an
ordinary build does not run them. Keeping them off `main` is deliberate: a measurement wired into
`check` would run on shared CI runners and report the runner's noise, and a threshold over that
noise either never fires or fires constantly — while the harness itself would sit in the build
configuration of two published modules for the sake of a number nobody reads on most days.

Whatever produces a future table, it must print the JVM, the OS, the architecture and the core
count. **Record that line with the numbers**: a table without it cannot be compared to anything.

## The environment these numbers come from

```
OpenJDK 64-Bit Server VM 26.0.1 · Mac OS X aarch64 · 10 CPU · 2026-08-09
BouncyCastle bcprov 1.85 · Vault 1.18 in a Testcontainers dev-mode container on the same machine
```

## Per message, by provider

Medians of five repetitions. The provider is what a consumer passes to
`PushSender.Builder.cryptoProvider(...)`; the first column is what the library uses when nothing is
passed. The message payload is 41 bytes — the last three rows grow with it, the rest do not.

| Step | JDK (SunEC/SunJCE) | BouncyCastle |
|---|---|---|
| `Origin.serialize` | ~0.26 µs | ~0.26 µs |
| `EndpointPolicy.validate` | ~0.25 µs | ~0.25 µs |
| Build the JWT — JSON and base64url | ~0.18 µs | ~0.18 µs |
| Decode `p256dh`, on-curve check included | 1.2 µs | 2.4 µs |
| HKDF-SHA-256, 2 extract + 3 expand | 2.0 µs | 8.9 µs |
| Ephemeral P-256 key pair | 91.4 µs | 79.4 µs |
| **ECDH** | **509.6 µs** | **182.9 µs** |
| VAPID signature, ES256, local signer | 115.6 µs | 80.2 µs |
| `Authorization` header whole — JWT, signature, `k` | 114.6 µs | 80.4 µs |
| Encrypt one record, ephemeral pair supplied | 517.0 µs | 201.3 µs |
| Encrypt one record whole | 606.5 µs | 290.2 µs |
| **`PushSender.send`, stub transport** | **726.6 µs** | **372.8 µs** |

The first three rows touch no provider and are measured once; they are repeated across the columns
so each column reads as a complete budget. They are printed to two significant figures on purpose:
everything above ~90 µs reproduces between runs within a few percent, while the sub-microsecond rows
move by around a fifth, which is more than the difference between them. Read them as "a quarter of a
microsecond, and it does not matter", not as a ranking.

Both providers register `SHA256withECDSAinP1363Format`, so on both the library signs in the raw
`r || s` form directly and the DER re-encoding path is not exercised. That path is not dead — a
FIPS-only platform reaches it, which is what `push2u-core`'s `fipsTest` source set exists for — but
it costs nothing here.

The two providers are always measured in the same order, the JDK first, so the library's own glue is
already warm when BouncyCastle starts. That bias runs against the faster provider, not for it.

## Per message, through Vault Transit

The Vault behind these numbers is a dev-mode container **on the same machine**, over plain HTTP,
with no TLS and no network between it and the sender. Every figure is therefore a lower bound for a
real deployment. Run to run they move by 10–20 %, more than the local figures above.

| Step | Median |
|---|---|
| `VaultTransitVapidSigner.publicKey()` | 7 ns |
| `VaultTransitVapidSigner.sign()` — one Transit round trip | 0.9–1.3 ms |
| `PushSender.send`, Vault signer, stub transport | 2.2–2.5 ms |

The `send` row is more than the signature plus the local remainder, and the gap is not attributed:
the suite measures the whole and the parts, not the difference between them.

## What the numbers say

**Validation is free, and there is nothing to reclaim by relaxing it.** Every check on the send path
— the endpoint policy, the origin serialization, decoding `p256dh` with its on-curve check against
the configured provider's parameters — adds up to 1.7 µs on the JDK provider and 2.9 µs on
BouncyCastle: a quarter of a percent of the local send, and three quarters of one. The library
re-validates the subscription key on every send rather than trusting that it came through
`Subscription`'s constructor, and that safety property costs nothing measurable.

**Three elliptic-curve operations are the local cost.** ECDH, the ES256 signature and the ephemeral
key pair are 716.6 µs of the 726.6 µs `send` on the JDK provider — 98.6 %. Everything else in the
library, including all the parsing, encoding, HKDF and AES-GCM, is the remaining 1.4 %.

**ECDH is the single most expensive step, and how expensive depends on the provider.** On SunEC it
is 5.6× the cost of generating a key pair, though both are one scalar multiplication; on
BouncyCastle it is 2.3× and 2.8× faster in absolute terms. Part of the gap is inherent — key
generation and signing multiply the curve's *fixed* generator, for which a provider can precompute
tables, while ECDH multiplies the *arbitrary* point of the subscriber, where there is nothing to
precompute — but a factor of 2.8 between providers is not inherent, and it is the largest single
lever measured here.

Three explanations for that cost were tested and rejected rather than assumed, and all three checks
are steps in the suite rather than recollections of a terminal session. A key straight from the
generator agrees with the imported one to the last measurable digit (509.6 µs against 509.6 µs on
the JDK provider, 183.2 against 182.9 on BouncyCastle), and so does the same point re-imported with
the generator's own parameter object (508.7 µs), so neither the import nor the parameters explain
anything. The JCA lookup does not either: `getInstance` measures well under 100 ns against a
half-millisecond agreement, so obtaining a fresh non-thread-safe object per call — which is what
keeps the library safe to share between threads — costs nothing worth reclaiming. Treat that last
figure as a floor rather than a reading: the object it creates never escapes the measurement, so a
JIT is free to elide part of the work, and only the order of magnitude is being claimed.

**BouncyCastle roughly halves the local send** — 373 µs against 727 µs — winning on ECDH, on
signing and on key generation, and losing on HKDF (4.5× slower, 8.9 µs against 2.0 µs) and on
decoding (2× slower, 1.2 µs of difference). Both losses are noise at this scale. For a deployment
whose fan-out is large enough for the sender's CPU to matter, passing a `BouncyCastleProvider` to
`cryptoProvider(...)` is worth measuring on its own hardware; the core takes no dependency either
way, since the provider is supplied by the application.

**Through Vault, one signature costs more than everything else put together.** 0.9–1.3 ms against
the ~0.6 ms the rest of the send spends locally, and that is the lower bound described above. The
JWT is rebuilt and re-signed for every message even though the token depends only on the push
service's origin, the contact and an expiry that defaults to 12 hours — so a fan-out to 100 000
subscriptions spends one and a half to two minutes of sequential waiting on Vault for a value that changes
twice a day. `publicKey()`, by contrast, is a field clone at 7 ns — near the floor of what this
harness can resolve at all: the fetched mode reads Vault once at startup and never again.

**Parallelism, not micro-optimisation, is what scales a fan-out.** The expensive steps are CPU-bound
and independent per subscription, so `sendAsync` with an executor is the lever that uses the other
cores; the Vault signature is not CPU-bound at all, and a cache would remove it from the path rather
than speed it up.

## Keeping this document honest

Re-record when the send path changes, when the JDK baseline moves, or when a provider is added — and
replace the whole table rather than editing a cell, because the environment line belongs to the
numbers. Keep the previous table only if the comparison is the point; otherwise a stale row that
looks current is worse than no row.

A table here is a snapshot someone took, not an output the build maintains. If it stops being
re-recorded it should be deleted rather than left to age quietly: a stale measurement is read with
exactly the confidence a fresh one earns.
