# Performance

What one message costs, step by step, so that a change to the send path can be checked against
something rather than argued about. The numbers below are recorded from the measurement suites in
this repository and are meant to be **re-recorded**, not trusted forever: they describe one machine,
one JVM and one moment.

This is not a benchmark suite and not a regression gate. The resolution it claims is an order of
magnitude — enough to answer "is this step worth optimising at all" and "is one provider in a
different class from another", not enough to defend a five-percent difference. Nothing in CI runs
it.

## Reproducing

```bash
./gradlew :push2u-core:test --tests "*HotPathMeasurement" -Dpush2u.measure=true
./gradlew :push2u-signer-vault:test --tests "*HotPathMeasurement" -Dpush2u.measure=true   # needs Docker
```

Without `-Dpush2u.measure=true` both suites are skipped, which is why an ordinary build never pays
for them. Each step is driven for a fixed wall-clock budget after a warm-up of the same shape,
repeated five times, and reported as the median; every result is summed into a sink that is printed,
so no step can be optimised away as dead code. The suites live beside the code they measure —
`push2u-core`'s in the library's own package, because half the steps are package-private.

Both print the JVM, the OS, the architecture and the core count. **Record that line with the
numbers**: a table without it cannot be compared to anything.

## The environment these numbers come from

```
OpenJDK 64-Bit Server VM 26.0.1 · Mac OS X aarch64 · 10 CPU · 2026-08-09
BouncyCastle bcprov 1.85 · Vault 1.18 in a Testcontainers dev-mode container on the same machine
```

## Per message, by provider

Medians. The provider is what a consumer passes to `PushSender.Builder.cryptoProvider(...)`; the
first column is what the library uses when nothing is passed.

| Step | JDK (SunEC/SunJCE) | BouncyCastle |
|---|---|---|
| `Origin.serialize` | 300 ns | 300 ns |
| `EndpointPolicy.validate` | 249 ns | 249 ns |
| Build the JWT — JSON and base64url | 182 ns | 182 ns |
| `getInstance` for ECDH | 56 ns | 59 ns |
| `getInstance` for the EC `KeyFactory` | 55 ns | 52 ns |
| Decode `p256dh`, on-curve check included | 1.3 µs | 2.5 µs |
| HKDF-SHA-256, 2 extract + 3 expand | 2.0 µs | 8.3 µs |
| Ephemeral P-256 key pair | 96.4 µs | 80.1 µs |
| **ECDH** | **528.9 µs** | **189.7 µs** |
| VAPID signature, ES256, local signer | 119.2 µs | 81.8 µs |
| `Authorization` header whole — JWT, signature, `k` | 118.3 µs | 81.6 µs |
| Encrypt one record, ephemeral pair supplied | 539.4 µs | 214.2 µs |
| Encrypt one record whole | 625.4 µs | 295.2 µs |
| **`PushSender.send`, stub transport** | **757.1 µs** | **379.5 µs** |

The first three rows touch no provider and are measured once; they are repeated across the columns
so each column reads as a complete budget.

Both providers register `SHA256withECDSAinP1363Format`, so on both the library signs in the raw
`r || s` form directly and the DER re-encoding path is not exercised. That path is not dead — a
FIPS-only platform reaches it, which is what `push2u-core`'s `fipsTest` source set exists for — but
it costs nothing here.

## Per message, through Vault Transit

The Vault behind these numbers is a dev-mode container **on the same machine**, over plain HTTP,
with no TLS and no network between it and the sender. Every figure is therefore a lower bound for a
real deployment. Run to run they move by 10–20 %, more than the local figures above.

| Step | Median |
|---|---|
| `VaultTransitVapidSigner.publicKey()` | 16 ns |
| `VaultTransitVapidSigner.sign()` — one Transit round trip | 1.1–1.3 ms |
| `PushSender.send`, Vault signer, stub transport | 2.0–3.0 ms |

## What the numbers say

**Validation is free, and there is nothing to reclaim by relaxing it.** Every check on the send path
— the endpoint policy, the origin serialization, decoding `p256dh` with its on-curve check against
the configured provider's parameters — adds up to under 2 µs, a quarter of a percent of the local
send. The library re-validates the subscription key on every send rather than trusting that it came
through `Subscription`'s constructor, and that safety property costs nothing measurable.

**Three elliptic-curve operations are the local cost.** ECDH, the ES256 signature and the ephemeral
key pair are 744 µs of the 757 µs `send` on the JDK provider — 98 %. Everything else in the library,
including all the parsing, encoding, HKDF and AES-GCM, is the remaining 2 %.

**ECDH is the single most expensive step, and how expensive depends on the provider.** On SunEC it
is 5.5× the cost of generating a key pair, though both are one scalar multiplication; on
BouncyCastle it is 2.4× and 2.8× faster in absolute terms. Part of the gap is inherent — key
generation and signing multiply the curve's *fixed* generator, for which a provider can precompute
tables, while ECDH multiplies the *arbitrary* point of the subscriber, where there is nothing to
precompute — but a factor of 2.8 between providers is not inherent, and it is the largest single
lever measured here.

Three explanations for the ECDH cost were tested and rejected rather than assumed: the JCA lookup
(`getInstance` is under 60 ns, so obtaining a fresh non-thread-safe object per call is free and the
thread-safety rule costs nothing), a slow path for a key imported through `KeyFactory` (a key
straight from the generator measures the same), and parameters that differ from the provider's own
(re-importing with the generator's parameter object measures the same).

**BouncyCastle roughly halves the local send** — 379 µs against 757 µs — winning on ECDH, on
signing and on key generation, and losing on HKDF (4× slower, 8.3 µs against 2.0 µs) and on decoding
(2× slower, 1.2 µs of difference). Both losses are noise at this scale. For a deployment whose
fan-out is large enough for the sender's CPU to matter, passing a `BouncyCastleProvider` to
`cryptoProvider(...)` is worth measuring on its own hardware; the core takes no dependency either
way, since the provider is supplied by the application.

**Through Vault, one signature costs more than everything else put together.** 1.1–1.3 ms against
the ~0.6 ms the rest of the send spends locally, and that is the lower bound described above. The
JWT is rebuilt and re-signed for every message even though the token depends only on the push
service's origin, the contact and an expiry that defaults to 12 hours — so a fan-out to 100 000
subscriptions spends roughly two minutes of sequential waiting on Vault for a value that changes
twice a day. `publicKey()`, by contrast, is a field clone at 16 ns: the fetched mode reads Vault once
at startup and never again.

**Parallelism, not micro-optimisation, is what scales a fan-out.** The expensive steps are CPU-bound
and independent per subscription, so `sendAsync` with an executor is the lever that uses the other
cores; the Vault signature is not CPU-bound at all, and a cache would remove it from the path rather
than speed it up.

## Keeping this document honest

Re-record when the send path changes, when the JDK baseline moves, or when a provider is added — and
replace the whole table rather than editing a cell, because the environment line belongs to the
numbers. Keep the previous table only if the comparison is the point; otherwise a stale row that
looks current is worse than no row.

The suites are deliberately not wired into `check`. A measurement that runs in CI on shared runners
would report the runner's noise as a regression, and a threshold on top of it would either be so
loose it never fires or so tight it fires constantly.
