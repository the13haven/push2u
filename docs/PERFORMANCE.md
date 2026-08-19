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
  key and an ephemeral key pair per message. The ES256 signature is *per token* rather than per
  message — a signed VAPID token is reused for every send to a push-service origin until it nears
  expiry — so the per-message figure to size against is the send that serves a cached token, and
  the send that signs is what the first message to each origin pays. Parsing, validation, key
  decoding, HKDF and AES-GCM together are a rounding error, and so is the cache lookup that
  replaced the signature.
- **The expensive steps left per message are CPU-bound and independent per subscription**, so a
  fan-out scales with cores. `sendAsync` with an executor is what uses them; what remains on that
  path is the protocol's own arithmetic, which does not benefit from being made cleverer.
- **The JCE provider is a throughput decision, not only a policy one.** Between the two measured
  here the whole local send differs by a factor of two, and it is worth confirming on your own
  hardware before assuming either way.
- **A remote signer's round trip is the dominant cost of the send that pays it**, and only that
  send pays it. With Vault Transit one signature costs more than everything else the library does
  put together, and a send that signs is measured here at two to three times a send that does not.
  A send serving a cached token costs what a local send costs: the Transit round trip is not on it
  at all. That falls on the first send to an origin within a token's life, and on none of the sends
  that follow — unless the deployment meets more origins than the cache is sized for, where
  eviction returns the evicted ones to a signature per send, or reuse is switched off
  (`jwtReuse(false)`), where the sender's throughput is again a property of the round trip to Vault
  rather than of its own cryptography.
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
OpenJDK 64-Bit Server VM 26.0.1 · Mac OS X aarch64 · 10 CPU · 2026-08-19
BouncyCastle bcprov 1.85.2 · Vault 1.18 in a Testcontainers dev-mode container on the same machine
```

## Per message, by provider

Medians of five repetitions. The provider is what a consumer passes to
`PushSender.Builder.cryptoProvider(...)`; the first column is what the library uses when nothing is
passed. The message payload is 41 bytes — the encryption and `send` rows grow with it, the rest do
not.

| Step | JDK (SunEC/SunJCE) | BouncyCastle |
|---|---|---|
| `PushSender.assessPayloadSize` | ~4 ns | ~4 ns |
| Token cache key — `publicKey()` and base64url | ~32 ns | ~31 ns |
| Build the JWT — JSON and base64url | ~0.17 µs | ~0.17 µs |
| `EndpointPolicy.validate` | ~0.24 µs | ~0.24 µs |
| `Origin.serialize` | ~0.25 µs | ~0.25 µs |
| Decode `p256dh`, on-curve check included | 1.3 µs | 2.3 µs |
| HKDF-SHA-256, 2 extract + 3 expand | 2.1 µs | 8.8 µs |
| Ephemeral P-256 key pair | 95.9 µs | 81.3 µs |
| **ECDH** | **528.8 µs** | **181.0 µs** |
| VAPID signature, ES256, local signer | 119.3 µs | 84.4 µs |
| `Authorization` header whole — JWT, signature, `k` | 121.3 µs | 82.9 µs |
| Encrypt one record, ephemeral pair supplied | 537.5 µs | 201.0 µs |
| Encrypt one record whole | 639.5 µs | 295.0 µs |
| **`PushSender.send`, cached token, stub transport** | **648.4 µs** | **293.4 µs** |
| **`PushSender.send`, signing every time, stub transport** | **753.2 µs** | **374.0 µs** |

**The two `send` rows are the same code under `jwtReuse(true)` and `jwtReuse(false)`, each measured
whole.** The first is what a deployment pays per message once an origin's token exists; the second
is what the first send to each origin pays, and what every send paid before the token was reused at
all. Neither is derived from the other: this suite measures wholes and parts, never differences
between them, so the cached row is not the signing row minus the signature row and is not presented
as one.

The first five rows are the sub-microsecond ones, ordered by cost rather than by where they fall in
the pipeline. Four of them touch no provider and are measured once, then repeated across the columns
so each column reads as a complete budget; the cache-key row does read the signer's advertised key,
which is why it is measured per column even though the two agree. All five are printed coarsely on
purpose: everything above ~90 µs reproduces between runs within a few percent, while the
sub-microsecond rows move by around a fifth, which is more than the difference between them. Read
them as "far below anything else on the path, and it does not matter", not as a ranking.

Both providers register `SHA256withECDSAinP1363Format`, so on both the library signs in the raw
`r || s` form directly and the DER re-encoding path is not exercised. That path is not dead — a
FIPS-only platform reaches it, which is what `push2u-core`'s `fipsTest` source set exists for — but
it costs nothing here.

The two providers are always measured in the same order, the JDK first, so the library's own glue is
already warm when BouncyCastle starts. That bias runs against the faster provider, not for it.

## Per message, through Vault Transit

The Vault behind these numbers is a dev-mode container **on the same machine**, over plain HTTP,
with no TLS and no network between it and the sender. Every figure is therefore a lower bound for a
real deployment. Run to run the rows containing a round trip move by 20–30 %, far more than the
local figures above, which is why they are given as ranges over the runs rather than as single
medians.

| Step | Median |
|---|---|
| `VaultTransitVapidSigner.publicKey()`, eager mode | 8 ns |
| `VaultTransitVapidSigner.publicKey()`, deferred mode after the fetch | 8 ns |
| `VaultTransitVapidSigner.sign()` — one Transit round trip | 0.9–1.2 ms |
| **`PushSender.send`, Vault signer, cached token, stub transport** | **0.63–0.67 ms** |
| **`PushSender.send`, Vault signer, signing every time, stub transport** | **1.5–1.9 ms** |

**The cached row is the one to size a deployment against, and it is a local send.** 0.63–0.67 ms
against the 0.65 ms the JDK provider spends on a local send with no Vault in the picture at all:
nothing of Transit is on the path of a send that serves a token already signed, which is what the
two rows together say and what neither says alone. The signing row is the first send to an origin
within a token's life, and every send under `jwtReuse(false)`.

The signing row is more than the signature plus the local remainder, and the gap is not attributed:
the suite measures the whole and the parts, not the difference between them. Its range is wider
than the local table's for the same reason the signature row's is — it contains the round trip.

The two `publicKey()` rows agree because they are the same read: both construction modes retain one
pair and reach it through a single volatile read, and the deferred mode's one fetch is paid by the
call that triggers it, outside every measured repetition. A signer that fetches reads Vault exactly
once — at startup in the eager mode, at first use in the deferred one — and never again, so no
later `publicKey()` pays a round trip in either.

## What the numbers say

**Validation is free, and there is nothing to reclaim by relaxing it.** Every check on the send path
— the endpoint policy, the origin serialization, decoding `p256dh` with its on-curve check against
the configured provider's parameters — adds up to 1.8 µs on the JDK provider and 2.8 µs on
BouncyCastle: about a quarter of a percent of the cached send, and just under one. The library
re-validates the subscription key on every send rather than trusting that it came through
`Subscription`'s constructor, and that safety property costs nothing measurable. Asking
`assessPayloadSize` first is likewise free at ~4 ns, so the advice to render against the answer
costs nothing to follow.

**Two elliptic-curve operations are what a message costs, and a third is what a token costs.** ECDH
and the ephemeral key pair are 624.7 µs of the 648.4 µs cached `send` on the JDK provider — 96.3 %.
Add the ES256 signature and the three are 744.0 µs of the 753.2 µs signing `send` — 98.8 %.
Everything else in the library, including all the parsing, encoding, HKDF, AES-GCM and the cache
lookup itself, is the remainder in both cases. Both figures are the sum of measured parts set
beside a measured whole, which is the only arithmetic this document does; the two `send` rows are
never subtracted from each other.

**ECDH is the single most expensive step, and how expensive depends on the provider.** On SunEC it
is 5.5× the cost of generating a key pair, though both are one scalar multiplication; on
BouncyCastle it is 2.2× and 2.9× faster in absolute terms. Part of the gap is inherent — key
generation and signing multiply the curve's *fixed* generator, for which a provider can precompute
tables, while ECDH multiplies the *arbitrary* point of the subscriber, where there is nothing to
precompute — but a factor of 2.8 between providers is not inherent, and it is the largest single
lever measured here.

Three explanations for that cost were tested and rejected rather than assumed, and all three checks
are steps in the suite rather than recollections of a terminal session. A key straight from the
generator agrees with the imported one to within the run-to-run spread (531.6 µs against 528.8 µs on
the JDK provider, 178.3 against 181.0 on BouncyCastle), and so does the same point re-imported with
the generator's own parameter object (523.9 µs and 181.0 µs), so neither the import nor the
parameters explain anything. The JCA lookup does not either: `getInstance` measures well under
100 ns against a half-millisecond agreement, so obtaining a fresh non-thread-safe object per call —
which is what keeps the library safe to share between threads — costs nothing worth reclaiming.
Treat that last figure as a floor rather than a reading: the object it creates never escapes the
measurement, so a JIT is free to elide part of the work, and only the order of magnitude is being
claimed.

**BouncyCastle roughly halves the local send** — 293 µs against 648 µs for a cached send, 374 µs
against 753 µs for one that signs — winning on ECDH, on signing and on key generation, and losing on
HKDF (4.2× slower, 8.8 µs against 2.1 µs) and on decoding (1.8× slower, 1.0 µs of difference). Both
losses are noise at this scale, and the gap is the same either side of the token cache: the provider
decision does not depend on which of the two rows a deployment reads. For a deployment whose fan-out
is large enough for the sender's CPU to matter, passing a `BouncyCastleProvider` to
`cryptoProvider(...)` is worth measuring on its own hardware; the core takes no dependency either
way, since the provider is supplied by the application.

**Through Vault, one signature costs more than everything else put together — and a message does
not pay it.** 0.9–1.2 ms against the ~0.65 ms the rest of the send spends locally, and that is the
lower bound described above. Nothing in the token is per-message — it depends only on the push
service's origin, the contact and an expiry that defaults to 12 hours — so the sender signs one per
origin and reuses it until it nears expiry, and a large fan-out waits on Vault once per distinct
origin met rather than once per subscription. The two `send` rows measure both ends of that: 1.5–1.9
ms when every send signs, 0.63–0.67 ms when the token is already there, which is a local send with
no Transit on it. `publicKey()` is 8 ns in both construction modes — near the floor of what this
harness can resolve at all — because the retained pair reaches every caller through one volatile
read and no later call pays a round trip.

**Parallelism, not micro-optimisation, is what scales a fan-out.** The expensive steps are CPU-bound
and independent per subscription, so `sendAsync` with an executor is the lever that uses the other
cores; the Vault signature is not CPU-bound at all, and the token cache took it off the per-message
path rather than speeding it up — which is what a cache can do for a cost that is a round trip. The
cache lookup that replaced it is ~32 ns: three orders of magnitude below the local signature it
replaces, and four below a Transit round trip.

## Keeping this document honest

Re-record when the send path changes, when the JDK baseline moves, or when a provider is added — and
replace the whole table rather than editing a cell, because the environment line belongs to the
numbers. Keep the previous table only if the comparison is the point; otherwise a stale row that
looks current is worse than no row.

**Both tables were re-recorded after VAPID token reuse landed**, which is what the paired `send`
rows are for: the question the previous recording left open — what a send serving a cached token
costs — is answered by measuring that send rather than by adjusting the other one. The signing rows
are the comparable half, and they sit within a few percent of the figures the previous recording
took on the same machine, so nothing on the path became slower while the cache was added to it.

Every `send` row is one POST, so the removal of the sender's retry loop leaves them where they are:
a stub transport answering `2xx` was never repeated. What no longer exists is the *worst case*
around them — a `send` is bounded by one exchange rather than by a schedule of attempts, so a
budget for one is the transport's per-request timeout plus the figures above.

A table here is a snapshot someone took, not an output the build maintains. If it stops being
re-recorded it should be deleted rather than left to age quietly: a stale measurement is read with
exactly the confidence a fresh one earns.
