# ADR-020 — The subscription endpoint is bounded in length

**Status:** Accepted

Nothing bounded the length of a `Subscription`'s endpoint. The endpoint is attacker-influenced
wherever subscriptions arrive from clients — the premise ADR-016 works from — and a domain rule
admits any subdomain of its zone at any depth with no name resolution (ADR-017), so under a policy
carrying one, or under `EndpointPolicies.unrestricted()`, the party supplying subscriptions chooses
the endpoint's size. `Origin.serialize` turns the endpoint into the VAPID audience, every send
embeds that audience base64url-encoded in the `Authorization` header it POSTs, and the token cache
added for https://github.com/the13haven/push2u/issues/102 (ADR-019) stores the audience twice —
once in the cache key and once inside the header it retains. Measured on that branch: a 253-char
host costs 1.0 KB per entry, a 10 000-char host 23 KB, a 1 000 000-char host 2.3 MB — linear at
~2.33 bytes per host character per entry, 142 MB across the default 64 entries at the last size,
with no ceiling. The cache did not create the cost, it made it *retained*: a megabyte endpoint
produced a megabyte header on every POST before the cache existed. No real push service can supply
such a value — RFC 1035 caps a domain name at 253 characters in presentation form, so no longer
host resolves — which is what makes a bound safe to impose.

**Decision.** `Subscription` refuses an endpoint longer than **2048 characters** at construction,
with an `IllegalArgumentException` naming the limit and the actual length — and not the endpoint,
not even redacted: the redaction's origin half carries the host, which is the very part of an
oversized endpoint that is oversized. The number is argued structurally, not from any vendor: a
resolvable host cannot exceed RFC 1035's 253, so only the capability path and query legitimately
vary, and a capability needs only enough characters to be unguessable — a 256-bit token is 43
base64url characters, leaving the ~1780 characters of headroom two orders of magnitude above that.
No claim is made about any named push service's endpoint lengths; no vendor documents one.

- **The bound is on `Subscription`, not on the cache**, because it fixes the root: the per-POST
  header cost that predates the cache disappears with the same check, and the cache then needs no
  second mechanism — with the endpoint bounded, ADR-019's entry-count bound bounds the cache
  absolutely (worst case ~4.8 KB per entry, a few hundred KB across 64 entries). ADR-019 is
  untouched and not superseded: its claim that the entry-count bound is what makes the cache safe
  to hold becomes true under this decision rather than false.
- **The check lives in `Subscription`'s constructor, not in `Endpoints.requireSecure`.** ADR-016
  and ADR-017 both close by keeping `requireSecure` "a protocol check, not a security control",
  and this bound is a resource control with no RFC 8030 clause behind it. Every construction path
  runs the canonical constructor, so no path evades it.
- **What this is not:** not a validity judgement about the endpoint — a 2048-char endpoint is
  almost certainly garbage and still constructs; not a substitute for the endpoint policy, which
  keeps deciding *where* a send may go; and it performs no name resolution — ADR-017's reasoning
  against resolving stands untouched.

Rejected alternatives:

- **A weight-bounded cache** — a second bound to reconcile with `jwtCacheSize`, guarding a value
  that, once the endpoint is bounded, can no longer arrive.
- **Refusing to cache oversized entries** — leaves the per-POST cost and the pre-existing
  transient path exactly as they were.
- **A configurable limit** — a knob nobody can set correctly, on a value with a structural
  ceiling.
- **Deriving the bound by resolving the host** — ADR-017 settled that the library resolves
  nothing.

This rules out an endpoint above 2048 characters inside a `Subscription`; a size or weight bound
inside the token cache; a configurable endpoint-length limit; a bound derived by name resolution;
and the endpoint — raw or redacted — inside the refusal's message. `Endpoints.requireSecure` is
untouched and stays what ADR-005 called it: a protocol check, not a security control.
