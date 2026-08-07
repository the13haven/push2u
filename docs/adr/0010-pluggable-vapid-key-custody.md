# ADR-010 — Pluggable VAPID key custody

**Status:** Accepted

The VAPID private key is the application's identity to every push service, and it never expires on
its own: rotating it invalidates every existing browser subscription. Deployments that hold such a
key in a KMS, an HSM or Vault cannot hand a raw scalar to a library, and deployments that are
happy to configure one should not have to run a key service to send a push.

Key custody is therefore behind `VapidSigner` (ADR-005) rather than fixed in the pipeline. The
default `LocalEcVapidSigner` holds a scalar in process, which is what makes the getting-started
path two lines; a remote signer improves the custody boundary without the send pipeline knowing
that anything changed — it asks for a signature and a public key either way.

The consequence that shapes the contract is that the pipeline cannot see how a signature was made,
so a signer's two outputs are checked on every send instead of being trusted (`push2u-testkit`
exists to let an implementation find that out in its own suite rather than against a push
service).
