# ADR-006 — `aes128gcm` only

**Status:** Accepted

RFC 8291 specifies `aes128gcm`; the earlier `aesgcm` and `aesgcm128` codings were interim schemes
with a different key derivation and a different header layout, and every current browser push
service accepts `aes128gcm`.

The library implements `aes128gcm` and nothing else. Supporting a legacy coding would double the
encryption path — the part where a mistake is silent, because a wrongly encrypted message is
accepted by the push service and only fails inside the browser — in exchange for compatibility
with clients that no longer exist.

There is no configuration switch for it, so the choice cannot be made wrongly at runtime.
