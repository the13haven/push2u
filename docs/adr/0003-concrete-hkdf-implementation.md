# ADR-003 — Concrete HKDF implementation

**Status:** Accepted

RFC 8291 needs HKDF-SHA-256, and the JDK offers no HKDF primitive on the Java 21 baseline
(ADR-001). Pulling in a crypto library for it would breach ADR-002.

HKDF is therefore a small RFC 5869 implementation over JCA `Mac("HmacSHA256")`, pinned by the
RFC's published vectors, and it is not an extension point. The same holds for the RFC 8291
encryptor and the RFC 6454 origin serialization.

Making any of them replaceable would not change intended behaviour — there is exactly one correct
output — while adding a failure mode the library cannot detect: an alternative implementation that
produces a wrong ciphertext or a wrong `aud` value fails at the browser, long after the send
reported success.
