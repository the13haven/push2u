# ADR-011 — Size limit expressed on the encrypted body

**Status:** Accepted; one clause superseded by [ADR-023](0023-one-size-limit-answerable-before-a-send.md)

RFC 8030 §7.2 constrains what a push service must accept: the *entity body*, at least 4096 bytes.
A limit expressed on the plaintext would be a restatement of that clause with the `aes128gcm`
overhead already applied, so an operator raising it for a push service documented to accept more
would be converting between two numbers by hand.

The configurable limit is therefore `maxEncryptedBodyBytes`, and the plaintext maximum is derived
from it — 3993 bytes at the 4096-byte default, from the format the encryptor actually emits rather
than a constant written into the code. A configured limit therefore always names the plaintext
maximum correctly, including for a limit nobody anticipated.

`recordSize` stays an independent parameter and is never adjusted to follow the body limit: `rs`
is advertised in the RFC 8188 header, so silently changing it would change what goes out on the
wire in answer to a question about how much the push service accepts. Raising one without the
other rejects an oversized message rather than quietly re-framing it.
