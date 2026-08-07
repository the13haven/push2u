# Generating a VAPID key pair

push2u ships no key generator: the VAPID (RFC 8292) P-256 pair is your application's identity to
the push services, so it is created once, outside the application, and handed to it as
configuration. This is that one-time recipe — [`README.md` → VAPID keys](README.md#vapid-keys)
covers the pair's lifecycle and where its two halves go afterwards.

## What has to come out

Any P-256 generator will do, as long as it emits the encodings used here: the public key as the
**65-byte uncompressed X9.62 point**, which is what
[RFC 8292 §3.2](https://datatracker.ietf.org/doc/html/rfc8292#section-3.2) defines for the `k`
parameter and what browsers take as `applicationServerKey`, and the private key as the **raw 32-byte
scalar**, which is what `VapidKeys` takes. Both unpadded base64url. The JDK you already build with
can do it, through `jshell`.

Run it where you would handle any other secret — a workstation or a bastion, not CI. The private
half is printed to the terminal, so it lands in scrollback and in whatever your multiplexer or
terminal emulator keeps; move it into the secret store, then clear the buffer. Nothing here writes
it to disk, and the heredoc keeps it out of shell history, which records the command and not its
output.

## With `jshell`

<!-- vapid-keygen:begin -->
```bash
jshell -q - <<'EOF'
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.Base64;

byte[] fixed32(BigInteger value) {
    byte[] raw = value.toByteArray(), out = new byte[32];
    int len = Math.min(raw.length, 32);
    System.arraycopy(raw, raw.length - len, out, 32 - len, len);
    return out;
}

var generator = KeyPairGenerator.getInstance("EC");
generator.initialize(new ECGenParameterSpec("secp256r1"));
var pair = generator.generateKeyPair();

var point = ((ECPublicKey) pair.getPublic()).getW();
var publicKey = new byte[65];
publicKey[0] = 0x04;
System.arraycopy(fixed32(point.getAffineX()), 0, publicKey, 1, 32);
System.arraycopy(fixed32(point.getAffineY()), 0, publicKey, 33, 32);
var privateKey = fixed32(((ECPrivateKey) pair.getPrivate()).getS());

var base64url = Base64.getUrlEncoder().withoutPadding();
System.out.println("public:  " + base64url.encodeToString(publicKey));
System.out.println("private: " + base64url.encodeToString(privateKey));
/exit
EOF
```
<!-- vapid-keygen:end -->

That block is POSIX-shell syntax — `bash`, `zsh` or `sh`. On PowerShell or `cmd.exe`, save everything
between the `jshell -q - <<'EOF'` line and the closing `EOF` to a file, say `vapid.jsh`, and run
`jshell -q vapid.jsh` instead.

**`fixed32` is the reason this is longer than a three-liner, and it is not optional.** The JCA hands
out `BigInteger` coordinates, and `toByteArray()` is a two's-complement encoding rather than a fixed
32-byte field element: it prepends a `0x00` sign byte whenever the high bit is set — about half of
all generated pairs — and drops leading zeros, returning fewer than 32 bytes about once in two
hundred. So "strip the sign byte" is wrong half the time, and "strip but do not left-pad" is wrong
once in two hundred — the worse of the two, because the key looks perfectly fine right up to the
point where a signature does not verify. That second defect is exactly the one
`nl.martijndwars:web-push`'s own generator has (see
[`MIGRATION.md`](MIGRATION.md#vapid-key-encoding)); copying the block whole avoids both. push2u's
own test suite runs this block out of this file, so a snippet that stops printing a usable pair
fails the build.

## With npm `web-push`

If you already have Node.js around, the npm `web-push` package prints the same two values in the
same encoding, and either source is equally good:

```bash
npx web-push generate-vapid-keys
```
