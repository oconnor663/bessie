<h1>Bessie<a href="https://github.com/oconnor663/bessie/actions"><img align="right" src="https://github.com/oconnor663/bessie/workflows/tests/badge.svg"></a></h1>

[docs.rs](https://docs.rs/bessie) — [crates.io lib](https://crates.io/crates/bessie) — [crates.io bin](https://crates.io/crates/bessie_bin)

Bessie is an authenticated, chunked cipher based on
[BLAKE3](https://github.com/BLAKE3-team/BLAKE3). The [design](./design.md) has
been stable for a while, but it hasn't been audited or used in the real world
as far as I know. Use with caution.

Features and design goals:

- general-purpose authenticated encryption
- no practical limits on the number or size of messages
- internal random nonce generation, to prevent mistakes
- streaming encryption and decryption of large messages
- seekable decryption of large messages
- key commitment

Non-features and non-goals:

- Not formally/strongly misuse-resistant. Generating random nonces internally
  avoids a lot of common mistakes, and mixing auth tags into the stream makes
  nonce reuse somewhat less catastrophic. But nonce reuse does allow an
  attacker to mix-and-match chunks from different messages, and
  chunked/streaming constructions are also [inherently vulnerable to nonce
  reuse exploits](https://web.cs.ucdavis.edu/~rogaway/papers/oae.pdf) that
  all-at-once constructions like AES-SIV are not.
- No built-in associated data parameters. Callers who need associated data can
  mix it with their key using a KDF or a keyed hash.
- Not optimal as a building block for encrypted network protocols like TLS.
  TLS-oriented ciphers like AES-GCM and ChaCha20-Poly1305 prioritize bytes on
  the wire and short-message performance above all else. They're often used
  with ephemeral keys, where random nonces and key commitment aren't important.
  For comparison, an empty AES-GCM ciphertext is 16 bytes, while an empty
  Bessie ciphertext is 56 bytes. For a TLS-oriented cipher based on BLAKE3, see
  [BLAKE3-AEAD](https://github.com/oconnor663/blake3_aead).

Although the Bessie cipher and its library implementations are eventually
intended for production use, the `bessie` CLI tool will always be for testing
and demo purposes only. A general-purpose encryption CLI for real people needs
to support public-key encryption and various ways of encoding and managing
keys, neither of which are in scope for this project. If you are a real person
and you need a general-purpose encryption CLI, consider
[`age`](https://github.com/FiloSottile/age).

## Usage

To install the `bessie` CLI tool, which is for testing and demo purposes only:

```
cargo install bessie_bin
```

Or to build and install from this repo:

```
cargo install --path rust/bin
```

To encrypt and decrypt a 1 MB file using the all-zero key (seriously, testing
and demo purposes only):

```
head -c 1000000 /dev/urandom > myfile
bessie encrypt zero myfile myfile_enc
bessie decrypt zero myfile_enc myfile_copy
cmp myfile myfile_copy
```

To decrypt just the last byte of the encrypted file:

```
bessie decrypt zero myfile_enc myfile_last --seek=999999
```

To run tests for the whole project:

```
./test.py
```
