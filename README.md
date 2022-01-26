<h1>Bessie<a href="https://github.com/oconnor663/bessie/actions"><img align="right" src="https://github.com/oconnor663/bessie/workflows/tests/badge.svg"></a></h1>

[docs.rs](https://docs.rs/bessie) — [crates.io lib](https://crates.io/crates/bessie) — [crates.io bin](https://crates.io/crates/bessie_bin)

Bessie is an authenticated, chunked cipher based on
[BLAKE3](https://github.com/BLAKE3-team/BLAKE3). Right now it's in the early
design stages. See [`design.md`](./design.md). A high-performance
implementation of this design is blocked on some upstream refactoring of
`blake3`, to add SIMD optimizations to extended outputs.

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
