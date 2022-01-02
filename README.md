# Bessie [![Actions Status](https://github.com/oconnor663/bessie/workflows/tests/badge.svg)](https://github.com/oconnor663/bessie/actions) [![crates.io](https://img.shields.io/crates/v/bessie.svg)](https://crates.io/crates/bessie) [![crates.io](https://img.shields.io/crates/v/bessie_bin.svg)](https://crates.io/crates/bessie_bin)

Bessie is an authenticated, chunked cipher based on
[BLAKE3](https://github.com/BLAKE3-team/BLAKE3). Right now it's in the early
design stages. See [`design.md`](./design.md).

Although the Bessie cipher and its library implementations are eventually
intended for production use, the `bessie` CLI tool will always be for testing
and demo purposes only. A real-world encryption CLI needs to support public-key
encryption and various ways of encoding and managing keys, neither of which are
in scope for this project. If you need a real-world encryption CLI, consider
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
cmp myfile myfile2
```

To decrypt just the last byte of the encrypted file:

```
bessie decrypt zero myfile_enc myfile_last --seek=999999
```

To run tests for the whole project:

```
./test.py
```
