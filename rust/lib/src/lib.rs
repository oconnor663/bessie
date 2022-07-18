//! Bessie is an authenticated, chunked cipher based on
//! [BLAKE3](https://github.com/BLAKE3-team/BLAKE3). It's still in the design stages, and it's not
//! suitable for production use.
//!
//! # Examples
//!
//! Encrypt a message.
//!
//! ```rust
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let key = bessie::generate_key();
//! let ciphertext: Vec<u8> = bessie::encrypt(&key, b"hello world");
//! # Ok(())
//! # }
//! ```
//!
//! Decrypt that message.
//!
//! ```rust
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let key = bessie::generate_key();
//! # let ciphertext: Vec<u8> = bessie::encrypt(&key, b"hello world");
//! let plaintext: Vec<u8> = bessie::decrypt(&key, &ciphertext)?;
//! assert_eq!(b"hello world", &plaintext[..]);
//! # Ok(())
//! # }
//! ```
use std::cmp::min;
use std::io;
use std::io::prelude::*;
use std::io::SeekFrom;

#[cfg(test)]
mod test;

pub const KEY_LEN: usize = 32;
pub const CHUNK_LEN: usize = 16384; // 2^14
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 32;

type Key = [u8; KEY_LEN];
type Nonce = [u8; NONCE_LEN];

/// An opaque decryption error.
///
/// Errors could represent either corruption, where ciphertext bytes or key bytes have been
/// changed, or truncation, where a valid ciphertext has been cut short. Some truncations are also
/// indistinguishable from corruption. `Error::to_string` does its best to distinguish between
/// these two cases to help with debugging, but application code should treat them as equivalent.
#[derive(Debug)]
pub struct Error {
    msg: &'static str,
}

impl Error {
    fn truncated() -> Self {
        Self {
            msg: "ciphertext has been truncated",
        }
    }

    fn corrupt() -> Self {
        Self {
            msg: "ciphertext is corrupt",
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, e.msg)
    }
}

impl std::error::Error for Error {}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
enum FinalFlag {
    NotFinal = 0,
    Final = 1,
}

// returns (auth_key, stream_key)
fn chunk_keys(
    long_term_key: &Key,
    nonce: &Nonce,
    chunk_index: u64,
    final_flag: FinalFlag,
) -> (Key, Key) {
    let mut input = [0; NONCE_LEN + 8 + 1];
    input[..NONCE_LEN].copy_from_slice(nonce);
    input[NONCE_LEN..][..8].copy_from_slice(&chunk_index.to_le_bytes());
    input[NONCE_LEN + 8] = final_flag as u8;
    let mut output = [0; 2 * KEY_LEN];
    blake3::Hasher::new_keyed(long_term_key)
        .update(&input)
        .finalize_xof()
        .fill(&mut output);
    (
        output[..KEY_LEN].try_into().unwrap(),
        output[KEY_LEN..].try_into().unwrap(),
    )
}

fn xor_stream(mut stream_reader: blake3::OutputReader, input: &[u8], output: &mut [u8]) {
    assert_eq!(input.len(), output.len());
    let mut position = 0;
    while position < input.len() {
        let mut stream_block = [0; 64];
        stream_reader.fill(&mut stream_block);
        let take = min(64, input.len() - position);
        for _ in 0..take {
            output[position] = input[position] ^ stream_block[position % 64];
            position += 1;
        }
    }
}

fn encrypt_chunk(
    long_term_key: &Key,
    nonce: &Nonce,
    chunk_index: u64,
    final_flag: FinalFlag,
    plaintext: &[u8],
    ciphertext: &mut [u8],
) {
    debug_assert!(plaintext.len() <= CHUNK_LEN);
    debug_assert_eq!(plaintext.len() + TAG_LEN, ciphertext.len());
    match final_flag {
        FinalFlag::NotFinal => debug_assert_eq!(plaintext.len(), CHUNK_LEN),
        FinalFlag::Final => debug_assert!(plaintext.len() < CHUNK_LEN),
    }
    let (auth_key, stream_key) = chunk_keys(long_term_key, nonce, chunk_index, final_flag);
    let tag = blake3::keyed_hash(&auth_key, plaintext);
    let stream_reader = blake3::Hasher::new_keyed(&stream_key)
        .update(tag.as_bytes())
        .finalize_xof();
    xor_stream(stream_reader, plaintext, &mut ciphertext[..plaintext.len()]);
    ciphertext[plaintext.len()..].copy_from_slice(tag.as_bytes());
}

fn decrypt_chunk(
    long_term_key: &Key,
    nonce: &Nonce,
    chunk_index: u64,
    final_flag: FinalFlag,
    ciphertext: &[u8],
    plaintext: &mut [u8],
) -> Result<(), Error> {
    if ciphertext.len() < TAG_LEN {
        return Err(Error::truncated());
    }
    debug_assert!(plaintext.len() <= CHUNK_LEN);
    debug_assert_eq!(plaintext.len() + TAG_LEN, ciphertext.len());
    match final_flag {
        FinalFlag::NotFinal => debug_assert_eq!(plaintext.len(), CHUNK_LEN),
        FinalFlag::Final => debug_assert!(plaintext.len() < CHUNK_LEN),
    }
    let (auth_key, stream_key) = chunk_keys(long_term_key, nonce, chunk_index, final_flag);
    let tag_bytes: &[u8; TAG_LEN] = ciphertext[ciphertext.len() - TAG_LEN..].try_into().unwrap();
    let stream_reader = blake3::Hasher::new_keyed(&stream_key)
        .update(tag_bytes)
        .finalize_xof();
    xor_stream(stream_reader, &ciphertext[..plaintext.len()], plaintext);
    let computed_tag: blake3::Hash = blake3::keyed_hash(&auth_key, plaintext);
    // NB: blake3::Hash implements constant-time equality checking.
    if &computed_tag != tag_bytes {
        // Wipe the output buffer out of an abundance of caution.
        plaintext.fill(0);
        return Err(Error::corrupt());
    }
    Ok(())
}

/// Compute the length of a ciphertext, given the length of a plaintext.
///
/// This function returns `None` if the resulting ciphertext length would overflow a `u64`.
pub fn ciphertext_len(plaintext_len: u64) -> Option<u64> {
    let num_chunks = (plaintext_len / CHUNK_LEN as u64) + 1;
    plaintext_len
        .checked_add(NONCE_LEN as u64)?
        .checked_add(num_chunks * TAG_LEN as u64)
}

/// Compute the length of a plaintext, given the length of a ciphertext.
///
/// Ciphertexts contain nonces and tags of a fixed size, so not all possible values of
/// `ciphertext_len` are valid. For invalid lengths, this function returns `None`.
pub fn plaintext_len(ciphertext_len: u64) -> Option<u64> {
    let chunks_len = ciphertext_len.checked_sub(NONCE_LEN as u64)?;
    let whole_chunks = chunks_len / (CHUNK_LEN + TAG_LEN) as u64;
    let last_chunk = chunks_len % (CHUNK_LEN + TAG_LEN) as u64;
    Some((whole_chunks * CHUNK_LEN as u64) + last_chunk.checked_sub(TAG_LEN as u64)?)
}

/// Create a new 32-byte key from a cryptographically secure random number generator.
pub fn generate_key() -> Key {
    // NB: rand::random() is a cryptographically secure RNG. This is a security requirement.
    rand::random()
}

fn generate_nonce() -> Nonce {
    // NB: rand::random() is a cryptographically secure RNG. This isn't strictly speaking a
    // security requirement, but it's crucial that nonces never repeat. If we ever switch to a
    // non-cryptographic RNG here as a performance optimization (unlikely), we'll need to make sure
    // that the seed still comes from the OS.
    rand::random()
}

/// Encrypt a message and return the ciphertext as a `Vec<u8>`.
///
/// This function generates a new random nonce internally, so its output will be different every
/// time, even with exactly the same inputs.
pub fn encrypt(key: &Key, plaintext: &[u8]) -> Vec<u8> {
    let ciphertext_len: usize = ciphertext_len(plaintext.len() as u64)
        .expect("length overflows a u64")
        .try_into()
        .expect("length overflows a usize");
    let mut ciphertext = vec![0; ciphertext_len];
    encrypt_to_slice(key, plaintext, &mut ciphertext);
    ciphertext
}

/// Encrypt a message and write the ciphertext to an existing slice.
///
/// This function does not allocate memory. However, `ciphertext.len()` must be exactly equal to
/// [`ciphertext_len(plaintext.len())`](ciphertext_len), or else this function will panic.
///
/// This function generates a new random nonce internally, so its output will be different every
/// time, even with exactly the same inputs.
pub fn encrypt_to_slice(key: &Key, plaintext: &[u8], ciphertext: &mut [u8]) {
    let nonce = generate_nonce();
    ciphertext[..NONCE_LEN].copy_from_slice(&nonce);

    // Encrypt all non-final chunks.
    let mut chunk_index = 0;
    let mut plaintext_chunks = plaintext.chunks_exact(CHUNK_LEN);
    let mut ciphertext_chunks = ciphertext[NONCE_LEN..].chunks_exact_mut(CHUNK_LEN + TAG_LEN);
    for (plaintext_chunk, ciphertext_chunk) in plaintext_chunks.by_ref().zip(&mut ciphertext_chunks)
    {
        encrypt_chunk(
            key,
            &nonce,
            chunk_index,
            FinalFlag::NotFinal,
            plaintext_chunk,
            ciphertext_chunk,
        );
        chunk_index += 1;
    }

    // Encrypt the final chunk.
    encrypt_chunk(
        key,
        &nonce,
        chunk_index,
        FinalFlag::Final,
        plaintext_chunks.remainder(),
        ciphertext_chunks.into_remainder(),
    );
}

/// Decrypt a message and return the plaintext as `Result` of `Vec<u8>`.
///
/// If the ciphertext or key has been changed, decryption will return `Err`.
pub fn decrypt(key: &Key, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let plaintext_len = if let Some(len) = plaintext_len(ciphertext.len() as u64) {
        len as usize
    } else {
        return Err(Error::truncated());
    };
    let mut plaintext = vec![0; plaintext_len];
    decrypt_to_slice(key, ciphertext, &mut plaintext)?;
    Ok(plaintext)
}

/// Decrypt a message, write the plaintext to an existing slice, and return a `Result`.
///
/// If the ciphertext or key has been changed, decryption will return `Err`.
///
/// This function does not allocate memory. However, `plaintext.len()` must be exactly equal to
/// [`plaintext_len(ciphertext.len())`](plaintext_len), or else this function will panic.
///
/// If decryption fails, this function will zero out the entire `plaintext` slice, as an extra
/// precaution to prevent callers who ignore the returned `Err` from reading unauthenticated
/// plaintext. However, this behavior is not guaranteed.
pub fn decrypt_to_slice(key: &Key, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), Error> {
    // Extract the nonce.
    let nonce: &Nonce = &ciphertext[..NONCE_LEN].try_into().unwrap();

    // Decrypt all non-final chunks.
    let mut chunk_index = 0;
    let mut ciphertext_chunks = ciphertext[NONCE_LEN..].chunks_exact(CHUNK_LEN + TAG_LEN);
    let mut plaintext_chunks = plaintext.chunks_exact_mut(CHUNK_LEN);
    for (ciphertext_chunk, plaintext_chunk) in ciphertext_chunks.by_ref().zip(&mut plaintext_chunks)
    {
        let chunk_result = decrypt_chunk(
            key,
            &nonce,
            chunk_index,
            FinalFlag::NotFinal,
            ciphertext_chunk,
            plaintext_chunk,
        );
        if let Err(e) = chunk_result {
            // Wipe the whole output slice out of an abundance of caution.
            plaintext.fill(0);
            return Err(e);
        }
        chunk_index += 1;
    }

    // Decrypt the final chunk.
    let chunk_result = decrypt_chunk(
        key,
        &nonce,
        chunk_index,
        FinalFlag::Final,
        ciphertext_chunks.remainder(),
        plaintext_chunks.into_remainder(),
    );
    if let Err(e) = chunk_result {
        // Wipe the whole output slice out of an abundance of caution.
        plaintext.fill(0);
        return Err(e);
    }

    Ok(())
}

/// An incremental encrypter supporting [`std::io::Write`].
///
/// For incremental decryption, see [`DecryptReader`].
///
/// # Example
///
/// Encrypt a file incrementally.
///
/// ```rust
/// # use std::io::prelude::*;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let some_file = Vec::new();
/// // let some_file = std::fs::File::create(...)?;
/// let key = bessie::generate_key();
/// let mut encrypter = bessie::EncryptWriter::new(&key, some_file);
/// encrypter.write_all(b"foo")?;
/// encrypter.write_all(b"bar")?;
/// encrypter.write_all(b"baz")?;
/// // NOTE: Calling finalize is required. If you forget to finalize, decryption will fail.
/// encrypter.finalize()?;
/// # assert_eq!(b"foobarbaz"[..], bessie::decrypt(&key, &encrypter.into_inner()).unwrap());
/// # Ok(())
/// # }
/// ```
pub struct EncryptWriter<W: Write> {
    inner_writer: W,
    long_term_key: Key,
    nonce: Nonce,
    chunk_index: u64,
    plaintext_buf: [u8; CHUNK_LEN],
    plaintext_buf_len: usize,
    did_error: bool, // write errors for this writer are unrecoverable
}

impl<W: Write> EncryptWriter<W> {
    /// Construct a new `EncryptWriter` from a key and an output stream.
    ///
    /// Each `EncryptWriter` is created with a new, random, internal nonce.
    pub fn new(key: &Key, inner_writer: W) -> Self {
        Self {
            inner_writer,
            long_term_key: *key,
            nonce: generate_nonce(),
            chunk_index: 0,
            plaintext_buf: [0; CHUNK_LEN],
            plaintext_buf_len: 0,
            did_error: false,
        }
    }

    fn bail_if_errored_before(&self) -> io::Result<()> {
        if self.did_error {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "already encountered an error",
            ))
        } else {
            Ok(())
        }
    }

    fn encrypt_and_write_buf(&mut self, final_flag: FinalFlag) -> io::Result<usize> {
        // Set did_error back to false if we make it to the end.
        debug_assert!(!self.did_error);
        self.did_error = true;

        // If this is the first chunk, write out the nonce.
        if self.chunk_index == 0 {
            self.inner_writer.write_all(&self.nonce)?;
        }

        // Encrypt the chunk.
        let mut ciphertext_array = [0; CHUNK_LEN + TAG_LEN];
        let ciphertext_slice = &mut ciphertext_array[..self.plaintext_buf_len + TAG_LEN];
        encrypt_chunk(
            &self.long_term_key,
            &self.nonce,
            self.chunk_index,
            final_flag,
            &self.plaintext_buf[..self.plaintext_buf_len],
            ciphertext_slice,
        );
        // NB: We must *never ever ever* encrypt with the same nonce+chunk_index combination more
        // than once. That would lead to stream cipher nonce reuse, which ruins all our security.
        // Increment the chunk index here, before the write, to guarantee we can't reuse it. This
        // tends to make transient IO errors unrecoverable, but that's better than losing security.
        assert!(self.chunk_index < u64::MAX, "chunk index overflow");
        self.chunk_index += 1;
        self.plaintext_buf_len = 0;

        // Write out the encrypted ciphertext.
        self.inner_writer.write_all(ciphertext_slice)?;

        self.did_error = false;
        Ok(self.plaintext_buf_len)
    }

    /// Encrypt and write the final chunk. You must call `finalize` after you're done writing, or
    /// else the final chunk will be missing and decryption will fail.
    pub fn finalize(&mut self) -> io::Result<()> {
        self.bail_if_errored_before()?;
        // This will debug_assert! that the final chunk is short.
        self.encrypt_and_write_buf(FinalFlag::Final)?;
        Ok(())
    }

    /// Consume self and return the inner writer. Note any unfinalized plaintext in the internal
    /// buffer will be lost.
    pub fn into_inner(self) -> W {
        self.inner_writer
    }
}

impl<W: Write> Write for EncryptWriter<W> {
    fn write(&mut self, plaintext: &[u8]) -> io::Result<usize> {
        self.bail_if_errored_before()?;

        // Copy as many bytes as possible into the plaintext buffer.
        let want = CHUNK_LEN - self.plaintext_buf_len;
        let take = min(want, plaintext.len());
        self.plaintext_buf[self.plaintext_buf_len..][..take].copy_from_slice(&plaintext[..take]);
        self.plaintext_buf_len += take;

        // If the plaintext buffer is full, write it out and clear it.
        if self.plaintext_buf_len == CHUNK_LEN {
            self.encrypt_and_write_buf(FinalFlag::NotFinal)?;
        }

        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner_writer.flush()
    }
}

// Implement Debug explicitly, to avoid leaking keys.
impl<W: Write> std::fmt::Debug for EncryptWriter<W> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.debug_struct("EncryptWriter").finish()
    }
}

/// An incremental decrypter supporting [`std::io::Read`] and [`std::io::Seek`].
///
/// If this stream encounters any decryption errors, they will be converted into [`std::io::Error`]
/// with [`ErrorKind::InvalidData`](std::io::ErrorKind). Other IO errors are returned unmodified.
///
/// For incremental encryption, see [`EncryptWriter`].
///
/// # Example
///
/// Decrypt a file incrementally. Assume the encrypted plaintext is `foobarbaz`, as in the
/// [`EncryptWriter`] example.
///
/// ```rust
/// # use std::io::prelude::*;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let key = bessie::generate_key();
/// # let ciphertext = bessie::encrypt(&key, b"foobarbaz");
/// # let mut some_file = std::io::Cursor::new(ciphertext);
/// // let key = ...;
/// // let some_file = std::fs::File::open(...)?;
/// let mut decrypter = bessie::DecryptReader::new(&key, some_file);
/// let mut read_buf = [0; 3];
/// decrypter.read_exact(&mut read_buf)?;
/// assert_eq!(b"foo", &read_buf);
/// decrypter.read_exact(&mut read_buf)?;
/// assert_eq!(b"bar", &read_buf);
/// decrypter.read_exact(&mut read_buf)?;
/// assert_eq!(b"baz", &read_buf);
/// assert_eq!(0, decrypter.read(&mut read_buf)?, "EOF");
/// # Ok(())
/// # }
/// ```
///
/// Seek to the end of the same file.
///
/// ```rust
/// # use std::io::prelude::*;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let key = bessie::generate_key();
/// # let ciphertext = bessie::encrypt(&key, b"foobarbaz");
/// # let mut some_file = std::io::Cursor::new(ciphertext);
/// // let key = ...;
/// // let some_file = std::fs::File::open(...)?;
/// let mut decrypter = bessie::DecryptReader::new(&key, some_file);
/// decrypter.seek(std::io::SeekFrom::End(-3))?;
/// let mut rest = String::new();
/// decrypter.read_to_string(&mut rest)?;
/// assert_eq!("baz", rest);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct DecryptReader<R: Read> {
    inner_reader: R,
    long_term_key: Key,
    nonce: Option<Nonce>,
    plaintext_buf: [u8; CHUNK_LEN],
    plaintext_buf_pos: u16, // our current position within the plaintext buffer, pos <= len
    plaintext_buf_len: u16, // the length of the plaintext buffer
    plaintext_buf_end_offset: u64, // the absolute stream offset of the end of the plaintext buffer
    at_eof: bool,
    authenticated_plaintext_length: Option<u64>,
}

impl<R: Read> DecryptReader<R> {
    /// Construct a new `DecryptReader` from a key and a stream of ciphertext.
    pub fn new(key: &Key, inner_reader: R) -> Self {
        Self {
            inner_reader,
            long_term_key: *key,
            nonce: None,
            plaintext_buf: [0; CHUNK_LEN],
            plaintext_buf_pos: 0,
            plaintext_buf_len: 0,
            plaintext_buf_end_offset: 0,
            at_eof: false,
            authenticated_plaintext_length: None,
        }
    }

    /// Consume self and return the inner reader. Note any decrypted plaintext in the internal
    /// buffer will be lost.
    pub fn into_inner(self) -> R {
        self.inner_reader
    }

    fn get_nonce(&mut self) -> io::Result<Nonce> {
        match self.nonce {
            Some(nonce) => Ok(nonce),
            None => {
                let mut nonce = [0; NONCE_LEN];
                self.inner_reader.read_exact(&mut nonce)?;
                self.nonce = Some(nonce);
                Ok(nonce)
            }
        }
    }

    /// The current absolute stream position, equivalent to `Seek::stream_position`.
    pub fn position(&self) -> u64 {
        debug_assert!(self.plaintext_buf_pos <= self.plaintext_buf_len);
        debug_assert!(self.plaintext_buf_len as u64 <= self.plaintext_buf_end_offset);
        self.plaintext_buf_end_offset - self.plaintext_buf_len as u64
            + self.plaintext_buf_pos as u64
    }
}

// Try to fill `buf`, potentially with multiple reads, but return early if we encounter EOF. Retry
// and ErrorKind::Interrupted errors.
fn read_exact_or_eof<'buf>(
    reader: &mut impl Read,
    buf: &'buf mut [u8],
) -> io::Result<&'buf mut [u8]> {
    let mut total_read = 0;
    let mut remaining_buf = &mut buf[..];
    while !remaining_buf.is_empty() {
        match reader.read(&mut remaining_buf) {
            Ok(n) => {
                total_read += n;
                if n == 0 {
                    // EOF
                    break;
                }
                remaining_buf = &mut remaining_buf[n..];
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
        }
    }
    Ok(&mut buf[..total_read])
}

impl<R: Read> DecryptReader<R> {
    fn read_and_decrypt_next_chunk(&mut self, next_chunk_start_offset: u64) -> io::Result<()> {
        debug_assert_eq!(next_chunk_start_offset % CHUNK_LEN as u64, 0);

        // If we haven't read the nonce yet, do that first.
        let nonce = self.get_nonce()?;

        // Clear the plaintext buffer defensively, so that there's no way we could return stale,
        // possibly even unauthenticated plaintext in some unusual seek+error+retry case.
        // (decrypt_chunk does zero out the plaintext buffer when authentication fails, but we
        // don't want to rely on that.)
        self.plaintext_buf_pos = 0;
        self.plaintext_buf_len = 0;

        // Read the next ciphertext chunk.
        let mut ciphertext_array = [0; CHUNK_LEN + TAG_LEN];
        let chunk_ciphertext = read_exact_or_eof(&mut self.inner_reader, &mut ciphertext_array)?;
        if chunk_ciphertext.len() < TAG_LEN {
            return Err(Error::truncated().into());
        }

        // Decrypt the chunk we just read.
        let next_chunk_index = next_chunk_start_offset / CHUNK_LEN as u64;
        let final_flag = if chunk_ciphertext.len() == CHUNK_LEN + TAG_LEN {
            FinalFlag::NotFinal
        } else {
            FinalFlag::Final
        };
        let chunk_plaintext = &mut self.plaintext_buf[..chunk_ciphertext.len() - TAG_LEN];
        decrypt_chunk(
            &self.long_term_key,
            &nonce,
            next_chunk_index,
            final_flag,
            chunk_ciphertext,
            chunk_plaintext,
        )?;

        // Decryption succeeded. Update internal state with the results of the read.
        self.plaintext_buf_end_offset = next_chunk_start_offset
            .checked_add(chunk_plaintext.len() as u64)
            .expect("position overflow");
        self.plaintext_buf_len = chunk_plaintext.len() as u16;
        self.at_eof = matches!(final_flag, FinalFlag::Final);
        if self.at_eof {
            self.authenticated_plaintext_length = Some(self.plaintext_buf_end_offset);
        }

        Ok(())
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // If the plaintext buffer is empty, and we're not at EOF, read and decrypt another chunk.
        if !self.at_eof && self.plaintext_buf_pos == self.plaintext_buf_len {
            self.read_and_decrypt_next_chunk(self.plaintext_buf_end_offset)?;
        }

        // Copy as many bytes as possible into the caller's buffer.
        let available = self.plaintext_buf_len - self.plaintext_buf_pos;
        let take = min(buf.len(), available as usize);
        buf[..take].copy_from_slice(&self.plaintext_buf[self.plaintext_buf_pos as usize..][..take]);
        self.plaintext_buf_pos += take as u16;

        Ok(take)
    }
}

impl<R: Read + Seek> DecryptReader<R> {
    // If the caller hasn't yet read the end of the file, we need to seek to and verify the final
    // chunk. This authenticates the length, which makes it safe to do EOF-relative seeks or seeks
    // past EOF. Note that this changes the current stream position, so it's important that we only
    // call this when we intend to do a seek afterwards.
    fn get_authenticated_plaintext_length(&mut self) -> io::Result<u64> {
        if let Some(len) = self.authenticated_plaintext_length {
            return Ok(len);
        }

        // Make sure we've read the nonce before we do any seeking.
        self.get_nonce()?;

        let apparent_ciphertext_length = self.inner_reader.seek(SeekFrom::End(0))?;
        let apparent_plaintext_length = plaintext_len(apparent_ciphertext_length)
            .ok_or_else(|| io::Error::from(Error::truncated()))?;
        // Invalid ciphertext lengths bail on the line above, so we don't need to check the
        // following arithmetic.
        let apparent_last_chunk_ciphertext_length =
            (apparent_ciphertext_length - NONCE_LEN as u64) % (CHUNK_LEN + TAG_LEN) as u64;
        let apparent_last_chunk_plaintext_length = apparent_plaintext_length % CHUNK_LEN as u64;
        let apparent_last_chunk_ciphertext_start =
            apparent_ciphertext_length - apparent_last_chunk_ciphertext_length;
        let apparent_last_chunk_plaintext_start =
            apparent_plaintext_length - apparent_last_chunk_plaintext_length;

        self.inner_reader
            .seek(SeekFrom::Start(apparent_last_chunk_ciphertext_start))?;
        self.read_and_decrypt_next_chunk(apparent_last_chunk_plaintext_start)?;

        // If read_and_decrypt_next_chunk succeeded above, then self.authenticated_plaintext_length
        // should now be set. However there's a weird corner case: It's possible that reading the
        // next chunk succeeded but did *not* encounter EOF. That would require some sort of
        // filesystem race in between our first seek and our read. (Or maybe data corruption on
        // disk leading to inconsistencies.) But since this is an IO issue and not a bug in this
        // library, we don't want to panic on it. Just check for it and bail.
        if let Some(len) = self.authenticated_plaintext_length {
            Ok(len)
        } else {
            Err(Error::truncated().into())
        }
    }
}

impl<R: Read + Seek> Seek for DecryptReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // Make sure we've read the nonce before we do any seeking.
        self.get_nonce()?;

        // The call to get_authenticated_plaintext_length might change our position. Cache it here,
        // so that we can use it to compute SeekFrom::Current seeks below.
        let starting_position = self.position();

        // We don't actually need to authenticate the plaintext length if the seek target is to the
        // left. But it's simpler to just always do it.
        let plaintext_len = self.get_authenticated_plaintext_length()?;

        let mut target = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::Current(n) => (starting_position as i128 + n as i128)
                .try_into()
                .expect("seek target overflow"),
            SeekFrom::End(n) => (plaintext_len as i128 + n as i128)
                .try_into()
                .expect("seek target overflow"),
        };

        // If the seek target is past EOF, cap it at EOF.
        if target > plaintext_len {
            target = plaintext_len;
        }

        // If the seek is within the current plaintext buffer (which might have been modified by
        // get_authenticated_plaintext_length above) adjust the buffer and exit early.
        if target <= self.plaintext_buf_end_offset {
            let remaining = self.plaintext_buf_end_offset - target;
            if remaining <= self.plaintext_buf_len as u64 {
                self.plaintext_buf_pos = self.plaintext_buf_len - remaining as u16;
                // self.at_eof may be true or false at this point. Leave it as-is.
                debug_assert_eq!(target, self.position());
                return Ok(target);
            }
        }

        // Read the target chunk and adjust the buffer offset, so that the next read will start at
        // the correct byte.
        let target_chunk_index = target / CHUNK_LEN as u64;
        let target_position_within_chunk = (target % CHUNK_LEN as u64) as u16;
        let target_chunk_start = target - target_position_within_chunk as u64;
        let target_ciphertext_chunk_start = ((CHUNK_LEN + TAG_LEN) as u64)
            .checked_mul(target_chunk_index)
            .and_then(|s| s.checked_add(NONCE_LEN as u64))
            .expect("ciphertext target overflow");
        self.inner_reader
            .seek(SeekFrom::Start(target_ciphertext_chunk_start))?;
        self.read_and_decrypt_next_chunk(target_chunk_start)?;
        if self.plaintext_buf_len < target_position_within_chunk {
            // This condition would represent another weird IO inconsistency in the final chunk,
            // like the one described in get_authenticated_plaintext_length above. Again we need to
            // check for it and bail.
            return Err(Error::truncated().into());
        }
        self.plaintext_buf_pos = target_position_within_chunk;
        debug_assert_eq!(target, self.position());
        Ok(target)
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        Ok(self.position())
    }
}

// Implement Debug explicitly, to avoid leaking keys.
impl<R: Read> std::fmt::Debug for DecryptReader<R> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.debug_struct("DecryptReader").finish()
    }
}
