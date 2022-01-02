use std::cmp::min;
use std::io;
use std::io::prelude::*;
use std::io::SeekFrom;

pub const KEY_LEN: usize = 32;
pub const CHUNK_LEN: usize = 16384; // 2^14
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 32;

type Key = [u8; KEY_LEN];
type Nonce = [u8; NONCE_LEN];

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

fn ciphertext_len(plaintext_len: u64) -> Option<u64> {
    let num_chunks = (plaintext_len / CHUNK_LEN as u64) + 1;
    plaintext_len
        .checked_add(NONCE_LEN as u64)?
        .checked_add(num_chunks * TAG_LEN as u64)
}

fn plaintext_len(ciphertext_len: u64) -> Option<u64> {
    let chunks_len = ciphertext_len.checked_sub(NONCE_LEN as u64)?;
    let whole_chunks = chunks_len / (CHUNK_LEN + TAG_LEN) as u64;
    let last_chunk = chunks_len % (CHUNK_LEN + TAG_LEN) as u64;
    Some((whole_chunks * CHUNK_LEN as u64) + last_chunk.checked_sub(TAG_LEN as u64)?)
}

pub fn encrypt(key: &Key, plaintext: &[u8]) -> Vec<u8> {
    let ciphertext_len: usize = ciphertext_len(plaintext.len() as u64)
        .expect("length overflows a u64")
        .try_into()
        .expect("length overflows a usize");
    let mut ciphertext = vec![0; ciphertext_len];

    // NB: This is a cryptographically secure RNG.
    let nonce: Nonce = rand::random();
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

    ciphertext
}

pub fn decrypt(key: &Key, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let plaintext_len = if let Some(len) = plaintext_len(ciphertext.len() as u64) {
        len as usize
    } else {
        return Err(Error::truncated());
    };
    let mut plaintext = vec![0; plaintext_len];

    // Extract the nonce.
    let nonce: &Nonce = &ciphertext[..NONCE_LEN].try_into().unwrap();

    // Decrypt all non-final chunks.
    let mut chunk_index = 0;
    let mut ciphertext_chunks = ciphertext[NONCE_LEN..].chunks_exact(CHUNK_LEN + TAG_LEN);
    let mut plaintext_chunks = plaintext.chunks_exact_mut(CHUNK_LEN);
    for (ciphertext_chunk, plaintext_chunk) in ciphertext_chunks.by_ref().zip(&mut plaintext_chunks)
    {
        decrypt_chunk(
            key,
            &nonce,
            chunk_index,
            FinalFlag::NotFinal,
            ciphertext_chunk,
            plaintext_chunk,
        )?;
        chunk_index += 1;
    }

    // Decrypt the final chunk.
    decrypt_chunk(
        key,
        &nonce,
        chunk_index,
        FinalFlag::Final,
        ciphertext_chunks.remainder(),
        plaintext_chunks.into_remainder(),
    )?;

    Ok(plaintext)
}

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
    pub fn new(key: &Key, inner_writer: W) -> Self {
        Self {
            inner_writer,
            long_term_key: *key,
            // NB: This is a cryptographically secure RNG.
            nonce: rand::random(),
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

    pub fn finalize(&mut self) -> io::Result<()> {
        self.bail_if_errored_before()?;
        // This will debug_assert! that the final chunk is short.
        self.encrypt_and_write_buf(FinalFlag::Final)?;
        Ok(())
    }

    /// Consume self and return the inner writer. Note any unfinalized plaintext in internal buffer
    /// will be lost.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const INPUT_SIZES: &[usize] = &[
        0,
        1,
        63,
        64,
        65,
        CHUNK_LEN - 1,
        CHUNK_LEN,
        CHUNK_LEN + 1,
        2 * CHUNK_LEN - 1,
        2 * CHUNK_LEN,
        2 * CHUNK_LEN + 1,
        3 * CHUNK_LEN - 1,
        3 * CHUNK_LEN,
        3 * CHUNK_LEN + 1,
    ];

    fn paint_input(input: &mut [u8]) {
        for i in 0..input.len() {
            // 251 is the largest prime that fits in a byte.
            input[i] = (i % 251) as u8;
        }
    }

    fn test_key() -> Key {
        let mut key = [0; KEY_LEN];
        paint_input(&mut key);
        key
    }

    fn test_input(size: usize) -> Vec<u8> {
        let mut input = vec![0; size];
        paint_input(&mut input);
        input
    }

    #[test]
    fn test_round_trip() {
        for &size in INPUT_SIZES {
            let input = test_input(size);
            let ciphertext = encrypt(&test_key(), &input);
            assert_eq!(decrypt(&test_key(), &ciphertext).unwrap(), input);
        }
    }

    #[test]
    fn test_big_and_small_encryption_writes() {
        for &size in INPUT_SIZES {
            dbg!(size);
            let input = test_input(size);

            let mut all_at_once_writer = EncryptWriter::new(&test_key(), Vec::new());

            // Make a verbatim copy of the writer. This is nonce reuse, which would normally be
            // extremely unsafe, and the privacy rules normally forbid this. It works here because
            // this test is within the module that defines EncryptWriter.
            let mut one_at_a_time_writer = EncryptWriter {
                inner_writer: Vec::new(),
                ..all_at_once_writer
            };

            // Feed the input into all_at_once_writer with a single large write.
            all_at_once_writer.write_all(&input).unwrap();
            all_at_once_writer.finalize().unwrap();
            let all_at_once_ciphertext = all_at_once_writer.into_inner();

            // Feed the input into one_at_a_time_writer with many small writes.
            for &byte in &input {
                one_at_a_time_writer.write_all(&[byte]).unwrap();
            }
            one_at_a_time_writer.finalize().unwrap();
            let one_at_a_time_ciphertext = one_at_a_time_writer.into_inner();

            // Make sure the two ciphertexts are identical.
            assert_eq!(all_at_once_ciphertext, one_at_a_time_ciphertext);

            // Make sure the ciphertext decrypts successfully and correctly.
            assert_eq!(
                decrypt(&test_key(), &all_at_once_ciphertext).unwrap(),
                input
            );
        }
    }

    #[test]
    fn test_big_and_small_decryption_reads() {
        for &size in INPUT_SIZES {
            dbg!(size);
            let input = test_input(size);
            let ciphertext = encrypt(&test_key(), &input);

            let mut all_at_once_reader = DecryptReader::new(&test_key(), &ciphertext[..]);

            // Make a verbatim copy of the reader. Unlike the writer in the previous test, this is
            // safe, and the public API also allows this.
            let mut one_at_a_time_reader = all_at_once_reader.clone();

            // Read the all_at_once_reader with big reads.
            let mut all_at_once_plaintext = Vec::with_capacity(size);
            all_at_once_reader
                .read_to_end(&mut all_at_once_plaintext)
                .unwrap();
            assert_eq!(all_at_once_plaintext, input);
            if input.len() > 0 {
                assert_eq!(all_at_once_plaintext.capacity(), input.len());
            }

            // Read the one_at_a_time_reader with small reads. Assert the bytes are the same.
            for i in 0..input.len() {
                let mut buf = [0];
                assert_eq!(one_at_a_time_reader.read(&mut buf).unwrap(), 1);
                assert_eq!(buf[0], input[i]);
            }
            assert_eq!(one_at_a_time_reader.read(&mut [0]).unwrap(), 0);
        }
    }

    #[test]
    fn test_length_functions() {
        for &size in INPUT_SIZES {
            let ciphertext = encrypt(&[0; 32], &vec![0; size]);
            assert_eq!(Some(ciphertext.len() as u64), ciphertext_len(size as u64));
            assert_eq!(Some(size as u64), plaintext_len(ciphertext.len() as u64));
        }

        assert_eq!(None, plaintext_len(0));
        assert_eq!(None, plaintext_len((NONCE_LEN + TAG_LEN - 1) as u64));
        assert_eq!(
            None,
            plaintext_len((NONCE_LEN + CHUNK_LEN + TAG_LEN) as u64)
        );
        assert_eq!(None, ciphertext_len(u64::MAX));
    }

    #[test]
    fn test_just_seek() {
        for &size in INPUT_SIZES {
            dbg!(size);
            let input = test_input(size);
            let ciphertext = encrypt(&test_key(), &input);

            for &target in INPUT_SIZES {
                dbg!(target);

                // from start
                {
                    let mut reader = DecryptReader::new(&test_key(), Cursor::new(&ciphertext[..]));
                    let n = reader.seek(SeekFrom::Start(target as u64)).unwrap();
                    assert_eq!(n as usize, min(target, size));
                    let n = reader.seek(SeekFrom::Start(target as u64)).unwrap();
                    assert_eq!(n as usize, min(target, size));
                }

                // from current
                {
                    let mut reader = DecryptReader::new(&test_key(), Cursor::new(&ciphertext[..]));
                    let n = reader.seek(SeekFrom::Current(target as i64)).unwrap();
                    assert_eq!(n as usize, min(target, size));
                    let n = reader.seek(SeekFrom::Current(target as i64)).unwrap();
                    // seeks past EOF get capped
                    assert_eq!(n as usize, min(2 * target, size));
                }

                // from end
                {
                    let mut reader = DecryptReader::new(&test_key(), Cursor::new(&ciphertext[..]));
                    let n = reader.seek(SeekFrom::End(target as i64)).unwrap();
                    // seeks past EOF get capped
                    assert_eq!(n, size as u64);
                    if target <= size {
                        let n = reader.seek(SeekFrom::End(-(target as i64))).unwrap();
                        assert_eq!(n, (size - target) as u64);
                    }
                }
            }
        }
    }

    #[test]
    fn test_seek_and_read() {
        for &size in INPUT_SIZES {
            dbg!(size);
            let input = test_input(size);
            let ciphertext = encrypt(&test_key(), &input);

            // Test regular from-the-start seeks.
            for &seek_target in INPUT_SIZES {
                dbg!(seek_target);
                let mut reader = DecryptReader::new(&test_key(), Cursor::new(&ciphertext[..]));
                reader.seek(SeekFrom::Start(seek_target as u64)).unwrap();
                let mut output = Vec::new();
                reader.read_to_end(&mut output).unwrap();
                let expected = &input[min(size, seek_target)..];
                assert_eq!(expected, output);
            }

            // Test a negative EOF-relative seek followed by a current-relative seek.
            for &eof_seek in INPUT_SIZES {
                dbg!(eof_seek);
                // We'll use this as a negative offset.
                let capped_eof_seek = min(size, eof_seek);
                let eof_target = size - capped_eof_seek;
                let mut reader = DecryptReader::new(&test_key(), Cursor::new(&ciphertext[..]));
                reader
                    .seek(SeekFrom::End(-(capped_eof_seek as i64)))
                    .unwrap();
                for &current_seek in INPUT_SIZES {
                    dbg!(current_seek);
                    let current_target = min(size, eof_target + current_seek);
                    let mut reader = reader.clone();
                    reader.seek(SeekFrom::Current(current_seek as i64)).unwrap();
                    let mut output = Vec::new();
                    reader.read_to_end(&mut output).unwrap();
                    let expected = &input[current_target..];
                    assert_eq!(expected, output);
                }
            }
        }
    }
}
