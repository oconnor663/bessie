use std::io::prelude::*;

pub const KEY_LEN: usize = 32;
const CHUNK_LEN: usize = 16384; // 2^14
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 32;

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

impl From<Error> for std::io::Error {
    fn from(e: Error) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e.msg)
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
        let take = std::cmp::min(64, input.len() - position);
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
    let num_chunks = (chunks_len / (CHUNK_LEN + TAG_LEN) as u64) + 1;
    chunks_len.checked_sub(num_chunks * TAG_LEN as u64)
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

    fn bail_if_errored_before(&self) -> std::io::Result<()> {
        if self.did_error {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "already encountered an error",
            ))
        } else {
            Ok(())
        }
    }

    fn encrypt_and_write_buf(&mut self, final_flag: FinalFlag) -> std::io::Result<usize> {
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

    pub fn finalize(&mut self) -> std::io::Result<()> {
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
    fn write(&mut self, plaintext: &[u8]) -> std::io::Result<usize> {
        self.bail_if_errored_before()?;

        // Copy as many bytes as possible into the plaintext buffer.
        let want = CHUNK_LEN - self.plaintext_buf_len;
        let take = std::cmp::min(want, plaintext.len());
        self.plaintext_buf[self.plaintext_buf_len..][..take].copy_from_slice(&plaintext[..take]);
        self.plaintext_buf_len += take;

        // If the plaintext buffer is full, write it out and clear it.
        if self.plaintext_buf_len == CHUNK_LEN {
            self.encrypt_and_write_buf(FinalFlag::NotFinal)?;
        }

        Ok(take)
    }

    fn flush(&mut self) -> std::io::Result<()> {
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
    next_chunk_index: u64,
    plaintext_buf: [u8; CHUNK_LEN],
    plaintext_buf_pos: usize,
    plaintext_buf_end: usize,
    at_eof: bool,
}

impl<R: Read> DecryptReader<R> {
    pub fn new(key: &Key, inner_reader: R) -> Self {
        Self {
            inner_reader,
            long_term_key: *key,
            nonce: None,
            next_chunk_index: 0,
            plaintext_buf: [0; CHUNK_LEN],
            plaintext_buf_pos: 0,
            plaintext_buf_end: 0,
            at_eof: false,
        }
    }

    pub fn into_inner(self) -> R {
        self.inner_reader
    }

    fn get_nonce(&mut self) -> std::io::Result<Nonce> {
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
}

// Try to fill `buf`, potentially with multiple reads, but return early if we encounter EOF. Retry
// and ErrorKind::Interrupted errors.
fn read_exact_or_eof(reader: &mut impl Read, mut buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total_read = 0;
    while !buf.is_empty() {
        match reader.read(&mut buf) {
            Ok(n) => {
                total_read += n;
                if n == 0 {
                    // EOF
                    break;
                }
                buf = &mut buf[n..];
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
        }
    }
    Ok(total_read)
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let nonce = self.get_nonce()?;

        // If the plaintext buffer is empty, and we're not at EOF, read and decrypt another chunk.
        if !self.at_eof && self.plaintext_buf_pos == self.plaintext_buf_end {
            self.plaintext_buf_pos = 0;
            self.plaintext_buf_end = 0;
            let mut ciphertext_array = [0; CHUNK_LEN + TAG_LEN];
            let len = read_exact_or_eof(&mut self.inner_reader, &mut ciphertext_array)?;
            let ciphertext_slice = &ciphertext_array[..len];
            let plaintext_slice = &mut self.plaintext_buf[..len - TAG_LEN];
            let final_flag = if plaintext_slice.len() == CHUNK_LEN {
                FinalFlag::NotFinal
            } else {
                FinalFlag::Final
            };
            decrypt_chunk(
                &self.long_term_key,
                &nonce,
                self.next_chunk_index,
                final_flag,
                ciphertext_slice,
                plaintext_slice,
            )?;
            self.next_chunk_index += 1;
            self.plaintext_buf_end = plaintext_slice.len();
            if let FinalFlag::Final = final_flag {
                self.at_eof = true;
            }
        }

        // Copy as many bytes as possible into the caller's buffer.
        let available = self.plaintext_buf_end - self.plaintext_buf_pos;
        let take = std::cmp::min(buf.len(), available);
        buf[..take].copy_from_slice(&self.plaintext_buf[self.plaintext_buf_pos..][..take]);
        self.plaintext_buf_pos += take;

        Ok(take)
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

    #[test]
    fn test_round_trip() {
        let mut key = [0; KEY_LEN];
        paint_input(&mut key);

        for &size in INPUT_SIZES {
            let mut input = vec![0; size];
            paint_input(&mut input);

            let ciphertext = encrypt(&key, &input);
            assert_eq!(decrypt(&key, &ciphertext).unwrap(), input);
        }
    }

    #[test]
    fn test_big_and_small_encryption_writes() {
        let mut key = [0; KEY_LEN];
        paint_input(&mut key);

        for &size in INPUT_SIZES {
            dbg!(size);
            let mut input = vec![0; size];
            paint_input(&mut input);

            let mut all_at_once_writer = EncryptWriter::new(&key, Vec::new());

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
            assert_eq!(decrypt(&key, &all_at_once_ciphertext).unwrap(), input);
        }
    }

    #[test]
    fn test_big_and_small_decryption_reads() {
        let mut key = [0; KEY_LEN];
        paint_input(&mut key);

        for &size in INPUT_SIZES {
            dbg!(size);
            let mut input = vec![0; size];
            paint_input(&mut input);
            let ciphertext = encrypt(&key, &input);

            let mut all_at_once_reader = DecryptReader::new(&key, &ciphertext[..]);

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
}
