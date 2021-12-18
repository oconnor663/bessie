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

fn bessie_ciphertext_len(plaintext_len: u64) -> Option<u64> {
    let num_chunks = (plaintext_len / CHUNK_LEN as u64) + 1;
    plaintext_len
        .checked_add(NONCE_LEN as u64)?
        .checked_add(num_chunks * TAG_LEN as u64)
}

fn bessie_plaintext_len(ciphertext_len: u64) -> Option<u64> {
    let chunks_len = ciphertext_len.checked_sub(NONCE_LEN as u64)?;
    let num_chunks = (chunks_len / (CHUNK_LEN + TAG_LEN) as u64) + 1;
    chunks_len.checked_sub(num_chunks * TAG_LEN as u64)
}

pub fn bessie_encrypt(key: &Key, plaintext: &[u8]) -> Vec<u8> {
    let ciphertext_len: usize = bessie_ciphertext_len(plaintext.len() as u64)
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

pub fn bessie_decrypt(key: &Key, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let plaintext_len = if let Some(len) = bessie_plaintext_len(ciphertext.len() as u64) {
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
    ];

    fn paint_input(input: &mut [u8]) {
        for i in 0..input.len() {
            // 251 is the largest prime that fits in a byte.
            input[i] = (i % 251) as u8;
        }
    }

    #[test]
    fn test_round_trip() {
        for &size in INPUT_SIZES {
            let mut input = vec![0; size];
            paint_input(&mut input);

            let mut key = [0; KEY_LEN];
            paint_input(&mut key);

            let ciphertext = bessie_encrypt(&key, &input);
            assert_eq!(bessie_decrypt(&key, &ciphertext).unwrap(), input);
        }
    }
}
