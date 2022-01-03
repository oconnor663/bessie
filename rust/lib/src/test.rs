use crate::*;
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

#[test]
fn test_bad_ciphertext() {
    for &size in INPUT_SIZES {
        dbg!(size);
        let input = test_input(size);
        let mut ciphertext = encrypt(&test_key(), &input);
        decrypt(&test_key(), &ciphertext).unwrap();
        // Corrupt a byte of ciphertext. If the input is longer than one chunk, put the
        // corruption in the first byte of the second chunk.
        if size > CHUNK_LEN {
            ciphertext[NONCE_LEN + CHUNK_LEN + TAG_LEN] ^= 1;
        } else {
            ciphertext[0] ^= 1;
        }
        decrypt(&test_key(), &ciphertext).unwrap_err();

        // Test the incremental decrypter.
        let mut reader = DecryptReader::new(&test_key(), Cursor::new(&ciphertext[..]));
        // If the input is longer than one chunk, confirm that the first chunk decrypts
        // successfully.
        if size > CHUNK_LEN {
            let mut first_chunk = [0; CHUNK_LEN];
            reader.read_exact(&mut first_chunk).unwrap();
        }
        // Fail on the corrupt chunk.
        let e = reader.read(&mut [0]).unwrap_err();
        assert_eq!(io::ErrorKind::InvalidData, e.kind());
        // If the input is longer than two chunks, confirm that seeking past the corrupt chunk
        // makes the rest decrypt successfully.
        if size > 2 * CHUNK_LEN {
            let mut rest = Vec::new();
            reader.seek(SeekFrom::Start(2 * CHUNK_LEN as u64)).unwrap();
            reader.read_to_end(&mut rest).unwrap();
            assert_eq!(&input[2 * CHUNK_LEN..], rest);
        }
    }
}

#[test]
fn test_zeroing_after_decryption_failure() {
    let input = vec![0xaa; 2 * CHUNK_LEN + 1];
    let mut ciphertext = encrypt(&test_key(), &input);
    let mut plaintext = vec![0xbb; 2 * CHUNK_LEN + 1];
    // Decrypt the ciphertext with the wrong key and make sure that the plaintext buffer gets
    // entirely zeroed out.
    decrypt_to_slice(&[0; 32], &ciphertext, &mut plaintext).unwrap_err();
    assert_eq!(plaintext, vec![0; plaintext.len()]);
    // Same but with the right key and a corrupted final byte.
    *ciphertext.last_mut().unwrap() ^= 1;
    let mut plaintext = vec![0xbb; 2 * CHUNK_LEN + 1];
    decrypt_to_slice(&test_key(), &ciphertext, &mut plaintext).unwrap_err();
    assert_eq!(plaintext, vec![0; plaintext.len()]);
}
