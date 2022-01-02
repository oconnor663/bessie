use bessie::CHUNK_LEN;
use duct::cmd;
use std::io::prelude::*;

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

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_bessie")
}

#[test]
fn test_encrypt_decrypt() {
    for &size in INPUT_SIZES {
        dbg!(size);
        let mut input = vec![0; size];
        paint_input(&mut input);
        let keys = [
            "4242424242424242424242424242424242424242424242424242424242424242",
            "zero",
        ];
        for key in keys {
            dbg!(key);
            // Encrypt the input.
            let ciphertext = cmd!(bin_path(), "encrypt", key)
                .stdin_bytes(&input[..])
                .stdout_capture()
                .run()
                .unwrap()
                .stdout;

            // Decrypt the input and compare.
            let plaintext = cmd!(bin_path(), "decrypt", key)
                .stdin_bytes(&ciphertext[..])
                .stdout_capture()
                .run()
                .unwrap()
                .stdout;
            assert_eq!(input, plaintext);

            // Seek halfway through the input and compare again.
            let mut tmp = tempfile::NamedTempFile::new().unwrap();
            tmp.write_all(&ciphertext).unwrap();
            tmp.flush().unwrap();
            let seek_target = size / 2;
            dbg!(seek_target);
            let half_input = &input[seek_target..];
            let half_plaintext = cmd!(
                bin_path(),
                "decrypt",
                key,
                tmp.path().to_str().expect("invalid uft8 tempfile path"),
                "--seek",
                seek_target.to_string(),
            )
            .stdout_capture()
            .run()
            .unwrap()
            .stdout;
            assert_eq!(half_input, half_plaintext);
        }
    }
}

#[test]
fn test_decryption_failure() {
    let mut ciphertext = bessie::encrypt(&[0; 32], b"hello world");
    // Corrupt the last byte of ciphertext.
    *ciphertext.last_mut().unwrap() ^= 1;
    let status = cmd!(bin_path(), "decrypt", "zero")
        .stdin_bytes(ciphertext)
        .stderr_null()
        .stdout_null()
        .unchecked()
        .run()
        .unwrap()
        .status;
    assert!(!status.success());
}
