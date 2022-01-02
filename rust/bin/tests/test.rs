use bessie::CHUNK_LEN;
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

fn bessie_cmd(args: &[&str], input: &[u8]) -> Vec<u8> {
    duct::cmd(env!("CARGO_BIN_EXE_bessie"), args)
        .stdin_bytes(input)
        .stdout_capture()
        .run()
        .expect("command failed")
        .stdout
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
            for use_hex in [true, false] {
                dbg!(use_hex);

                // Encrypt the input.
                let mut encrypt_args = vec!["encrypt", key];
                if use_hex {
                    encrypt_args.push("--hex");
                }
                let ciphertext = bessie_cmd(&encrypt_args, &input);

                // Decrypt the input and compare.
                let mut decrypt_args = vec!["decrypt", key];
                if use_hex {
                    decrypt_args.push("--hex");
                }
                let plaintext = bessie_cmd(&decrypt_args, &ciphertext);
                assert_eq!(input, plaintext);

                // Seek halfway through the input and compare again.
                let mut tmp = tempfile::NamedTempFile::new().unwrap();
                tmp.write_all(&ciphertext).unwrap();
                tmp.flush().unwrap();
                let seek_target = size / 2;
                dbg!(seek_target);
                let half_input = &input[seek_target..];
                let mut seek_args = decrypt_args.clone();
                let seek_flag = format!("--seek={}", seek_target);
                seek_args.push(&seek_flag);
                let path_string = tmp.path().to_str().expect("invalid uft8 tempfile path");
                seek_args.push(&path_string);
                let half_plaintext = bessie_cmd(&seek_args, &ciphertext);
                assert_eq!(half_input, half_plaintext);
            }
        }
    }
}
