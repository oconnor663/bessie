#![feature(test)]

extern crate test;

use rand::prelude::*;
use test::Bencher;

const KIB: usize = 1024;
const MIB: usize = 1024 * 1024;

// This struct randomizes two things:
// 1. The actual bytes of input.
// 2. The page offset the input starts at.
pub struct RandomInput {
    buf: Vec<u8>,
    len: usize,
    offsets: Vec<usize>,
    offset_index: usize,
}

impl RandomInput {
    pub fn new(b: &mut Bencher, len: usize) -> Self {
        b.bytes += len as u64;
        let page_size: usize = page_size::get();
        let mut buf = vec![0u8; len + page_size];
        let mut rng = rand::rng();
        rng.fill_bytes(&mut buf);
        let mut offsets: Vec<usize> = (0..page_size).collect();
        offsets.shuffle(&mut rng);
        Self {
            buf,
            len,
            offsets,
            offset_index: 0,
        }
    }

    pub fn get(&mut self) -> &[u8] {
        let offset = self.offsets[self.offset_index];
        self.offset_index += 1;
        if self.offset_index >= self.offsets.len() {
            self.offset_index = 0;
        }
        &self.buf[offset..][..self.len]
    }
}

fn bench_encrypt(b: &mut Bencher, size: usize) {
    let mut r = RandomInput::new(b, size);
    let key: [u8; 32] = rand::random();
    b.iter(|| bessie::encrypt(&key, r.get()));
}

#[bench]
fn bench_encrypt_bytes_01(b: &mut Bencher) {
    bench_encrypt(b, 1);
}

#[bench]
fn bench_encrypt_bytes_64(b: &mut Bencher) {
    bench_encrypt(b, 64);
}

#[bench]
fn bench_encrypt_kib_01(b: &mut Bencher) {
    bench_encrypt(b, KIB);
}

#[bench]
fn bench_encrypt_kib_16(b: &mut Bencher) {
    bench_encrypt(b, 16 * KIB);
}

#[bench]
fn bench_encrypt_mib_1(b: &mut Bencher) {
    bench_encrypt(b, MIB);
}

fn bench_decrypt(b: &mut Bencher, size: usize) {
    let mut r = RandomInput::new(b, size);
    let key: [u8; 32] = rand::random();
    let ciphertext = bessie::encrypt(&key, r.get());
    b.iter(|| bessie::decrypt(&key, &ciphertext));
}

#[bench]
fn bench_decrypt_bytes_01(b: &mut Bencher) {
    bench_decrypt(b, 1);
}

#[bench]
fn bench_decrypt_bytes_64(b: &mut Bencher) {
    bench_decrypt(b, 64);
}

#[bench]
fn bench_decrypt_kib_01(b: &mut Bencher) {
    bench_decrypt(b, KIB);
}

#[bench]
fn bench_decrypt_kib_16(b: &mut Bencher) {
    bench_decrypt(b, 16 * KIB);
}

#[bench]
fn bench_decrypt_mib_1(b: &mut Bencher) {
    bench_decrypt(b, MIB);
}
