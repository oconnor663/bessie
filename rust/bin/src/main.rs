use std::io::prelude::*;

const KEY_ARG: &str = "key";

const DECRYPT_ARG: &str = "decrypt";
const HEX_ARG: &str = "hex";
const ZERO_KEY_ARG: &str = "zero-key";

fn parse_args() -> clap::ArgMatches<'static> {
    clap::App::new("bessie")
        .version(env!("CARGO_PKG_VERSION"))
        .arg(clap::Arg::with_name(KEY_ARG).required_unless(ZERO_KEY_ARG))
        .arg(
            clap::Arg::with_name(DECRYPT_ARG)
                .long(DECRYPT_ARG)
                .short("d"),
        )
        .arg(clap::Arg::with_name(HEX_ARG).long(HEX_ARG))
        .arg(clap::Arg::with_name(ZERO_KEY_ARG).long(ZERO_KEY_ARG))
        .get_matches()
}

struct HexWriter<W> {
    inner_writer: W,
}

impl<W: Write> Write for HexWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner_writer.write_all(hex::encode(buf).as_bytes())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner_writer.flush()
    }
}

fn encrypt(key: &[u8; 32], input: &mut dyn Read, output: &mut dyn Write) {
    let mut encrypter = bessie::EncryptWriter::new(key, output);
    std::io::copy(input, &mut encrypter).expect("IO error");
    encrypter.finalize().expect("IO error");
}

fn decrypt(key: &[u8; 32], input: &mut dyn Read, output: &mut dyn Write) {
    let mut decrypter = bessie::DecryptReader::new(key, input);
    std::io::copy(&mut decrypter, output).expect("decryption error");
}

fn main() {
    let args = parse_args();

    let key_vec = if args.is_present(ZERO_KEY_ARG) {
        vec![0; 32]
    } else {
        hex::decode(args.value_of(KEY_ARG).unwrap()).expect("invalid hex")
    };
    let key_array: &[u8; 32] = key_vec[..].try_into().expect("key must be 32 bytes");

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();

    let input: &mut dyn Read = &mut stdin.lock();
    let mut output: &mut dyn Write = &mut stdout.lock();

    let mut hexer;
    if args.is_present(HEX_ARG) {
        hexer = HexWriter {
            inner_writer: output,
        };
        output = &mut hexer;
    }

    if args.is_present(DECRYPT_ARG) {
        decrypt(key_array, input, output);
    } else {
        encrypt(key_array, input, output);
    }

    if args.is_present(HEX_ARG) {
        println!();
    }
}
