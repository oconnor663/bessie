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
        .arg(
            clap::Arg::with_name(HEX_ARG)
                .long(HEX_ARG)
                .help("either encrypt to hex, or decrypt from hex"),
        )
        .arg(
            clap::Arg::with_name(ZERO_KEY_ARG)
                .long(ZERO_KEY_ARG)
                .short("z"),
        )
        .get_matches()
}

struct HexWriter<W> {
    inner_writer: W,
}

impl<W: Write> Write for HexWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Quick and dirty. A more serious implementation would avoid heap allocation entirely.
        self.inner_writer.write_all(hex::encode(buf).as_bytes())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner_writer.flush()
    }
}

struct HexReader<R> {
    inner_reader: R,
}

impl<R: Read> Read for HexReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Quick and dirty. A more serious implementation would avoid heap allocation entirely.
        let hex_buf_size = std::cmp::min(65536, buf.len().checked_mul(2).unwrap());
        let mut hex_buf = Vec::with_capacity(hex_buf_size);
        self.inner_reader
            .by_ref()
            .take(hex_buf_size as u64)
            .read_to_end(&mut hex_buf)?;
        debug_assert_eq!(hex_buf.capacity(), hex_buf_size);
        // Strip trailing whitespace.
        while hex_buf
            .last()
            .map(|c| c.is_ascii_whitespace())
            .unwrap_or(false)
        {
            hex_buf.pop();
        }
        let decoded = hex::decode(&hex_buf)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid hex"))?;
        buf[..decoded.len()].copy_from_slice(&decoded);
        Ok(decoded.len())
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

    let mut input: &mut dyn Read = &mut stdin.lock();
    let mut output: &mut dyn Write = &mut stdout.lock();

    let mut hex_writer;
    let mut hex_reader;
    if args.is_present(HEX_ARG) {
        if args.is_present(DECRYPT_ARG) {
            hex_reader = HexReader {
                inner_reader: input,
            };
            input = &mut hex_reader;
        } else {
            hex_writer = HexWriter {
                inner_writer: output,
            };
            output = &mut hex_writer;
        }
    }

    if args.is_present(DECRYPT_ARG) {
        decrypt(key_array, input, output);
    } else {
        encrypt(key_array, input, output);
    }

    if args.is_present(HEX_ARG) && !args.is_present(DECRYPT_ARG) {
        println!();
    }
}
