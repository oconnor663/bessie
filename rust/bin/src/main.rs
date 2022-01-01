use clap::Parser;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

#[derive(clap::Parser, Debug)]
#[clap(version, about)]
struct Args {
    #[clap(subcommand)]
    subcommand: Subcommand,

    #[clap(short, long)]
    help: bool,
}

#[derive(clap::Subcommand, Debug)]
enum Subcommand {
    Encrypt(SubcommandArgs),
    Decrypt(SubcommandArgs),
}

#[derive(clap::Args, Debug)]
struct SubcommandArgs {
    // positional
    /// the 32-byte key, encoded as hex (or "zero" for 32 null bytes)
    key: String,
    /// the input file (if omitted, stdin is used; if provided, output is also required)
    #[clap(requires = "output")]
    input: Option<PathBuf>,
    /// the output file (if omitted, stdout is used)
    output: Option<PathBuf>,

    // flags
    /// hex-encode after encryption, or hex-decode before decryption
    #[clap(long, short)]
    hex: bool,
}

#[test]
fn test_clap_asserts() {
    <Args as clap::IntoApp>::into_app().debug_assert();
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
    let args = Args::parse();

    let is_encrypt = matches!(args.subcommand, Subcommand::Encrypt(_));
    let subcommand_args = match &args.subcommand {
        Subcommand::Encrypt(a) => a,
        Subcommand::Decrypt(a) => a,
    };

    let key_vec = if subcommand_args.key == "zero" {
        vec![0; 32]
    } else {
        hex::decode(&subcommand_args.key).expect("invalid hex")
    };
    let key_array: &[u8; 32] = key_vec[..].try_into().expect("key must be 32 bytes");

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input: &mut dyn Read = &mut stdin.lock();
    let mut output: &mut dyn Write = &mut stdout.lock();

    let mut input_file;
    if let Some(path) = &subcommand_args.input {
        input_file = File::open(path).expect("opening input failed");
        input = &mut input_file;
    }

    let mut output_file;
    if let Some(path) = &subcommand_args.output {
        output_file = File::create(path).expect("creating output file failed");
        output = &mut output_file;
    }

    let mut hex_writer;
    let mut hex_reader;
    if subcommand_args.hex {
        if is_encrypt {
            hex_writer = HexWriter {
                inner_writer: output,
            };
            output = &mut hex_writer;
        } else {
            hex_reader = HexReader {
                inner_reader: input,
            };
            input = &mut hex_reader;
        }
    }

    if is_encrypt {
        encrypt(key_array, input, output);
    } else {
        decrypt(key_array, input, output);
    }

    if subcommand_args.hex && is_encrypt {
        println!();
    }
}
