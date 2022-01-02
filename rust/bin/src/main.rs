use clap::Parser;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::PathBuf;

#[derive(clap::Parser, Debug)]
#[clap(version, about)]
struct Args {
    #[clap(subcommand)]
    sub: Subcommand,

    #[clap(short, long)]
    help: bool,
}

#[derive(clap::Subcommand, Debug)]
enum Subcommand {
    Encrypt {
        #[clap(flatten)]
        common: CommonSubcommandArgs,
        /// hex-encode the ciphertext after encryption
        #[clap(long, short)]
        hex: bool,
    },
    Decrypt {
        #[clap(flatten)]
        common: CommonSubcommandArgs,
        /// hex-decode the ciphertext before decryption
        #[clap(long, short)]
        hex: bool,
        /// begin output at the given plaintext offset
        #[clap(long)]
        seek: Option<u64>,
    },
}

#[derive(clap::Args, Debug)]
struct CommonSubcommandArgs {
    // positional
    /// the 32-byte key, encoded as hex (or "zero" for 32 null bytes)
    key: String,
    /// the input file (if omitted, stdin is used)
    input: Option<PathBuf>,
    /// the output file (if omitted, stdout is used)
    output: Option<PathBuf>,
}

#[test]
fn test_clap_asserts() {
    <Args as clap::IntoApp>::into_app().debug_assert();
}

enum Input {
    Stdin,
    File(File),
}

impl Read for Input {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::File(file) => file.read(buf),
            Self::Stdin => io::stdin().read(buf),
        }
    }
}

impl Seek for Input {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        match self {
            Self::File(file) => file.seek(pos),
            Self::Stdin => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "stdin cannot seek",
            )),
        }
    }
}

enum Output {
    Stdout,
    File(File),
}

impl Write for Output {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::File(file) => file.write(buf),
            Self::Stdout => io::stdout().write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::File(file) => file.flush(),
            Self::Stdout => io::stdout().flush(),
        }
    }
}

struct HexWriter<W> {
    inner_writer: W,
}

impl<W> HexWriter<W> {
    fn new(inner_writer: W) -> Self {
        Self { inner_writer }
    }
}

impl<W: Write> Write for HexWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Quick and dirty. A more serious implementation would avoid heap allocation entirely.
        self.inner_writer.write_all(hex::encode(buf).as_bytes())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner_writer.flush()
    }
}

struct HexReader<R> {
    inner_reader: R,
}

impl<R> HexReader<R> {
    fn new(inner_reader: R) -> Self {
        Self { inner_reader }
    }
}

impl<R: Read> Read for HexReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Quick and dirty. A more serious implementation would avoid heap allocation entirely.
        let hex_buf_size = std::cmp::min(65536, buf.len().checked_mul(2).unwrap());
        let mut hex_buf = Vec::with_capacity(hex_buf_size);
        self.inner_reader
            .by_ref()
            .take(hex_buf_size as u64)
            .read_to_end(&mut hex_buf)?;
        debug_assert_eq!(hex_buf.capacity(), hex_buf_size);
        let decoded = hex::decode(&hex_buf)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid hex"))?;
        buf[..decoded.len()].copy_from_slice(&decoded);
        Ok(decoded.len())
    }
}

impl<R: Read + Seek> Seek for HexReader<R> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let target = match pos {
            io::SeekFrom::Start(n) => self
                .inner_reader
                .seek(io::SeekFrom::Start(n.checked_mul(2).expect("overflow")))?,
            io::SeekFrom::Current(n) => self
                .inner_reader
                .seek(io::SeekFrom::Current(n.checked_mul(2).expect("overflow")))?,
            io::SeekFrom::End(n) => self
                .inner_reader
                .seek(io::SeekFrom::End(n.checked_mul(2).expect("overflow")))?,
        };
        assert_eq!(target % 2, 0, "offsets in hex can't be odd");
        Ok(target / 2)
    }
}

fn encrypt<W: Write>(key: [u8; 32], mut input: Input, mut output: W) {
    let mut encrypter = bessie::EncryptWriter::new(&key, &mut output);
    io::copy(&mut input, &mut encrypter).expect("IO error");
    encrypter.finalize().expect("IO error");
}

fn decrypt<R: Read + Seek>(key: [u8; 32], input: R, mut output: Output, seek: Option<u64>) {
    let mut decrypter = bessie::DecryptReader::new(&key, input);
    if let Some(offset) = seek {
        decrypter
            .seek(io::SeekFrom::Start(offset))
            .expect("seek error");
    }
    let result = io::copy(&mut decrypter, &mut output);
    if let Err(e) = result {
        if e.kind() != io::ErrorKind::BrokenPipe {
            panic!("decryption error: {}", e);
        }
    }
}

fn handle_common_args(common: &CommonSubcommandArgs) -> ([u8; 32], Input, Output) {
    let key_vec = if common.key == "zero" {
        vec![0; 32]
    } else {
        hex::decode(&common.key).expect("invalid hex")
    };
    let key_array: [u8; 32] = key_vec[..].try_into().expect("key must be 32 bytes");
    let input = if let Some(path) = &common.input {
        Input::File(File::open(path).expect("opening input file failed"))
    } else {
        Input::Stdin
    };
    let output = if let Some(path) = &common.output {
        Output::File(File::create(path).expect("creating output file failed"))
    } else {
        Output::Stdout
    };
    (key_array, input, output)
}

fn main() {
    match Args::parse() {
        Args {
            sub: Subcommand::Encrypt { common, hex },
            ..
        } => {
            let (key, input, output) = handle_common_args(&common);
            if hex {
                encrypt(key, input, HexWriter::new(output));
            } else {
                encrypt(key, input, output);
            }
        }
        Args {
            sub: Subcommand::Decrypt { common, hex, seek },
            ..
        } => {
            let (key, input, output) = handle_common_args(&common);
            if hex {
                decrypt(key, HexReader::new(input), output, seek);
            } else {
                decrypt(key, input, output, seek);
            }
        }
    }
}
