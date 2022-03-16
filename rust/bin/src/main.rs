use clap::Parser;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::PathBuf;

#[derive(clap::Parser, Debug)]
#[clap(name(env!("CARGO_BIN_NAME")), version, about)]
struct Args {
    #[clap(subcommand)]
    sub: Subcommand,
}

#[derive(clap::Subcommand, Debug)]
enum Subcommand {
    Encrypt {
        #[clap(flatten)]
        common: CommonSubcommandArgs,
    },
    Decrypt {
        #[clap(flatten)]
        common: CommonSubcommandArgs,
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
    <Args as clap::CommandFactory>::command().debug_assert();
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

fn encrypt(key: [u8; 32], mut input: Input, mut output: Output) -> anyhow::Result<()> {
    let mut encrypter = bessie::EncryptWriter::new(&key, &mut output);
    io::copy(&mut input, &mut encrypter)?;
    encrypter.finalize()?;
    Ok(())
}

fn decrypt(
    key: [u8; 32],
    mut input: Input,
    mut output: Output,
    seek: Option<u64>,
) -> anyhow::Result<()> {
    let mut decrypter = bessie::DecryptReader::new(&key, &mut input);
    if let Some(offset) = seek {
        decrypter.seek(io::SeekFrom::Start(offset))?;
    }
    let result = io::copy(&mut decrypter, &mut output);
    if let Err(e) = result {
        if e.kind() != io::ErrorKind::BrokenPipe {
            anyhow::bail!("decryption error: {}", e);
        }
    }
    Ok(())
}

fn handle_common_args(common: &CommonSubcommandArgs) -> anyhow::Result<([u8; 32], Input, Output)> {
    let key_vec = if common.key == "zero" {
        vec![0; 32]
    } else {
        hex::decode(&common.key)?
    };
    let key_array: [u8; 32] = key_vec[..].try_into()?;
    let input = if let Some(path) = &common.input {
        Input::File(File::open(path)?)
    } else {
        Input::Stdin
    };
    let output = if let Some(path) = &common.output {
        Output::File(File::create(path)?)
    } else {
        Output::Stdout
    };
    Ok((key_array, input, output))
}

fn main() -> anyhow::Result<()> {
    match Args::parse() {
        Args {
            sub: Subcommand::Encrypt { common },
            ..
        } => {
            let (key, input, output) = handle_common_args(&common)?;
            encrypt(key, input, output)?;
        }
        Args {
            sub: Subcommand::Decrypt { common, seek },
            ..
        } => {
            let (key, input, output) = handle_common_args(&common)?;
            decrypt(key, input, output, seek)?;
        }
    }
    Ok(())
}
