use clap::{value_parser, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Clone)]
struct Wolf {
    name: String,
}

impl From<&str> for Wolf {
    fn from(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// PCRs to use for sealing/unsealing
    #[arg(short, long, value_name = "PCR List")]
    pcrs: Option<String>,

    /// Wolf
    #[arg(short, default_value="Wolfy", value_parser=value_parser!(Wolf))]
    wolf: Wolf,

    /// Luks device
    #[arg(short = 'L', long, value_name = "device")]
    luks_dev: PathBuf,

    /// TPM device
    #[arg(short, long, value_name = "device", default_value = "/dev/tpmrm0")]
    tpm_dev: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a passphrase, seal in the TPM, and add to a LUKS keyslot
    Seal,
    /// Unseal a key from the TPM and use to activate a LUKS device
    Unseal,
    /// Show PCR digest for current running system
    Digest,
}

fn main() {
    let cli = Cli::parse();
    dbg!(cli);
}
