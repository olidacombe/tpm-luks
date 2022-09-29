use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// PCRs to use for sealing/unsealing
    #[arg(short, long, value_name = "PCR List")]
    pcrs: Option<String>,

    /// Luks device
    #[arg(short, long, value_name = "device")]
    dev: PathBuf,

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
