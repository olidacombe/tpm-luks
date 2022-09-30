use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tpm_luks::pcr::parse_pcr_selection_list;
use tss_esapi::structures::PcrSelectionList;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// PCRs to use for sealing/unsealing
    #[arg(short, long, value_name = "PCR List", default_value="sha1:0,1,2,3,4,7", value_parser=parse_pcr_selection_list)]
    pcrs: PcrSelectionList,

    /// TPM device
    #[arg(short, long, value_name = "device", default_value = "/dev/tpmrm0")]
    tpm_dev: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a passphrase, seal in the TPM, and add to a LUKS keyslot
    Seal {
        /// LUKS device name, e.g. `crypt_root`
        #[arg(value_name = "name")]
        luks_dev: String,
    },
    /// Unseal a key from the TPM and use to activate a LUKS device
    Unseal {
        /// LUKS device name, e.g. `crypt_root`
        #[arg(value_name = "name")]
        luks_dev: String,
    },
    /// Show PCR digest for current running system
    Digest,
}

fn main() {
    let cli = Cli::parse();
    dbg!(cli);
}
