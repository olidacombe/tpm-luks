use crate::pcr::parse_pcr_selection_list;
use crate::tpm::get_pcr_digest;
use clap::{Parser, Subcommand};
use eyre::Result;
use std::env;
use tss_esapi::structures::PcrSelectionList;

const TPM_ENV_VAR: &'static str = "TCTI";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// PCRs to use for sealing/unsealing
    #[arg(short, long, value_name = "PCR List", default_value="sha1:0,1,2,3,4,7", value_parser=parse_pcr_selection_list)]
    pcrs: PcrSelectionList,

    /// TPM device specified in TCTI format
    #[arg(short = 'T', long, default_value = "device:/dev/tpmrm0", env = TPM_ENV_VAR)]
    tcti: String,

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

impl Cli {
    pub fn new() -> Self {
        let cli = Cli::parse();
        env::set_var(TPM_ENV_VAR, &cli.tcti);
        cli
    }

    pub fn run(&self) -> Result<&Self> {
        dbg!(self);
        match &self.command {
            Commands::Digest => self.show_pcr_digest()?,
            Commands::Seal { luks_dev } => todo!(),
            Commands::Unseal { luks_dev } => todo!(),
        };
        Ok(self)
    }

    fn show_pcr_digest(&self) -> Result<()> {
        println!("Current PCR Digest: {}", get_pcr_digest(&self.pcrs)?);
        Ok(())
    }
}
