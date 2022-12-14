use crate::luks::{add_key_to_device, open_device};
use crate::pcr::{parse_pcr_selection_list, PcrPolicyOptions};
use crate::tpm::{get_pcr_digests, get_sealed_passphrase, seal_random_passphrase};
use clap::{Parser, Subcommand};
use eyre::{eyre, Result};
use hex;
use serde_yaml;
use std::convert::TryInto;
use std::env;
use std::path::PathBuf;
use tss_esapi::handles::PersistentTpmHandle;
use tss_esapi::structures::{Digest, PcrSelectionList};

const TPM_ENV_VAR: &str = "TCTI";
const DEFAULT_PERSISTENT_HANDLE: &str = "0x81000000";

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

impl Default for Cli {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a passphrase, seal in the TPM, and add to a LUKS keyslot
    Seal {
        /// LUKS device path
        #[arg(value_name = "dev")]
        luks_dev: PathBuf,

        /// PCR digest
        #[arg(short = 'D', long, value_name = "digest", value_parser = digest_from_hex_string)]
        pcr_digest: Option<Digest>,

        /// Storage handle for keeping the LUKS key in the TPM
        #[arg(short = 'H', long, value_name = "handle", value_parser = handle_from_hex_string, default_value = DEFAULT_PERSISTENT_HANDLE)]
        handle: PersistentTpmHandle,
    },
    /// Unseal a key from the TPM and use to open a LUKS device
    Unseal {
        /// LUKS device path
        #[arg(value_name = "dev")]
        luks_dev: PathBuf,

        /// LUKS device name
        #[arg(value_name = "name")]
        luks_dev_name: String,

        /// TPM persistent storage handle from which to retrieve the LUKS key
        #[arg(short = 'H', long, value_name = "handle", value_parser = handle_from_hex_string, default_value = DEFAULT_PERSISTENT_HANDLE)]
        handle: PersistentTpmHandle,
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
        log::debug!("{:#?}", self);
        match &self.command {
            Commands::Digest => self.show_pcr_digest(),
            Commands::Seal {
                luks_dev,
                pcr_digest,
                handle,
            } => self.seal(luks_dev, pcr_digest, *handle),
            Commands::Unseal {
                luks_dev,
                luks_dev_name,
                handle,
            } => self.unseal(luks_dev, luks_dev_name.as_str(), *handle),
        }?;
        Ok(self)
    }

    fn seal(
        &self,
        luks_dev_path: &PathBuf,
        pcr_digest: &Option<Digest>,
        handle: PersistentTpmHandle,
    ) -> Result<()> {
        let opts = PcrPolicyOptions {
            digest: pcr_digest.clone(),
            pcr_selection_list: self.pcrs.clone(),
        };
        let passphrase = seal_random_passphrase(opts, 32, handle)?;
        let prev_key = env::var("PASSPHRASE")
            .ok()
            .and_then(|p| p.as_bytes().try_into().ok());
        add_key_to_device(luks_dev_path, passphrase, prev_key)?;
        Ok(())
    }

    fn unseal(
        &self,
        luks_dev_path: &PathBuf,
        luks_dev_name: &str,
        handle: PersistentTpmHandle,
    ) -> Result<()> {
        let passphrase = get_sealed_passphrase(self.pcrs.clone(), handle)?;
        open_device(luks_dev_path, luks_dev_name, passphrase)?;

        Ok(())
    }

    fn show_pcr_digest(&self) -> Result<()> {
        let digests = get_pcr_digests(&self.pcrs)?;
        println!("{}", serde_yaml::to_string(&digests)?);
        Ok(())
    }
}

fn digest_from_hex_string(s: &str) -> Result<Digest> {
    Ok(Digest::try_from(hex::decode(s)?)?)
}

/// Get a PersistentTpmHandle from a hex string representation
fn handle_from_hex_string(s: &str) -> Result<PersistentTpmHandle> {
    let v = hex::decode(s.to_lowercase().trim_start_matches("0x"))?;
    if v.len() != 4 {
        return Err(eyre!("Persistent handle must be 4 bytes, got `{}`", s));
    }

    // looks like Vec to array APIs are experimental only at the moment
    // so preallocate an array, and copy over
    let mut a: [u8; 4] = [0; 4];
    a.copy_from_slice(v.as_slice());

    Ok(PersistentTpmHandle::new(u32::from_be_bytes(a))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eyre::Result;

    #[test]
    fn happy_handle_from_string() -> Result<()> {
        handle_from_hex_string("81000000")?;
        Ok(())
    }

    #[test]
    fn happy_handle_from_0x_prefix_string() -> Result<()> {
        handle_from_hex_string("0x81000000")?;
        Ok(())
    }
}
