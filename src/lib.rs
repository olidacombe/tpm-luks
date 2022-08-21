//! # Get Started
//!
//! ## On Linux with hardware TPM:
//! ```bash
//! make dev-local
//! ```
//!
//! ## On something else, e.g. Mac:
//! ```bash
//! make dev
//! ```

use once_cell::sync::Lazy;
use std::sync::{Mutex, MutexGuard};
use thiserror::Error;
use tss_esapi::structures::Public;

#[derive(Error, Debug)]
pub enum TpmError {
    #[error(transparent)]
    TssEsapi(#[from] tss_esapi::Error),
}

pub type Result<T, E = TpmError> = core::result::Result<T, E>;

pub struct Context(MutexGuard<'static, tss_esapi::Context>);

static AUTOMATION_KEY_HANDLE: Lazy<tss_esapi::handles::KeyHandle> = Lazy::new(|| 0x81010001.into());

static PCR_SELECTION_LIST: Lazy<tss_esapi::structures::pcr_selection_list::PcrSelectionList> =
    Lazy::new(|| {
        use tss_esapi::interface_types::algorithm::HashingAlgorithm;
        use tss_esapi::structures::pcr_slot::PcrSlot;
        tss_esapi::structures::pcr_selection_list::PcrSelectionList::builder()
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0, PcrSlot::Slot7])
            .build()
            .unwrap()
    });

static CONTEXT: Lazy<Mutex<tss_esapi::Context>> = Lazy::new(|| {
    use tss_esapi::tcti_ldr::TctiNameConf;

    let context =
        tss_esapi::Context::new(TctiNameConf::from_environment_variable().unwrap()).unwrap();
    Mutex::new(context)
});

fn pubkey() -> Result<Public> {
    use tss_esapi::attributes::ObjectAttributesBuilder;
    use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
    use tss_esapi::structures::{
        Digest, KeyedHashScheme, PublicBuilder, PublicKeyedHashParameters,
    };

    let object_attributes = ObjectAttributesBuilder::new()
        .with_sign_encrypt(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .build()?;
    Ok(PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
            KeyedHashScheme::HMAC_SHA_256,
        ))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()?)
}

impl Context {
    pub fn new() -> Self {
        Self(CONTEXT.lock().unwrap())
    }

    pub fn revision(&mut self) -> Result<Option<u32>> {
        use tss_esapi::constants::property_tag::PropertyTag;

        Ok(self.0.get_tpm_property(PropertyTag::Revision)?)
    }

    pub fn seal(&mut self) -> Result<()> {
        use tss_esapi::constants::{SessionType, StartupType};
        use tss_esapi::interface_types::{
            algorithm::HashingAlgorithm, session_handles::PolicySession,
        };
        use tss_esapi::structures::SymmetricDefinition;

        self.0.startup(StartupType::Clear).unwrap();

        let key = pubkey()?;

        let session: PolicySession = self
            .0
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Policy,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )?
            .expect("Received invalid handle")
            .try_into()?;

        // TODO
        //self.0.policy_pcr(session, , *PCR_SELECTION_LIST)?;
        //self.0
        //.create(*AUTOMATION_KEY_HANDLE, key, None, None, None, None)?;

        Ok(())
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eyre::Result;

    //#[test]
    //fn list_nvs() -> Result<()> {
    //use tss_esapi::abstraction::nv::list;
    //let mut context = Context::new();
    //let nvs = list(&mut context)?;
    //for (_, name) in nvs {
    //if let Ok(s) = std::str::from_utf8(name.value()) {
    //dbg!(s);
    //}
    //}
    //Ok(())
    //}

    #[test]
    fn get_revision() -> Result<()> {
        let mut context = Context::new();
        let revision = context.revision()?;
        assert!(revision.is_some());

        Ok(())
    }

    //https://tpm2-software.github.io/2020/04/13/Disk-Encryption.html#pcr-policy-authentication---access-control-of-sealed-pass-phrase-on-tpm2-with-pcr-sealing
    #[test]
    fn seal() -> Result<()> {
        let mut context = Context::new();

        context.seal()?;

        Ok(())
    }
}
