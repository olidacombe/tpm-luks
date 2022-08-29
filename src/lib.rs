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
use tss_esapi::structures::{Digest, PcrSelectionList, Public, SensitiveData};

#[derive(Error, Debug)]
pub enum TpmError {
    #[error("PCR digest length > 1")]
    PcrDigestLength,
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
    use tss_esapi::structures::{KeyedHashScheme, PublicBuilder, PublicKeyedHashParameters};

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

    /// Returns the digest for a PCR selection list only if it could be computed as a single
    /// value.
    fn pcr_digest(&mut self, pcr_selection_list: &PcrSelectionList) -> Result<Digest> {
        let (_update_counter, _selection_list, digest_list) =
            self.0.pcr_read(pcr_selection_list.clone())?;

        if digest_list.len() > 1 {
            return Err(TpmError::PcrDigestLength);
        }
        digest_list
            .value()
            .get(0)
            .ok_or(TpmError::PcrDigestLength)
            .map(|digest| digest.clone())
    }

    pub fn seal(&mut self, data: SensitiveData) -> Result<()> {
        use tss_esapi::constants::{SessionType, StartupType};
        use tss_esapi::interface_types::{
            algorithm::HashingAlgorithm, session_handles::PolicySession,
        };
        use tss_esapi::structures::pcr_selection_list::PcrSelectionList;
        use tss_esapi::structures::pcr_slot::PcrSlot;
        use tss_esapi::structures::SymmetricDefinition;

        // TODO expose seal method only on a type which is retrieved
        // only by clearing - all that kind of good stuff
        self.0.startup(StartupType::Clear).unwrap();

        let key = pubkey()?;

        let selections = PcrSelectionList::builder()
            //.with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0])
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot7])
            .build()?;

        let digest = self.pcr_digest(&selections)?;

        // todo authed type that flushes on destruct?
        let session = self
            .0
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )?
            .expect("Received invalid handle");
        //.try_into()?;

        self.0
            .policy_pcr(session.try_into()?, digest, selections.clone())?;

        self.0.execute_with_session(Some(session), |ctx| {
            ctx.create(
                *AUTOMATION_KEY_HANDLE,
                key,
                None,
                Some(data),
                None,
                Some(selections.clone()),
            )
            .expect("Failed to seal data");
        });

        // TODO some kind of unconditional `finally` behavior
        self.0.clear_sessions();

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

        let data = SensitiveData::try_from("Hello".as_bytes().to_vec())
            .expect("Failed to create dummy sensitive buffer");

        context.seal(data)?;

        Ok(())
    }
}
