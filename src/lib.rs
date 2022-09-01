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

use delegate::delegate;
use once_cell::sync::Lazy;
use std::sync::{Mutex, MutexGuard};
use thiserror::Error;
use tss_esapi::constants::SessionType;
use tss_esapi::constants::StartupType;
use tss_esapi::handles::KeyHandle;
use tss_esapi::handles::ObjectHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::{AuthSession, HmacSession, PolicySession};
use tss_esapi::structures::DigestList;
use tss_esapi::structures::Nonce;
use tss_esapi::structures::SymmetricDefinition;
use tss_esapi::structures::{
    Auth, CreatePrimaryKeyResult, Data, Digest, PcrSelectionList, Public, SensitiveData,
};

#[derive(Error, Debug)]
pub enum TpmError {
    #[error("PCR digest length > 1")]
    PcrDigestLength,
    #[error(transparent)]
    TssEsapi(#[from] tss_esapi::Error),
}

pub type Result<T, E = TpmError> = core::result::Result<T, E>;

pub struct Context(MutexGuard<'static, tss_esapi::Context>);
pub struct OwnedContext {
    ctx: Context,
    key: KeyHandle,
    public: Public,
    hmac_session: HmacSession,
}
pub struct PcrPolicyContext {
    ctx: OwnedContext,
    policy_session: PolicySession,
}

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
    delegate! {
        to self.0 {
            fn clear_sessions(&mut self);
            fn create_primary(
                &mut self,
                primary_handle: Hierarchy,
                public: Public,
                auth_value: Option<Auth>,
                initial_data: Option<SensitiveData>,
                outside_info: Option<Data>,
                creation_pcrs: Option<PcrSelectionList>
            ) -> tss_esapi::Result<CreatePrimaryKeyResult>;
            fn execute_with_session<F, T>(
                &mut self,
                session_handle: Option<AuthSession>,
                f: F
            ) -> T
            where
                F: FnOnce(&mut tss_esapi::Context) -> T;
            fn pcr_read(
                &mut self,
                pcr_selection_list: PcrSelectionList
            ) -> tss_esapi::Result<(u32, PcrSelectionList, DigestList)>;
            fn get_random(&mut self, num_bytes: usize) -> tss_esapi::Result<Digest>;
            fn startup(&mut self, startup_type: StartupType) -> tss_esapi::Result<()>;
            fn start_auth_session(
                &mut self,
                tpm_key: Option<KeyHandle>,
                bind: Option<ObjectHandle>,
                nonce: Option<Nonce>,
                session_type: SessionType,
                symmetric: SymmetricDefinition,
                auth_hash: HashingAlgorithm
            ) -> tss_esapi::Result<Option<AuthSession>>;
        }
    }
    pub fn new() -> Self {
        let mut context = CONTEXT.lock().unwrap();
        context.clear_sessions();
        Self(context)
    }

    pub fn own(mut self) -> Result<OwnedContext> {
        use tss_esapi::attributes::SessionAttributesBuilder;
        use tss_esapi::constants::{SessionType, StartupType};
        use tss_esapi::handles::KeyHandle;
        use tss_esapi::interface_types::algorithm::RsaSchemeAlgorithm;
        use tss_esapi::interface_types::key_bits::RsaKeyBits;
        use tss_esapi::interface_types::{
            algorithm::HashingAlgorithm, resource_handles::Hierarchy,
            session_handles::PolicySession,
        };
        use tss_esapi::structures::pcr_selection_list::PcrSelectionList;
        use tss_esapi::structures::pcr_slot::PcrSlot;
        use tss_esapi::structures::RsaExponent;
        use tss_esapi::structures::RsaScheme;
        use tss_esapi::structures::{Auth, SymmetricDefinition};
        use tss_esapi::utils::create_unrestricted_signing_rsa_public;

        self.startup(StartupType::Clear)?;
        self.clear_sessions();

        let session = self
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )?
            .expect("Received invalid handle");

        // Create public area for a rsa key
        let public_area = create_unrestricted_signing_rsa_public(
            RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
                .expect("Failed to create RSA scheme"),
            RsaKeyBits::Rsa2048,
            RsaExponent::default(),
        )
        .expect("Failed to create rsa public area");

        // Configure session attributes
        let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();

        let random_digest = self.get_random(16).expect("Call to get_random failed");
        let key_auth =
            Auth::try_from(random_digest.value().to_vec()).expect("Failed to create Auth");

        let CreatePrimaryKeyResult {
            key_handle: key,
            out_public: public,
            ..
        } = self.execute_with_session(Some(session), |ctx| {
            ctx.create_primary(Hierarchy::Owner, public_area, None, None, None, None)
                .expect("Failed to create primary")
        });

        Ok(OwnedContext {
            ctx: self,
            key,
            public,
            hmac_session: session.try_into()?,
        })
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
        use tss_esapi::attributes::SessionAttributesBuilder;
        use tss_esapi::constants::{SessionType, StartupType};
        use tss_esapi::handles::KeyHandle;
        use tss_esapi::interface_types::algorithm::RsaSchemeAlgorithm;
        use tss_esapi::interface_types::key_bits::RsaKeyBits;
        use tss_esapi::interface_types::{
            algorithm::HashingAlgorithm, resource_handles::Hierarchy,
            session_handles::PolicySession,
        };
        use tss_esapi::structures::pcr_slot::PcrSlot;
        use tss_esapi::structures::RsaExponent;
        use tss_esapi::structures::RsaScheme;
        use tss_esapi::structures::{Auth, SymmetricDefinition};
        use tss_esapi::utils::create_unrestricted_signing_rsa_public;

        // TODO expose seal method only on a type which is retrieved
        // only by clearing - all that kind of good stuff
        self.startup(StartupType::Clear).unwrap();

        //let public = pubkey()?;
        // Create public area for a rsa key
        let public_area = create_unrestricted_signing_rsa_public(
            RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
                .expect("Failed to create RSA scheme"),
            RsaKeyBits::Rsa2048,
            RsaExponent::default(),
        )
        .expect("Failed to create rsa public area");

        let selections = PcrSelectionList::builder()
            //.with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0])
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot7])
            .build()?;

        let digest = self.pcr_digest(&selections)?;
        let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();
        // todo authed type that flushes on destruct?
        let hmac_session = self
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )?
            .expect("Received invalid handle");
        let policy_session = self
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Policy,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )?
            .expect("Received invalid handle");
        //.try_into()?;
        //self.0
        //.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
        //.expect("Failed to set attributes on session");

        //self.0
        //.policy_pcr(session.try_into()?, digest, selections.clone())?;

        let random_digest = self.get_random(16).expect("Call to get_random failed");
        let key_auth =
            Auth::try_from(random_digest.value().to_vec()).expect("Failed to create Auth");

        self.execute_with_session(Some(hmac_session), |ctx| {
            // TODO wrap in OwnedContext type which can only be created from a Context.take_ownership method!!!
            let primary = ctx
                .create_primary(
                    Hierarchy::Owner,
                    public_area,
                    /*Some(key_auth),*/ None,
                    None,
                    None,
                    None,
                )
                .expect("Failed to create primary");
            // end TODO
            //ctx.create(
            //primary.key_handle,
            //primary.out_public,
            //None,
            //Some(data),
            //None,
            //Some(selections.clone()),
            //)
            //.expect("Failed to seal data");
        });

        // TODO some kind of unconditional `finally` behavior
        self.clear_sessions();

        Ok(())
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        self.0.clear_sessions();
    }
}

pub struct PcrPolicyOptions {
    digest: Option<Digest>,
    pcr_list: PcrSelectionList,
}

impl PcrPolicyOptions {
    pub fn with_digest(mut self, digest: Digest) -> Self {
        self.digest = Some(digest);
        self
    }
}

impl Default for PcrPolicyOptions {
    fn default() -> Self {
        use tss_esapi::structures::pcr_slot::PcrSlot;
        let pcr_list = PcrSelectionList::builder()
            //.with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0])
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot7])
            .build()
            .unwrap();
        Self {
            digest: None,
            pcr_list,
        }
    }
}

impl OwnedContext {
    pub fn seal(&mut self, data: SensitiveData) -> Result<()> {
        Ok(())
    }
    pub fn policy(mut self, options: PcrPolicyOptions) -> Result<PcrPolicyContext> {
        let policy_session = self
            .ctx
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
        Ok(PcrPolicyContext {
            ctx: self,
            policy_session,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eyre::Result;

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
        let data = SensitiveData::try_from("Hello".as_bytes().to_vec())
            .expect("Failed to create dummy sensitive buffer");

        let context = Context::new().own()?.policy(PcrPolicyOptions::default())?;

        Ok(())
    }
}
