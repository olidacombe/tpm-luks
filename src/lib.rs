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
use tss_esapi::attributes::{SessionAttributes, SessionAttributesBuilder, SessionAttributesMask};
use tss_esapi::constants::{SessionType, StartupType};
use tss_esapi::handles::{KeyHandle, ObjectHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, RsaSchemeAlgorithm};
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::{AuthSession, HmacSession, PolicySession};
use tss_esapi::structures::{
    CreatePrimaryKeyResult, Digest, MaxBuffer, Nonce, PcrSelectionList, Public, RsaExponent,
    RsaScheme, SymmetricDefinition,
};
use tss_esapi::utils::create_unrestricted_signing_rsa_public;

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

impl Context {
    delegate! {
        to self.0 {
            fn clear_sessions(&mut self);
            fn execute_without_session<F, T>(&mut self, f: F) -> T
            where
                F: FnOnce(&mut tss_esapi::Context) -> T;
            fn execute_with_session<F, T>(
                &mut self,
                session_handle: Option<AuthSession>,
                f: F
            ) -> T
            where
                F: FnOnce(&mut tss_esapi::Context) -> T;
            fn policy_pcr(
                &mut self,
                policy_session: PolicySession,
                pcr_policy_digest: Digest,
                pcr_selection_list: PcrSelectionList
            ) -> tss_esapi::Result<()>;
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
            fn tr_sess_set_attributes(
                &mut self,
                session: AuthSession,
                attributes: SessionAttributes,
                mask: SessionAttributesMask
            ) -> tss_esapi::Result<()>;
        }
    }
    pub fn new() -> Self {
        let mut context = CONTEXT.lock().unwrap();
        context.clear_sessions();
        Self(context)
    }

    pub fn own(mut self) -> Result<OwnedContext> {
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
        self.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)?;

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

    /// Returns the digest for a PCR selection list
    fn pcr_digest(&mut self, pcr_selection_list: &PcrSelectionList) -> Result<Digest> {
        let (_update_counter, _selection_list, digest_list) =
            self.execute_without_session(|ctx| ctx.pcr_read(pcr_selection_list.clone()))?;

        let concatenated_pcr_digests = digest_list
            .value()
            .iter()
            .map(|x| x.value())
            .collect::<Vec<&[u8]>>()
            .concat();
        let concatenated_pcr_digests = MaxBuffer::try_from(concatenated_pcr_digests)?;

        let (digest, _ticket) = self.execute_without_session(|ctx| {
            ctx.hash(
                concatenated_pcr_digests,
                HashingAlgorithm::Sha256,
                Hierarchy::Owner,
            )
        })?;

        Ok(digest)
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
    pcr_selection_list: PcrSelectionList,
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
        let pcr_selection_list = PcrSelectionList::builder()
            //.with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0])
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot7])
            .build()
            .unwrap();
        Self {
            digest: None,
            pcr_selection_list,
        }
    }
}

impl OwnedContext {
    delegate! {
        to self.ctx {
            fn pcr_digest(&mut self, pcr_selection_list: &PcrSelectionList) -> Result<Digest>;
            fn policy_pcr(
                &mut self,
                policy_session: PolicySession,
                pcr_policy_digest: Digest,
                pcr_selection_list: PcrSelectionList
            ) -> tss_esapi::Result<()>;
            fn start_auth_session(
                &mut self,
                tpm_key: Option<KeyHandle>,
                bind: Option<ObjectHandle>,
                nonce: Option<Nonce>,
                session_type: SessionType,
                symmetric: SymmetricDefinition,
                auth_hash: HashingAlgorithm
            ) -> tss_esapi::Result<Option<AuthSession>>;
            fn tr_sess_set_attributes(
                &mut self,
                session: AuthSession,
                attributes: SessionAttributes,
                mask: SessionAttributesMask
            ) -> tss_esapi::Result<()>;
        }
    }
    pub fn policy(mut self, options: PcrPolicyOptions) -> Result<PcrPolicyContext> {
        let policy_session: PolicySession = self
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

        let (session_attributes, session_attributes_mask) = SessionAttributes::builder()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();
        self.tr_sess_set_attributes(
            AuthSession::PolicySession(policy_session),
            session_attributes,
            session_attributes_mask,
        )?;

        let PcrPolicyOptions {
            digest,
            pcr_selection_list,
        } = options;

        let digest = match digest {
            Some(digest) => digest,
            None => self.pcr_digest(&pcr_selection_list)?,
        };

        self.policy_pcr(policy_session, digest, pcr_selection_list)?;

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
    use tss_esapi::structures::SensitiveData;

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
        let _data = SensitiveData::try_from("Hello".as_bytes().to_vec())
            .expect("Failed to create dummy sensitive buffer");

        let _context = Context::new().own()?.policy(PcrPolicyOptions::default())?;

        Ok(())
    }
}
