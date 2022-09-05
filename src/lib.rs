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
use tss_esapi::attributes::ObjectAttributes;
use tss_esapi::attributes::{SessionAttributes, SessionAttributesBuilder, SessionAttributesMask};
use tss_esapi::constants::{SessionType, StartupType};
use tss_esapi::handles::{KeyHandle, ObjectHandle};
use tss_esapi::interface_types::algorithm::{
    HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm,
};
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::{AuthSession, HmacSession, PolicySession};
use tss_esapi::structures::{
    Auth, CreateKeyResult, CreatePrimaryKeyResult, Data, Digest, KeyedHashScheme, MaxBuffer, Nonce,
    PcrSelectionList, Public, PublicKeyRsa, PublicKeyedHashParameters, PublicRsaParametersBuilder,
    RsaExponent, RsaScheme, SensitiveData, SymmetricDefinition, SymmetricDefinitionObject,
};
use tss_esapi::utils::{
    create_restricted_decryption_rsa_public, create_unrestricted_encryption_decryption_rsa_public,
    create_unrestricted_signing_rsa_public,
};

#[derive(Error, Debug)]
pub enum TpmError {
    #[error("failed to create auth session")]
    AuthSessionCreate,
    #[error(transparent)]
    TssEsapi(#[from] tss_esapi::Error),
}

pub type Result<T, E = TpmError> = core::result::Result<T, E>;

pub struct Context(MutexGuard<'static, tss_esapi::Context>);
pub struct OwnedContext {
    ctx: Context,
    key: KeyHandle,
    public: Public,
}
pub struct PcrSealedContext {
    ctx: OwnedContext,
    pcr_selection_list: PcrSelectionList,
    policy_digest: Digest,
}

static CONTEXT: Lazy<Mutex<tss_esapi::Context>> = Lazy::new(|| {
    use tss_esapi::tcti_ldr::TctiNameConf;

    let context =
        tss_esapi::Context::new(TctiNameConf::from_environment_variable().unwrap()).unwrap();
    dbg!("NEW CONTEXT");
    Mutex::new(context)
});

impl Context {
    delegate! {
        to self.0 {
            fn clear_sessions(&mut self);
            fn execute_without_session<F, T>(&mut self, f: F) -> T
            where
                F: FnOnce(&mut tss_esapi::Context) -> T;
            fn execute_with_nullauth_session<F, T, E>(&mut self, f: F) -> Result<T, E>
            where
                F: FnOnce(&mut tss_esapi::Context) -> Result<T, E>,
                E: From<tss_esapi::Error>;
            fn execute_with_session<F, T>(
                &mut self,
                session_handle: Option<AuthSession>,
                f: F
            ) -> T
            where
                F: FnOnce(&mut tss_esapi::Context) -> T;
            fn flush_context(&mut self, handle: ObjectHandle) -> tss_esapi::Result<()>;
            fn get_random(&mut self, num_bytes: usize) -> tss_esapi::Result<Digest>;
            fn policy_get_digest(
                &mut self,
                policy_session: PolicySession
            ) -> tss_esapi::Result<Digest>;
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

        //let public = create_unrestricted_encryption_decryption_rsa_public(
        //RsaKeyBits::Rsa2048,
        //RsaExponent::default(),
        //)?;

        let public = create_restricted_decryption_rsa_public(
            SymmetricDefinitionObject::AES_128_CFB,
            RsaKeyBits::Rsa2048,
            RsaExponent::default(),
        )?;

        //let object_attributes = ObjectAttributes::builder()
        //.with_fixed_tpm(true)
        //.with_fixed_parent(true)
        //.with_sensitive_data_origin(true)
        //.with_user_with_auth(true)
        //.with_decrypt(true)
        //.with_sign_encrypt(false)
        //.with_restricted(true)
        //.build()?;

        //let public = Public::builder()
        //.with_public_algorithm(PublicAlgorithm::Rsa)
        //.with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        //.with_object_attributes(object_attributes)
        //.with_rsa_parameters(
        //PublicRsaParametersBuilder::new()
        //.with_scheme(RsaScheme::Null)
        //.with_key_bits(RsaKeyBits::Rsa2048)
        //.with_exponent(RsaExponent::default())
        //.with_is_signing_key(false)
        //.with_is_decryption_key(true)
        //.with_restricted(true)
        //.build()?,
        //)
        //.with_rsa_unique_identifier(PublicKeyRsa::default())
        //.build()?;

        let CreatePrimaryKeyResult {
            key_handle: key,
            out_public: public,
            ..
        } = self.execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)
        })?;

        Ok(OwnedContext {
            ctx: self,
            key,
            public,
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
            fn execute_with_nullauth_session<F, T, E>(&mut self, f: F) -> Result<T, E>
            where
                F: FnOnce(&mut tss_esapi::Context) -> Result<T, E>,
                E: From<tss_esapi::Error>;
            fn execute_with_session<F, T>(
                &mut self,
                session_handle: Option<AuthSession>,
                f: F
            ) -> T
            where
                F: FnOnce(&mut tss_esapi::Context) -> T;
            fn execute_without_session<F, T>(&mut self, f: F) -> T
            where
                F: FnOnce(&mut tss_esapi::Context) -> T;
            fn flush_context(&mut self, handle: ObjectHandle) -> tss_esapi::Result<()>;
            fn pcr_digest(&mut self, pcr_selection_list: &PcrSelectionList) -> Result<Digest>;
            fn policy_get_digest(
                &mut self,
                policy_session: PolicySession
            ) -> tss_esapi::Result<Digest>;
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
    fn flush_session(&mut self, session: AuthSession) -> Result<()> {
        let handle = match session {
            AuthSession::HmacSession(session) => match session {
                HmacSession::HmacSession { session_handle, .. } => Some(session_handle.into()),
                _ => None,
            },
            AuthSession::PolicySession(session) => match session {
                PolicySession::PolicySession { session_handle, .. } => Some(session_handle.into()),
                _ => None,
            },
            _ => None,
        };
        if let Some(handle) = handle {
            self.flush_context(handle)?;
        }
        Ok(())
    }
    fn make_session(&mut self, t: SessionType) -> Result<AuthSession> {
        let session = self
            .start_auth_session(
                None,
                None,
                None,
                t,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )?
            .ok_or(TpmError::AuthSessionCreate)?;
        let (session_attributes, session_attributes_mask) = SessionAttributes::builder()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();
        self.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)?;
        Ok(session)
    }
    pub fn with_pcr_policy(mut self, options: PcrPolicyOptions) -> Result<PcrSealedContext> {
        let session = self.make_session(SessionType::Trial)?;

        let PcrPolicyOptions {
            digest,
            pcr_selection_list,
        } = options;

        let digest = match digest {
            Some(digest) => digest,
            None => self.pcr_digest(&pcr_selection_list)?,
        };

        self.policy_pcr(session.try_into()?, digest, pcr_selection_list.clone())?;
        let policy_digest = self.policy_get_digest(session.try_into()?)?;

        self.flush_session(session)?;

        Ok(PcrSealedContext {
            ctx: self,
            pcr_selection_list,
            policy_digest,
        })
    }
}

impl PcrSealedContext {
    delegate! {
        to self.ctx {
            fn execute_with_nullauth_session<F, T, E>(&mut self, f: F) -> Result<T, E>
            where
                F: FnOnce(&mut tss_esapi::Context) -> Result<T, E>,
                E: From<tss_esapi::Error>;
            fn execute_with_session<F, T>(
                &mut self,
                session_handle: Option<AuthSession>,
                f: F
            ) -> T
            where
            F: FnOnce(&mut tss_esapi::Context) -> T;
            fn execute_without_session<F, T>(&mut self, f: F) -> T
            where
                F: FnOnce(&mut tss_esapi::Context) -> T;
            fn policy_get_digest(
                &mut self,
                policy_session: PolicySession
            ) -> tss_esapi::Result<Digest>;
            fn make_session(&mut self, t: SessionType) -> Result<AuthSession>;
        }
    }

    pub fn seal(&mut self, data: SensitiveData) -> Result<()> {
        let key = self.ctx.key;

        let object_attributes = ObjectAttributes::builder()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(false)
            .with_user_with_auth(false)
            .with_decrypt(false)
            .with_sign_encrypt(false)
            .with_restricted(false)
            .build()?;

        let public = Public::builder()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
                KeyedHashScheme::HMAC_SHA_256,
                //KeyedHashScheme::Null,
            ))
            // TODO properly somehow?
            .with_keyed_hash_unique_identifier(self.ctx.ctx.get_random(32)?)
            .build()?;

        let pcrs = self.pcr_selection_list.clone();
        let session = self.make_session(SessionType::Trial)?;
        self.execute_with_session(Some(session), |ctx| {
            let CreateKeyResult {
                out_private,
                out_public,
                ..
            } = ctx.create(key, public, None, Some(data), None, Some(pcrs))?;
            //let transient = ctx.load(key, out_private, out_public)?;
            Ok::<(), TpmError>(())
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eyre::Result;

    //#[test]
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

        let _context = Context::new()
            .own()?
            .with_pcr_policy(PcrPolicyOptions::default())?
            .seal(data)?;
        Ok(())
    }
}
