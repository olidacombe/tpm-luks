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
//!
//! > I'm currently just trying to re-enact this:
//! ```bash
//! #!/usr/bin/env bash
//!
//! set -xeou pipefail
//!
//! docker kill swtpm || true
//! docker run -d --rm --name swtpm -p 2321:2321 -p 2322:2322 olidacombe/swtpm
//! sleep 2
//!
//! rm -f prim.ctx.log \
//!       session.dat \
//!       policy.dat
//!
//! tpm2_createprimary -C e -g sha256 -G ecc -c prim.ctx | tee prim.ctx.log
//! tpm2_pcrread -o pcr.dat "sha1:0,1,2,3"
//!
//! tpm2_startauthsession -S session.dat
//! tpm2_sessionconfig session.dat
//! tpm2_policypcr -S session.dat -l "sha1:0,1,2,3" -f pcr.dat -L policy.dat
//! tpm2_flushcontext session.dat
//!
//! echo hi | tpm2_create -u key.pub -r key.priv -C prim.ctx -L policy.dat -i-
//! tpm2_flushcontext -t
//! tpm2_load -C prim.ctx -u key.pub -r key.priv -n unseal.key.name -c
//! unseal.key.ctx
//!
//! tpm2_startauthsession --policy-session -S session.dat
//! tpm2_sessionconfig session.dat
//! tpm2_policypcr -S session.dat -l "sha1:0,1,2,3" -f pcr.dat -L policy.dat
//!
//! tpm2_unseal -psession:session.dat -c unseal.key.ctx
//! tpm2_flushcontext session.dat
//! ```

use delegate::delegate;
use once_cell::sync::Lazy;
use std::sync::{Mutex, MutexGuard};
use thiserror::Error;
use tss_esapi::attributes::ObjectAttributes;
use tss_esapi::attributes::{SessionAttributes, SessionAttributesBuilder, SessionAttributesMask};
use tss_esapi::constants::{CapabilityType, SessionType, StartupType};
use tss_esapi::handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{
    HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm,
};
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::{Hierarchy, Provision};
use tss_esapi::interface_types::session_handles::{AuthSession, HmacSession, PolicySession};
use tss_esapi::structures::{
    Auth, CapabilityData, CreateKeyResult, CreatePrimaryKeyResult, Data, Digest, EccPoint,
    KeyedHashScheme, MaxBuffer, Nonce, PcrSelectionList, Public, PublicEccParametersBuilder,
    PublicKeyRsa, PublicKeyedHashParameters, PublicRsaParametersBuilder, RsaExponent, RsaScheme,
    SensitiveData, SymmetricDefinition, SymmetricDefinitionObject,
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
pub struct AuthedContext {
    ctx: Context,
    session: AuthSession,
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
            fn get_capability(
                &mut self,
                capability: CapabilityType,
                property: u32,
                property_count: u32
            ) -> tss_esapi::Result<(CapabilityData, bool)>;
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

    fn flush_transient(&mut self) -> Result<()> {
        let (capabilities, _) = self.get_capability(CapabilityType::Handles, 0, 80)?;
        if let CapabilityData::Handles(handles) = capabilities {
            for handle in handles.into_inner().into_iter().filter_map(|h| match h {
                TpmHandle::Transient(_) => Some(h),
                _ => None,
            }) {
                let handle = self.execute_without_session(|ctx| ctx.tr_from_tpm_public(handle))?;
                self.flush_context(handle).ok();
            }
        }
        Ok(())
    }

    fn auth(mut self, pcr_selection_list: PcrSelectionList) -> Result<AuthedContext> {
        let digest = self.pcr_digest(&pcr_selection_list, HashingAlgorithm::Sha256)?;
        //let session = self.make_session(SessionType::Policy)?;
        let session = self
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Policy,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )?
            .ok_or(TpmError::AuthSessionCreate)?;
        // TODO
        self.policy_pcr(session.try_into()?, digest, pcr_selection_list)?;
        Ok(AuthedContext { ctx: self, session })
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

    pub fn new() -> Result<Self> {
        let mut context = CONTEXT.lock().unwrap();
        context.clear_sessions();
        let mut ctx = Self(context);
        ctx.flush_transient()?;
        Ok(ctx)
    }

    pub fn own(mut self) -> Result<OwnedContext> {
        self.startup(StartupType::Clear)?;

        //let public = create_unrestricted_encryption_decryption_rsa_public(
        //RsaKeyBits::Rsa2048,
        //RsaExponent::default(),
        //)?;

        //let public = create_restricted_decryption_rsa_public(
        //SymmetricDefinitionObject::AES_128_CFB,
        //RsaKeyBits::Rsa2048,
        //RsaExponent::default(),
        //)?;

        let object_attributes = ObjectAttributes::builder()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_sign_encrypt(false)
            .with_restricted(true)
            .build()?;

        let public = Public::builder()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_ecc_parameters(
                PublicEccParametersBuilder::new_restricted_decryption_key(
                    SymmetricDefinitionObject::AES_128_CFB,
                    EccCurve::NistP256,
                )
                .build()?,
            )
            // TODO check we're doing something proper here
            .with_ecc_unique_identifier(EccPoint::default())
            .build()?;

        let CreatePrimaryKeyResult {
            key_handle: key,
            out_public: public,
            ..
        } = self.execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Endorsement, public, None, None, None, None)
        })?;

        Ok(OwnedContext {
            ctx: self,
            key,
            public,
        })
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

    pub fn revision(&mut self) -> Result<Option<u32>> {
        use tss_esapi::constants::property_tag::PropertyTag;

        Ok(self.0.get_tpm_property(PropertyTag::Revision)?)
    }

    /// Returns the digest for a PCR selection list
    fn pcr_digest(
        &mut self,
        pcr_selection_list: &PcrSelectionList,
        hashing_algorithm: HashingAlgorithm,
    ) -> Result<Digest> {
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
                hashing_algorithm, // must match start_auth_session, regardless of PCR banks used
                Hierarchy::Owner,
            )
        })?;

        Ok(digest)
    }
}

// TODO acknowlege this does nothing useful?
impl Drop for Context {
    fn drop(&mut self) {
        self.0.clear_sessions();
    }
}

impl Drop for AuthedContext {
    fn drop(&mut self) {
        self.ctx.flush_session(self.session).ok();
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
            .with_selection(HashingAlgorithm::Sha1, &[PcrSlot::Slot0, PcrSlot::Slot1])
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
            fn flush_session(&mut self, session: AuthSession) -> Result<()>;
            fn flush_transient(&mut self) -> Result<()>;
            fn make_session(&mut self, t: SessionType) -> Result<AuthSession>;
            fn pcr_digest(&mut self, pcr_selection_list: &PcrSelectionList, hashing_algorithm: HashingAlgorithm) -> Result<Digest>;
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
    pub fn with_pcr_policy(mut self, options: PcrPolicyOptions) -> Result<PcrSealedContext> {
        let session = self.make_session(SessionType::Trial)?;

        let PcrPolicyOptions {
            digest,
            pcr_selection_list,
        } = options;

        let digest = match digest {
            Some(digest) => digest,
            None => self.pcr_digest(&pcr_selection_list, HashingAlgorithm::Sha256)?,
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
            fn flush_session(&mut self, session: AuthSession) -> Result<()>;
            fn flush_transient(&mut self) -> Result<()>;
            fn policy_get_digest(
                &mut self,
                policy_session: PolicySession
            ) -> tss_esapi::Result<Digest>;
            fn make_session(&mut self, t: SessionType) -> Result<AuthSession>;
        }
    }

    pub fn seal(&mut self, data: SensitiveData, handle: PersistentTpmHandle) -> Result<()> {
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
                //KeyedHashScheme::HMAC_SHA_256,
                KeyedHashScheme::Null, // according to https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_create.1/
            ))
            // TODO properly somehow?
            .with_keyed_hash_unique_identifier(Digest::default())
            .build()?;

        //self.flush_transient()?;
        let retrieved_persistent_handle = self
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(TpmHandle::Persistent(handle)))?;
        // Evict the persitent handle from the tpm
        // An authorization session is required!
        let _ = self.execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.evict_control(
                Provision::Owner,
                retrieved_persistent_handle,
                Persistent::Persistent(handle),
            )
        })?;

        let pcrs = self.pcr_selection_list.clone();
        self.execute_with_session(Some(AuthSession::Password), |ctx| {
            let CreateKeyResult {
                out_private,
                out_public,
                ..
            } = ctx.create(key, public, None, Some(data), None, Some(pcrs))?;
            let transient = ctx.load(key, out_private, out_public)?.into();
            ctx.evict_control(Provision::Owner, transient, Persistent::Persistent(handle))?;
            Ok::<(), TpmError>(())
        })?;
        Ok(())
    }
}

impl AuthedContext {
    delegate! {
        to self.ctx {
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
            fn flush_transient(&mut self) -> Result<()>;
        }
    }

    pub fn unseal(mut self, handle: PersistentTpmHandle) -> Result<SensitiveData> {
        //return Ok(SensitiveData::try_from("Schmello".as_bytes().to_vec())?);
        let object_handle =
            self.execute_without_session(|ctx| ctx.tr_from_tpm_public(handle.into()))?;
        let data =
            self.execute_with_session(Some(self.session), |ctx| ctx.unseal(object_handle.into()))?;
        // TODO extend
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eyre::Result;

    //#[test]
    fn get_revision() -> Result<()> {
        let mut context = Context::new()?;
        let revision = context.revision()?;
        assert!(revision.is_some());

        Ok(())
    }

    //https://tpm2-software.github.io/2020/04/13/Disk-Encryption.html#pcr-policy-authentication---access-control-of-sealed-pass-phrase-on-tpm2-with-pcr-sealing
    #[test]
    fn seal() -> Result<()> {
        let data = SensitiveData::try_from("Hello".as_bytes().to_vec())?;
        let handle = PersistentTpmHandle::new(u32::from_be_bytes([0x81, 0x00, 0x00, 0x01]))?;

        Context::new()?
            .own()?
            .with_pcr_policy(PcrPolicyOptions::default())?
            .seal(data.clone(), handle)?;

        let unsealed = Context::new()?
            .auth(PcrPolicyOptions::default().pcr_selection_list)?
            .unseal(handle)?;

        assert_eq!(data, unsealed);

        Ok(())
    }
}
