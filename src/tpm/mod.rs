use self::pcr::{AggregateDigest, PcrError};
use ambassador::{delegatable_trait, Delegate};
use once_cell::sync::Lazy;
use pcr::{pcr_slot_to_handle, PcrPolicyOptions};
use std::ops::{Deref, DerefMut};
use std::sync::{Mutex, MutexGuard};
use thiserror::Error;
use tss_esapi::attributes::ObjectAttributes;
use tss_esapi::attributes::SessionAttributes;
use tss_esapi::constants::{CapabilityType, SessionType, StartupType};
use tss_esapi::handles::{KeyHandle, PcrHandle, PersistentTpmHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::{Hierarchy, Provision};
use tss_esapi::interface_types::session_handles::{AuthSession, HmacSession, PolicySession};
use tss_esapi::structures::{
    CapabilityData, CreateKeyResult, CreatePrimaryKeyResult, Digest, DigestList, DigestValues,
    EccPoint, KeyedHashScheme, PcrSelectionList, Public, PublicEccParametersBuilder,
    PublicKeyedHashParameters, SensitiveData, SymmetricDefinition, SymmetricDefinitionObject,
};

pub mod pcr;

#[derive(Error, Debug)]
pub enum TpmError {
    #[error("failed to create auth session")]
    AuthSessionCreate,
    #[error("empty PCR selection list, expected at least on selection")]
    EmptyPcrSelectionList,
    #[error(transparent)]
    TssEsapi(#[from] tss_esapi::Error),
    #[error(transparent)]
    PcrError(#[from] PcrError),
}

pub type Result<T, E = TpmError> = core::result::Result<T, E>;

pub type Context = MutexGuard<'static, tss_esapi::Context>;
pub trait TContext: DerefMut<Target = tss_esapi::Context> {}
impl TContext for Context {}

pub struct Ctx<C: TContext, S: ContextState> {
    ctx: C,
    state: S,
}

#[delegatable_trait]
trait FlushSession {
    fn flush_session(&mut self, session: AuthSession) -> Result<()>;
}

impl FlushSession for Context {
    fn flush_session(&mut self, session: AuthSession) -> Result<()> {
        let handle = match session {
            AuthSession::HmacSession(session) => match session {
                HmacSession::HmacSession { session_handle, .. } => Some(session_handle.into()),
            },
            AuthSession::PolicySession(session) => match session {
                PolicySession::PolicySession { session_handle, .. } => Some(session_handle.into()),
            },
            _ => None,
        };
        if let Some(handle) = handle {
            self.flush_context(handle)?;
        }
        Ok(())
    }
}

impl<C: TContext, S: ContextState> Ctx<C, S> {
    pub fn evict_persistent(&mut self, handle: PersistentTpmHandle) {
        self.ctx
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(TpmHandle::Persistent(handle)))
            .ok()
            .map(|retrieved| {
                // Evict the persitent handle from the tpm
                // An authorization session is required!
                // [this](https://docs.rs/tss-esapi/latest/src/tss_esapi/context/tpm_commands/context_management.rs.html#397)
                // was really helpful
                self.ctx
                    .execute_with_session(Some(AuthSession::Password), |ctx| {
                        ctx.evict_control(
                            Provision::Owner,
                            retrieved,
                            Persistent::Persistent(handle),
                        )
                    })
                    .ok()
            });
        self.flush_transient().ok();
    }

    fn flush_transient(&mut self) -> Result<()> {
        let (capabilities, _) = self.ctx.get_capability(CapabilityType::Handles, 0, 80)?;
        if let CapabilityData::Handles(handles) = capabilities {
            for handle in handles
                .into_inner()
                .into_iter()
                .filter(|h| matches!(h, TpmHandle::Transient(_)))
            {
                let handle = self
                    .ctx
                    .execute_without_session(|ctx| ctx.tr_from_tpm_public(handle))?;
                self.ctx.flush_context(handle).ok();
            }
        }
        Ok(())
    }

    pub fn get_random(&mut self, num_bytes: usize) -> Result<Digest> {
        Ok(self.ctx.get_random(num_bytes)?)
    }

    fn make_session(&mut self, t: SessionType) -> Result<AuthSession> {
        let session = self
            .ctx
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
        self.ctx
            .tr_sess_set_attributes(session, session_attributes, session_attributes_mask)?;
        Ok(session)
    }

    /// Retrieves a PCR digest list given a selection list
    fn digest_list(&mut self, pcr_selection_list: &PcrSelectionList) -> Result<DigestList> {
        let (_update_counter, _selection_list, digest_list) = self
            .ctx
            .execute_without_session(|ctx| ctx.pcr_read(pcr_selection_list.clone()))?;
        Ok(digest_list)
    }

    /// Returns the digest for a PCR selection list
    fn pcr_digest(
        &mut self,
        pcr_selection_list: &PcrSelectionList,
        hashing_algorithm: HashingAlgorithm,
    ) -> Result<Digest> {
        Ok(self
            .digest_list(pcr_selection_list)?
            .digest(hashing_algorithm)?)
    }
}

pub struct Initial;
pub type InitialContext = Ctx<Context, Initial>;
pub struct PrimaryKey;
#[derive(Delegate)]
#[delegate(FlushSession, target = "ctx")]
pub struct PkCtx {
    ctx: Context,
    pub key: KeyHandle,
}
impl Deref for PkCtx {
    type Target = tss_esapi::Context;
    fn deref(&self) -> &Self::Target {
        &self.ctx
    }
}
impl DerefMut for PkCtx {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.ctx
    }
}
impl Drop for PkCtx {
    fn drop(&mut self) {
        self.ctx.flush_context(self.key.into()).ok();
    }
}
impl TContext for PkCtx {}
pub type PrimaryKeyContext = Ctx<PkCtx, PrimaryKey>;
pub struct PcrPolicy {
    policy_digest: Digest,
}
pub type PcrPolicyContext = Ctx<PkCtx, PcrPolicy>;
pub struct PcrAuthed {
    pcr_selection_list: PcrSelectionList,
}
#[derive(Delegate)]
#[delegate(FlushSession, target = "ctx")]
pub struct PcrAuthedCtx {
    ctx: Context,
    pub session: AuthSession,
}
impl Deref for PcrAuthedCtx {
    type Target = tss_esapi::Context;
    fn deref(&self) -> &Self::Target {
        &self.ctx
    }
}
impl DerefMut for PcrAuthedCtx {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.ctx
    }
}
impl Drop for PcrAuthedCtx {
    fn drop(&mut self) {
        self.ctx.flush_session(self.session).ok();
    }
}
impl TContext for PcrAuthedCtx {}
pub type PcrAuthedContext = Ctx<PcrAuthedCtx, PcrAuthed>;

pub trait ContextState {}
impl ContextState for Initial {}
impl ContextState for PrimaryKey {}
impl ContextState for PcrPolicy {}
impl ContextState for PcrAuthed {}

impl InitialContext {
    pub fn pcr_auth(mut self, pcr_selection_list: PcrSelectionList) -> Result<PcrAuthedContext> {
        let digest = self.pcr_digest(&pcr_selection_list, HashingAlgorithm::Sha256)?;
        let session = self.make_session(SessionType::Policy)?;
        self.ctx
            .policy_pcr(session.try_into()?, digest, pcr_selection_list.clone())?;
        Ok(PcrAuthedContext {
            ctx: PcrAuthedCtx {
                ctx: self.ctx,
                session,
            },
            state: PcrAuthed { pcr_selection_list },
        })
    }
    pub fn create_primary(mut self) -> Result<PrimaryKeyContext> {
        //self.ctx.startup(StartupType::Clear)?;

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
            .with_ecc_unique_identifier(EccPoint::default())
            .build()?;

        let CreatePrimaryKeyResult {
            key_handle: key, ..
        } = self.ctx.execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)
        })?;
        self.flush_transient().ok();

        Ok(PrimaryKeyContext {
            ctx: PkCtx { ctx: self.ctx, key },
            state: PrimaryKey,
        })
    }
}

impl PrimaryKeyContext {
    pub fn with_pcr_policy(mut self, options: PcrPolicyOptions) -> Result<PcrPolicyContext> {
        let session = self.make_session(SessionType::Trial)?;

        let PcrPolicyOptions {
            digest,
            pcr_selection_list,
        } = options;

        let digest = match digest {
            Some(digest) => digest,
            None => self.pcr_digest(&pcr_selection_list, HashingAlgorithm::Sha256)?,
        };

        self.ctx
            .policy_pcr(session.try_into()?, digest, pcr_selection_list.clone())?;
        let policy_digest = self.ctx.policy_get_digest(session.try_into()?)?;
        self.ctx.flush_session(session)?;

        Ok(PcrPolicyContext {
            ctx: self.ctx,
            state: PcrPolicy { policy_digest },
        })
    }
}

impl PcrPolicyContext {
    pub fn seal(&mut self, data: SensitiveData, handle: PersistentTpmHandle) -> Result<&mut Self> {
        let key = self.ctx.key;

        let object_attributes = ObjectAttributes::builder()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .build()?;

        let public = Public::builder()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_auth_policy(self.state.policy_digest.clone())
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
                KeyedHashScheme::Null, // according to https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_create.1/
            ))
            .with_keyed_hash_unique_identifier(Digest::default())
            .build()?;

        // Make sure there isn't data already stored at our intended handle
        self.evict_persistent(handle);

        self.ctx
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                let CreateKeyResult {
                    out_private,
                    out_public,
                    ..
                } = ctx.create(key, public, None, Some(data), None, None)?;
                let transient = ctx.load(key, out_private, out_public)?.into();
                let mut persistent =
                    ctx.evict_control(Provision::Owner, transient, Persistent::Persistent(handle))?;
                ctx.flush_context(transient)?;
                ctx.flush_context(key.into())?;
                ctx.tr_close(&mut persistent)?;
                Ok::<(), TpmError>(())
            })?;
        Ok(self)
    }
}

impl PcrAuthedContext {
    // TODO consume self?
    fn extend(&mut self, pcr_handle: Option<PcrHandle>) -> Result<()> {
        let pcr_handle = pcr_handle
            .or_else(|| {
                self.state
                    .pcr_selection_list
                    .get_selections()
                    .iter()
                    .find_map(|s| match s.is_empty() {
                        true => None,
                        false => s.selected().first().map(pcr_slot_to_handle),
                    })
            })
            .ok_or(TpmError::EmptyPcrSelectionList)?;
        let random_digest_sha1 = self.ctx.get_random(20)?;
        let random_digest_sha256 = self.ctx.get_random(32)?;
        let mut vals = DigestValues::new();
        vals.set(HashingAlgorithm::Sha1, random_digest_sha1);
        vals.set(HashingAlgorithm::Sha256, random_digest_sha256);
        let session = self.make_session(SessionType::Hmac)?;
        self.ctx
            .execute_with_session(Some(session), |ctx| ctx.pcr_extend(pcr_handle, vals))?;

        Ok(())
    }

    pub fn unseal(mut self, handle: PersistentTpmHandle) -> Result<SensitiveData> {
        let object_handle = self
            .ctx
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(handle.into()))?;
        let session = self.ctx.session;
        let data = self
            .ctx
            .execute_with_session(Some(session), |ctx| ctx.unseal(object_handle))?;
        self.ctx.flush_session(self.ctx.session)?;
        self.extend(None)?;
        Ok(data)
    }
}

static CONTEXT: Lazy<Mutex<tss_esapi::Context>> = Lazy::new(|| {
    use tss_esapi::tcti_ldr::TctiNameConf;

    let conf = TctiNameConf::from_environment_variable().expect("Invalid TCTI config");
    log::debug!("TCTI config {:?}", conf);
    let context = tss_esapi::Context::new(conf).expect("Failed to init TPM context");
    Mutex::new(context)
});

pub fn get_context() -> Result<InitialContext> {
    let mut ctx = CONTEXT.lock().unwrap();
    ctx.startup(StartupType::Clear)?;
    let mut ctx = Ctx {
        ctx,
        state: Initial {},
    };
    ctx.flush_transient()?;
    Ok(ctx)
}

pub fn get_pcr_digest(pcr_selection_list: &PcrSelectionList) -> Result<Digest> {
    Ok(get_context()?.pcr_digest(pcr_selection_list, HashingAlgorithm::Sha256)?)
}

pub fn seal_random_passphrase(
    opts: PcrPolicyOptions,
    length: usize,
    handle: PersistentTpmHandle,
) -> Result<SensitiveData> {
    let mut ctx = get_context()?;
    let passphrase = SensitiveData::try_from(ctx.get_random(length)?.value())?;

    ctx.create_primary()?
        .with_pcr_policy(opts)?
        .seal(passphrase.clone(), handle)?;

    let u: u32 = handle.into();
    log::info!("Sealed random passphrase at {:#10x}", u);

    Ok(passphrase)
}

pub fn get_sealed_passphrase(
    pcr_selection_list: PcrSelectionList,
    handle: PersistentTpmHandle,
) -> Result<SensitiveData> {
    let passphrase = get_context()?
        .pcr_auth(pcr_selection_list)?
        .unseal(handle)?;

    Ok(passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eyre::Result;

    #[test]
    fn seal_unseal() -> Result<()> {
        let data = SensitiveData::try_from("Howdy".as_bytes().to_vec())?;
        let handle = PersistentTpmHandle::new(u32::from_be_bytes([0x81, 0x01, 0x00, 0x02]))?;

        get_context()?
            .create_primary()?
            .with_pcr_policy(PcrPolicyOptions::default())?
            .seal(data.clone(), handle)?;

        let unsealed = get_context()?
            .pcr_auth(PcrPolicyOptions::default().pcr_selection_list)?
            .unseal(handle)?;

        assert_eq!(data, unsealed);

        let should_fail = get_context()?
            .pcr_auth(PcrPolicyOptions::default().pcr_selection_list)?
            .unseal(handle);

        assert!(should_fail.is_err());

        Ok(())
    }
}
