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
//! PCRS="sha1:0,1,2,3"
//! PERM_HANDLE=0x81010001
//!
//! docker kill swtpm || true
//! docker run -d --rm --name swtpm -p 2321:2321 -p 2322:2322 olidacombe/swtpm
//! sleep 2
//!
//! rm -f   prim.ctx.log \
//!         session.dat \
//!         policy.dat
//!
//! tpm2_createprimary -C e -g sha256 -G ecc -c prim.ctx | tee prim.ctx.log
//! tpm2_pcrread -o pcr.dat $PCRS
//!
//! tpm2_startauthsession -S session.dat
//! tpm2_policypcr -S session.dat -l $PCRS -f pcr.dat -L policy.dat
//! tpm2_flushcontext session.dat
//!
//! echo hi | tpm2_create -u key.pub -r key.priv -C prim.ctx -L policy.dat -i-
//! tpm2_flushcontext -t
//! tpm2_load -C prim.ctx -u key.pub -r key.priv -c $PERM_HANDLE -n unseal.key.name
//!
//! tpm2_startauthsession --policy-session -S session.dat
//! tpm2_policypcr -S session.dat -l $PCRS
//!
//! tpm2_unseal -psession:session.dat -c $PERM_HANDLE
//! tpm2_flushcontext session.dat
//! ```

use ambassador::{delegatable_trait, Delegate};
use delegate::delegate;
use once_cell::sync::Lazy;
use std::ops::{Deref, DerefMut};
use std::sync::{Mutex, MutexGuard};
use thiserror::Error;
use tss_esapi::attributes::ObjectAttributes;
use tss_esapi::attributes::{SessionAttributes, SessionAttributesMask};
use tss_esapi::constants::{CapabilityType, SessionType, StartupType};
use tss_esapi::handles::{KeyHandle, ObjectHandle, PcrHandle, PersistentTpmHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::{Hierarchy, Provision};
use tss_esapi::interface_types::session_handles::{AuthSession, HmacSession, PolicySession};
use tss_esapi::structures::{
    CapabilityData, CreateKeyResult, CreatePrimaryKeyResult, Digest, DigestValues, EccPoint,
    KeyedHashScheme, MaxBuffer, Nonce, PcrSelectionList, PcrSlot, Public,
    PublicEccParametersBuilder, PublicKeyedHashParameters, SensitiveData, SymmetricDefinition,
    SymmetricDefinitionObject,
};

#[derive(Error, Debug)]
pub enum TpmError {
    #[error("failed to create auth session")]
    AuthSessionCreate,
    #[error("empty PCR selection list, expected at least on selection")]
    EmptyPcrSelectionList,
    #[error(transparent)]
    TssEsapi(#[from] tss_esapi::Error),
}

pub type Result<T, E = TpmError> = core::result::Result<T, E>;

pub struct Context(MutexGuard<'static, tss_esapi::Context>);

pub type Qontext = MutexGuard<'static, tss_esapi::Context>;
pub trait TContext: DerefMut<Target = tss_esapi::Context> {}
impl TContext for Qontext {}

pub struct Ctx<C: TContext, S: ContextState> {
    ctx: C,
    state: S,
}

#[delegatable_trait]
trait FlushSession {
    fn flush_session(&mut self, session: AuthSession) -> Result<()>;
}

impl FlushSession for Qontext {
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
    /// Returns the digest for a PCR selection list
    fn pcr_digest(
        &mut self,
        pcr_selection_list: &PcrSelectionList,
        hashing_algorithm: HashingAlgorithm,
    ) -> Result<Digest> {
        let (_update_counter, _selection_list, digest_list) = self
            .ctx
            .execute_without_session(|ctx| ctx.pcr_read(pcr_selection_list.clone()))?;

        let concatenated_pcr_digests = digest_list
            .value()
            .iter()
            .map(|x| x.value())
            .collect::<Vec<&[u8]>>()
            .concat();
        let concatenated_pcr_digests = MaxBuffer::try_from(concatenated_pcr_digests)?;

        let (digest, _ticket) = self.ctx.execute_without_session(|ctx| {
            ctx.hash(
                concatenated_pcr_digests,
                hashing_algorithm, // must match start_auth_session, regardless of PCR banks used
                Hierarchy::Owner,
            )
        })?;

        Ok(digest)
    }
}

pub struct Initial;
pub type InitialContext = Ctx<Qontext, Initial>;
pub struct PrimaryKey;
#[derive(Delegate)]
#[delegate(FlushSession, target = "ctx")]
pub struct PkCtx {
    ctx: Qontext,
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
    ctx: Qontext,
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
    fn create_primary(mut self) -> Result<PrimaryKeyContext> {
        //TODO not?
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

    let context =
        tss_esapi::Context::new(TctiNameConf::from_environment_variable().unwrap()).unwrap();
    Mutex::new(context)
});

pub fn get_context() -> Result<InitialContext> {
    let mut ctx = CONTEXT.lock().unwrap();
    ctx.startup(StartupType::Clear)?;
    //ctx.clear_sessions();
    let mut ctx = Ctx {
        ctx,
        state: Initial {},
    };
    ctx.flush_transient()?;
    Ok(ctx)
}

pub struct OwnedContext {
    ctx: Context,
    key: KeyHandle,
}
pub struct PcrSealedContext {
    ctx: OwnedContext,
    policy_digest: Digest,
}
pub struct AuthedContext {
    ctx: Context,
    session: AuthSession,
    pcr_selection_list: PcrSelectionList,
}

fn pcr_slot_to_handle(slot: &PcrSlot) -> PcrHandle {
    match slot {
        PcrSlot::Slot0 => PcrHandle::Pcr0,
        PcrSlot::Slot1 => PcrHandle::Pcr1,
        PcrSlot::Slot2 => PcrHandle::Pcr2,
        PcrSlot::Slot3 => PcrHandle::Pcr3,
        PcrSlot::Slot4 => PcrHandle::Pcr4,
        PcrSlot::Slot5 => PcrHandle::Pcr5,
        PcrSlot::Slot6 => PcrHandle::Pcr6,
        PcrSlot::Slot7 => PcrHandle::Pcr7,
        PcrSlot::Slot8 => PcrHandle::Pcr8,
        PcrSlot::Slot9 => PcrHandle::Pcr9,
        PcrSlot::Slot10 => PcrHandle::Pcr10,
        PcrSlot::Slot11 => PcrHandle::Pcr11,
        PcrSlot::Slot12 => PcrHandle::Pcr12,
        PcrSlot::Slot13 => PcrHandle::Pcr13,
        PcrSlot::Slot14 => PcrHandle::Pcr14,
        PcrSlot::Slot15 => PcrHandle::Pcr15,
        PcrSlot::Slot16 => PcrHandle::Pcr16,
        PcrSlot::Slot17 => PcrHandle::Pcr17,
        PcrSlot::Slot18 => PcrHandle::Pcr18,
        PcrSlot::Slot19 => PcrHandle::Pcr19,
        PcrSlot::Slot20 => PcrHandle::Pcr20,
        PcrSlot::Slot21 => PcrHandle::Pcr21,
        PcrSlot::Slot22 => PcrHandle::Pcr22,
        PcrSlot::Slot23 => PcrHandle::Pcr23,
        PcrSlot::Slot24 => PcrHandle::Pcr24,
        PcrSlot::Slot25 => PcrHandle::Pcr25,
        PcrSlot::Slot26 => PcrHandle::Pcr26,
        PcrSlot::Slot27 => PcrHandle::Pcr27,
        PcrSlot::Slot28 => PcrHandle::Pcr28,
        PcrSlot::Slot29 => PcrHandle::Pcr29,
        PcrSlot::Slot30 => PcrHandle::Pcr30,
        PcrSlot::Slot31 => PcrHandle::Pcr31,
    }
}

impl Context {
    delegate! {
        to self.0 {
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

    pub fn evict_persistent(&mut self, handle: PersistentTpmHandle) {
        self.execute_without_session(|ctx| ctx.tr_from_tpm_public(TpmHandle::Persistent(handle)))
            .ok()
            .map(|retrieved| {
                // Evict the persitent handle from the tpm
                // An authorization session is required!
                // [this](https://docs.rs/tss-esapi/latest/src/tss_esapi/context/tpm_commands/context_management.rs.html#397)
                // was really helpful
                self.execute_with_session(Some(AuthSession::Password), |ctx| {
                    ctx.evict_control(Provision::Owner, retrieved, Persistent::Persistent(handle))
                })
                .ok()
            });
        self.flush_transient().ok();
    }

    fn flush_transient(&mut self) -> Result<()> {
        let (capabilities, _) = self.get_capability(CapabilityType::Handles, 0, 80)?;
        if let CapabilityData::Handles(handles) = capabilities {
            for handle in handles
                .into_inner()
                .into_iter()
                .filter(|h| matches!(h, TpmHandle::Transient(_)))
            {
                let handle = self.execute_without_session(|ctx| ctx.tr_from_tpm_public(handle))?;
                self.flush_context(handle).ok();
            }
        }
        Ok(())
    }

    pub fn auth(mut self, pcr_selection_list: PcrSelectionList) -> Result<AuthedContext> {
        let digest = self.pcr_digest(&pcr_selection_list, HashingAlgorithm::Sha256)?;
        let session = self.make_session(SessionType::Policy)?;
        self.policy_pcr(session.try_into()?, digest, pcr_selection_list.clone())?;
        Ok(AuthedContext {
            ctx: self,
            session,
            pcr_selection_list,
        })
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
        } = self.execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)
        })?;
        self.flush_transient().ok();

        Ok(OwnedContext { ctx: self, key })
    }

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

impl Drop for Context {
    fn drop(&mut self) {
        self.flush_transient().ok();
        self.0.clear_sessions();
    }
}

impl Drop for AuthedContext {
    fn drop(&mut self) {
        self.flush_session(self.session).ok();
    }
}

pub struct PcrPolicyOptions {
    digest: Option<Digest>,
    pub pcr_selection_list: PcrSelectionList,
}

impl PcrPolicyOptions {
    pub fn with_digest(mut self, digest: Digest) -> Self {
        self.digest = Some(digest);
        self
    }
}

impl Default for PcrPolicyOptions {
    fn default() -> Self {
        let pcr_selection_list = PcrSelectionList::builder()
            .with_selection(
                HashingAlgorithm::Sha1,
                &[
                    PcrSlot::Slot0,
                    PcrSlot::Slot1,
                    PcrSlot::Slot2,
                    PcrSlot::Slot3,
                ],
            )
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
            fn evict_persistent(&mut self, handle: PersistentTpmHandle);
            fn execute_with_session<F, T>(
                &mut self,
                session_handle: Option<AuthSession>,
                f: F
            ) -> T
            where
                F: FnOnce(&mut tss_esapi::Context) -> T;
            fn flush_session(&mut self, session: AuthSession) -> Result<()>;
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
            policy_digest,
        })
    }
}

impl PcrSealedContext {
    delegate! {
        to self.ctx {
            fn evict_persistent(&mut self, handle: PersistentTpmHandle);
            fn execute_with_session<F, T>(
                &mut self,
                session_handle: Option<AuthSession>,
                f: F
            ) -> T
            where
            F: FnOnce(&mut tss_esapi::Context) -> T;
        }
    }

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
            .with_auth_policy(self.policy_digest.clone())
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
                KeyedHashScheme::Null, // according to https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_create.1/
            ))
            .with_keyed_hash_unique_identifier(Digest::default())
            .build()?;

        // Make sure there isn't data already stored at our intended handle
        self.evict_persistent(handle);

        self.execute_with_session(Some(AuthSession::Password), |ctx| {
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
            fn flush_session(&mut self, session: AuthSession) -> Result<()>;
            fn get_random(&mut self, num_bytes: usize) -> tss_esapi::Result<Digest>;
            fn make_session(&mut self, t: SessionType) -> Result<AuthSession>;
        }
    }

    fn extend(&mut self, pcr_handle: Option<PcrHandle>) -> Result<()> {
        let pcr_handle = pcr_handle
            .or_else(|| {
                self.pcr_selection_list
                    .get_selections()
                    .iter()
                    .find_map(|s| match s.is_empty() {
                        true => None,
                        false => s.selected().first().map(pcr_slot_to_handle),
                    })
            })
            .ok_or(TpmError::EmptyPcrSelectionList)?;
        let random_digest_sha1 = self.get_random(20)?;
        let random_digest_sha256 = self.get_random(32)?;
        let mut vals = DigestValues::new();
        vals.set(HashingAlgorithm::Sha1, random_digest_sha1);
        vals.set(HashingAlgorithm::Sha256, random_digest_sha256);
        let session = self.make_session(SessionType::Hmac)?;
        self.execute_with_session(Some(session), |ctx| ctx.pcr_extend(pcr_handle, vals))?;

        Ok(())
    }

    pub fn unseal(mut self, handle: PersistentTpmHandle) -> Result<SensitiveData> {
        let object_handle =
            self.execute_without_session(|ctx| ctx.tr_from_tpm_public(handle.into()))?;
        let data =
            self.execute_with_session(Some(self.session), |ctx| ctx.unseal(object_handle))?;
        self.extend(None)?;
        self.flush_session(self.session)?;
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eyre::Result;

    //#[test]
    //fn seal_unseal() -> Result<()> {
    //let data = SensitiveData::try_from("Howdy".as_bytes().to_vec())?;
    //let handle = PersistentTpmHandle::new(u32::from_be_bytes([0x81, 0x01, 0x00, 0x01]))?;

    //Context::new()?
    //.own()?
    //.with_pcr_policy(PcrPolicyOptions::default())?
    //.seal(data.clone(), handle)?;

    //let unsealed = Context::new()?
    //.auth(PcrPolicyOptions::default().pcr_selection_list)?
    //.unseal(handle)?;

    //assert_eq!(data, unsealed);

    //Ok(())
    //}

    //#[test]
    //fn no_unseal_twice() -> Result<()> {
    //let data = SensitiveData::try_from("Howdy".as_bytes().to_vec())?;
    //let handle = PersistentTpmHandle::new(u32::from_be_bytes([0x81, 0x01, 0x00, 0x02]))?;

    //Context::new()?
    //.own()?
    //.with_pcr_policy(PcrPolicyOptions::default())?
    //.seal(data.clone(), handle)?;

    //let unsealed = Context::new()?
    //.auth(PcrPolicyOptions::default().pcr_selection_list)?
    //.unseal(handle)?;

    //assert_eq!(data, unsealed);

    //let should_fail = Context::new()?
    //.auth(PcrPolicyOptions::default().pcr_selection_list)?
    //.unseal(handle);

    //assert!(should_fail.is_err());

    //Ok(())
    //}

    #[test]
    fn seal_unseal() -> Result<()> {
        let data = SensitiveData::try_from("Howdy".as_bytes().to_vec())?;
        let handle = PersistentTpmHandle::new(u32::from_be_bytes([0x81, 0x01, 0x00, 0x03]))?;

        get_context()?
            .create_primary()?
            .with_pcr_policy(PcrPolicyOptions::default())?
            .seal(data.clone(), handle)?;

        let unsealed = get_context()?
            .pcr_auth(PcrPolicyOptions::default().pcr_selection_list)?
            .unseal(handle)?;

        assert_eq!(data, unsealed);

        Ok(())
    }

    #[test]
    fn no_unseal_twice() -> Result<()> {
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
