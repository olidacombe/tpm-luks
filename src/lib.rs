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
use tss_esapi::Error;

pub struct Context(MutexGuard<'static, tss_esapi::Context>);

static CONTEXT: Lazy<Mutex<tss_esapi::Context>> = Lazy::new(|| {
    use tss_esapi::tcti_ldr::TctiNameConf;

    let context =
        tss_esapi::Context::new(TctiNameConf::from_environment_variable().unwrap()).unwrap();
    Mutex::new(context)
});

impl Context {
    pub fn new() -> Self {
        Self(CONTEXT.lock().unwrap())
    }

    pub fn revision(&mut self) -> Result<Option<u32>, Error> {
        use tss_esapi::constants::property_tag::PropertyTag;

        self.0.get_tpm_property(PropertyTag::Revision)
    }

    pub fn seal(&mut self) -> Result<(), Error> {
        use tss_esapi::constants::{SessionType, StartupType};
        use tss_esapi::interface_types::{
            algorithm::HashingAlgorithm, session_handles::PolicySession,
        };
        use tss_esapi::structures::SymmetricDefinition;

        self.0.startup(StartupType::Clear).unwrap();

        let _session: PolicySession = self
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
        Ok(())
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
