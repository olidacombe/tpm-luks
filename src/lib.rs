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
use std::sync::Mutex;
use tss_esapi::{tcti_ldr::TctiNameConf, Context};

static CONTEXT: Lazy<Mutex<Context>> = Lazy::new(|| {
    Mutex::new(Context::new(TctiNameConf::from_environment_variable().unwrap()).unwrap())
});

#[cfg(test)]
mod tests {
    use super::*;
    use eyre::Result;

    #[test]
    fn list_nvs() -> Result<()> {
        use tss_esapi::abstraction::nv::list;
        let mut context = CONTEXT.lock().unwrap();
        let nvs = list(&mut context)?;
        for (_, name) in nvs {
            if let Ok(s) = std::str::from_utf8(name.value()) {
                dbg!(s);
            }
        }
        Ok(())
    }

    #[test]
    fn get_revision() -> Result<()> {
        use tss_esapi::constants::property_tag::PropertyTag;
        let mut context = CONTEXT.lock().unwrap();

        context
            .get_tpm_property(PropertyTag::Revision)
            .expect("Wrong value from TPM")
            .expect("Value is not supported");

        Ok(())
    }

    //https://tpm2-software.github.io/2020/04/13/Disk-Encryption.html#pcr-policy-authentication---access-control-of-sealed-pass-phrase-on-tpm2-with-pcr-sealing
    #[test]
    fn seal() -> Result<()> {
        use tss_esapi::constants::SessionType;
        use tss_esapi::interface_types::{
            algorithm::HashingAlgorithm, session_handles::PolicySession,
        };
        use tss_esapi::structures::SymmetricDefinition;
        let mut context = CONTEXT.lock().unwrap();

        let _session: PolicySession = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Policy,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .expect("Failed to create session")
            .expect("Received invalid handle")
            .try_into()?;

        Ok(())
    }
}
