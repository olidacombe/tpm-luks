//! # Get Started
//!
//! ```bash
//! # at basecamp
//! fswatch -o . | xargs -n1 -I{} ./sync.sh
//! # on remote (e.g. Metal) machine
//! # TCTI=device:/dev/tpm0 cargo watch -x "test -- --nocapture"
//! mkdir /tmp/mytpm
//! chown tss:root /tmp/mytpm
//! swtpm_setup --overwrite --tpmstate /tmp/mytpm/ --create-ek-cert --create-platform-cert --tpm2 \
//! --lock-nvram
//! swtpm socket --tpmstate dir=/tmp/mytpm --tpm2 --ctrl type=tcp,port=2322 --log level=20 --server type=tcp,port=2321
//! tpm2_startup --tcti swtpm -c
//! TCTI=swtpm:port=2321,host=127.0.0.1  cargo watch -x "test -- --nocapture"
//! ```

use once_cell::sync::Lazy;
use std::sync::{Arc, Mutex};
use tss_esapi::{tcti_ldr::TctiNameConf, Context, Result as TSSResult};

static CONTEXT: Lazy<Mutex<Context>> = Lazy::new(|| {
    Mutex::new(Context::new(TctiNameConf::from_environment_variable().unwrap()).unwrap())
});

#[cfg(test)]
mod tests {
    use super::*;
    use eyre::Result;
    use tss_esapi::{
        interface_types::algorithm::HashingAlgorithm, structures::SymmetricDefinition,
    };

    #[test]
    fn yada() -> Result<()> {
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

    //https://tpm2-software.github.io/2020/04/13/Disk-Encryption.html#pcr-policy-authentication---access-control-of-sealed-pass-phrase-on-tpm2-with-pcr-sealing
    #[test]
    fn seal_101() -> Result<()> {
        use tss_esapi::attributes::object::ObjectAttributesBuilder;
        use tss_esapi::constants::property_tag::PropertyTag;
        use tss_esapi::constants::session_type::SessionType;
        use tss_esapi::interface_types::algorithm::PublicAlgorithm;
        use tss_esapi::interface_types::resource_handles::Hierarchy;
        use tss_esapi::structures::{
            Digest, KeyedHashScheme, MaxBuffer, PublicBuilder, PublicKeyedHashParameters,
        };
        // Create a key
        let object_attributes = ObjectAttributesBuilder::new()
            .with_sign_encrypt(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .build()
            .expect("Failed to build object attributes");
        let key_pub = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
                KeyedHashScheme::HMAC_SHA_256,
            ))
            .with_keyed_hash_unique_identifier(Digest::default())
            .build()
            .unwrap();
        let mut context = CONTEXT.lock().unwrap();

        //let hmac = context
        //.execute_with_nullauth_session(|ctx| {
        //let key = ctx
        //.create_primary(Hierarchy::Owner, key_pub, None, None, None, None)
        //.unwrap();
        //Ok::<(), tss_esapi::Error>(())
        //})
        //.unwrap();

        let rev = context
            .get_tpm_property(PropertyTag::Revision)
            .expect("Wrong value from TPM")
            .expect("Value is not supported");
        assert_eq!(rev, 164);

        let session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .expect("Failed to create session")
            .expect("Received invalid handle");
        Ok(())
    }

    //#[test]
    //fn bla() {
    //use tss_esapi::{
    //interface_types::algorithm::HashingAlgorithm,
    //structures::{PcrSelectionListBuilder, PcrSlot},
    //tcti_ldr::TctiNameConf,
    //Context,
    //};
    //let mut context =
    //Context::new(TctiNameConf::from_environment_variable().expect("Failed to get TCTI"))
    //.expect("Failed to create Context");
    //// Create PCR selection list with slots in a bank
    //// that is going to be read.
    //let pcr_selection_list = PcrSelectionListBuilder::new()
    //.with_selection(
    //HashingAlgorithm::Sha256,
    //&[
    //PcrSlot::Slot0,
    //PcrSlot::Slot1,
    //PcrSlot::Slot2,
    //PcrSlot::Slot3,
    //PcrSlot::Slot4,
    //PcrSlot::Slot5,
    //PcrSlot::Slot6,
    //PcrSlot::Slot7,
    //PcrSlot::Slot8,
    //PcrSlot::Slot9,
    //PcrSlot::Slot10,
    //PcrSlot::Slot11,
    //PcrSlot::Slot12,
    //PcrSlot::Slot13,
    //PcrSlot::Slot14,
    //PcrSlot::Slot15,
    //PcrSlot::Slot16,
    //PcrSlot::Slot17,
    //PcrSlot::Slot18,
    //PcrSlot::Slot19,
    //PcrSlot::Slot20,
    //PcrSlot::Slot21,
    //],
    //)
    //.build()
    //.expect("Failed to build PcrSelectionList");
    ////let _pcr_data = tss_esapi::abstraction::pcr::read_all(&mut context, pcr_selection_list)
    ////.expect("pcr::read_all failed");
    //}
}
