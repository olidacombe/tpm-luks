use cryptsetup_rs::api::{
    Keyslot, Luks1CryptDeviceHandle, Luks2CryptDeviceHandle, LuksCryptDevice,
};
use either::Either;
use thiserror::Error;
use tss_esapi::structures::SensitiveData;

#[derive(Error, Debug)]
pub enum LuksError {
    #[error(transparent)]
    CryptSetup(#[from] cryptsetup_rs::Error),
}

pub type Result<T, E = LuksError> = core::result::Result<T, E>;

pub struct LuksManager {
    device: Box<dyn LuksCryptDevice>,
}

impl LuksManager {
    fn add_key(&mut self, key: SensitiveData) -> Result<Keyslot> {
        Ok(self.device.add_keyslot(key.value(), None, None)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eyre::Result;

    #[test]
    fn add_key() -> Result<()> {
        Ok(())
    }
}
