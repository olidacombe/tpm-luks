use cryptsetup_rs::api::LuksCryptDevice;
use cryptsetup_rs::open;
use either::for_both;
use std::fmt::Debug;
use std::path::PathBuf;
use thiserror::Error;
use tss_esapi::structures::SensitiveData;

#[derive(Error, Debug)]
pub enum LuksError {
    #[error(transparent)]
    CryptSetup(#[from] cryptsetup_rs::Error),
}

pub type Result<T, E = LuksError> = core::result::Result<T, E>;

pub struct LuksManager {
    dev: Box<dyn LuksCryptDevice>,
}

impl LuksManager {
    pub fn activate(&mut self, name: &str, key: &SensitiveData) -> Result<&mut Self> {
        self.dev.activate(name, key)?;
        Ok(self)
    }
    pub fn add_key(
        &mut self,
        key: SensitiveData,
        prev_key: Option<SensitiveData>,
    ) -> Result<&mut Self> {
        let keyslot =
            self.dev
                .add_keyslot(key.value(), prev_key.as_ref().map(|k| k.value()), None)?;
        log::debug!("Added key to slot {}", keyslot);
        Ok(self)
    }
    pub fn new(path: &PathBuf) -> Result<Self> {
        log::debug!("Attempting to get LUKS device `{}`", path.display());
        let dev = open(path)?.luks()?;
        let dev: Box<dyn LuksCryptDevice> = for_both!(dev, d => Box::new(d));
        Ok(Self { dev })
    }
    pub fn open(&mut self, key: SensitiveData, name: &str) -> Result<&mut Self> {
        self.dev.activate(name, key.value())?;
        Ok(self)
    }
}

pub fn add_key_to_device(
    device_path: &PathBuf,
    key: SensitiveData,
    prev_key: Option<SensitiveData>,
) -> Result<()> {
    let mut manager = LuksManager::new(device_path)?;
    manager.add_key(key, prev_key)?;
    Ok(())
}

pub fn open_device(device_path: &PathBuf, name: &str, key: SensitiveData) -> Result<()> {
    log::debug!(
        "Attempting to open LUKS device `{}` as `{}`",
        device_path.display(),
        name
    );
    let mut manager = LuksManager::new(device_path)?;
    manager.open(key, name)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptsetup_rs::api::CryptDeviceFormatBuilder;
    use cryptsetup_rs::{crypt_device_type, crypt_rng_type, CryptDeviceType};
    use eyre::Result;
    use std::path::PathBuf;
    use std::process::Command;
    use tempfile::{Builder, TempDir};
    use uuid::Uuid;

    struct TestContext {
        _dir: TempDir,
        file: PathBuf,
    }

    impl TestContext {
        fn new(name: String) -> TestContext {
            let _ = env_logger::builder().is_test(true).try_init();
            cryptsetup_rs::enable_debug(true);
            let dir = Builder::new().prefix(&name).tempdir().expect("Tempdir!");
            let file = dir.path().join(format!("{}.image", name));
            TestContext { file, _dir: dir }
        }

        fn new_crypt_device(&self) -> CryptDeviceFormatBuilder {
            let fallocate_status = Command::new("fallocate")
                .arg("-l")
                .arg("20MiB")
                .arg(&self.file)
                .status()
                .unwrap();
            if !fallocate_status.success() {
                panic!("Failed to create disk image at {}", &self.file.display());
            }

            cryptsetup_rs::format(&self.file).unwrap()
        }
    }

    fn create_new_luks1_manager() -> Result<(LuksManager, TestContext)> {
        let ctx = TestContext::new("new_luks1_cryptdevice".to_string());
        let uuid = Uuid::new_v4();

        let device_format = ctx
            .new_crypt_device()
            .rng_type(crypt_rng_type::CRYPT_RNG_URANDOM)
            .iteration_time(42);

        let mut dev = device_format.luks1("aes", "xts-plain", "sha256", 256, Some(&uuid))?;

        assert_eq!(dev.device_type(), crypt_device_type::LUKS1);

        dev.add_keyslot(b"thunderdome", None, None)?;

        let manager = LuksManager { dev: Box::new(dev) };

        Ok((manager, ctx))
    }

    fn create_new_luks2_manager() -> Result<(LuksManager, TestContext)> {
        let ctx = TestContext::new("new_luks2_cryptdevice".to_string());

        let mut dev = ctx
            .new_crypt_device()
            .luks2("aes", "xts-plain", 256, None, None, None)
            .label("test")
            .argon2i("sha256", 200, 1, 1024, 1)
            .start()?;

        assert_eq!(dev.device_type(), crypt_device_type::LUKS2);

        dev.add_keyslot(b"thunderball", None, None)?;

        let manager = LuksManager { dev: Box::new(dev) };

        Ok((manager, ctx))
    }

    #[test]
    fn add_key_luks1() -> Result<()> {
        let key = SensitiveData::try_from("Insecure".as_bytes().to_vec())?;

        let (mut dev, _ctx) = create_new_luks1_manager()?;
        dev.add_key(key, None)?;

        Ok(())
    }

    #[test]
    fn add_key_luks2() -> Result<()> {
        let key = SensitiveData::try_from("Insecure".as_bytes().to_vec())?;

        let (mut dev, _ctx) = create_new_luks2_manager()?;
        dev.add_key(key, None)?;

        Ok(())
    }
}
