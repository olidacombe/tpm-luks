//! This is intended for encapsulating a common use case of leveraging
//! a TPM device to decrypt LUKS volumes in a single statically-compiled
//! binary.
//!
//! I use it in an `initramfs-tools` `init-premount` script to decrypt
//! a LUKS-encrypted array when PCRs match a particular policy at boot
//! time.
//!
//! The binary is used for [sealing](#sealing) and [unsealing](#unsealing).
//!
//! Please see the command help for guidance on usage:
//!
//! ```bash
//! > tpm-luks -h
//! Automate LUKS keys stored in TPM
//!
//! Usage: tpm-luks [OPTIONS] <COMMAND>
//!
//! Commands:
//!   seal    Generate a passphrase, seal in the TPM, and add to a LUKS keyslot
//!   unseal  Unseal a key from the TPM and use to open a LUKS device
//!   digest  Show PCR digest for current running system
//!   help    Print this message or the help of the given subcommand(s)
//!
//! Options:
//!   -p, --pcrs <PCR List>  PCRs to use for sealing/unsealing [default: sha1:0,1,2,3,4,7]
//!   -T, --tcti <TCTI>      TPM device specified in TCTI format [env: TCTI=] [default: device:/dev/tpmrm0]
//!   -h, --help             Print help information
//!   -V, --version          Print version information
//! ```
//!
//! ## Sealing
//!
//! The `sealing` process in the case of `tpm-luks` describes the following
//! steps performed as a single action:
//!
//! + generate a random disk-encryption password (not returned to the caller)
//! + store that password in the TPM, sealed against a PCR policy
//! + ~~extend the PCRs so the password can't be immediately retrieved~~ (TODO?)
//! + add the generated password as a decryption key for a specified LUKS volume
//!
//! How to use for sealing:
//!
//! ```bash
//! > tpm-luks seal /dev/my_device
//! ```
//!
//! This will perform the sealing process on `/dev/my_device` and requires a valid
//! `PASSPHRASE` environment variable to be set to authorize the LUKS operation of
//! adding a keyslot.
//!
//! To specify different registers from the default, use the global `-p` option (see above).
//!
//! To specify a custom digest (I seal from an in-memory OS before
//! imaging so the PCR digest at that time is not useful) you can supply the `-D` option after
//! `seal`:
//!
//! ```bash
//! > tpm-luks seal -h
//! Generate a passphrase, seal in the TPM, and add to a LUKS keyslot
//!
//! Usage: tpm-luks seal [OPTIONS] <dev>
//!
//! Arguments:
//!   <dev>  LUKS device path
//!
//! Options:
//!   -D, --pcr-digest <digest>  PCR digest
//!   -H, --handle <handle>      Storage handle for keeping the LUKS key in the TPM [default: 0x81000000]
//!   -h, --help                 Print help information
//! ```
//!
//! E.g.
//!
//! ```bash
//! > tpm-luks -p sha1:0,1,2,3,4,5,6,7 seal \
//! -D 0123456789012345678901345678901234567890123456789012345789012345 \
//! /dev/md127p2
//! ```
//!
//! ## Unsealing
//!
//! This will:
//! + try to retrieve a passphrase from the TPM, which will only work if the policy specified during the `seal` operation is satisfied by the current PCR values.
//! + extend the PCRs so retrieval cannot be repeated
//! + try to decrypt the specified volume using the retrieved passphrase (never returned to the caller)
//!
//! Again, you can supply a `-p` option before `unseal` (much like during the `seal` operation), as
//! well as any `unseal`-specific options after `unseal`:
//!
//! ```bash
//! > tpm-luks unseal  -h
//! Unseal a key from the TPM and use to open a LUKS device
//!
//! Usage: tpm-luks unseal [OPTIONS] <dev> <name>
//!
//! Arguments:
//!   <dev>   LUKS device path
//!   <name>  LUKS device name
//!
//! Options:
//!   -H, --handle <handle>  TPM persistent storage handle from which to retrieve the LUKS key [default: 0x81000000]
//!   -h, --help             Print help information
//! ```
//!
//! # Build / Push
//!
//! ```bash
//! make build
//! make push
//! ```
//!
//! # Development
//!
//! to start development run
//! ```bash
//! # We use Lima if we're on aarch64
//! # We need ssh access to get the private repositories
//! eval `ssh-agent`
//! ssh-add /Users/..../.ssh/...
//! cd /Users/..../tpm-luks
//! sudo apt install build-essential pkg-config libtss2-dev libcryptsetup-dev
//! curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh # install rust
//! export PATH=$HOME/.cargo/bin:$PATH
//! make init # install development requirements
//! make readme
//! cargo build
//! ```
//!
//! For a more rapid development cycle, it's recommended to experiment on an appropriate machine.
//! The flow involves writing dummy values for PCRs
//!
//! 1. `ssh` into an appropriate box
//! 1. Find the partition that hosts the encrypted root with `lsblk`
//! 1. sudo `tpm-luks -p sha1:0,1,2,3,4,5,6,7 seal /dev/md127p4`
//! 1. test by running `make-luks-image.sh` and `losetup -f`
//! 1. To seal `sudo SEAL_PCRS=sha1:0,1,2,3,4,5,6,7 ENC_DEVICE=/dev/loop0 ENC_ROOT=crypto ./initramfs.sh`
//! 1. To clean up run `sudo cryptsetup remove crypty`
//!
//! > TODO a proper CONTRIBUTING.md
//!
//! ## On Linux with hardware TPM:
//! ```bash
//! > make dev-local
//! ```
//!
//! ## On something else, e.g. Mac:
//! ```bash
//! > make dev
//! ```

pub mod cli;
pub mod luks;
pub mod tpm;
pub use self::tpm::pcr;
