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

pub mod cli;
pub mod luks;
pub mod tpm;
pub use self::tpm::pcr;
