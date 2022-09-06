# tpm-luks

## Get Started

### On Linux with hardware TPM:
```bash
make dev-local
```

### On something else, e.g. Mac:
```bash
make dev
```

> I'm currently just trying to re-enact this:
```bash
#!/usr/bin/env bash

set -eou pipefail

docker kill swtpm || true
docker run -d --rm --name swtpm -p 2321:2321 -p 2322:2322 olidacombe/swtpm
sleep 2

rm -f prim.ctx.log \
      session.dat \
      policy.dat

tpm2_createprimary -C e -g sha256 -G ecc -c prim.ctx | tee prim.ctx.log
tpm2_pcrread -o pcr.dat "sha1:0,1,2,3"

tpm2_startauthsession -S session.dat
tpm2_policypcr -S session.dat -l "sha1:0,1,2,3" -f pcr.dat -L policy.dat
tpm2_flushcontext session.dat

echo hi | tpm2_create -Q -u key.pub -r key.priv -C prim.ctx -L policy.dat -i-
tpm2_flushcontext -t
tpm2_load -C prim.ctx -u key.pub -r key.priv -n unseal.key.name -c
unseal.key.ctx

tpm2_startauthsession --policy-session -S session.dat
tpm2_policypcr -S session.dat -l "sha1:0,1,2,3" -f pcr.dat -L policy.dat

tpm2_unseal -psession:session.dat -c unseal.key.ctx
tpm2_flushcontext session.dat
```

License: MIT OR Apache-2.0
