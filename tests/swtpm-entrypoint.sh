#!/usr/bin/env bash

set -xeuo pipefail

############################
# Run the TPM SWTPM server #
############################
mkdir /tmp/tpmdir
chown tss:root /tmp/tpmdir
swtpm_setup --tpm2 \
    --tpmstate /tmp/tpmdir \
    --createek --decryption --create-ek-cert \
    --create-platform-cert \
    --pcr-banks sha1,sha256 \
    --display
swtpm socket --tpm2 \
    --tpmstate dir=/tmp/tpmdir \
    --flags startup-clear \
    --ctrl type=tcp,port=2322,bindaddr=0.0.0.0 \
    --server type=tcp,port=2321,bindaddr=0.0.0.0 \
    #--daemon
#tpm2-abrmd \
    #--logger=stdout \
    #--tcti=swtpm: \
    #--allow-root \
    #--session \
    #--flush-all
