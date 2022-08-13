# tpm-luks

## Get Started

```bash
# at basecamp
fswatch -o . | xargs -n1 -I{} ./sync.sh
# on remote (e.g. Metal) machine
# TCTI=device:/dev/tpm0 cargo watch -x "test -- --nocapture"
mkdir /tmp/mytpm
chown tss:root /tmp/mytpm
swtpm_setup --overwrite --tpmstate /tmp/mytpm/ --create-ek-cert --create-platform-cert --tpm2 \
--lock-nvram
swtpm socket --tpmstate dir=/tmp/mytpm --tpm2 --ctrl type=tcp,port=2322 --log level=20 --server type=tcp,port=2321
tpm2_startup --tcti swtpm -c
TCTI=swtpm:port=2321,host=127.0.0.1  cargo watch -x "test -- --nocapture"
```

License: MIT OR Apache-2.0
