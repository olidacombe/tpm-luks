# tpm-luks

## Get Started

```bash
# at basecamp
fswatch -o . | xargs -n1 -I{} ./sync.sh
# on remote (e.g. Metal) machine
TCTI=device:/dev/tpm0 cargo watch -x "test -- --nocapture"
```

License: MIT OR Apache-2.0
