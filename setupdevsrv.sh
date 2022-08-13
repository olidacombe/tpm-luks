#!/bin/bash

set -xeuo pipefail

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# to run cargo test in https://github.com/parallaxsecond/rust-tss-esapi
apt-get update
apt-get install build-essential
apt-get install pkg-config
apt-get install libtss2-dev tss2
apt-get install swtpm{,-tools}
