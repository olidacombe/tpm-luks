#!/bin/bash

set -xeuo pipefail

rsync -Pav --exclude=target . tipi:tpm-luks/
