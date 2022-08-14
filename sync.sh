#!/bin/bash

set -xeuo pipefail

rsync -Pav --exclude={target,.git} . $1
