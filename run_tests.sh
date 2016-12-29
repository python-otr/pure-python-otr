#!/bin/sh -eu

# the directory that this script is in
SRC_ROOT=$(cd -P $(dirname "$0") && pwd)
export PYTHONPATH="$SRC_ROOT/src"

python tests/testBasic.py
