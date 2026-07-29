#!/bin/sh

# Compatibility entry point. New automation should use macos-shipping-lane.sh.
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
exec "$script_dir/macos-shipping-lane.sh" "$@"
