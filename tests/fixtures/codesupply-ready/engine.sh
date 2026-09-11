#!/bin/sh
# Synthetic engine: ignores scan arguments and emits only the committed report.
# It never reads or executes the target. SecureFlow hashes the target separately.
set -eu
exec cat "$(dirname "$0")/engine-report.json"
