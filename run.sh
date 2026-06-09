#!/usr/bin/env bash
# Launches build/main with the bundled libpqxx-7.10 so the existing binary
# (linked against libpqxx 7.10) runs even though the system now has libpqxx 8.0.
# Runs from the project root, so it loads the root ./config.json.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
export LD_LIBRARY_PATH="$HERE/build/libs${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec ./build/main "$@"
