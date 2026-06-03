#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <snapshot-file> <destination>" >&2
  exit 64
fi

cp -a "$1" "$2"
