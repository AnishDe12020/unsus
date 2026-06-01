#!/bin/sh
set -eu

if [ "$#" -eq 0 ]; then
  echo "No sandbox command provided" >&2
  exit 64
fi

exec "$@"
