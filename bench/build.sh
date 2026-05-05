#!/usr/bin/env bash
#  Build the Go side of the bench (server + client). The Ada side
#  is built separately via `alr build` in crates/examples.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/go"

mkdir -p ../bin
go build -o ../bin/go_server ./server
go build -o ../bin/go_client ./client

echo "built:"
ls -la ../bin/go_server ../bin/go_client
