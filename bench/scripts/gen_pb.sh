#!/usr/bin/env bash
#  Generate the Python protobuf+gRPC stubs that the mux_*_test.py
#  scripts import. Re-run if helloworld.proto changes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if ! python3 -c 'import grpc_tools.protoc' 2>/dev/null; then
   echo "FATAL: grpcio-tools not installed." >&2
   echo "    pip3 install --user grpcio grpcio-tools" >&2
   exit 2
fi

python3 -m grpc_tools.protoc \
   -I "$BENCH_DIR" \
   --python_out="$SCRIPT_DIR" \
   --grpc_python_out="$SCRIPT_DIR" \
   "$BENCH_DIR/helloworld.proto"

echo "generated:"
ls -la "$SCRIPT_DIR"/helloworld*.py
