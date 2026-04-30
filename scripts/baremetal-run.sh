#!/usr/bin/env bash
# Run the bare-metal PoC binary in QEMU.
#
# Default: runs to "halting in idle loop" then auto-terminates after
# 5 seconds (the ELF spins forever; we kill it from outside).
#
# Pass --interactive (or -i) to disable the timeout, useful for
# debugging.

set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
ELF=$REPO/crates/baremetal_pic/obj/baremetal_pic

if [[ ! -f "$ELF" ]]; then
  echo "FATAL: $ELF not found. Run scripts/baremetal-build.sh first." >&2
  exit 2
fi

if ! command -v qemu-system-arm >/dev/null 2>&1; then
  echo "FATAL: qemu-system-arm not on PATH." >&2
  echo "Install with: brew install qemu  (macOS)" >&2
  exit 2
fi

TIMEOUT_SEC=5
if [[ "${1:-}" == "-i" || "${1:-}" == "--interactive" ]]; then
  TIMEOUT_SEC=0
  shift
fi

if [[ "$TIMEOUT_SEC" == "0" ]]; then
  exec qemu-system-arm -M lm3s6965evb -nographic -kernel "$ELF" "$@"
else
  # Use perl one-liner for cross-platform timeout (BSD timeout is
  # different from GNU's; macOS has neither by default).
  qemu-system-arm -M lm3s6965evb -nographic -kernel "$ELF" "$@" &
  QEMU_PID=$!
  sleep "$TIMEOUT_SEC"
  kill "$QEMU_PID" 2>/dev/null || true
  wait "$QEMU_PID" 2>/dev/null || true
fi
