#!/usr/bin/env bash
# Build the baremetal_pic PoC for ARM Cortex-M3 (TI Stellaris LM3S811).
# Wraps gprbuild with the right toolchain + runtime + GPR_PROJECT_PATH
# so the PoC builds independently of the host's Alire workspace
# state.

set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
ARM_TOOLCHAIN_DIR=$(ls -d "$HOME/.local/share/alire/toolchains/gnat_arm_elf_"* 2>/dev/null | head -1)
GPR_TOOLCHAIN_DIR=$(ls -d "$HOME/.local/share/alire/toolchains/gprbuild_"* 2>/dev/null | head -1)

if [[ -z "$ARM_TOOLCHAIN_DIR" ]]; then
  echo "FATAL: gnat_arm_elf toolchain not found." >&2
  echo "Install with:  alr toolchain --select --disable-assistant gnat_arm_elf" >&2
  echo "(The toolchain selection is global; you can switch back to" >&2
  echo " gnat_native afterwards — both can live side by side.)" >&2
  exit 2
fi

export PATH="$GPR_TOOLCHAIN_DIR/bin:$ARM_TOOLCHAIN_DIR/bin:$PATH"
export GPR_PROJECT_PATH="$REPO/crates/rflx_runtime:$REPO/crates/http2_core"

cd "$REPO/crates/baremetal_pic"
exec gprbuild --target=arm-eabi --RTS=light-lm3s -P baremetal_pic.gpr "$@"
