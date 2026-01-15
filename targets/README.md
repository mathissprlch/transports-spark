# Targets

Board-specific configuration (Ada runtime profile, linker scripts,
memory layout) for cross-compilation. Populated as bare-metal work
begins.

Planned:

- `stm32f4/` — STM32 Cortex-M class. `light-tasking` runtime,
  bounded everything.
- `zynq7000/` — Xilinx Zynq-7000 (dual Cortex-A9 + FPGA fabric).
  Bare-metal or RTOS on the PS side, not Linux.
