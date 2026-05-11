# tls_interop crate — design notes

## Why a separate crate

`tls_interop` + `tls_interop_peers` are currently in `crates/examples/`.
They're 2100 LOC and growing (bench integration, XFAIL support, JSON
output). They don't belong in `examples/` because:

1. They have their own test-infrastructure dependencies (GNAT.OS_Lib,
   GNATCOLL.JSON, process management) that other examples don't need.
2. They're the primary quality gate — the interop matrix is what
   determines release readiness. Release tooling shouldn't live in
   `examples/`.
3. The bench mode adds stats computation, multi-run orchestration,
   and result formatting that's test-infra, not demo code.
4. They'll grow further: throughput bench, MQTT-over-TLS bench,
   gRPC-over-TLS bench, CI integration, result-file management.

## Proposed layout

```
crates/tls_interop/
├── alire.toml
├── tls_interop.gpr
└── src/
    ├── tls_interop.adb          -- main: CLI, output formatting, bench loop
    ├── tls_interop-cells.ads    -- Cell_Result, Run_Cell, cell timeout
    ├── tls_interop-cells.adb
    ├── tls_interop-peers.ads    -- Peer_Kind, Feature_Kind, Build_Command,
    │                            -- Peer_Supports, Ada_Supports, Ada_Can_Attempt
    ├── tls_interop-peers.adb
    ├── tls_interop-bench.ads    -- Bench_Run, stats (mean/sd/min/max)
    ├── tls_interop-bench.adb
    └── tls_interop-output.ads   -- Md_Peer_Header, Md_Feature_Row, Json output
        tls_interop-output.adb
```

## Split rationale

Current `tls_interop.adb` is 1058 lines in one procedure with nested
declarations. The split follows the existing logical sections:

| Current section | New package | Responsibility |
|---|---|---|
| `Run_Cell` + port allocation + cell timeout | `Tls_Interop.Cells` | Spawn peer + Ada processes, measure wall-clock |
| `Peer_Kind`, `Feature_Kind`, `Build_Command`, `Peer_Supports`, `Ada_Supports` | `Tls_Interop.Peers` | Per-peer CLI construction, feature coverage map |
| `Md_Peer_Header`, `Md_Feature_Row`, `Image_Time`, JSON output | `Tls_Interop.Output` | Formatting (Markdown + JSON) |
| Bench loop, stats computation, per-run collection | `Tls_Interop.Bench` | Multi-run orchestration, mean/sd/min/max |
| CLI parsing, Init_Run, main loop | `tls_interop.adb` (main) | Top-level orchestration |

## Dependencies

```
tls_interop.gpr
├── depends on: gnatcoll (JSON output)
├── depends on: tls_core.gpr (only for fixture paths / type references)
└── no dependency on examples.gpr or any protocol crate
```

The interop binary calls `tls_cli` as a subprocess — it doesn't link
against the TLS library. This means `tls_interop.gpr` is lightweight:
just GNATCOLL + GNAT runtime.

## Migration steps

1. Create `crates/tls_interop/` with GPR, alire.toml.
2. Move `tls_interop.adb` → `src/tls_interop.adb`, rename nested
   procedures to child packages.
3. Move `tls_interop_peers.ads/adb` → `src/tls_interop-peers.ads/adb`
   (rename package from `Tls_Interop_Peers` to `Tls_Interop.Peers`).
4. Extract `Run_Cell` + helpers → `Tls_Interop.Cells`.
5. Extract output formatters → `Tls_Interop.Output`.
6. Extract bench loop → `Tls_Interop.Bench`.
7. Update `examples.gpr` to remove the two source files + gnatcoll dep.
8. Update Makefile `TLS_INTEROP` path.
9. Verify: `make tls-interop`, `make tls-bench-quick` still work.

## Rules

- Max ~300 lines per file (per CLAUDE.md feedback rule).
- `Tls_Interop.Cells.Run_Cell` is the unit-test surface — its
  signature shouldn't change when bench or output changes.
- `BUILD_MODE` scenario variable propagates through the GPR.
- Bench mode should be optional at compile time (conditional `with`
  or always-linked but gated by CLI flag — current approach is fine).
- Fixtures path stays relative to repo root (hardcoded in Peers),
  discovered via `Repo` constant derived from the binary's location.
