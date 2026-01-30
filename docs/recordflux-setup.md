# RecordFlux setup

[RecordFlux](https://github.com/AdaCore/RecordFlux) is officially Linux-only
(RHEL, SUSE, Ubuntu LTS;
[reference](https://docs.adacore.com/live/wave/recordflux/html/recordflux_ug/10-introduction.html)).
On macOS the dev workflow runs RecordFlux inside a Linux container; the
generated SPARK Ada lands back in the host repo and compiles with the
host's Alire-managed GNAT.

Two parallel container paths are provided:

| Path | Tag | Runtime | Speed | Matches AdaCore CI |
|---|---|---|---|---|
| **arm64** (default) | `transports-spark/rflx:latest` | Docker | native, fast | no — Alire 2.1.0 + GNAT 15.x |
| **amd64** | `transports-spark/rflx:amd64` | Apple `container` | emulated, slower | yes — Alire 2.0.1 + GNAT 14.1.3 |

Use **arm64** for day-to-day generation. Use **amd64** when you need an
exact match to AdaCore's verified configuration (e.g. cross-checking
proof obligations against their CI).

## Quick start (arm64, default)

```sh
$ docker info >/dev/null   # any Docker engine on macOS works (colima, Docker Desktop)

$ scripts/rflx --version
RecordFlux 0.26.0
...

$ scripts/rflx generate \
      -d crates/mqtt_core/generated \
      crates/mqtt_core/specs/mqtt.rflx
```

First invocation builds the image (~30 min on Apple Silicon).
Subsequent runs reuse the cached image.

## Quick start (amd64, AdaCore-canonical)

```sh
$ container --version
container CLI version 0.12.x ...

$ scripts/rflx-amd64 --version
RecordFlux 0.26.0
...
```

Apple's `container` runs the image on Apple's Virtualization Framework
with linux/amd64 emulation. First build takes ~30-40 min.

## Docker shell

```sh
$ scripts/rflx-shell
root@host:/workspace# rflx --help
```

For the amd64 path, drop into a shell directly:

```sh
$ container run --rm -it --platform linux/amd64 \
      --entrypoint /bin/bash transports-spark/rflx:amd64
```

## What's in the container

`tools/recordflux/Dockerfile` (arm64) and
`tools/recordflux/Dockerfile.amd64` (amd64) build from RecordFlux's
source tree using AdaCore's documented dev path
(`make install_gnat; eval $(make printenv_gnat); make install`).

Stack:

- Ubuntu 24.04 LTS (arm64) / 22.04 LTS (amd64).
- Alire 2.1.0 aarch64-linux (arm64) / 2.0.1 x86_64-linux (amd64).
- GNAT 15.2.1 + gprbuild 25.0.1 (arm64) / GNAT 14.1.3 + gprbuild 22.0.1 (amd64),
  provisioned by Alire under `build/alire/`.
- Rust 1.77 (Langkit's parser-generator).
- Node.js 20 (RecordFlux dev guide requirement).
- Poetry 2.x for the Python install.
- RecordFlux v0.26.0 from source, installed into `/opt/rflx-src/.venv/`.

The image is fat (~7 GB) but built once and cached.

## Day-to-day

- Edit `.rflx` specs on the host (any editor).
- Run `scripts/rflx generate ...` to regenerate SPARK Ada — output is
  checked in under `crates/<core>/generated/` so the regular Alire
  build doesn't depend on RecordFlux being available.
- Run the regular Ada build (`make build` / `alr build`) on the host
  via Alire's GNAT — fast, native arm64, no container needed.

## Patches we apply to RecordFlux's build

The Dockerfiles patch RecordFlux's Makefile in two places:

1. `install: $(RFLX) rapidflux_devel` → `install: $(RFLX)`. Drops the
   coverage/audit/mutation cargo dev tools (cargo-llvm-cov, cargo-audit,
   cargo-mutants) — they're test-time only and slow to build.
2. `alr -n with aunit gnatcoll_iconv gnatcoll_gmp` → `... libgpr`.
   `gnatcoll_projects.gpr` does `with "gpr";` and the default deps don't
   pull `libgpr` transitively in current Alire indices.

We also prepend the umbrella, `core/`, `projects/`, `minimal/` subdirs
of the deployed gnatcoll to `GPR_PROJECT_PATH` before running `make
install`. Alire's `printenv` only adds `core/` for gnatcoll, but
`librflxlang` transitively imports the others.

## Tests

The build runs a smoke check (`rflx --version`) but skips RecordFlux's
full `make test` suite — several tests assume a non-root user and fail
in containers (e.g. `test_install_permission_denied`,
`test_validate_output_not_writable`). To run the full suite manually:

```sh
$ scripts/rflx-shell
# inside container:
$ cd /opt/rflx-src && make test
```

Expect ~10 root-environment failures; the meaningful tests
(end-to-end, compilation, language) pass.

## Reproducibility

Pin the Ubuntu base, Alire version, GNAT version, RecordFlux version
in the Dockerfiles. To upgrade RecordFlux: bump `RECORDFLUX_VERSION` in
both Dockerfiles, rebuild, regenerate any checked-in SPARK that needs
to track the new version.
