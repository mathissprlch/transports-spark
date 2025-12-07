# AWS integration

How `grpc_ada` consumes the patched [AWS](https://github.com/AdaCore/aws),
what works, and what's blocked.

## Status

| Step | Status |
|------|--------|
| Trailer-emit patches written and applied | done — `vendor/aws-patches/{0001,0002}*.patch` |
| Patches verified clean against pinned upstream | done — `./vendor/bootstrap.sh` |
| Pre-generated `os_lib.ads` overlay for darwin-arm64 | done — `vendor/aws-overlays/darwin-arm64-openssl/os_lib.ads`, installed by bootstrap |
| `grpc_ada` depends on patched AWS | next up |
| `GRPC.Transport.HTTP2` body | next up |
| End-to-end helloworld over the wire | **blocked** |

## What was blocking

The upstream Alire `aws=25.2.0` crate's `Post_Fetch` runs `make setup`, which
introspects system constants to generate `os_lib.ads` (the package
`AWS.OS_Lib` renames). On macOS Apple Silicon the resulting file is truncated
to ~32 lines (just the header and a single `pragma Style_Checks`) — every
package body that does `with AWS.OS_Lib;` then fails to compile with

```
aws-os_lib.ads:30:01: error: cannot compile configuration pragmas with gcc
aws-os_lib.ads:30:01: error: use gnatchop -c to process configuration pragmas
```

This is reproducible without our patches: a fresh `alr init` + `depends-on aws
= "*"` hits the same wall. Our patches don't go anywhere near `os_lib`, so
they're not the cause.

## Path forward

Three options, in order of effort:

1. **Wait for / contribute the upstream fix.** The Alire AWS crate's setup
   probably needs a tweak for Apple Silicon (xoscons or equivalent invocation).
   Cost: external. Tracking: file an Alire issue.
2. **Vendor a pre-generated `os_lib.ads` per platform. ← what we did.**
   Generation pipeline (run once per platform; output committed):
   `clang -E -C` reads the SDK headers → `clang -S -O1 -fno-integrated-as`
   emits `.s` with marker comments → `xoscons` (an Ada tool AWS ships)
   parses those markers → writes `os_lib.ads` (an Ada package of
   platform constants like `EAGAIN : constant := 35`). GNAT then
   compiles that .ads as part of AWS. Clang is just a constant
   harvester — no clang-produced object file is ever shipped, only Ada
   source whose numbers came from the SDK. We need clang specifically
   because GNAT's bundled gcc-15 has a broken `stdio.h` shim on recent
   macOS; clang reads the SDK correctly, and `-fno-integrated-as`
   routes through Apple's `as` which preserves the `->CND:` marker
   comments xoscons relies on.

   Vendored overlays live under `vendor/aws-overlays/<platform>-openssl/`.
   `bootstrap.sh` detects the host and copies the right one into
   `vendor/aws/<target>/setup/src/`. Currently shipped: darwin-arm64.
   Add more platforms by re-running the same generation pipeline.
3. **Port what we need from AWS into `grpc_ada` directly.** AWS is a big
   library; we use a small slice (HTTP/2 server, TLS, sockets). Painful but
   possible. Last resort.

Once unblocked, integration is straightforward: `crates/grpc_ada/alire.toml`
gets a `depends-on { aws = "*" }` and `[[pins]]` entry pointing at
`vendor/aws`, plus we add the patches to a CI step.

## What we ship in the meantime

- `GRPC.Transport.HTTP2` package spec defining the AWS-callback adapter
  shape. The body raises `Program_Error with "pending AWS integration"`.
- Working architecture for everything else: status, metadata, framing,
  deadline, call, server dispatch, channel, message codegen, service codegen.
  All layered above an abstract `GRPC.Transport.Stream` so the HTTP/2
  implementation can drop in without touching higher layers.
- A `helloworld` example scaffolded to compile against the API; running it
  end-to-end is gated on AWS integration.

This means today the project is a *complete* gRPC + protobuf Ada library
*minus* the wire transport. The transport is the smallest layer (~300 lines
once written) and is unblocked by any of the three options above.
