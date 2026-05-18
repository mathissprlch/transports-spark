# transports-spark

SPARK 2014 transport stack — TLS 1.3, HTTP/2 (+ HPACK, + gRPC),
MQTT 3.1.1, HTTP/1.1 — implemented from scratch, no third-party
C libraries on the data path.

## The idea

Take a well-defined, human-readable spec — RFC 8446, RFC 9113,
RFC 7541, OASIS MQTT 3.1.1, the protobuf wire format —
transform it into a RecordFlux `.rflx` spec for the binary
frames and the protocol state machine, and let the RFLX
toolchain generate SPARK Ada that is **AoRTE-proven by
construction**. Then wrap the generated parser / FSM in a
hand-written SPARK layer carrying a functional `Post` that
cites the RFC clause (or the HACL\* / miTLS lemma) it
implements, and let gnatprove discharge the proof.

That's the loop: **spec → RFLX → AoRTE → SPARK wrapper with
functional Post → gnatprove**. A reader can trace any byte in
the stack from the `.rflx` source through the wrapper's `Post`
to the RFC paragraph it satisfies. Walkthrough in
`docs/wrapper-pattern.md`; the bug log in `docs/bug-log.md`
classifies every interop-found bug along this same line —
"we misread the spec" vs "we need a stronger Post" turn out to
be the dominant failure modes.

Everything else still matters, in roughly decreasing order:

- **No third-party C libraries on the data path.** SPARK 2014
  end-to-end; `Tcp_Transport` wraps `GNAT.Sockets` as the only
  documented `SPARK_Mode (Off)` exception (`docs/conventions.md`
  §0d).
- **Code-gen as much as possible.** `rflx convert iana` derives
  the IANA TLS / HTTP/2 enum tables; `protoc-gen-grpc-ada`
  generates Ada from `.proto`. Every line we don't hand-write
  is one less line that can drift from the spec.
- **Port, don't invent.** Every crypto primitive ports a HACL\*
  `Hacl.Spec.*.fst` line-by-line as a SPARK ghost function;
  protocol logic mirrors miTLS contract structures (§0c, §5).
- **Production-default scope.** Only ship what real peers
  (openssl, gnutls, mbedtls, rustls, Go, BoringSSL, wolfSSL)
  accept by default — RFC defining a feature isn't enough (§0a).
- **Determinism-friendly runtime.** No garbage collector, no
  per-operation heap allocation (caller-owned buffers), bounded
  stack depth. Runs on hosted Linux/macOS today; bare-metal
  Cortex-M port is in progress (memory-loopback Transport +
  QEMU bring-up landed; protocol stacks not yet wired through).

## What's in here

- **TLS 1.3** (RFC 8446) — cert + resumption-PSK; AES-GCM,
  ChaCha20-Poly1305; X25519, P-256; ECDSA-P256, RSA-PSS
  (verify); HelloRetryRequest, NewSessionTicket, KeyUpdate,
  alerts, multi-record reassembly.
- **HTTP/2** (RFC 9113) — frame layer, HPACK (RFC 7541),
  multi-stream server, full §6.9 outbound flow control via an
  RFLX session machine.
- **MQTT 3.1.1** (OASIS) — client + broker, QoS 0/1/2, retained
  messages, persistent sessions, will/testament.
- **gRPC** on top of HTTP/2 (framing + protobuf codec +
  `protoc-gen-grpc-ada` plugin).
- **HTTP/1.1** minimal server.

## Proof results

`gnatprove --level=4` across every SPARK crate (2026-05-16 sweep).
Raw per-crate `gnatprove.out` under `bench/proof-results/`;
aggregated summary at `docs/proof-results.txt`. Deduped by
Ada package + source location (per-crate runs overlap on the
shared closure):

| Package family | Subprograms (proved / total) | VCs (proved / total) | %  |
|---|---:|---:|---:|
| `Tls_Core.*` | 117 / 160 | 4,439 / 4,716 | 94% |
| `RFLX.*` (generated) | 3,111 / 3,184 | 23,963 / 24,032 | 100% |
| `Http2_Core.*` | 33 / 54 | 928 / 1,061 | 87% |
| `Mqtt_Core.*` | 4 / 39 | 656 / 755 | 87% |
| `Grpc_Core.*` | 4 / 4 | 96 / 96 | 100% |
| **Total** | **3,269 / 3,441** | **30,082 / 30,660** | **98%** |

Headline including flow-analysis checks: **37,861 / 38,739
proved (98%), 878 unproved**. 216 SPARK units analysed.

Audit (§0d) clean: 0 `SPARK_Mode (Off)` outside the
GNAT.Sockets boundary, 0 `pragma Assume`, 0 stub `Spec_*`
ghosts, 0 `pragma Annotate (GNATprove, …)` justifications. The
prover-emitted warnings under `--proof-warnings=on` flag only
a handful of dead local-array initializations (cosmetic, no
soundness implication).

The unproved VCs cluster in the hand-rolled wire walkers that
the v0.5.x roadmap lifts to the wrapper pattern: `Tls_Core.Hello`
(224 gap), `Mqtt_Core.Wire` (90), `Http2_Core.Hpack` (70 across
the encoder + dynamic table + string-literal + Huffman subtree),
`Tls_Core.X509` (23), `Tls_Core.Ext_Walk_Rflx` (10). Roughly
80 % of the total gap. The rest are RFLX auto-generator
length-setter quirks. `Http1_Core.*` shows 0 VCs because its
body is not currently in SPARK proof scope (the `.adb`s don't
assert `SPARK_Mode`); `Tls_Transport.*` is the documented
`SPARK_Mode (Off)` GNAT.Sockets boundary.

Reproduce with `make prove` (~2-3 h cold on 10-core M-series at
`--level=4`). For per-subprogram detail (🟢 all proved / 🟡
partial / ⚪ skipped — straight from `gnatprove/gnatprove.out`,
no annotation layer), see `docs/proof-coverage.md` — collapsible
tree per crate / package / subprogram, regenerated via `make
prove-coverage`. The `make prove-quick` target is the level=1
inner-loop variant for iterative SPARK editing.

## Interop matrix

Seven production TLS 1.3 implementations. **PASS** end-to-end,
**NI-3P** peer CLI doesn't expose the feature (path works the
other direction), **XFAIL** known Ada-side gap.

| Feature | openssl | gnutls | mbedtls | wolfSSL | Go | rustls | bssl |
|---|---|---|---|---|---|---|---|
| cert-ec-chacha20  | ✅/✅ | ✅/✅ | ✅/✅ | NI-3P/NI-3P | ✅/✅ | NI-3P/✅ | NI-3P/✅ |
| cert-ec-aes128    | ✅/✅ | ✅/✅ | ✅/✅ | NI-3P/NI-3P | ✅/✅ | NI-3P/✅ | NI-3P/✅ |
| cert-ec-aes256    | ✅/✅ | ✅/✅ | ✅/✅ | NI-3P/NI-3P | ✅/✅ | NI-3P/✅ | NI-3P/✅ |
| cert-rsa-pss-sha256 | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL |
| psk-chacha20      | ✅/✅ | ✅/✅ | ✅/✅ | NI-3P | NI-3P | NI-3P | NI-3P |
| psk-aes128        | ✅/✅ | ✅/✅ | ✅/✅ | NI-3P | NI-3P | NI-3P | NI-3P |
| psk-aes256        | XFAIL | ✅/✅ | ✅/✅ | NI-3P | NI-3P | NI-3P | NI-3P |
| psk-resumption    | ✅/XFAIL | NI-3P | NI-3P | NI-3P | NI-3P | NI-3P | NI-3P |
| hello-retry       | ✅/✅ | ✅/✅ | ✅/✅ | NI-3P/NI-3P | ✅/✅ | NI-3P/✅ | NI-3P/✅ |
| sni+alpn          | ✅/✅ | ✅/✅ | ✅/✅ | NI-3P/NI-3P | ✅/✅ | NI-3P/✅ | NI-3P/✅ |
| key-update        | ✅/✅ | ✅/✅ | ✅/✅ | NI-3P/NI-3P | ✅/✅ | NI-3P/✅ | NI-3P/✅ |
| zero-rtt          | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL |

Zero real FAILs. XFAILs: RSA-PSS **sign** not yet ported
(verify is platinum-proven; chain validation works);
PSK-external AES-256 matrix glue pending; server-side
resumption-accept pending; 0-RTT out of scope per §0a.
Reproduce: `make tls-interop`.

## Performance

Release build, loopback, single Go gRPC client driving the Ada
gRPC server end-to-end (`protobuf_core → grpc_core → http2_core
→ TCP`). Apple Silicon dev box, single TCP connection, no warmup.

| Workload | Ada RPCs/s | Ada p50 | Ada p99 | Go RPCs/s | Go p50 |
|---|---:|---:|---:|---:|---:|
| unary, 4 B            | 1029 |  951 µs | 1164 µs | 14 493 |  65 µs |
| unary, 1 KiB          | 1037 |  951 µs | 1085 µs | 14 124 |  67 µs |
| unary, 8 KiB          | 1008 |  976 µs | 1124 µs | 12 377 |  76 µs |
| server-stream, 5 msgs |  999 |  984 µs | 1163 µs | 12 539 |  76 µs |
| client-stream, 8 msgs |  322 | 3071 µs | 3392 µs | 11 852 |  81 µs |
| bidi, 5 msgs each way |  370 | 2641 µs | 3052 µs |  3 097 | 318 µs |

Two scaling shapes worth noting:

- **Per-RPC throughput is flat across payload size** (~1000
  RPCs/s at 4 B / 1 KiB / 8 KiB). The cost is per-RPC (stream
  open, HPACK, trailer), not per-byte — useful bytes ride free
  above the fixed floor, so bytes/sec scales linearly with
  payload and the gap to Go narrows accordingly.
- **Long-lived streams collapse per-message cost ~5×.**
  Unary RPC: ~950 µs/msg. Server-stream-5: ~197 µs/msg.
  Bidi-5+5: ~264 µs/direction-msg. That's the regime this stack
  is built for — a controller holding one bidi stream open to a
  ground station and pushing telemetry continuously, not
  tearing down a fresh HTTP/2 stream per data point.

p99 stays within ~20 % of p50 across every Ada workload
(consistent with no GC and no per-op allocator — the
implementation has neither). Statistical bounds, not WCET;
formal worst-case timing is a v0.6+ item. Reproduce:
`make grpc-bench` (~3 min) or `make grpc-bench-quick` (10 s
per workload). Raw JSON in `bench/results/`.

## How this was built

This stack was written with AI assistance: an LLM coding
assistant read the RFCs, drafted SPARK Ada (parsers, encoders,
decoders, key schedules, contracts), iterated against build /
test / proof failures, and helped refactor. What makes that
credible is the toolchain the drafts flow into and the oracles
that validate the result:

- **Verified toolchain.** AdaCore RecordFlux compiles `.rflx`
  specs to AoRTE-proven SPARK Ada by construction. gnatprove +
  Why3 + CVC5 / Z3 / Alt-Ergo discharge the functional proof
  obligations. SPARK 2014 is the verified language subset.
  `docs/conventions.md` §0d is enforced by automated,
  deterministic grep-based checks that reject the four common
  bypasses: VC suppression (`SPARK_Mode (Off)`), assumed axioms
  (`pragma Assume`), justification annotations (`pragma Annotate
  (GNATprove, …)`), and **vacuous post-conditions** backed by
  stub ghost specifications — a `Post => Output = Spec_X (Input)`
  whose `Spec_X` always returns a constant, so the Post
  discharges trivially against the stub instead of being a real
  claim about behaviour. When the audit greps return empty, the
  proven VCs hold against real specifications, not tautologies
  — that's what makes the headline numbers trustable.
- **Battle-tested interop peers.** openssl, gnutls, mbedtls,
  rustls, Go, BoringSSL, wolfSSL act as TLS 1.3 conformance
  oracles — handshakes complete or they don't, against the same
  RFC clauses the contracts cite. The Go gRPC reference server
  is the performance baseline.
- **Human-owned design, discipline, scope, judgement.**
  Architecture, the no-bypass platinum definition, the wrapper
  pattern, the production-default scope rule, code review, the
  bug-log classifications — those are human decisions and live
  in `docs/conventions.md`.

The composition — AI drafting + machine-checked verification +
real-peer interop + spec-cited honest reporting — is the
methodology this project is structured around. It's what makes
the proof numbers and the interop matrix above worth reading,
because every claim is falsifiable: each audit clause has a
grep, each primitive has a `[VERIFIED — …]` tag, each
interop-found bug has a row in `docs/bug-log.md` with its
classification.

## Quick start

```sh
make build         # all crates
make test          # all test suites
make tls-interop   # TLS interop matrix against installed peers
make tls-prove     # gnatprove --level=2 on tls_core (~5 min)
make tls-audit     # §0d audit greps (must all return zero)
make help          # full target list
```

Prereqs: **GNAT FSF 14+** via Alire (`alr`), on macOS also
`xcode-select --install` for the SDK; **gnatprove** via
`alr install gnatprove` for proofs; **RecordFlux** via Docker
(`scripts/rflx`) — host doesn't need a local install since
`crates/<crate>/generated/` is committed. Interop needs at
least one of openssl / gnutls / mbedtls / rustls / Go / bssl /
wolfssl; unavailable peers show NI-3P.

## Repo layout

```
crates/
├── tls_core/            SPARK TLS 1.3 (RFC 8446)
├── http2_core/          SPARK HTTP/2 + HPACK + multi-stream server
├── mqtt_core/           SPARK MQTT 3.1.1 + session machines
├── grpc_core/           gRPC framing on top of HTTP/2
├── http1_core/          Minimal HTTP/1.1 (RFC 9112)
├── protobuf_core/       SPARK-verified protobuf wire codec
├── protoc_gen_grpc_ada/ protoc plugin → Ada
├── tls_transport/       TLS adapter (Connect/Send/Receive/Close)
├── tls_interop/         Interop matrix runner + perf bench
├── rflx_runtime/        Shared RecordFlux runtime
├── logger/              Compile-time-strippable structured logger
├── baremetal_pic/       Bare-metal Cortex-M3 demo
└── examples/            tls_cli, grpc demo, mqtt demos

docs/
├── conventions.md       Project rules (§-cited from source)
├── wrapper-pattern.md   Walkthrough of the RFLX + SPARK pattern
├── bug-log.md           Consolidated interop / bench / fuzz bug log
├── proof-results.txt    gnatprove --level=4 sweep aggregation
└── proof-coverage.md    Per-subprogram tree (claim vs gnatprove)
```

`.ads` files carry per-crate build/run docs directly
(`docs/conventions.md` §4).

## License

Dual-licensed under either **MIT** (`LICENSE-MIT`) or
**Apache-2.0 with LLVM exceptions** (`LICENSE-APACHE`), at your
option — same convention as the Rust ecosystem. The LLVM
exception waives Apache §4(a/b/d) redistribution requirements
for code statically embedded into a binary, which matters for
bare-metal firmware images. See `NOTICE` for upstream
attributions (HACL\*, miTLS, EverParse, RecordFlux, IANA).
