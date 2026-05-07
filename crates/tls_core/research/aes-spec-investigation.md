# Portable Pure-SW AES Spec Investigation (v0.5 platinum gap)

Date:    2026-05-07
Author:  research pass per CLAUDE.md §0b
Scope:   determine whether a portable pure-software AES-128 / AES-256
         functional spec exists in any verified-crypto project that we
         could port to SPARK to achieve platinum on
         `Tls_Core.Aes128` / `Tls_Core.Aes256`.

This is a research report. **No tls_core source files were modified.**

---

## TL;DR

**A portable AES *spec* exists.** Two viable options:

1. **HACL\*** ships `specs/Spec.AES.fst` — a pure-functional F\* spec
   covering AES-128 *and* AES-256 (encrypt, decrypt, key expansion,
   plus CTR mode). 425 lines total / 353 LOC. Same project family as
   the Curve25519 / Ed25519 / SHA-256 specs we are already porting,
   so the porting *style* is already established in our codebase.

2. **libsparkcrypto** (Componolit) ships a working SPARK 2014
   AES-128/192/256 implementation under BSD 3-Clause. Repository
   archived 2024-08; last commit 2021-01. **AoRTE-only proofs** — no
   functional postconditions on `Encrypt` / `Decrypt`. So porting it
   gives us a *better* AoRTE foundation but does **not** by itself
   satisfy clause §0d-5 (functional correctness Post).

Neither option is "free." HACL\* gives us a spec but no Ada body;
libsparkcrypto gives us an Ada body but no spec. The platinum path
is **HACL\* spec + our existing Ada body, with the spec ported as a
SPARK ghost function** — same pattern we are using elsewhere for
`tls_core` primitives.

**Recommendation:** option **(c)** below — port `Spec.AES.fst` to a
SPARK ghost spec and add functional-correctness postconditions to
`Tls_Core.Aes128` / `Tls_Core.Aes256`. Estimate **2–3 working days**
for the spec port + Post wiring; full proof discharge effort is a
separate question (see "Proof tractability" section).

If the time is not available in the v0.5 window, fall back to option
**(d)**: tag both modules `[VERIFIED — AoRTE]` and document the gap
explicitly in the v0.5 release report under "open functional-correctness
gaps," per CLAUDE.md §0b.

---

## What was searched, and what was found

### 1. FIAT-Crypto (`mit-plv/fiat-crypto`) — NO AES

Per the project README: scope is "Synthesizing Correct-by-Construction
Code for Cryptographic Primitives," but in practice the primitives are
**only** field-arithmetic / number-theoretic:

- Curve25519, Ed25519, NIST-P256, secp256k1
- Poly1305 (modular arithmetic over the prime 2^130 - 5)
- Solinas / Montgomery / Barrett reduction

No AES, no Rijndael, no symmetric block cipher, no S-box. FIAT-Crypto's
specialty is field-arithmetic *kernels*; AES rounds (table lookups,
GF(2^8) ops, byte-level permutations) are out of scope by design.

> Source: <https://github.com/mit-plv/fiat-crypto> README + the
> project's IEEE S&P 2019 paper "Simple High-Level Code For
> Cryptographic Arithmetic"
> <https://jasongross.github.io/papers/2019-fiat-crypto-ieee-sp.pdf>

**Verdict: dead end.** Do not search further.

---

### 2. formosa-crypto / Jasmin / libjade — NO PORTABLE AES SPEC USABLE FOR US

`libjade` (the formosa-crypto library) advertises an AES-NI-only
implementation — verified, but bound to Intel hardware intrinsics,
which is exactly the same dead-end shape as the HACL\* `code/aes-gcm-intrinsics`
that prompted this investigation.

Confirmed against the libjade README: AES is **not on the public
primitive list** at all (the list is SHA-2, SHA-3, Poly1305, ChaCha,
Curve25519, Kyber, Falcon, etc.). Earlier Jasmin/EasyCrypt papers do
describe AES-NI implementations with EasyCrypt proofs against a
"Hacspec specification of the AES standard" (see *High Speed High
Assurance implementations of …*, eprint.iacr.org/2024/1893), but:

- The functional spec is **Hacspec** (Rust DSL), not directly portable
  to SPARK — would still require a transcription pass to Ada.
- The verified *implementation* is AES-NI assembly. Nothing to port
  to portable software.

> Source: <https://github.com/formosa-crypto/libjade> README,
> <https://eprint.iacr.org/2024/1893.pdf>

**Verdict: not directly usable.** Hacspec → SPARK is the same
transcription effort as FIPS 197 → SPARK, with the disadvantage that
Hacspec is itself a research DSL (less stable, less documented).

---

### 3. HACL\* `Spec.AES.fst` — PORTABLE PURE-FUNCTIONAL SPEC EXISTS

Located at `hacl-star/hacl-star:main:specs/Spec.AES.fst`.

> Source: <https://github.com/hacl-star/hacl-star/blob/main/specs/Spec.AES.fst>

Per HACL\* project documentation, all `specs/*.fst` files are written
in the **Pure fragment of F\***, depend only on F\* builtins and the
HACL\* `lib/`, and are explicitly intended as the trusted-computing-base
mathematical reference. They are *not* hardware-dependent — the HW
intrinsics live in `code/aes-gcm-intrinsics/`, which is the
*implementation*, not the spec.

**Coverage:** AES-128 *and* AES-256 fully — encrypt, decrypt, key
expansion, plus CTR mode helpers. (AES-192 not present, but we don't
need 192 for TLS 1.3 either — the AEAD ciphersuites are AES-128-GCM
and AES-256-GCM only.)

**Size:** 425 lines total, ~353 LOC excluding blanks/comments.

**Style sample (paraphrased from WebFetch):**

```fstar
let sub_byte (input:elem) =
  let s = finv input in
  s ^. (s <<<. size 1) ^. (s <<<. size 2) ^. (s <<<. size 3)
    ^. (s <<<. size 4) ^. (to_elem 99)

let mix4 (s0 s1 s2 s3:elem) : Tot elem =
  (s0 `fmul` two) `fadd` (s1 `fmul` three) `fadd` s2 `fadd` s3
```

That is, SubBytes is defined via the field-inversion + affine-map
formulation (not the table) and MixColumns is defined directly over
GF(2^8) arithmetic. This is **the cleanest possible spec shape for
porting to SPARK ghost functions** — it's short, mathematical, and
each operation is a simple expression we can transcribe to Ada
verbatim with `Ghost` aspect.

The same project-family Spec.\*.fst files we are already porting in
`tls_core` (Curve25519, Ed25519, HKDF, etc.) follow exactly this style;
the porting workflow is already established.

**License:** HACL\* is dual-licensed Apache-2.0 / MIT — fully
compatible with this project.

**Verdict: best candidate.** This is the spec to port.

---

### 4. libsparkcrypto (Componolit) — SPARK AES BODY EXISTS, NO FUNCTIONAL POST

> Source: <https://github.com/Componolit/libsparkcrypto>

Repository status: **archived 2024-08-12, last meaningful commit
2021-01-26**. License: **BSD 3-Clause**. SPARK 2014.

**AES coverage:** AES-128, AES-192, AES-256, plus CBC mode. Key files
under `src/shared/generic/`:

- `lsc-internal-aes.ads` (181 lines) — public spec: types
  (`AES128_Key_Type`, `AES_Enc_Context`, `Block_Type`, etc.) and
  subprograms (`Create_AES{128,192,256}_Enc_Context`,
  `Encrypt`, `Decrypt`).
- `lsc-internal-aes.adb` (~520 lines) — body. Uses T-tables
  (Rijndael lookup tables T1–T4, U1–U4 inverse) for hot path,
  S-box for last round.
- `lsc-internal-aes-tables.ads` — the T-tables and S-box constants.
- `lsc-aes_generic.{ads,adb}`, `lsc-aes.ads`, `lsc-aes-cbc.ads` —
  outer layers / mode helpers.

**Verification status: AoRTE only.** Quote from the project README
(verified via WebFetch): *"For the complete library proofs of the
absence of run-time errors like type range violations, division by
zero and numerical overflows are available, and **some of its
subprograms include proofs of partial correctness**."*

Direct inspection of `lsc-internal-aes.adb` confirms: `Encrypt` and
`Decrypt` carry `Pre =>` preconditions and `pragma Loop_Invariant` /
`pragma Assert_And_Cut` cuts to discharge run-time-error VCs, but
**no `Post =>` postcondition referencing a functional spec**. There
is no ghost AES spec in the repo. Partial-correctness proofs in
libsparkcrypto are mainly on SHA-2 and HMAC, not AES.

**Implication:** porting libsparkcrypto's AES gives us an
already-SPARK-discharged AoRTE proof — saving us the Bronze/Silver
work — but does **not** by itself satisfy CLAUDE.md §0d clause 5
(*"every public procedure's Post …"*). Platinum still requires
a functional spec from elsewhere, which sends us back to HACL\*
`Spec.AES.fst` anyway.

**Hybrid option (option (b) below):** port libsparkcrypto's body
as the *implementation*, port HACL\* spec as the ghost reference,
and write the Post linking the two. This is the lowest-risk path
*if* the v0.5 timeline is tight on AoRTE-discharge effort for our
own hand-written body — but our existing `Tls_Core.Aes128` /
`Tls_Core.Aes256` files already exist (untracked), so this only
helps if our current body is not yet AoRTE-clean.

---

### 5. OpenTitan / lowRISC `sw/device/lib/crypto/impl/aes` — HARDWARE WRAPPER, NOT SOFTWARE

> Source: <https://opentitan.org/gen/doxy/lib_2crypto_2drivers_2aes_8c_source.html>

The OpenTitan crypto library's AES implementation is an MMIO driver
that programs the OpenTitan **AES hardware IP block**. The C file
`sw/device/lib/crypto/impl/aes.c` calls `aes_encrypt_begin()` /
`aes_update()` against the IP register interface; there is no
software round function in the file at all. The functional
correctness story for OpenTitan AES lives at the **hardware** level
(SystemVerilog + UVM testbench), not as a portable software spec.

There is **no Cryptol or formal-method spec** for the software side
that I could find — the software is treated as a thin driver, and
correctness rests on the hardware verification.

**Verdict: not applicable to our use case.** We need pure-SW AES
because our targets include hosted Linux x86_64 (no OpenTitan IP
access) and bare-metal Cortex-M3 / Zynq (no OpenTitan IP either).

---

### 6. NIST FIPS 197 directly — viable but more work than option (c)

The AES standard itself is short — about 50 pages, of which the
algorithmic content is maybe 20 pages. Direct transcription to a
SPARK ghost spec is feasible:

- 4 transformations (SubBytes, ShiftRows, MixColumns, AddRoundKey)
  × 2 directions (forward / inverse) × ~30 LOC each = ~240 LOC
- Key expansion: ~100 LOC for AES-128 + AES-256
- Round driver (10 / 14 rounds): ~30 LOC
- Total spec: **~400 LOC** of SPARK ghost code, which is roughly
  what HACL\* `Spec.AES.fst` is.

Doing it from FIPS 197 directly vs. porting `Spec.AES.fst` is mostly
a question of which source we trust more. HACL\* `Spec.AES.fst` has
been formally checked against the HACL\* AES *implementation* —
i.e. it is a spec that has actually been used to discharge proofs,
not just a transcription. That's a meaningful "no transcription
bugs" signal that pure FIPS 197 transcription doesn't have.

**Recommendation: prefer porting `Spec.AES.fst` over transcribing
FIPS 197.** Use FIPS 197 only as a cross-reference during the port
to catch translation bugs.

---

## Options summary

| Option | Source for spec        | Source for body            | Effort      | Outcome                            |
|--------|------------------------|----------------------------|-------------|------------------------------------|
| (a)    | none                   | our existing hand-written  | 0           | `[VERIFIED — AoRTE]` only          |
| (b)    | HACL\* Spec.AES.fst    | libsparkcrypto's AES (BSD) | medium-high | platinum candidate, two ports      |
| (c)    | HACL\* Spec.AES.fst    | our existing hand-written  | medium      | platinum candidate, one port       |
| (d)    | FIPS 197 transcription | our existing hand-written  | medium-high | platinum candidate, no upstream cross-check |

Option (a) is the §0b "flag the gap" path. Options (b), (c), (d) are
all platinum candidates, distinguished by where the spec and body come
from.

**Best path: (c).** Single artifact to port (the spec); we keep the
body we already have; HACL\* spec is the most-trustworthy source
we found.

---

## Effort estimates for option (c)

Port `Spec.AES.fst` (~353 F\* LOC) to a SPARK ghost package
`Tls_Core.Aes_Spec` and wire `Post =>` postconditions on
`Tls_Core.Aes128.Encrypt` / `Decrypt` and `Tls_Core.Aes256.Encrypt`
/ `Decrypt`.

**Phase 1 — spec transcription (1–1.5 days):**
- Translate `elem` (GF(2^8) byte) and arithmetic ops to Ada.
- Translate SubBytes / InvSubBytes / ShiftRows / MixColumns /
  AddRoundKey as `with Ghost` functions.
- Translate `aes128_key_expansion` and `aes256_key_expansion`.
- Translate the round driver as a recursive-or-iterative ghost
  function returning a `Block`.
- Cross-check against FIPS 197 test vectors (AES-128 + AES-256
  appendix worked examples).

**Phase 2 — Post wiring (0.5 day):**
- Add `Post => Result = Aes_Spec.Encrypt_<N>(Plain, Key)` etc.
- Run `gnatprove --level=2`. Expect first run to leave many VCs
  unproven (loop invariants linking iterative implementation to
  declarative spec).

**Phase 3 — proof discharge (open-ended, 1–N days):**
- Add loop invariants relating intermediate state to the spec's
  per-round reduction.
- This is **the hard part** and the cost is genuinely uncertain.
  AES proofs against a declarative spec have been done (see
  Galois/Cryptol AES proofs, miTLS), but they take real effort —
  on the order of days to a couple of weeks for someone fluent
  in the prover.
- *If* this phase blows past budget, fall back to option (a) and
  flag in §0b. The Phase 1+2 work is not wasted: the ghost spec
  remains in tree as documentation and as the foundation for a
  later platinum push.

**Total realistic budget for v0.5: 2–4 working days for Phases 1+2;
treat Phase 3 as best-effort with a hard fallback to option (a).**

---

## Proof tractability — caveats worth surfacing

AES is one of the harder primitives to prove against a declarative
spec because:

1. **Table-based fast path.** Production AES uses T-table lookups
   that fold SubBytes + ShiftRows + MixColumns into a single 32-bit
   table read. Proving `T1[byte] = MixColumns(SubBytes(byte))` row-wise
   against the declarative spec is doable but tedious. (libsparkcrypto's
   AES uses exactly this T-table style; HACL\*'s spec is the round-by-round
   declarative form.)

2. **Galois-field arithmetic.** GF(2^8) multiplication via
   `xtime` / log-exp tables needs lemmas tying the implementation
   primitive to the field-axiom spec. SPARK has weak support for
   GF reasoning out of the box.

3. **State as 4×4 byte matrix vs. 4-word array.** The spec naturally
   uses a 16-byte state; production implementations use four 32-bit
   words. The transposition-permutation has to be reasoned about.

These are **not blockers** — published verified AES implementations
exist (Vale's AES-NI proof, Cryptol/SAW AES, Hacspec→Coq AES) — but
they mean Phase 3 effort is genuinely uncertain in advance.

If we want a smoother proof path, we could use the round-by-round
implementation (no T-tables) to keep the body shape isomorphic to
the spec. Performance loss vs T-tables is ~4–6x but for v0.5 we are
not promising production AES throughput, and the proof effort
saving is substantial.

---

## Recommendation

**Primary: pursue option (c) — port HACL\* `Spec.AES.fst` to a SPARK
ghost spec.** Time-box Phase 3 (proof discharge) at 3 working days;
if it doesn't close, fall back to option (a) with the §0b flag and
the partially-finished spec checked in for future use.

**Fallback: option (a) — tag `Tls_Core.Aes128` / `Tls_Core.Aes256`
as `[VERIFIED — AoRTE]` and document in v0.5 release report under
"open functional-correctness gaps":**

> Per CLAUDE.md §0b: AES-128 / AES-256 portable software ship with
> AoRTE proof only. A portable functional spec is available
> (HACL\* `specs/Spec.AES.fst`, ~353 LOC F\*) but porting +
> proof-discharge effort exceeded the v0.5 budget. Tracked for
> v0.6 as the lowest-risk path to platinum on these modules. No
> portable AES is available from FIAT-Crypto, formosa-crypto/libjade
> (AES-NI only), or OpenTitan (HW driver only).

That paragraph, dropped into the v0.5 release report, is the §0b-compliant
record of the gap.

---

## Sources

- HACL\* repository: <https://github.com/hacl-star/hacl-star>
- HACL\* AES spec: <https://github.com/hacl-star/hacl-star/blob/main/specs/Spec.AES.fst>
- HACL\* paper: <https://eprint.iacr.org/2017/536.pdf>
- libsparkcrypto: <https://github.com/Componolit/libsparkcrypto>
- libsparkcrypto AES files: `src/shared/generic/lsc-internal-aes.{ads,adb}`,
  `lsc-internal-aes-tables.ads`, `lsc-aes_generic.{ads,adb}`
- FIAT-Crypto: <https://github.com/mit-plv/fiat-crypto>
- FIAT-Crypto paper: <https://jasongross.github.io/papers/2019-fiat-crypto-ieee-sp.pdf>
- formosa-crypto / libjade: <https://github.com/formosa-crypto/libjade>
- formosa-crypto AES paper: <https://eprint.iacr.org/2024/1893.pdf>
- OpenTitan AES driver:
  <https://opentitan.org/gen/doxy/lib_2crypto_2drivers_2aes_8c_source.html>
- NIST FIPS 197: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf>
