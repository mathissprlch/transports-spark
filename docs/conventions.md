# transports-spark — project conventions

Source-citation target. Source comments referring to `§0a`, `§0d`,
`§9a`, etc. point at the sections below.

These rules govern proof discipline, interop testing, code structure,
and release reporting. They are constraints, not suggestions — if a
rule conflicts with a "more elegant" approach, the rule wins.

---

## RULE ZERO — Mirror miTLS / HACL\* before opening any TLS proof

Before opening a SPARK proof on any TLS-related unit — driver, wire
parser, key schedule, AEAD, anything — find the miTLS / HACL\*
equivalent first and read how the upstream proof is structured.

1. **Find the module**: `project-everest/mitls-fstar` for protocol
   logic (Record, Handshake, StAE, Parsers); `hacl-star/hacl-star`
   for crypto primitives.
2. **Read the contract structure**: what Pre/Post/invariant pattern
   does the upstream use? Are bounds carried in refinement types
   (mapped to SPARK subtypes)? Are parsers built from combinators
   with built-in bounds? Is state tracked via ghost variables?
3. **Mirror the structure in SPARK** — same decomposition, same
   invariant shape, same staged-assert pattern. The SPARK proof
   should look like a line-by-line structural translation of the
   F\* proof, not a novel invention.

### Quick-reference: miTLS patterns that closed 49 VCs in cert-handshake driver

Use as the template for similar driver/composition proofs.

| VC class | miTLS pattern | SPARK translation |
|---|---|---|
| Missing Pre on entry (buffer bounds) | Types carry buffer-size refinements | Add `Pre => In_Bytes'First = 1 and then In_Bytes'Length <= 16645 and then Out_Buf'First = 1 and then Out_Buf'Length >= 4096`; propagate up to caller |
| Decoder-returned indices unbound | Parsers Post-bind all output indices within input range | Add Post to decoder: `Sid_First in 0 .. In_Bytes'Last` etc. Plus defensive runtime guard for indices crossing procedure boundaries |
| Helper output length unknown | Helpers carry exact-length Posts | Add `Post => Out_Last = 4 + Body_Bytes'Length` to wrapper procedures |
| AEAD sequence number not tracked | `StAE` carries counter in abstract state; `encrypt` Post says counter = old + 1 | Post on `Aead_Channel.Send`: `Seq_Of(D.Stream) = Seq_Of(D'Old.Stream) + 1`; init Post: `Seq_Of = 0` |
| Buffer-arithmetic on bounded fields | Refinement-typed lengths | `Field_Len : Natural range 0 .. 64` instead of plain Natural |
| Array indices reused after slicing | Parsers validate indices before access | `pragma Assert (Idx <= Buf'Last)` before loop, or defensive `if` guard |
| Cross-buffer index composition | Parsers return indices in the ORIGINAL buffer (no rebasing) | Defensive runtime guard, not SMT assertion chain |
| Output bound lost through state mutation | Finalise output BEFORE state mutation | Capture flight length in local, do state mutation, then `Out_Last := Flight_Last` last |

**Key principle**: when the SMT solver can't compose a fact through
a procedure call, the fix is almost never "give SMT more time"
(level=3/4). It is one of:

- **Add a Post to the called procedure** (the fact you need IS the
  callee's contract, not an SMT deduction).
- **Use a defensive runtime guard** (let the code prove the
  property, not the solver).
- **Restructure to keep the fact in scope** (the
  "output-before-mutation" pattern).

---

## §0 — v0.5 scope: full TLS 1.3, true platinum before interop

The v0.5 release goal: a complete TLS 1.3 implementation, fully
proven to true platinum, BEFORE any external-implementation interop
tests. Not v0.6. Not later.

**True platinum** means all five of:

- gnatprove: 100% proved at level=2 or higher
- **zero `SPARK_Mode (Off)` bodies in production code** — the only
  legitimate exception is `Tcp_Transport` / `Transport` wrapping
  `GNAT.Sockets` at the transport boundary, and that must be
  flagged as outside-SPARK, not folded into the proof claim
- zero `pragma Assume` papering over unproven VCs (assume is for
  axioms about external code only — never as a proof shortcut)
- bounds match the protocol spec (AEAD must handle 16640-byte
  plaintext per RFC 8446 §5.2; bounds tighter than that are bugs,
  not features)
- **functional correctness of every crypto primitive — not just
  AoRTE.** Each primitive's Post must reference a *real* executable
  ghost spec (ported from HACL\* `Hacl.Spec.*.fst` — see §0c). Tests
  + AoRTE alone is not platinum; that's only memory-safety with
  test confidence.

**Full TLS** for v0.5 means all of:

- psk_dhe_ke mode 3 (PSK + ECDHE) — required by every modern peer
- cert-mode handshake end-to-end against real PKI chains
- cipher-suite negotiation actually dispatching at runtime between
  ChaCha20-Poly1305 / AES-128-GCM / AES-256-GCM
- alert protocol (close_notify, fatal alerts, content type 0x15)
- HelloRetryRequest path with named-group renegotiation
- multi-record handshake message reassembly (cert chains > 16K)

---

## §0a — Implement only TLS 1.3 paths in production use

If a production TLS 1.3 implementation (OpenSSL ≥ 3.x, mbedTLS,
GnuTLS, rustls, BoringSSL, Go crypto/tls) accepts a path **by
default**, implement it. If a path is gated behind opt-in flags,
deprecated by the RFC, or simply not used in real traffic, do not
implement it — even if the RFC defines it.

### Concrete v0.5 scope decision matrix

**IMPLEMENT (production-used by default):**

- **Key exchange**: `psk_dhe_ke` (mode 3 — PSK + ECDHE, used for
  session resumption with FS); plain ECDHE (cert-mode initial
  handshake)
- **Cert-mode handshake**: Certificate + CertificateVerify against
  real PKI chains
- **Named groups**: `x25519`, `secp256r1`
- **Cipher suites**: `TLS_AES_128_GCM_SHA256`,
  `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`
- **Signature algorithms**: `rsa_pss_rsae_sha256`,
  `ecdsa_secp256r1_sha256`
- **Extensions**: `server_name` (SNI), `supported_versions`,
  `supported_groups`, `key_share`, `signature_algorithms`,
  `application_layer_protocol_negotiation` (ALPN),
  `psk_key_exchange_modes` (unconditional, matches production CH
  shape)
- **HelloRetryRequest**: full retry-with-different-group flow
- **Alert protocol**: `close_notify`, fatal alerts
- **NewSessionTicket / Session resumption**
- **KeyUpdate** (RFC 8446 §4.6.3)
- **Multi-record handshake reassembly** (cert chains > 16K)

**DO NOT IMPLEMENT (not in default production traffic):**

- `psk_ke` (mode 1, PSK without DHE) — RFC-discouraged
- 0-RTT / early data — production use is limited to a few CDNs
- Post-quantum hybrid KEMs — defer to a later version
- DTLS 1.3 — separate protocol; out of scope
- TLS 1.2 fallback — TLS 1.3 only
- `secp521r1` — exotic
- `Ed25519` cert signatures — minimal real use; verify path stays
- PSK without ticket / external PSKs — IoT-niche

### The openssl-default test

Before adding a new TLS feature: run `openssl s_server -tls1_3`
with no special flags and confirm production peers (`curl
--tlsv1.3`, `nghttp2`) accept it by default. If they don't, don't
ship it.

---

## §0b — Flag AoRTE-only primitives explicitly

When full functional correctness isn't feasible (e.g. upstream
HACL\* / FIAT-Crypto / formosa-crypto have no portable spec for
the case), document explicitly:

1. *"primitive X has only AoRTE proof; functional correctness is
   open; HACL\* / miTLS / FIAT-Crypto have no usable ported spec
   for this case."*
2. Flag it in the release report under "open functional-correctness
   gaps."
3. Don't pretend it's platinum. Don't drop the Post and move on
   silently — the gap goes in the report.
4. Investigate alternatives (FIAT-Crypto, formosa-crypto,
   OpenTitan verified-AES) before declaring it impossible.

---

## §0c — HACL\* / miTLS spec porting strategy

Do not write FIPS / RFC specs from scratch. Port them.

**For each TLS primitive:**

1. Find `Hacl.Spec.<X>.fst` (or equivalent) in `hacl-star/hacl-star`.
2. Translate the F\* `let` definitions (state type, init, update,
   finalize) to SPARK Ada ghost functions of the same structure.
3. Translate F\*'s loop invariants and intermediate-state bounds to
   `pragma Loop_Invariant` / `pragma Assert` in the SPARK
   imperative impl — same invariants, same shape; gnatprove redoes
   the SMT-level proof.
4. The Post on each public procedure references the ported ghost
   spec: `Post => Output = Spec_<X> (Input)`.
5. Cite the HACL\* file:line mirrored in a code comment.

| Primitive | Spec source | Status |
|---|---|---|
| SHA-256/384/512 | `Hacl.Spec.SHA2.Generic.fst` | available |
| HMAC | `Hacl.Spec.HMAC.fst` | available |
| HKDF | `Hacl.Spec.HKDF.fst` | available |
| Poly1305 | `Hacl.Spec.Poly1305.fst` | available |
| ChaCha20 | `Hacl.Spec.Chacha20.fst` | available |
| GHASH / GCM | `Hacl.Spec.GF128.fst` + `Hacl.Spec.GCM.fst` | available |
| AES-128/256 | HW intrinsics — pure-SW spec partial. | partial — flag if not portable |
| X25519 | `Hacl.Spec.Curve25519.fst` | available |
| Ed25519 | `Hacl.Spec.Ed25519.fst` | available |
| P-256 | `Hacl.Spec.P256.fst` | available |
| ECDSA-P256 | `Hacl.Spec.ECDSA.fst` | available |
| RSA-PSS | `Hacl.Spec.RSAPSS.fst` | available |
| X.509 / DER parsers | EverParse / miTLS `MiTLS.Parsers.*` | available |

**Cannot import directly:** F\*'s machine-checked proof terms —
different prover, different soundness foundations. Re-prove with
gnatprove guided by the upstream invariant structure.

---

## §0d — Definition of "platinum" + ban on every bypass

**Platinum** for a SPARK package means **all six** of the following
hold simultaneously, with no exceptions:

1. **gnatprove level≥2 reports zero unproved VCs** for the package.
2. **No `SPARK_Mode (Off)` / `SPARK_Mode => Off`** anywhere in the
   package, nested packages, generic instantiations, private parts,
   or bodies. The single global exception is `Tcp_Transport` /
   `Transport` wrapping `GNAT.Sockets`, reported as outside-SPARK
   in the audit (not lumped into the proof claim).
3. **No `pragma Assume`** in the package body. None. (`pragma
   Assume` is reserved for asserting properties of genuinely-
   external code we have no SPARK source for — e.g.
   `GNAT.Sockets`. For internal SPARK code, the answer is no.)
4. **No stub `Spec_*` ghost functions** whose body is `return
   False` / `return Default` / similar constant. Every ghost
   referenced by a Post must have a real, computable body that
   actually defines the function over its inputs.
5. **Functional correctness**: every public procedure's Post
   references the real spec of what it computes — not a tautology,
   not a length-only shape. For crypto primitives, this means
   `Output = Spec_X (Input)` where `Spec_X` is the ported
   HACL\* / FIAT-Crypto / miTLS computational spec.
6. **No bypass mechanism by another name.** If a future clever
   trick (`pragma Annotate (GNATprove, Inline_For_Proof)`,
   `pragma Annotate (GNATprove, False_Positive)`, abstract states
   without refinement, justification messages in `gnatprove.out`,
   hidden subtype predicates, etc.) is introduced, that's the
   same vice as the rules above and equally not platinum.

The rule, restated: **VCs come down only through real proofs, not
through any pragma, annotation, scope exception, or specification
trick.**

### Audit checklist (run on every claim of platinum):

```sh
# 1. SPARK_Mode (Off) — only Tcp_Transport allowed
grep -rnE "SPARK_Mode\s*\(\s*Off|SPARK_Mode\s*=>\s*Off" \
   crates/<crate>/src/

# 2. pragma Assume — must return zero
grep -rn "pragma Assume" crates/<crate>/src/

# 3. Stub Spec ghost functions — body returning a literal
grep -rE "^\s*function Spec_.*\sreturn .*\sis\s*$" \
   crates/<crate>/src/*.adb -A6 | grep -B1 \
   "return False\|return True\|others => 0"

# 4. GNATprove justification annotations — must return zero
grep -rnE "pragma Annotate\s*\(\s*GNATprove" crates/<crate>/src/

# 5. gnatprove headline
grep "^Total" crates/<crate>/obj/gnatprove/gnatprove.out
```

A platinum claim is rejected on the first non-empty result above.

---

## §0e — The Big_Integer-bridge wall: a real SPARK limitation

The standard SPARK approach for bignum / limb-arithmetic
correctness proofs — projecting the limb array to a `Big_Integer`
and reasoning about the projection — runs into a foundational
SPARK stdlib limitation that cannot be closed without a banned
bypass.

**Mechanism:** `Ada.Numerics.Big_Numbers.Big_Integers_Ghost.Unsigned_Conversions.To_Big_Integer`
has body `SPARK_Mode => Off`. It's an opaque axiomatization. The
prover therefore has no rule connecting `To_Big_Integer (X + Y)`
to `To_Big_Integer (X) + To_Big_Integer (Y)`, even when overflow
is excluded. Every limb-add → bignum-add bridge bounces off this.

**Path forward (multi-week):** mirror HACL\*'s limb-only proof
structure. Define `Spec_Add_Limbs / Spec_Mul_Limbs /
Spec_Mod_Reduce` recursively over limb arrays and prove the
algorithm preserves them without ever invoking `To_Big_Integer`.
This is what `Hacl.Spec.Bignum25519.Lemmas.fst` does.

When a primitive's functional Post can't be closed because of this
wall, tag it `[VERIFIED — AoRTE]` and cite §0e in the comment. Do
not bypass. Do not silently drop the Post. Do not claim platinum
on that primitive.

---

## §1 — Never game proof headlines via SPARK_Mode (Off) or stub-Spec + pragma Assume

A body marked `SPARK_Mode (Off)` has its VCs removed from the count.
The summary then looks clean while the proof gap is hidden. This is
not the same as proving the body — it is suppression.

**Equally bad — the stub-Spec + pragma Assume pattern:**

```ada
-- Spec ghost in spec file:
function Spec_Decode_OK (Buf : Octet_Array) return Boolean
with Ghost, Pre => Buf'First = 1 and then Buf'Length >= 2;

-- Body file: STUB
function Spec_Decode_OK (Buf : Octet_Array) return Boolean is
   pragma Unreferenced (Buf);
begin
   return False;            -- !!! placeholder, not a real spec
end Spec_Decode_OK;

-- Body bridges back to the stub via assume:
if not Step_OK then
   pragma Assume (Spec_Decode_OK (Buf) = False);  -- !!! shortcut
   return;
end if;
```

The `pragma Assume` discharges the Post against the placeholder.
Looks 100% proven, but the functional contract is hollow. Same vice
as `SPARK_Mode (Off)`, just a different mechanism.

**Hard rule:** `pragma Assume` is allowed only for genuine axioms
about *external* code (e.g. asserting a property of a foreign
function we can't see into). It is never allowed as a way to bridge
an imperative implementation to a stub ghost specification.

---

## §1a — gnatprove summary count is not enough on its own

A 100% headline can hide:
- `SPARK_Mode (Off)` (VCs not generated)
- stub-Spec + pragma Assume (VCs proved against `return False`)
- bodies declared but not analysed

**Real audit checklist before claiming platinum:**

1. Run all 5 greps from §0d.
2. The legit numbers (proven / honest-unproven / outside-SPARK)
   must each be reported separately. Never sum into a "X% proven"
   headline.

When reporting any gnatprove run, break the count into three
explicit categories — never collapse them into one number:

- (a) **Proved by gnatprove** — the X / Y from the summary.
- (b) **Suppressed via `SPARK_Mode (Off)` as trust axiom** — list
  every such body by name. NOT proven, treated as axiomatic.
- (c) **Outside SPARK boundary** — packages like `Tcp_Transport`
  that wrap `GNAT.Sockets` and cannot be SPARK by definition.

"Platinum" requires (a) = 100% AND (b) = empty. If (b) is
non-empty, say *"X% proven, Y trust axioms"* — never *"100%
proven."*

When proofs are hard, the legitimate options are: prove with loop
invariants / refined types; leave the unproven VCs visible and
documented; or refactor. **Suppression is the wrong answer.**

---

## §2 — Don't substitute different work for the asked-for test

When asked for test X (e.g. *"interop against battle-tested TLS
impls"*) and you discover mid-stream that X's precondition doesn't
hold (e.g. our PSK_KE mode 1 isn't accepted by openssl / GnuTLS /
rustls by default), **STOP and surface the gap.** Do NOT silently
substitute a different test (e.g. Ada-to-Ada self-test) and report
it as if it were the original.

**Hard rule:** Before starting any long-running test, validate the
precondition (do we even support what the test requires?). If
validation fails, kill the run and ask. Internal soak proves
determinism on test inputs; external interop is a separate,
not-yet-done thing — never describe internal round-trips as
"interop coverage."

---

## §3 — Don't run multi-hour autonomous work on stale premises

If a long-running job's value depends on a precondition you've
discovered is false, kill it and ask.

**Hard rule:** When you find a deferred-task gap mid-stream (mode 3
not implemented, cipher-suite negotiation not wired up, AEAD bound
too tight), surface it *before* substituting work, not after.
*"Y wasn't ready, what should I do?"* > *"I substituted X because
Y wasn't ready."*

---

## §4 (test/proof distinction) — Tests prove a different thing than proofs

A long soak proves determinism on the test inputs and freedom from
latent crashes / nondeterminism. **It does NOT prove:**

- correctness on adversarial / fuzz-style inputs
- side-channel resistance
- interop with anything that isn't us
- behaviour on unusual MTU / packet loss / fragmentation
- functional correctness on inputs not in the test set

**Hard rule:** Tests + proofs are complementary, not
interchangeable.

---

## §4 (readability) — Top-level readability: the .ads must say what's computed and that it's proven

Reading the `.ads` of a primitive should answer three questions
**without scrolling into the body or running gnatprove**:

1. **What does this compute?** (cite the canonical spec — FIPS,
   RFC, HACL\* / miTLS file:line)
2. **What's the functional contract?** (the `Post => Output =
   Spec_X (Inputs)` clause should be visible)
3. **What's the proven status?** (a tagged header)

**Required header form for every public procedure / function in
`crates/tls_core/src/`:**

```ada
   --------------------------------------------------------------------
   --  [VERIFIED — PLATINUM]  AES-256 block encryption.
   --
   --  Standard:    FIPS 197 §5.1 + §5.2 (Cipher())
   --  Spec mirror: HACL*  code/aes/Hacl.Spec.AES.fst : aes_encrypt_block
   --
   --  Functional: Output = Spec_AES256_Encrypt_Block (Key, Input)
   --  Proven at:  gnatprove --level=2 (0 unproved, audit-clean)
   --------------------------------------------------------------------
   procedure Encrypt_Block
     (Key    : Key_256;
      Input  : Block_16;
      Output : out Block_16)
   with
     Post => Output = Spec_AES256_Encrypt_Block (Key, Input);
```

**Tag vocabulary** — exactly one per public entity, no other
variants:

| Tag | Meaning |
|---|---|
| `[VERIFIED — PLATINUM]` | All six §0d clauses hold |
| `[VERIFIED — AoRTE]` | Body proven free of run-time errors only; functional spec not ported |
| `[OUTSIDE SPARK]` | GNAT.Sockets / FFI boundary — not analyzed |
| `[NOT VERIFIED]` | Work-in-progress; do not use in production |

The tag is binding — if you write `[VERIFIED — PLATINUM]` then the
audit checklist (§0d) must pass. Mismatched tag = bypass by
another name; treat as the same vice.

---

## §4a — Proof-engineering: use the same tricks miTLS / HACL\* use

Mirroring the upstream spec is necessary but not sufficient. Their
proofs go through fast because of **proof-engineering practice** —
patterns that keep the SMT solver unstuck. Apply the same in SPARK.

### Patterns to copy from HACL\* / miTLS

1. **Refinement-typed limbs as SPARK subtypes.** F\*'s `f51 :
   Type0 = x:UInt64.t{v x < pow2 51}` → SPARK
   `subtype Limb_51 is Interfaces.Unsigned_64 range 0 .. 2**51 - 1;`

2. **Lemma procedures**, not lemma comments. F\* `val foo_lemma :
   x:t -> Lemma (P x)` → SPARK ghost procedure with `Pre`+`Post`.
   Callers invoke it to bring the Post into local scope.

3. **Staged equational assertions.** F\* `assert (X == Y); assert
   (Y == Z);` → SPARK `pragma Assert (Foo (X) = Bar (X)); pragma
   Assert (Bar (X) = Baz (Y)); pragma Assert (Foo (X) = Baz (Y));`.
   Stages the work so SMT's heuristic search doesn't time out on
   the full chain.

4. **Loop invariants stated HACL\*-style** — concrete bounds at
   every iteration, indexed on the loop variable when the bound
   varies. Don't reach for a single uniform `2**60` bound when the
   algorithm has a non-uniform per-iteration bound.

5. **Tight Pre/Post on every helper.** Decompose hard proofs into
   trivial helpers. miTLS's parser layer is built from ~10-line
   functions each with 2–3 line contracts.

6. **Ghost variables to track auxiliary state.** Carry chains need
   a ghost array tracking cumulative carry; add it as `Ghost`.

7. **Avoid nested quantifiers in Posts.** Reformulate using a
   Skolem ghost function: define `Witness (X) : Y` and write
   `(forall X => P X (Witness X))`.

8. **`Contract_Cases`** for case-splitting — easier for SMT than a
   disjunctive Post.

9. **`pragma Loop_Variant (Decreases => ...)`** wherever
   termination is non-obvious.

10. **`Always_Terminates` aspect** on functions whose totality is
    needed for them to appear in a Post.

11. **Ghost spec body must be executable.** No `pragma Unreferenced
    (Input); return Default;` — the body has to actually compute
    the function.

12. **Define operations on ghost types via concrete equations**,
    not abstract axioms.

### Bypass disguised as proof-engineering — forbidden

Anything whose effect is to make a VC disappear *without* a real
proof is a bypass, even if it looks like a proof-engineering
pragma. That includes `pragma Annotate (GNATprove,
Inline_For_Proof)`, abstract states without refinement, hidden
predicates that elide checks. If in doubt, ask: did the SMT solver
actually run on this VC and prove it from explicit assumptions, or
did some annotation make the obligation go away?

---

## §5 — Don't roll schoolbook proofs — mirror miTLS / HACL\*

For any SPARK proof work on TLS-relevant code, **read the verified
F\* / Low\* equivalent first** and mirror its invariant pattern.
Don't reinvent loop invariants from scratch.

**Reference projects:**

- **miTLS** (`project-everest/mitls-fstar`): F\* TLS reference.
  Particularly `src/tls/MiTLS.Record.fst`, `MiTLS.StAE.fst`,
  `MiTLS.Crypto.AEAD.fst`, `MiTLS.Parsers.*`.
- **HACL\*** (`hacl-star/hacl-star`): verified crypto primitives.
- **EverParse** (`project-everest/everparse`): the parser-
  combinator framework miTLS uses.

**Practical rule before opening a SPARK proof:**

1. Find the equivalent in miTLS / HACL\* / EverParse.
2. Read their refinement types and loop invariants.
3. Translate that *structure* into SPARK.
4. If something doesn't translate, name what's different and ask
   before improvising.

---

## §5a — Fastest algorithm AND platinum-proven (both, not either)

The algorithm constraint is joint:

- Must be **the fastest typically used in production verified TLS
  stacks** (not schoolbook / not TweetNaCl-style baseline)
- AND must be **truly platinum-proven** in SPARK (no `SPARK_Mode
  (Off)`, no stub-Spec + assume bridge, no honest unproven gaps
  left as deferred)

These aren't in tension because HACL\* / miTLS already ship the
fastest-known verified versions of every primitive needed.

| Operation | Schoolbook (avoid) | Fastest verified (target) |
|---|---|---|
| Ed25519 mod-L reduction | TweetNaCl byte-loop | HACL\* Barrett with 51-bit limbs (`Hacl.Bignum25519`) |
| GHASH | bit-by-bit | HACL\* 4-bit table or 64-bit Karatsuba (`Hacl.GHash`) |
| RSA Mod_Exp | naive square-and-multiply | Montgomery CIOS |
| AES round | per-step | T-tables |
| ChaCha20 | per-byte | 4-block parallel (`Hacl.Chacha20.Vec128`) |
| Bignum P-256 mul | schoolbook 8-limb | HACL\* fast reduction (`Hacl.Spec.P256.MontgomeryMultiplication`) |

Before introducing a primitive, look up the HACL\* / miTLS
fastest-known version. If you don't, you're committing future
rework.

---

## §6 — Honest reporting language

| Don't say | Say |
|---|---|
| "platinum" (when there are `SPARK_Mode Off` bodies) | "X% proven, Y trust axioms" |
| "interop tested" (when only Ada-to-Ada) | "internal round-trip tested; external interop deferred" |
| "0 unproved" (when bodies are suppressed) | "0 unproved in N analysed bodies; M bodies suppressed" |
| "complete" (when partial) | "complete for cases A/B; case C deferred" |
| "C8 done" / "Phase 14 done" (when work landed in a sibling pkg, never wired into the production driver) | "C8 primitives landed in pkg X; production-driver integration deferred — see audit checklist" |

---

## §7 — Interop-phase discipline: wire everything before testing anything

When entering an external-interop phase, **finish all the wiring
first; run no test suite cells until the wiring is complete.**

**Hard rule for every interop phase:**

1. **Audit the production driver first.** Before any matrix run,
   grep for every advertised entry point claimed by the task list.
   For each "completed" feature, verify the production driver has
   the entry point and Step actually dispatches to it. Sibling
   packages with the primitive (e.g. wire-format encode/decode)
   are not the same as production-driver integration.

2. **Finish all wiring before running anything.** Includes:
   - all advertised driver entry points present in the production
     driver
   - all harness binaries built against the production driver
   - all peer harnesses installed and scripted
   - all cert/PKI fixtures in place
   - all matrix-doc cells listed
   - all sequencing dependencies between cells documented

3. **Then run the matrix once.** Failures attributable to the same
   root cause group together; you don't waste cycles diagnosing
   the same systemic gap N times.

**Audit checklist requirement:** every feature claimed in the task
list under a track (C-track, P-track, etc.) must be auditable via:

- a grep showing the public entry point in the production driver
- a test that drives the feature *through the production driver's
  Step API*, not just through the primitive package
- a pass/fail row in the matrix doc

If any feature can't be traced to all three, it doesn't count as
"landed in the production driver".

---

## §8 — Spec-first compliance: RFC 8446 is the source of truth, not openssl

The goal is a **platinum-proven TLS 1.3 implementation that
satisfies RFC 8446**, not "passes whatever openssl happens to
accept this week". When external interop reveals a mismatch, the
default framing is **"our implementation drifted from the spec"**,
not "openssl is being weird".

**Hard rule:**

1. Every wire-format / state-machine / cryptographic-input gap
   surfaced by interop testing must be classified primarily as an
   **RFC 8446 deviation** (with the offending §X.Y cited), and
   only secondarily as "peer X rejects". Bug reports + audit
   checklist entries lead with the spec citation.

2. **openssl / rustls / Go / mbedTLS / gnutls / BoringSSL are
   oracles for spec compliance, not compatibility targets to
   accommodate.** When a peer rejects our output, the question is
   "where did we deviate from RFC 8446?", not "what does the peer
   want?". The peer is right *because* it implements the spec.

3. **Don't add per-peer workarounds.** If our wire format is
   correct per RFC 8446, all conformant peers will accept it. If a
   peer rejects spec-conformant output, that's a bug in the peer,
   not us — and it's reportable upstream, not patchable here.

4. **A fix is not just "the peer accepts our output now"; it's
   "we now match the §X.Y spec text".** State the RFC citation in
   the commit message. If you can't cite the §, you don't yet
   understand the fix.

### Reporting language hardening (extends §6 table):

| Don't say | Say |
|---|---|
| "openssl accepts X now" | "now compliant with RFC 8446 §X.Y; openssl (and any conformant peer) accepts" |
| "we matched openssl's expectation" | "we matched the §X.Y spec; we agree with openssl because openssl implements the spec" |
| "rustls is stricter, so we need to add Y" | "rustls flagged a deviation from §X.Y we'd missed; the fix is to add Y per spec" |

---

## §9 — Bug-fix commits must classify root cause

Every commit that fixes a bug MUST record why the bug existed,
chosen from this taxonomy:

| Tag | Meaning | Prevention path |
|---|---|---|
| **(a) Spec misread** | We read the RFC / standard but missed a clause, nuance, or notation convention | Mirror miTLS / HACL\* per §5 |
| **(b) Spec correctly read, impl wrong** | We understood the spec; the Ada transcription was wrong | Tighter Pre/Post; encoder↔decoder round-trip test |
| **(c) Pure impl bug** | Ada-idiom error, off-by-one, slice `'First` confusion — spec wasn't load-bearing | See (c)+(d) pairing below |
| **(d) Proof gap** | The relevant property was AoRTE-only; a functional Post would have caught it at gnatprove time | Add the Post; lift the primitive from AoRTE to PLATINUM |
| **(e) Counterpart non-conformant** | The peer deviated from the spec, not us | Report upstream; do NOT patch our codebase per §8 |

**Required commit-message body:** an explicit `Root cause:` line
listing the tag(s) plus a one-paragraph explanation. If the fix
crosses categories, list all of them.

**(c) ↔ (d) pairing.** Pure impl bugs that slip past gnatprove
almost always pair with a proof gap: a stronger Post would have
flagged them. The honest classification is usually (c)+(d): "impl
bug + the property wasn't proven, so it landed."

**Discipline anchor for interop failures:** when a matrix cell
fails, the investigation MUST classify *before* patching. (a) →
re-read the cited RFC clause and quote it. (b) → diff the spec
text against the offending code line. (c)+(d) → patch and add the
missing Post. (e) → write the upstream report, don't patch.

---

## §9a — Per-feature bug log: every interop-found bug gets a permanent row

Every interop-/benchmark-/fuzz-found bug gets a row in the
**per-feature bug log** with these columns:

| Date | Found by | Component | RFC § | Tag(s) per §9 | One-line summary | Commit |
|---|---|---|---|---|---|---|

**One log file per feature**, in `docs/<feature>-bug-log.md`:

- `docs/v0.5-bug-log.md` — TLS v0.5 only
- `docs/http2-bug-log.md` — Http2_Core
- `docs/grpc-bug-log.md` — Grpc_Core + protoc-gen-grpc-ada
- `docs/mqtt-bug-log.md` — Mqtt_Core
- (more per feature as they accrue interop bugs)

A bug landing in one feature's stack goes into that feature's log,
not into a release-named log. Use the commit's version (v0.5.X)
to mark when the fix shipped — but the log itself is per-feature
and lives across releases.

The (d) entries are load-bearing — each one means "we shipped this
primitive as `[VERIFIED — AoRTE]` and a functional Post tied to
the spec mirror would have caught the bug at gnatprove time
instead of at interop." Those are precisely the units to revisit
in the next ghost-bignum / wrapper-pattern push.

---

## §10 — Harnesses, matrices, formalised wire code

### §10a — Test harness binaries must be production-shaped CLI tools

A harness that wires up *one* test case is not a harness; it is
per-test scaffolding. Every interop / soak run MUST be built on a
CLI binary that:

- Accepts mode (PSK / cert-ec / cert-rsa / resumption / 0-RTT /
  HRR) as flags, not as separate binaries.
- Accepts identity / cert / key / trust / hostname / ALPN / SNI /
  cipher constraints as flags.
- Reads sensitive material (keys, PSKs) from files, not hex
  strings.
- Uses ONLY public `Tls_Core.*` APIs — no peeking at Driver
  private fields, no `with` of internal modules.
- Is consumable by downstream stacks (`http_core`, `mqtt_core`,
  `grpc_core`, `examples/*`) as a TCP-replacement library or
  sub-binary. **The same code that runs the matrix runs the
  production stack.**
- Has graceful shutdown, alert handling, sane defaults.

### §10b — Interop matrices must cover the full production peer set

For TLS: openssl + rustls + Go + gnutls + mbedtls + BoringSSL +
wolfSSL by default. Single-peer matrix runs are not "Tier D"; they
are "Tier D against peer X."

If a matrix script doesn't yet support all peers, the report MUST
say so explicitly rather than letting silence read as completeness.

### §10c — Wire-format code should be formalised where it applies

Binary wire formats (TLS records, handshake message headers,
extension structs, length-prefix vectors, AEAD record layout) are
exactly the surface RecordFlux was built for.

**Going-forward rule**: any new TLS wire-format primitive (parsing
or emitting bytes that have a vector / length-prefix / variable-
length structure) starts as a `crates/<crate>/specs/*.rflx` spec
unless explicitly waived. Bug fixes to existing hand-rolled wire
code SHOULD include "lift this primitive to RFLX" as a follow-up.

For handshake-state code (the FSM in `Tls_Core.Tls13_Driver`),
RecordFlux session machines are the analogue.

**Caveat — text protocols and ad-hoc DER walks.** ABNF / textual
formats (HTTP/1.1, header field values) and DER walkers (X.509,
ECDSA-Sig-Value) don't fit RecordFlux; for those, the alternatives
per §5 are (a) miTLS-style parser combinators (EverParse) or (b)
hand-written SPARK with full functional Posts.

### §10d — Makefile targets for every long-running operation

Tests, gnatprove sweeps, perf benches, interop matrices, soaks,
fuzzers — anything you might want to re-run — gets a Makefile
target. `make test`, `make matrix`, `make matrix-openssl`, `make
perf`, `make prove`, `make soak`, `make bare-build`. The Makefile
is the public test-discovery surface.

---

## §11 — Abstract where it is meaningful; do not duplicate code

Both extremes hurt: copy-paste rot ("same fix needed in N places,
one was missed") AND premature-abstraction salad ("five layers to
add a flag"). The bar is whether a future reader has to wonder
"are these supposed to be the same?" — if yes, abstract.

### When to abstract (do it)

1. **The same shape appears 3+ times.** Two copies is a
   coincidence, three is a pattern.
2. **A change needs to land in N places.** If you find yourself
   editing the same 10 lines in 6 files, stop and lift.
3. **The thing has a name.** A noun phrase ("AEAD record framing",
   "PSK binder computation") deserves a subprogram with that name.
4. **Cross-cutting concerns.** Logging, error tagging, RFC-citation
   header comments, `[VERIFIED — …]` tags — write once, reference
   everywhere.

### When NOT to abstract (do not)

1. **Two-occurrence "duplication."**
2. **Coincidental similarity.** Two functions that *look* alike
   but model different concepts should stay separate.
3. **Generics-for-the-sake-of-generics.** A 50-line generic with
   one instantiation is worse than 50 lines of explicit code.
4. **Premature unification across peers / protocols.** First add
   the second case explicitly; the right abstraction shows itself
   when the third case arrives.

### Anti-patterns to avoid

- **`Pack(S0, S1, …, S20)` — variadic-via-defaults.** Use a real
  container (`String_Vectors`, `Argument_Builder`) and an `Append`
  API.
- **Per-peer / per-target / per-cipher-suite "near-twins."**
  Extract a `Build_Common` prelude.
- **Copy-paste with `s/old/new/`.** Default to "one function with
  a parameter".

---

## §12 — Highest-leverage path first; don't anchor on niche features

Before working on a task, ask:

1. **What's the goal?** Restate it in one sentence.
2. **Which paths exist to that goal?** List ≥2 alternatives.
3. **For each path, count: cells unblocked × time × risk.** Pick
   the highest cells-per-hour with acceptable risk.
4. **If you're working on #2 or #3 because #1 is "harder," ask
   why.** Usually because #1 means throwing out something you
   already half-built. That's the anchor speaking. The anchor is
   wrong.

Production-default features (§0a) win this calculation almost
every time. Niche features are niche *because* they unblock fewer
downstream consumers.

### Discipline anchor

When a task is "almost done but the last 20% is fighting niche
peer behaviour" — STOP. Run the leverage check. Usually the right
move isn't "finish this," it's "throw it out and pick the single
high-leverage alternative." The half-built work is a sunk cost.

§0a answers *what* to build; §12 answers *which order* to build
it in when there are multiple candidates.

---

## §13 — Production code is attribution-free

No reference to AI, LLMs, code-generation tools, or assistant
names in:

- Source code (`.adb`, `.ads`, `.gpr`, `.rflx`, `.proto`)
- Build files (`Makefile`, `alire.toml`, `.gpr`)
- Public documentation in `docs/` and crate-level READMEs
- Commit messages and commit-trailers
- Public-facing release notes
- Comments anywhere in the above

The project ships as a portfolio artifact and a public
SPARK-verified TLS implementation. The work — design choices,
proof structure, RFC-mirroring discipline, bug-log entries — is
the author's. Inline tool attribution muddles authorship,
signals a different style of project than what's been built, and
creates maintenance friction.

### Enforcement

A `scripts/scrub-attribution.sh` enumerates the banned strings
and a `git/hooks/pre-commit` hook rejects staged content
containing any of them. Both are checked in. CI runs the
scrub script across the full tree on every PR.

---

## §14 — Every feature must have debug logging from day one

Every new feature, protocol path, handshake step, or wire-format
decoder MUST include `Logger.Log` calls at every decision point
and data boundary **from the first implementation**, not added
later when debugging.

**Use the shared `Logger` crate** (`crates/logger/`). It provides
`Debug`, `Info`, `Warn`, `Error` levels with `Enable_Logging`
constant for compile-time dead-code elimination in release builds.

```ada
with Logger;
...
Logger.Log (Logger.Debug, "hs: state=" & State'Image (S)
            & " in=" & Natural'Image (N) & "B");
```

**What to log (minimum per feature):**

- State transitions (before and after)
- Bytes read / written counts
- AEAD encrypt / decrypt ok / fail
- Cipher suite negotiated
- Error paths with reason
- Any dispatch decision (which branch taken)

**Stripping:** `Logger.Enable_Logging` is a constant Boolean. When
False, the compiler eliminates all Log calls and their string
concatenation arguments. No runtime cost in release.

**Rule:** if a feature ships without logging and a debugging
session later requires adding log statements to understand a
failure, that's a bug — the logging should have been there from
the start.

---

## §15 — Long-running test/bench output: JSON to file, progress to stdout

Any benchmark, soak, fuzzer, multi-cell test, or other long-
running operation that produces structured numeric results MUST:

1. **Build results in memory as an array of objects** (typically a
   `GNATCOLL.JSON.JSON_Array` of per-row `JSON_Value`s in Ada).
2. **Serialise to a JSON file** under the run's log directory at
   the end. Default filename: `<run-name>.json`.
3. **Print one terse progress line per row to stderr** while
   running — peer / feature / result / mean. One line per
   significant unit of work. No tables, no decorations.
4. **Print the path to the JSON file on stdout** as the LAST
   line. Downstream consumers read this path.

**Schema convention** (use this shape; extend as needed):

```json
{
  "schema":   "<run-name>-v1",
  "log_dir":  "/tmp/spark-tls-interop/20260511-123456",
  "config":   { "runs": 5, "bytes": 1048576, "quick": false },
  "<group>":  [ { "peer": "openssl", "metric_x": 32 }, ... ]
}
```

The schema version (`-v1`) lets downstream parsers detect breaking
field changes.

**When this applies:** any operation that would otherwise dump
more than ~20 lines of table data to stdout.

---

## §16 — gnatprove operational discipline

A 200-VC unit takes 3–5 minutes for a first level=1 run;
incremental runs after a single contract edit take seconds to a
minute. Anything materially slower means something is wrong with
your usage, not with gnatprove.

The wrong-things checklist:

1. **Don't kill gnatprove with plain `pkill`.** The parent dies
   but `gnatwhy3` SMT-driver children keep running, holding locks
   on `obj/gnatprove/sessions/`. Use `pkill -INT -f gnatprove`,
   then a moment later `pkill -f gnatwhy3` to be sure. Better:
   don't interrupt at all — wait for the run to finish.

2. **Trust the session cache.** `obj/gnatprove/sessions/`
   content-hashes each VC; unchanged VCs are skipped on re-run.
   Never `rm -rf sessions/` to "force a clean run" unless
   gnatprove itself reports cache corruption.

3. **Don't read `gnatprove.out` while a run is in progress.** The
   summary file is written at the END of phase 3. Confirm
   completion via `pgrep -fla "gnatprove\|gnatwhy3"` returning
   nothing.

4. **Per-unit (`-u <file>`) when iterating.** Full-project re-
   checks everything; per-unit re-checks one file's VCs plus the
   contracts of `with`ed packages. Use full-project only for the
   final audit run.

5. **Level discipline.** `--level=1` for iterative work (cheap
   AoRTE triage), `--level=2` for the audit pass, `--level=3` for
   stubborn VCs where the SMT search needs more budget. Don't
   start at level=2.

**Reporting a proof run honestly:** the only number worth quoting
is the `gnatprove.out` summary for the entity you care about,
*after* the run has exited and no `gnatwhy3` is still alive.
