# Overnight test iteration 01 — summary

Run window: 2026-05-03 01:30 → ~02:30 (terminated early to fix bugs).
Codebase HEAD at start: `2558b92` (post-C+E SPARK_Mode + precondition cleanup).

## Headline

**Three bugs found, all in regions gnatprove flagged unproved.
Zero bugs found in the 4,901 discharged checks.** The proof was a
precise crash-locator: 100% true-positive rate on the unproved
obligations the fuzzer exercised, 100% true-negative rate on the
discharged ones at this sample size.

## Per-test results

### host_h2_fuzz — http2_core codec fuzzer

- Iterations completed: **2,270,000** (terminated early at 45% of
  the planned 5M target)
- Crashes: **6,139** — all the same `Ada.Assertions.Assertion_Error`
  raised from `http2_core-hpack-string_literal.ads:50`
- Other decoders (Huffman, Int_Codec at all four prefix widths):
  **zero crashes**

Single root cause: `Hpack.Decode` invokes `String_Literal.Decode`
without verifying that there is at least one byte left in the
input after consuming the integer prefix. The precondition
`First in Input'Range` fires when the prefix consumed the entire
input. This was one of the unproved obligations in the post-C+E
gnatprove run.

### host_grpc_fuzz — grpc_core codec fuzzer (COMPLETE)

- Iterations completed: **5,000,000**
- `Framing.Decode`: **2,500,064 Constraint_Error**, all
  `grpc_core-framing.adb:43 overflow check failed`. Exactly 50.001%
  of random inputs.
- `Status.From_String`: **zero crashes** across 5M random short
  ASCII strings (~1.6% mapped to valid status codes).

Single root cause: `Natural (Input(F+1)) * 16777216` overflows
32-bit `Natural'Last` when the high byte ≥ 0x80. Wide enough
intermediate type was not used. Direct, scale-invariant bug.

### http2_soak — Connection driver vs Python h2 echo (TERMINATED ON FIRST FAILURE)

- Iterations attempted: 5
- Successful round trips: 0
- Failures: 5, all `CONSTRAINT_ERROR : http2_core-connection.adb:371 range check failed`

Single root cause: `for I in 0 .. Header.Length - 1` with
`RFLX.RFLX_Types.Index (I)` underflows when I = 0 because Index'First
= 1. Off-by-one at the body-copy site of the inbound DATA branch.
Driver is currently unusable against any real peer.

### aarch64_h2_fuzz — linux/aarch64 portability (COMPLETE)

- Iterations completed: **1,000,000**
- Crashes: same `Hpack.Decode` Assertion_Error pattern, scaled
  proportionally to host
- Bit-identical Huffman / Int_Codec results vs darwin/arm64

This is a hosted-Linux portability check, not a bare-metal
validation. (See OVERNIGHT_REPORT.md for the bare-metal gap
discussion.)

### mqtt_soak — MQTT end-to-end vs Mosquitto (COMPLETE)

- Iterations completed: **10,000**
- Failures: **0**
- Mosquitto RSS at start: 2.31 MiB
- Mosquitto RSS at end: 2.31 MiB
- Per-iteration: full Open → Subscribe_Many → 4 round-trips →
  Publish_Qos1 → drain → Publish_Qos2 → drain → Unsubscribe_Many
  → Close

The mqtt_core path (gnatprove 99.79% discharged) ran clean across
10,000 full end-to-end iterations. Zero anomalies, zero memory
growth.

## What this iteration tells us

| Region | Proof status | Fuzz/runtime result |
|---|---|---|
| Hpack.Decode boundary to String_Literal | unproved obligation | bug found, 0.27% rate |
| Framing.Decode length arithmetic | unproved obligation | bug found, 50% rate |
| Connection.Round_Trip body-copy | unproved obligation | bug found, 100% rate |
| Hpack.Huffman | proven (96.84% block) | clean across 3M+ inputs |
| Hpack.Int_Codec | proven (96.84% block) | clean across 12M+ inputs |
| Hpack.Static_Table | fully proven post-predicate | clean |
| mqtt_core full path | 99.79% proven | 10k iter clean |

The proof's signal was tight and accurate. There were 160 unproved
obligations in http2_core; the fuzzer exercised the path through 3
of them and crashed at every one. Other unproved obligations exist
that the fuzzer didn't exercise — they're either harder to reach
from the fuzzer's API surface or harmless.

## Next iteration plan

Fix the three bugs:
1. `Hpack.Decode` — add bounds check before delegating to
   `String_Literal.Decode`.
2. `Grpc_Core.Framing.Decode` — use 64-bit intermediate.
3. `Http2_Core.Connection.Round_Trip:371` — fix off-by-one Index
   conversion.

Then re-run the full battery (iteration 02). Expect: crashes go to
zero in those three regions; total proof rate may shift up
slightly (depending on whether the fixes also discharge their
respective unproved obligations).

## Logs in this archive

- `host_h2_fuzz.log` + `fuzz_crashes.log` — http2 fuzzer
- `host_grpc_fuzz.log` + `grpc_fuzz_crashes.log` — grpc fuzzer
- `aarch64_h2_fuzz.log` — linux/aarch64 portability
- `mqtt_soak.log`, `mqtt_soak_anomalies.log`, `mqtt_rss.log` — MQTT soak
- `host_mqtt_soak_runner.log` — wrapper script log
