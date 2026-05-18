# Bug log

External-interop, benchmark, and fuzz-found bugs across the
transports-spark stack. One row per fixed bug per
`docs/conventions.md` §9a. The `Track` column tells you which
feature/crate the bug landed in; the `Tag(s)` column classifies
the root cause per §9.

The log is a release artifact: missing rows mean incomplete
bookkeeping, and the (d) tags are the honest-reporting caveat for
primitives shipped as `[VERIFIED — AoRTE]` whose functional Post
was insufficient (found-by-interop, not by gnatprove).

## How to read the log

- **Track**: TLS, HTTP/2, gRPC, MQTT. Drives which feature owner
  picks up the (d) follow-up.
- **Tag(s)**: §9 taxonomy. `(a)` spec misread · `(b)` spec read
  but impl wrong · `(c)` pure impl bug · `(d)` proof gap a
  functional Post would have caught · `(e)` peer non-conformance
  (not patched per §8).
- **Commit**: short hash, branch label, or release tag. `(WSn)` =
  workstream slice; `(open)` = not yet fixed.

## TLS — `tls_core`

| Date | Found by | Component | RFC § | Tag(s) | Summary | Commit |
|---|---|---|---|---|---|---|
| 2026-05-08 | openssl `tls_process_client_hello` | `Tls_Core.Hello.{Encode_Client_Hello_Psk, Encode_Client_Hello_Cert}` | RFC 8446 §4.4.1 | (a) | PSK binder hash covered the wrong byte range — included the binder length prefix when it should have stopped at `.identities`. | b7dc221 |
| 2026-05-08 | openssl `tls_process_server_hello` | `Tls_Core.Hello.Decode_Server_Hello_Psk_Key_Share` | RFC 8446 §4.2.8.1 | (a) | CH key_share length was 0x26 (38) — should be 0x24 (36) per §4.2.8.1; the u16 prefix excludes itself. | aefd98d |
| 2026-05-08 | openssl `s_client` | `Tls_Core.Tls13_Driver.Init_Psk_Client` | RFC 8446 §7.1 | (a) | binder_key derivation invoked HKDF-Expand-Label with empty Context; spec wants `Derive-Secret` which hashes Messages first. | aefd98d |
| 2026-05-08 | openssl handshake reassembly | `Tls_Core.Tls13_Driver.Hs_Trunc` | RFC 8446 §5.1 | (c)+(d) | 1024-byte transcript-truncation buffer too small for a real openssl 1487-byte ClientHello; bumped to 16640. AoRTE proved buffer wasn't read past `Last`; no functional Post said it must hold a full CH. | 6fb7ed0 |
| 2026-05-08 | openssl + mbedtls `tls_process_client_hello` | `Tls_Core.Hello.{Decode_Cert_Verify, Decode_Body_Single}` | RFC 8446 §4.2.3 | (c)+(d) | `Decode_Body_Single`'s consistency check `1+3+Cursor-4 /= List_Len` algebraically simplified to `Cursor /= List_Len` — off by 4. Pure transcription error. Post didn't bind decoded bytes to encoded bytes; a `Spec_Decode_Single` round-trip Post would have caught this. Latent until D-4-D's client cert receive made it the first call site. | 22cc27f |
| 2026-05-09 | openssl `tls_process_server_hello: invalid session id` | `Tls_Core.Hello.{Encode_Server_Hello_Psk, Encode_Server_Hello_Cert}` | RFC 8446 §4.1.3 | (a)+(d) | server hard-coded `legacy_session_id_echo = empty`; openssl/mbedtls clients abort on mismatch (gnutls passes — its client sends empty session_id). AoRTE Post said "produces ≥40 bytes shaped like SH"; functional Post `serverHelloMsg.legacy_session_id_echo == client.legacy_session_id` tied to miTLS would have rejected the encoder at gnatprove time. | (WS1) |
| 2026-05-09 | tls_core_tests range-check exception | `Tls_Core.Tls13_Driver` (driver session_id capture) | RFC 8446 §4.1.3 | (c) | guard `Sid_L >= Sid_F` matched both-zeros (empty session_id) and tried to slice `In_Bytes (0 .. 0)`; tightened to `Sid_F > 0 and then Sid_L >= Sid_F`. Not a spec issue — the captured-from-decoder branching forgot the empty-session case the decoder zeroes out. | (WS1) |
| 2026-05-09 | openssl `final_sig_algs: missing sigalgs extension` | `Tls_Core.Hello.Encode_Client_Hello_Psk` | RFC 8446 §4.2.3 + §9.2 | (a) | PSK ClientHello omitted `signature_algorithms`. RFC 8446 §9.2 requires it in every CH (including resumption-PSK CHs), even though PSK auth doesn't use cert signatures. openssl rejects the CH outright. Encoder now emits sig_algs (ecdsa_secp256r1_sha256 + rsa_pss_rsae_sha256) before key_share. | (WS3) |
| 2026-05-09 | constraint-error on Slot.Ticket length 192 vs cap 64 | `Tls_Core.Tls13_Driver.Init_Psk_Resumption_Client` Pre + `Identity_Bytes` subtype | RFC 8446 §4.2.11 | (a) | v0.5 cap was 64-byte identity; production NewSessionTicket bytes are larger (openssl ≈190 B, gnutls/bssl can push >256 B). Lifted `Psk_Identity_Len` and `Identity_Bytes` to 1..1024, matching driver-internal envelope. | (WS3) |
| 2026-05-09 | constraint-error: ECDHE shared = bogus (zeros) | `Tls_Core.Tls13_Driver.Init_Psk_Resumption_Client` body | RFC 8446 §4.2.11.2 | (b) | Init_Psk_Resumption_Client called Prime_Driver_Defaults but never called X25519.Derive_Public to populate `My_Ecdhe_Priv` / `My_Ecdhe_Pub`. The CH was emitted with a zero pubkey; openssl's ECDHE derivation failed. Now derives ephemeral from `Slot.Resumption_Secret` (each session has a unique secret). | (WS3) |
| 2026-05-09 | tls-interop psk-external-chacha20 c2s | `Tls_Core.Key_Sched.Derive_Handshake_Secrets` | RFC 8446 §7.1 | (a) | HKDF-Extract Salt/IKM swapped: `Extract(Salt => PSK, IKM => 0)` instead of `Extract(Salt => 0, IKM => PSK)`. Produced wrong Early_Secret for non-zero PSK, causing `bad_record_mac` on all external-PSK handshakes. Cert-mode unaffected (PSK = 0 makes Salt and IKM interchangeable). Introduced in e437d27 (inline→Key_Sched refactor); found by bisecting matrix regression. | f7036b5 |
| 2026-05-09 | tls-interop psk s2c openssl + gnutls cert-ec s2c | `Tls_Core.Tls13_Driver.Step_Awaiting_Ch` binder verify | RFC 8446 §4.2.11.2 | (c)+(d) | Uninitialized `Received : Binder_Bytes` local (48 bytes after widening) — bytes 33-48 contained garbage, causing `Verify` to return False on valid binders. Pure impl bug; a `Default_Value` aspect or flow-analysis warning would have caught it. | (v0.5.1) |
| 2026-05-09 | tls-interop gnutls cert-ec s2c | `Tls_Core.Tls13_Driver.Step_Awaiting_Ch` cert-mode X25519 copy | RFC 8446 §4.2.8 | (c) | Batch sed replaced `for I in 1 .. 32` with `Hash_Len(D.Suite)` in the X25519 key_share copy loop. X25519 keys are always 32 bytes regardless of hash; when AES-256 was in scope Hash_Len returned 48, reading 16 bytes past the key. | (v0.5.1) |
| 2026-05-11 | manual openssl + gnutls cert-ec s2c (TLS_AES_256_GCM_SHA384) | `Tls_Core.Tls13_Driver.Step_Awaiting_Ch_Cert` CV signing | RFC 8446 §4.4.3 | (a)+(d) | Server-side CertificateVerify signed the first 32 bytes of `Th_After_Cert` (hardcoded `(1 .. 32)`) instead of `(1 .. Hash_Len(D.Suite))`. For SHA-384 cipher suites the transcript hash is 48 bytes, so the signature covered a truncated hash — peers correctly rejected as bad signature. Matrix masked the bug because it forced `-ciphersuites TLS_CHACHA20_POLY1305_SHA256` (SHA-256). Functional Post `Signed_Content = Verify_Prefix ‖ Th_After_Cert(1..Hash_Len(Suite))` would have caught it. | (v0.5.1) |
| 2026-05-11 | MQTT-over-TLS against Mosquitto (AES-256-GCM-SHA384) | `step_awaiting_sf_cert.adb` + `key_sched.adb` + `tls13_driver.adb` | RFC 8446 §4.4.3 / §4.4.4 / §4.4.1 / §7.1 | (a)+(c)+(d) | "SHA-256 baked in as the only hash" class — five locations hardcoded `32` where `Hash_Len(D.Suite)` was needed. Surfaced by first SHA-384 server (Mosquitto). Fix: every hash-length literal now suite-dependent; transcript dual-context init; SF length/MAC checks generalized. Functional Post binding `Th'Length = Hash_Len(Suite)` would have caught all five at prove time. | (v0.5.1) |
| 2026-05-15 | §7 audit: production driver missing cert-mode dispatch | `Tls_Core.Tls13_Driver.Step` case statement | RFC 8446 §4.4.2 + §4.4.3 | (b) | Init_Cert_Server / Init_Cert_Client set `D.Mode := Cert_Mode` and the sibling Step_Awaiting_{Ch,Sf}_Cert handlers existed, but Step's case statement always dispatched to PSK-mode handlers regardless of `D.Mode`. Cert-mode appeared "C8 done" per the task list but no caller could actually drive a cert-mode handshake through Step — the §7 failure mode ("sibling package primitives ≠ production-driver integration"). Spec mirror: miTLS `serverHandshakeStep` (two-axis dispatch by state × mode). Full ECDSA-P256 loopback now passes; 598/598 tests green. | (D-4) |
| 2026-05-15 | wolfSSL cert-ec interop deferred status outdated | `Tls_Interop_Peers.Build_Wolfssl` (note only) | RFC 6125 §6.4 | (e) | Old "wolfSSL flight decode mismatch in both directions" note was stale post-D-4. Verified end-to-end against `wolfssl examples/server/server -v 4 -c server-ecc.pem -k ecc-key.pem`. Only remaining gap: wolfSSL's stock test fixture `certs/server-ecc.pem` has no X509 SubjectAltName, so our (correct, RFC 6125-compliant) hostname check rejects with `Bad_Signature`. Counterpart fixture below modern TLS bar — not an Ada-side bug. | (#139) |
| 2026-05-15 | bssl c2s interop deferred status outdated | `Tls_Interop_Peers.Build_Boringssl` (note only) | n/a (bssl tool quirk) | (e) | Same Ada client succeeds end-to-end against openssl/gnutls/mbedtls/wolfssl on identical fixtures, so this is bssl-specific. `bssl server -debug` shows full state-machine progression but `netstat -an` reports TCP send queues at 0 bytes in both directions during the stall. Hypothesis: bssl's example tool buffers the flight at the BIO layer pending a synchronous app-data write that never comes. Lift NI-3P when bssl exposes a flush flag or a different bssl-based server (Cronet) is wired. | (#137) |
| 2026-05-15 | Cert-mode CH missing `psk_key_exchange_modes` extension | `Tls_Core.Hello.Encode_Client_Hello_Cert` | RFC 8446 §4.2.9 (literal) + §0a (production shape) | (a) | RFC §4.2.9 says `psk_key_exchange_modes` "MUST be included when offering PSK" — read literally only required in PSK CHs. But every production TLS 1.3 client (openssl s_client, BoringSSL bssl client, gnutls-cli, Go crypto/tls, Chromium) emits this extension unconditionally. Our cert-mode CH omitted it (explicit design choice per the encoder comment). RFC-conformant but didn't match production-default shape, leaving a subtle interop fingerprint. Now emitted unconditionally per §0a. | (this commit) |
| 2026-05-10 | tls-interop gnutls s2c | `Tls_Core.Tls13_Driver` (server) | RFC 8446 §4.1.3 / §7.1 | TBD | gnutls-cli reports "invalid decryption" on first encrypted record from Ada server; key schedule mismatch. x25519-only priority still fails. openssl/mbedtls/go/rustls/bssl s2c all PASS — gnutls-specific. Needs wire-level key comparison. | (open) |

## HTTP/2 — `http2_core`

| Date | Found by | Component | RFC § | Tag(s) | Summary | Commit |
|---|---|---|---|---|---|---|
| 2026-05-15 | Go gRPC server: `FLOW_CONTROL_ERROR bytes_in_flight exceeded window` | `Http2_Core.Connection.Round_Trip` request DATA send | RFC 9113 §6.1 | (a) | Request body >16384 bytes was sent as a single DATA frame, exceeding SETTINGS_MAX_FRAME_SIZE. Now splits across multiple DATA frames; final frame carries END_STREAM. Found by gRPC benchmark with 64 KB payload. | (v0.5.1) |
| 2026-05-15 | Go gRPC server stalls on multi-frame response | `Http2_Core.Connection.Account_Inbound_Data` | RFC 9113 §6.9.1 | (a) | Per-stream WINDOW_UPDATE never sent — only connection-level (stream 0) was emitted. Server's per-stream send window exhausted at 65535 bytes, deadlocking the response. Added Stream_Id parameter; now refills both windows. | (v0.5.1) |
| 2026-05-15 | Response body corruption mid-frame | `Http2_Core.Connection.Account_Inbound_Data` | RFC 9113 §4.1 | (c)+(d) | WINDOW_UPDATE encoder wrote into `C.Buf` — the same buffer `Read_Frame` and the FSM read path use. Intermittent frame-decode failures when WU fired between frame reads. Switched to a heap-allocated 26-byte WU scratch buffer. Pure aliasing bug; no Post said `Encode_Window_Update` and `Read_Frame` must use disjoint buffers. | (v0.5.1) |
| 2026-05-15 | Go gRPC server: response body >65 KB hangs | `Http2_Core.Connection.Open` initial SETTINGS | RFC 9113 §6.5.2 + §6.9.2 | (a) | Client never advertised SETTINGS_INITIAL_WINDOW_SIZE; per-stream receive window stayed at 65535 default. Multi-MB responses exhausted the window and stalled. Now advertises 4 MB and bumps the connection-level window via WINDOW_UPDATE on stream 0 immediately after SETTINGS. | (v0.5.1) |
| 2026-05-15 | Go gRPC client: 2nd RPC on same connection failed | `Http2_Core.Server.Accept_And_Serve` | RFC 9113 §5.1.1 | (a) | Server processed exactly one stream per TCP connection and then closed. Go clients keep the TCP connection open and submit new HEADERS frames on monotonically-increasing stream IDs (§5.1.1) — server treated the second HEADERS as protocol violation. Wrapped the per-stream FSM cycle in a `Stream_Loop` that re-initializes `Stream::Open` on each new HEADERS, retains per-connection HPACK decoder state, exits cleanly on GOAWAY / RST_STREAM / EOF. | (v0.5.1) |
| 2026-05-15 | Ada server hang at ~65 KB cumulative inbound | `Http2_Core.Server.Accept_And_Serve` | RFC 9113 §6.9.1 | (a) | Server never advertised a larger connection-level receive window; defaulted to 65535. Multi-stream RPCs that accumulated >65 KB of inbound DATA across streams deadlocked. Now sends a connection-level WINDOW_UPDATE (Δ=2^30) after SETTINGS, plus a per-stream refill (Δ=2^20) at the end of each Stream_Loop iteration. | (v0.5.1) |
| 2026-05-15 | HPACK decode garbage on 2nd client | `Http2_Core.Server.Accept_And_Serve` | RFC 7541 §2.2 | (a)+(d) | Dynamic table state from the previous TCP client leaked into the next connection's decoder, producing "string longer than caller buffer" on fresh headers. Reset `L.Hpack_Decoder` at the start of each `Accept_And_Serve` call. (d): a Post saying "Initialize zeros the table" + a connection-scoped invariant "decoder Item_Count = 0 on entry" would have caught this. | (v0.5.1) |
| 2026-05-15 | Go gRPC client: `http2: frame too large` from server | `Http2_Core.Server.Send_Data_Frame` | RFC 9113 §6.1 | (a) | Server sent response DATA frames > 16384 bytes (default SETTINGS_MAX_FRAME_SIZE). Now splits payloads >16 KB across multiple DATA frames, with END_STREAM on the final fragment only. Mirrors the client-side fix earlier in this log. | (v0.5.1) |
| 2026-05-15 | Server stack overflow at large payloads | `Codegen.Emit_Server_V2` (generated handler) | n/a (codegen) | (c) | Generated handler allocated `PB_Out : Octet_Array (1 .. Max_Msg)` on the stack. With Max_Msg = 4 MB and macOS's 8 MB main-thread stack, the buffer alone consumed half the stack; combined with per-stream Request_Body (also stack) it overflowed. Switched to a heap-allocated `PB_Out_Ptr` with `Ada.Unchecked_Deallocation` after each call. | (v0.5.1) |
| 2026-05-15 | Server-side: Go client requests >64 KB stall | `Http2_Core.Server.Send_Initial_Settings` | RFC 9113 §6.5.2 + §6.9.2 | (a) | Server never advertised SETTINGS_INITIAL_WINDOW_SIZE; peer's per-stream send window stayed at 65535 default. Requests larger than that exhausted the client's outbound window mid-stream and deadlocked. Server now advertises 4 MB (parallel to client-side fix). | (v0.5.1) |
| 2026-05-15 | Server-side outbound flow control gap | `Http2_Core.Server.Send_Data_Frame` + WINDOW_UPDATE dispatch | RFC 9113 §6.9 / §6.9.1 / §6.9.2 | (a)+(d) | Server emitted DATA frames without honouring peer's advertised receive window: SETTINGS_INITIAL_WINDOW_SIZE was never parsed and inbound WINDOW_UPDATE was a no-op. Worked against Go (advertises large windows) but would FLOW_CONTROL_ERROR against a tighter peer. Fix: RFLX session machine `Flow_Gate::Send_Gate` in `specs/flow_gate.rflx` structurally enforces "Approve_Send reachable only when Bytes ≤ Conn_Window AND Bytes ≤ Stream_Window", with overflow guard on inbound WU per §6.9.1. Ada façade `Http2_Core.Flow_Gate` exposes Request_Send / Apply_Wu_Conn / Apply_Wu_Stream / Init_Stream. (d) reflects that AoRTE-only proofs on the prior hand-rolled state would not have caught the deviation — the FSM's reachability property is the new structural proof. | (v0.5.2) |
| 2026-05-15 | Server response slice `'Last + 1` range check | `Http2_Core.Server.Send_Data_Frame` chunk arithmetic | n/a (Ada bug) | (c)+(d) | `Remaining : RFLX.RFLX_Types.Index` (range 1..) failed when subtracting the final Chunk to 0. Single-chunk responses always crashed. Latent because the loop's `Remaining > 0` guard was *after* the failing assignment. Fix: switched the Remaining/Chunk counters to `Length` (0-based) with explicit `Index` cast on slice arithmetic. Mirror fix applied to client-side `Connection.Round_Trip`. (d): a Post on the chunked-send loop saying `Remaining'Old = Remaining + Chunk` would have flagged the 0-edge case. | (v0.5.2) |

## gRPC — `grpc_core` + `protoc-gen-grpc-ada`

| Date | Found by | Component | Reference | Tag(s) | Summary | Commit |
|---|---|---|---|---|---|---|
| 2026-05-15 | Generated server: protobuf decode of large names | `Codegen.Emit_Server_V2.Emit` handler body | n/a (codegen) | (c)+(d) | The generated `Handle` used `Request_Body'Last` (buffer end, e.g. 64 KB) instead of `Request_Body_Last` (actual data end, e.g. 1 KB) when constructing the protobuf input slice. Trailing zero bytes decoded as empty fields for small payloads, but >4 KB names produced bogus length-delim varints. Fixed by slicing to `RFLX.RFLX_Types.Index (Request_Body_Last)`. (d): a Post on the protobuf decoder saying `Input'Length <= Spec_Encoded_Length (Spec_Output)` would have prevented this class of caller error. | (v0.5.1) |

## Patterns visible across the log

- **(a) is the dominant failure mode in TLS work** — pure spec
  misreads. Mitigation per `docs/conventions.md` §5: mirror miTLS
  / HACL\* spec structure rather than re-reading the RFC each
  time.
- **(d) entries cluster on AoRTE-only primitives** whose
  functional Post was missing or too weak. Each one is a unit
  that would lift from `[VERIFIED — AoRTE]` to `[VERIFIED —
  PLATINUM]` once the relevant `Spec_X` ghost binds the missing
  property.
- **(c)+(d) pairing** is the usual classification for impl bugs
  that slip past gnatprove — a stronger Post would have flagged
  them at prove time.
- **(e) entries are rare**: only two so far, both peer-tool
  quirks (wolfSSL fixture without SAN, bssl example-server BIO
  buffering). Confirms §8 — when external interop fails, it is
  almost always our deviation from the spec, not the peer being
  weird.
- **HTTP/2 flow control** (§6.9.1 connection vs §6.9.2 stream,
  INITIAL_WINDOW_SIZE vs WINDOW_UPDATE) is the main trip hazard.
  The class would be eliminated by RecordFlux session machines
  for the flow-control side state (now done via
  `Flow_Gate::Send_Gate`) or a hand-mirrored nghttp2 reference.

## Implications for release reporting

When a release report describes the proof state, it MUST account
for every (d) row above as a primitive whose AoRTE proof was
insufficient and whose functional contract needs spec-mirror
tightening. The honest summary form per `docs/conventions.md`
§6:

> "98 % proven, 878 unproved VCs across the workspace at
> `gnatprove --level=4 --proof-warnings=on` (audit-clean on
> suppression — see `docs/proof-results.txt` for the per-package
> rollup and `docs/proof-coverage.md` for the per-subprogram
> tree). N (d)-tagged primitives in the bug log are AoRTE-proven
> but functionally under-specified; lifting them is the next
> wrapper-pattern push."

Not "100 % proven".
