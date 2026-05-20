--  tls_perf_bench — micro-benchmark for the v0.5 crypto primitives.
--
--  Runs each primitive N times under wall-clock measurement and
--  reports throughput. Targets the operations that dominate a TLS
--  handshake or steady-state record-layer:
--
--    SHA-256 of 1 KiB        — handshake transcript work
--    SHA-384 of 1 KiB        — TLS_AES_256_GCM_SHA384 transcript
--    AES-128 single-block    — round of AES-CTR / GHASH
--    AES-128-GCM seal 1 KiB  — record-layer outbound
--    AES-256-GCM seal 1 KiB  — record-layer outbound (other suite)
--    ChaCha20-Poly1305 seal  — record-layer outbound (third suite)
--    HMAC-SHA-256 of 1 KiB   — HKDF-Expand iteration
--    HKDF-Expand-Label SHA-256 32→32 — Derive-Secret cost
--    Tls13_Driver round-trip — full PSK_KE handshake (in-memory)

with Ada.Calendar;
with Ada.Text_IO;

with Tls_Core;
with Tls_Core.Sha256;
with Tls_Core.Sha384;
with Tls_Core.Aes128;
with Tls_Core.Aead_Aes128_Gcm;
with Tls_Core.Aead_Aes256_Gcm;
with Tls_Core.Aead_Chacha20_Poly1305;
with Tls_Core.Hmac_Sha256;
with Tls_Core.Hkdf_Sha256;
with Tls_Core.Hkdf;
with Tls_Core.Tls13_Driver;

procedure Tls_Perf_Bench is

   use Ada.Calendar;
   use Ada.Text_IO;

   procedure Report
     (Label : String; N : Positive; Bytes_Per_Op : Natural; Started_At : Time);
   procedure Report
     (Label : String; N : Positive; Bytes_Per_Op : Natural; Started_At : Time)
   is
      Elapsed     : constant Duration := Clock - Started_At;
      Ops_Per_Sec : constant Float :=
        Float (N) / Float'Max (Float (Elapsed), 1.0e-9);
      Mb_Per_Sec  : constant Float :=
        Float (N)
        * Float (Bytes_Per_Op)
        / 1_048_576.0
        / Float'Max (Float (Elapsed), 1.0e-9);
   begin
      Put_Line
        (Label
         & ":  "
         & Natural'Image (N)
         & " iters in"
         & Duration'Image (Elapsed)
         & "s = "
         & Integer'Image (Integer (Ops_Per_Sec))
         & " op/s, "
         & Integer'Image (Integer (Mb_Per_Sec))
         & " MiB/s");
   end Report;

   --  ---- 1) SHA-256 throughput ----
   procedure Bench_Sha256 (N : Positive);
   procedure Bench_Sha256 (N : Positive) is
      Buf   : constant Tls_Core.Octet_Array (1 .. 1024) := [others => 16#5A#];
      Out_D : Tls_Core.Sha256.Digest;
      T0    : constant Time := Clock;
   begin
      for I in 1 .. N loop
         Tls_Core.Sha256.Hash (Buf, Out_D);
      end loop;
      Report ("SHA-256 hash 1 KiB", N, 1024, T0);
   end Bench_Sha256;

   procedure Bench_Sha384 (N : Positive);
   procedure Bench_Sha384 (N : Positive) is
      Buf   : constant Tls_Core.Octet_Array (1 .. 1024) := [others => 16#5A#];
      Out_D : Tls_Core.Sha384.Digest;
      T0    : constant Time := Clock;
   begin
      for I in 1 .. N loop
         Tls_Core.Sha384.Hash (Buf, Out_D);
      end loop;
      Report ("SHA-384 hash 1 KiB", N, 1024, T0);
   end Bench_Sha384;

   --  ---- 2) AES-128 single block ----
   procedure Bench_Aes128_Block (N : Positive);
   procedure Bench_Aes128_Block (N : Positive) is
      Key : constant Tls_Core.Aes128.Key_Array := [others => 16#42#];
      Pt  : constant Tls_Core.Aes128.Block := [others => 16#11#];
      Ct  : Tls_Core.Aes128.Block;
      RK  : Tls_Core.Aes128.Round_Keys;
      T0  : Time;
   begin
      Tls_Core.Aes128.Expand_Key (Key, RK);
      T0 := Clock;
      for I in 1 .. N loop
         Tls_Core.Aes128.Encrypt_Block (RK, Pt, Ct);
      end loop;
      Report ("AES-128 single block (16 B)", N, 16, T0);
   end Bench_Aes128_Block;

   --  ---- 3) AEAD seal benchmarks ----
   procedure Bench_Aes128_Gcm_Seal (N : Positive);
   procedure Bench_Aes128_Gcm_Seal (N : Positive) is
      Key : constant Tls_Core.Aead_Aes128_Gcm.Key_Array := [others => 16#42#];
      IV  : constant Tls_Core.Aead_Aes128_Gcm.Nonce_Array :=
        [others => 16#11#];
      Pt  : constant Tls_Core.Octet_Array (1 .. 1024) := [others => 16#5A#];
      AAD : constant Tls_Core.Octet_Array (1 .. 0) := [others => 0];
      Ct  : Tls_Core.Octet_Array (1 .. 1024);
      Tag : Tls_Core.Aead_Aes128_Gcm.Tag_Array;
      T0  : constant Time := Clock;
   begin
      for I in 1 .. N loop
         Tls_Core.Aead_Aes128_Gcm.Seal (Key, IV, AAD, Pt, Ct, Tag);
      end loop;
      Report ("AES-128-GCM seal 1 KiB", N, 1024, T0);
   end Bench_Aes128_Gcm_Seal;

   procedure Bench_Aes256_Gcm_Seal (N : Positive);
   procedure Bench_Aes256_Gcm_Seal (N : Positive) is
      Key : constant Tls_Core.Aead_Aes256_Gcm.Key_Array := [others => 16#42#];
      IV  : constant Tls_Core.Aead_Aes256_Gcm.Nonce_Array :=
        [others => 16#11#];
      Pt  : constant Tls_Core.Octet_Array (1 .. 1024) := [others => 16#5A#];
      AAD : constant Tls_Core.Octet_Array (1 .. 0) := [others => 0];
      Ct  : Tls_Core.Octet_Array (1 .. 1024);
      Tag : Tls_Core.Aead_Aes256_Gcm.Tag_Array;
      T0  : constant Time := Clock;
   begin
      for I in 1 .. N loop
         Tls_Core.Aead_Aes256_Gcm.Seal (Key, IV, AAD, Pt, Ct, Tag);
      end loop;
      Report ("AES-256-GCM seal 1 KiB", N, 1024, T0);
   end Bench_Aes256_Gcm_Seal;

   procedure Bench_Chacha_Seal (N : Positive);
   procedure Bench_Chacha_Seal (N : Positive) is
      Key : constant Tls_Core.Aead_Chacha20_Poly1305.Key_Array :=
        [others => 16#42#];
      IV  : constant Tls_Core.Aead_Chacha20_Poly1305.Nonce_Array :=
        [others => 16#11#];
      Pt  : constant Tls_Core.Octet_Array (1 .. 1024) := [others => 16#5A#];
      AAD : constant Tls_Core.Octet_Array (1 .. 0) := [others => 0];
      Ct  : Tls_Core.Octet_Array (1 .. 1024);
      Tag : Tls_Core.Aead_Chacha20_Poly1305.Tag_Array;
      T0  : constant Time := Clock;
   begin
      for I in 1 .. N loop
         Tls_Core.Aead_Chacha20_Poly1305.Seal (Key, IV, AAD, Pt, Ct, Tag);
      end loop;
      Report ("ChaCha20-Poly1305 seal 1 KiB", N, 1024, T0);
   end Bench_Chacha_Seal;

   --  ---- 4) HMAC + HKDF-Expand-Label ----
   procedure Bench_Hmac_Sha256 (N : Positive);
   procedure Bench_Hmac_Sha256 (N : Positive) is
      Key : constant Tls_Core.Octet_Array (1 .. 32) := [others => 16#42#];
      Msg : constant Tls_Core.Octet_Array (1 .. 1024) := [others => 16#5A#];
      Tag : Tls_Core.Hmac_Sha256.Tag;
      T0  : constant Time := Clock;
   begin
      for I in 1 .. N loop
         Tls_Core.Hmac_Sha256.Compute (Key, Msg, Tag);
      end loop;
      Report ("HMAC-SHA-256 of 1 KiB", N, 1024, T0);
   end Bench_Hmac_Sha256;

   procedure Bench_Hkdf_Expand_Label (N : Positive);
   procedure Bench_Hkdf_Expand_Label (N : Positive) is
      procedure My_Expand is new
        Tls_Core.Hkdf.Expand_Label
          (Hash_Length      => 32,
           Spec_Hmac_Expand => Tls_Core.Hkdf_Sha256.Spec_HKDF_Expand,
           Hmac_Expand      => Tls_Core.Hkdf_Sha256.Hmac_Expand);
      Secret : constant Tls_Core.Octet_Array (1 .. 32) := [others => 16#42#];
      Label  : constant Tls_Core.Octet_Array (1 .. 9) :=
        [16#65#,
         16#78#,
         16#70#,
         16#20#,
         16#6D#,
         16#61#,
         16#73#,
         16#74#,
         16#65#];  --  "exp master"
      Ctx    : constant Tls_Core.Octet_Array (1 .. 32) := [others => 16#11#];
      Out_O  : Tls_Core.Octet_Array (1 .. 32);
      T0     : constant Time := Clock;
   begin
      for I in 1 .. N loop
         My_Expand (Secret, Label, Ctx, Out_O);
      end loop;
      Report ("HKDF-Expand-Label SHA-256 32→32", N, 32, T0);
   end Bench_Hkdf_Expand_Label;

   --  ---- 5) Full psk_dhe_ke (mode 3) handshake (in-memory) ----
   procedure Bench_Tls13_Handshake (N : Positive);
   procedure Bench_Tls13_Handshake (N : Positive) is
      Psk         : constant Tls_Core.Octet_Array (1 .. 32) :=
        [others => 16#42#];
      Identity    : constant Tls_Core.Octet_Array :=
        [16#54#, 16#65#, 16#73#, 16#74#];
      Server_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        [others => 16#11#];
      Client_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        [others => 16#22#];
      C, S        : Tls_Core.Tls13_Driver.Driver;
      Buf         : Tls_Core.Octet_Array (1 .. 4096);
      Buf_Last    : Natural;
      T0          : Time;
   begin
      T0 := Clock;
      for Iter in 1 .. N loop
         Tls_Core.Tls13_Driver.Init_Psk_Server (S, Psk, Identity, Server_Priv);
         Tls_Core.Tls13_Driver.Init_Psk_Client (C, Psk, Identity, Client_Priv);
         --  flight 1: client → CH
         Buf := [others => 0];
         Tls_Core.Tls13_Driver.Step
           (C, In_Bytes => Buf (1 .. 0), Out_Buf => Buf, Out_Last => Buf_Last);
         declare
            Ch         : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
            Reply      : Tls_Core.Octet_Array (1 .. 4096) := [others => 0];
            Reply_Last : Natural;
         begin
            Tls_Core.Tls13_Driver.Step
              (S, In_Bytes => Ch, Out_Buf => Reply, Out_Last => Reply_Last);
            declare
               Sf      : constant Tls_Core.Octet_Array :=
                 Reply (1 .. Reply_Last);
               Cf_Buf  : Tls_Core.Octet_Array (1 .. 4096) := [others => 0];
               Cf_Last : Natural;
            begin
               Tls_Core.Tls13_Driver.Step
                 (C, In_Bytes => Sf, Out_Buf => Cf_Buf, Out_Last => Cf_Last);
               declare
                  Cf           : constant Tls_Core.Octet_Array :=
                    Cf_Buf (1 .. Cf_Last);
                  Discard      : Tls_Core.Octet_Array (1 .. 1024) :=
                    [others => 0];
                  Discard_Last : Natural;
               begin
                  Tls_Core.Tls13_Driver.Step
                    (S,
                     In_Bytes => Cf,
                     Out_Buf  => Discard,
                     Out_Last => Discard_Last);
               end;
            end;
         end;
      end loop;
      Report ("Tls13_Driver PSK_KE handshake (in-mem)", N, 0, T0);
   end Bench_Tls13_Handshake;

begin
   Put_Line ("=== TLS v0.5 crypto-primitive performance bench ===");
   Bench_Sha256 (10_000);
   Bench_Sha384 (10_000);
   Bench_Aes128_Block (100_000);
   Bench_Aes128_Gcm_Seal (5_000);
   Bench_Aes256_Gcm_Seal (5_000);
   Bench_Chacha_Seal (5_000);
   Bench_Hmac_Sha256 (5_000);
   Bench_Hkdf_Expand_Label (5_000);
   Bench_Tls13_Handshake (1_000);
end Tls_Perf_Bench;
