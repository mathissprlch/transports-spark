--  Tls_Core.Hello_Retry — TLS 1.3 HelloRetryRequest support
--  (RFC 8446 §4.1.4 + §4.4.1 transcript-hash quirk).
--
--  HRR is structurally a ServerHello with the Random field set to
--  the well-known magic value SHA-256("HelloRetryRequest"), the
--  identity of which is fixed by §4.1.3.
--
--  The transcript-hash quirk: when the handshake includes an HRR,
--  the value of ClientHello1 in the transcript is replaced by a
--  synthetic message_hash handshake message:
--
--      [type=0xFE u8] [length=H_LEN u24] [Hash(ClientHello1)]
--
--  The transcript-hash input then becomes:
--      synthetic_msg || HRR || CH2 || SH || ...
--
--  This module is the SPARK-clean primitive layer; the handshake
--  driver dispatches into Build_Synthetic_Msg when it detects an
--  HRR (compares the SH's Random against Magic_Random).

with Interfaces;
with Tls_Core.Sha256;

package Tls_Core.Hello_Retry
with SPARK_Mode
is

   use type Interfaces.Unsigned_8;

   --  RFC 8446 §4.1.3 — fixed magic random value that flags an
   --  HRR. This is SHA-256 of the ASCII bytes "HelloRetryRequest".
   --  We hard-code the digest rather than recompute it because the
   --  RFC mandates the constant.
   Magic_Random : constant Octet_Array (1 .. 32) :=
     (16#CF#, 16#21#, 16#AD#, 16#74#, 16#E5#, 16#9A#, 16#61#, 16#11#,
      16#BE#, 16#1D#, 16#8C#, 16#02#, 16#1E#, 16#65#, 16#B8#, 16#91#,
      16#C2#, 16#A2#, 16#11#, 16#16#, 16#7A#, 16#BB#, 16#8C#, 16#5E#,
      16#07#, 16#9E#, 16#09#, 16#E2#, 16#C8#, 16#A8#, 16#33#, 16#9C#);

   --  Synthetic handshake type code for the message_hash record
   --  RFC 8446 §4.4.1 emits in place of ClientHello1.
   Synthetic_Type : constant Octet := 16#FE#;

   --  Test whether a 32-byte ServerHello.random equals Magic_Random.
   --  Constant-time over the bytes (fixed loop, no early exit).
   function Is_Hrr_Random (Random : Octet_Array) return Boolean
   with Pre => Random'Length = 32;

   --  Build the synthetic message_hash record for the SHA-256
   --  transcript: 4 header bytes (type=0xFE, length u24=0x000020) +
   --  32-byte Hash(ClientHello1). Output is 36 bytes.
   --
   --  Imperative Post: header bytes match the §4.4.1 layout and
   --  bytes 5..36 carry the input Ch1_Hash byte-for-byte.
   procedure Build_Synthetic_Msg_Sha256
     (Ch1_Hash : Tls_Core.Sha256.Digest;
      Out_Buf  : out Octet_Array)
   with
     Pre  => Out_Buf'First = 1 and then Out_Buf'Length = 36,
     Post =>
       Out_Buf (1) = Synthetic_Type
       and then Out_Buf (2) = 0
       and then Out_Buf (3) = 0
       and then Out_Buf (4) = 32
       and then
         (for all I in 1 .. 32 => Out_Buf (4 + I) = Ch1_Hash (I));

end Tls_Core.Hello_Retry;
