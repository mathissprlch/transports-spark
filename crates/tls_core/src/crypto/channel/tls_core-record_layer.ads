--  Tls_Core.Record_Layer — TLS 1.3 record-layer AEAD wrapper.
--
--  Source: RFC 8446 §5.2 (Record Layer) + §5.3 (Per-Record Nonce).
--
--      The per-record nonce for the AEAD construction is formed as
--      follows:
--        1. The 64-bit record sequence number is encoded in
--           network byte order and padded to the left with zeros
--           to iv_length.
--        2. The padded sequence number is XORed with either the
--           static client_write_iv or server_write_iv (depending
--           on the role).
--      The resulting quantity (of length iv_length) is used as
--      the per-record nonce.
--
--  miTLS reference (project-everest/mitls-fstar):
--    src/tls/MiTLS.Record.fst              ('frame', `seqn`)
--    src/tls/MiTLS.StAE.fst                (state-encryption layer)
--    src/tls/MiTLS.Crypto.AEAD.fst         (`encrypt` / `decrypt`)
--
--  miTLS proves "no nonce reuse" via a `frame` ghost that records
--  every (key, nonce) pair the AEAD has been called with; the StAE
--  layer's invariant says new calls always pick a nonce outside
--  that set. Our reformulation is equivalent but more concrete:
--  Stream.Seq is strictly monotonic, IV is fixed for the stream's
--  lifetime, and Lemma_Nonce_Injective shows distinct Seq values
--  give distinct nonces. By induction, every nonce a Stream emits
--  is unique to that stream.
--
--  This package owns the Seq/IV bookkeeping and the lemmas; the
--  AEAD primitive itself (ChaCha20-Poly1305 or AES-GCM) is a
--  generic formal whose contract mirrors miTLS' `encrypt` spec.

with Interfaces;

package Tls_Core.Record_Layer
  with SPARK_Mode
is

   use type Tls_Core.Octet;
   use type Interfaces.Unsigned_64;

   --  Both AES-128-GCM and ChaCha20-Poly1305 use a 12-byte nonce
   --  in TLS 1.3, so we hard-bound IV here. (TLS_AES_128_CCM_*
   --  also use 12; TLS_AES_256_GCM_SHA384 same.)
   subtype IV_Array is Octet_Array (1 .. 12);

   subtype Seq_Number is Interfaces.Unsigned_64;

   ---------------------------------------------------------------------
   --  Per-byte spec helpers (visible so contracts can name them).
   ---------------------------------------------------------------------

   --  The Ith byte (1..8, big-endian) of a u64 sequence number.
   function Seq_Byte (S : Seq_Number; I : Positive) return Octet
   is (Octet (Interfaces.Shift_Right (S, Natural (8 * (8 - I))) and 16#FF#))
   with Pre => I in 1 .. 8;

   ---------------------------------------------------------------------
   --  Nonce derivation per RFC 8446 §5.3.
   --
   --  pad_left(seq_be, 12) = 4 zero bytes ‖ Seq_Byte(S,1..8)
   --  nonce = pad_left(seq_be, 12) XOR IV
   --
   --  XOR with zero = identity, so:
   --    nonce(1..4)  = IV(1..4)
   --    nonce(5..12) = IV(5..12) XOR Seq_Byte(S, 1..8)
   ---------------------------------------------------------------------

   function Nonce (IV : IV_Array; S : Seq_Number) return IV_Array
   with
     Post =>
       (for all I in 1 .. 4 => Nonce'Result (I) = IV (I))
       and then (for all I in 5 .. 12 =>
                   Nonce'Result (I) = (IV (I) xor Seq_Byte (S, I - 4)));

   ---------------------------------------------------------------------
   --  Lemma — distinct sequence numbers give distinct nonces.
   --
   --  This is the "no nonce reuse with a fixed IV" property.
   --  Combined with Stream's monotonic Seq, it proves every nonce
   --  emitted from a Stream over its lifetime is unique. That is
   --  the AEAD security premise the upper layer (StAE / handshake)
   --  rests on, mirroring miTLS' nonce-freshness invariant.
   ---------------------------------------------------------------------

   procedure Lemma_Nonce_Injective (IV : IV_Array; A, B : Seq_Number)
   with Ghost, Pre => A /= B, Post => Nonce (IV, A) /= Nonce (IV, B);

   ---------------------------------------------------------------------
   --  Stream — per-direction record-layer state.
   --
   --  Carries the static IV (frozen at Init) and the monotonic Seq
   --  counter. The actual AEAD key and any cached cipher context
   --  are held by the AEAD primitive's instantiation, opaque from
   --  this layer's point of view.
   ---------------------------------------------------------------------

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   type Stream is private;

   function Seq_Of (S : Stream) return Seq_Number
   with Ghost;

   function IV_Of (S : Stream) return IV_Array
   with Ghost;

   function Next_Nonce (S : Stream) return IV_Array
   is (Nonce (IV_Of (S), Seq_Of (S)))
   with Ghost;

   procedure Init (S : out Stream; IV : IV_Array)
   with Post => Seq_Of (S) = 0 and then IV_Of (S) = IV;

   --  Advance the sequence counter by one. Refused (precondition
   --  violation) if seq has saturated; the upper layer must rekey
   --  rather than wrap. RFC 8446 §5.5 mandates rekey before 2^64-1.
   procedure Bump (S : in out Stream)
   with
     Pre  => Seq_Of (S) < Seq_Number'Last,
     Post =>
       Seq_Of (S) = Seq_Of (S'Old) + 1 and then IV_Of (S) = IV_Of (S'Old);

   --  After Bump, the stream's next nonce differs from the one it
   --  would have produced before the bump. Surfaced for callers
   --  who want to assert "no two sealed records share a nonce".
   procedure Lemma_Bump_Fresh_Nonce (S_Before, S_After : Stream)
   with
     Ghost,
     Pre  =>
       Seq_Of (S_Before) < Seq_Number'Last
       and then Seq_Of (S_After) = Seq_Of (S_Before) + 1
       and then IV_Of (S_After) = IV_Of (S_Before),
     Post => Next_Nonce (S_After) /= Next_Nonce (S_Before);

   ---------------------------------------------------------------------
   --  Aead — generic over the underlying seal/open primitive. For
   --  the TLS_CHACHA20_POLY1305_SHA256 suite we instantiate against
   --  Tls_Core.Aead_Chacha20_Poly1305 (slice 7).
   --
   --  The Stream provides the unique nonce per call; the AEAD
   --  primitive treats it as a fresh value by contract. Seal_Record
   --  bumps the Stream's Seq counter, so by Lemma_Bump_Fresh_Nonce
   --  the next call will use a different nonce — that's the
   --  no-reuse property surfaced operationally.
   ---------------------------------------------------------------------

   generic
      type Key_Type is private;
      type Tag_Type is private;
      with
        procedure Seal
          (Key        : Key_Type;
           Nonce      : IV_Array;
           AAD        : Octet_Array;
           Plaintext  : Octet_Array;
           Ciphertext : out Octet_Array;
           Tag        : out Tag_Type);
      with
        procedure Open
          (Key        : Key_Type;
           Nonce      : IV_Array;
           AAD        : Octet_Array;
           Ciphertext : Octet_Array;
           Tag        : Tag_Type;
           Plaintext  : out Octet_Array;
           OK         : out Boolean);
   package Aead is

      procedure Seal_Record
        (S          : in out Stream;
         Key        : Key_Type;
         AAD        : Octet_Array;
         Plaintext  : Octet_Array;
         Ciphertext : out Octet_Array;
         Tag        : out Tag_Type)
      with
        Pre  =>
          Seq_Of (S) < Seq_Number'Last
          and then Ciphertext'Length = Plaintext'Length
          and then AAD'Length <= 16640
          and then Plaintext'Length <= 16640
          and then AAD'Last < Integer'Last - 16640
          and then Plaintext'Last < Integer'Last - 16640
          and then Ciphertext'Last < Integer'Last - 16640,
        Post =>
          Seq_Of (S) = Seq_Of (S'Old) + 1 and then IV_Of (S) = IV_Of (S'Old);

      procedure Open_Record
        (S          : in out Stream;
         Key        : Key_Type;
         AAD        : Octet_Array;
         Ciphertext : Octet_Array;
         Tag        : Tag_Type;
         Plaintext  : out Octet_Array;
         OK         : out Boolean)
      with
        Pre  =>
          Seq_Of (S) < Seq_Number'Last
          and then Plaintext'Length = Ciphertext'Length
          and then AAD'Length <= 16640
          and then Ciphertext'Length <= 16640
          and then AAD'Last < Integer'Last - 16640
          and then Ciphertext'Last < Integer'Last - 16640
          and then Plaintext'Last < Integer'Last - 16640,
        Post =>
          Seq_Of (S) = Seq_Of (S'Old) + 1 and then IV_Of (S) = IV_Of (S'Old);

   end Aead;

private

   type Stream is record
      IV  : IV_Array := (others => 0);
      Seq : Seq_Number := 0;
   end record;

   function Seq_Of (S : Stream) return Seq_Number
   is (S.Seq);
   function IV_Of (S : Stream) return IV_Array
   is (S.IV);

end Tls_Core.Record_Layer;
