package body Tls_Core.Record_Layer
  with SPARK_Mode
is

   use Interfaces;

   ---------------------------------------------------------------------
   --  Nonce
   ---------------------------------------------------------------------

   function Nonce (IV : IV_Array; S : Seq_Number) return IV_Array is
      Result : IV_Array := [others => 0];
   begin
      --  Top 4 bytes XOR with zero = unchanged.
      Result (1 .. 4) := IV (1 .. 4);
      --  Bottom 8 bytes carry the BE-encoded sequence number XORed
      --  into the IV. Iterating instead of unrolling keeps the
      --  loop invariant compact.
      for I in 5 .. 12 loop
         Result (I) := IV (I) xor Seq_Byte (S, I - 4);
         pragma
           Loop_Invariant
             ((for all J in 1 .. 4 => Result (J) = IV (J))
                and then (for all J in 5 .. I =>
                            Result (J) = (IV (J) xor Seq_Byte (S, J - 4))));
      end loop;
      return Result;
   end Nonce;

   ---------------------------------------------------------------------
   --  Lemma_Nonce_Injective
   --
   --  Strategy: A /= B ⇒ exists a byte position I in 1..8 where
   --  Seq_Byte(A, I) /= Seq_Byte(B, I). That byte sits at nonce
   --  index J = I + 4. XORed with the same IV(J), distinct inputs
   --  give distinct outputs. So Nonce(IV, A)(J) /= Nonce(IV, B)(J),
   --  hence the arrays differ.
   --
   --  The "exists differing byte" step is the core of the lemma;
   --  it follows from u64 byte-decomposition being injective. We
   --  expose that as a separate helper Lemma_Bytes_Witness.
   ---------------------------------------------------------------------

   --  Reverse of Seq_Byte: reconstruct the u64 from its 8 BE bytes.
   --  The Post is the canonical bit-shift composition; gnatprove's
   --  bit-blast back-end discharges Lemma_Roundtrip from it.
   function From_Bytes
     (B1, B2, B3, B4, B5, B6, B7, B8 : Octet) return Seq_Number
   is (Shift_Left (Seq_Number (B1), 56)
       or Shift_Left (Seq_Number (B2), 48)
       or Shift_Left (Seq_Number (B3), 40)
       or Shift_Left (Seq_Number (B4), 32)
       or Shift_Left (Seq_Number (B5), 24)
       or Shift_Left (Seq_Number (B6), 16)
       or Shift_Left (Seq_Number (B7), 8)
       or Seq_Number (B8))
   with Ghost;

   procedure Lemma_Roundtrip (X : Seq_Number)
   with
     Ghost,
     Post =>
       From_Bytes
         (Seq_Byte (X, 1),
          Seq_Byte (X, 2),
          Seq_Byte (X, 3),
          Seq_Byte (X, 4),
          Seq_Byte (X, 5),
          Seq_Byte (X, 6),
          Seq_Byte (X, 7),
          Seq_Byte (X, 8))
       = X;

   procedure Lemma_Roundtrip (X : Seq_Number) is null;

   procedure Lemma_Bytes_Witness (A, B : Seq_Number)
   with
     Ghost,
     Pre  => A /= B,
     Post => (for some I in 1 .. 8 => Seq_Byte (A, I) /= Seq_Byte (B, I));

   procedure Lemma_Bytes_Witness (A, B : Seq_Number) is
   begin
      --  Roundtrip lemma: From_Bytes (Seq_Byte (X, 1..8)) = X for
      --  any X. So if A and B agreed on every byte, From_Bytes of
      --  those bytes would yield both A and B, hence A = B —
      --  contradicting Pre. By contrapositive, some byte differs.
      Lemma_Roundtrip (A);
      Lemma_Roundtrip (B);
   end Lemma_Bytes_Witness;

   procedure Lemma_Nonce_Injective (IV : IV_Array; A, B : Seq_Number) is
   begin
      Lemma_Bytes_Witness (A, B);
      --  Lemma_Bytes_Witness gave us a byte position I in 1..8 with
      --  Seq_Byte(A, I) /= Seq_Byte(B, I). The corresponding nonce
      --  byte is at index I + 4. XOR with the same IV byte keeps
      --  the difference, so the nonce arrays differ at I + 4.
      pragma
        Assert
          ((for some I in 1 .. 8 =>
              (IV (I + 4) xor Seq_Byte (A, I))
              /= (IV (I + 4) xor Seq_Byte (B, I))));
      pragma
        Assert
          ((for some I in 1 .. 8 =>
              Nonce (IV, A) (I + 4) /= Nonce (IV, B) (I + 4)));
   end Lemma_Nonce_Injective;

   ---------------------------------------------------------------------
   --  Init / Bump / Lemma_Bump_Fresh_Nonce
   ---------------------------------------------------------------------

   procedure Init (S : out Stream; IV : IV_Array) is
   begin
      S := Stream'(IV => IV, Seq => 0);
   end Init;

   procedure Bump (S : in out Stream) is
   begin
      S.Seq := S.Seq + 1;
   end Bump;

   procedure Lemma_Bump_Fresh_Nonce (S_Before, S_After : Stream) is
   begin
      --  Seq differs (Before vs Before+1) and IV is identical, so
      --  the lemma reduces to the per-Seq nonce injectivity.
      Lemma_Nonce_Injective
        (IV_Of (S_Before), Seq_Of (S_Before), Seq_Of (S_After));
   end Lemma_Bump_Fresh_Nonce;

   ---------------------------------------------------------------------
   --  Aead generic body
   ---------------------------------------------------------------------

   package body Aead is

      procedure Seal_Record
        (S          : in out Stream;
         Key        : Key_Type;
         AAD        : Octet_Array;
         Plaintext  : Octet_Array;
         Ciphertext : out Octet_Array;
         Tag        : out Tag_Type)
      is
         N : constant IV_Array := Nonce (S.IV, S.Seq);
      begin
         Seal
           (Key        => Key,
            Nonce      => N,
            AAD        => AAD,
            Plaintext  => Plaintext,
            Ciphertext => Ciphertext,
            Tag        => Tag);
         Bump (S);
      end Seal_Record;

      procedure Open_Record
        (S          : in out Stream;
         Key        : Key_Type;
         AAD        : Octet_Array;
         Ciphertext : Octet_Array;
         Tag        : Tag_Type;
         Plaintext  : out Octet_Array;
         OK         : out Boolean)
      is
         N : constant IV_Array := Nonce (S.IV, S.Seq);
      begin
         Open
           (Key        => Key,
            Nonce      => N,
            AAD        => AAD,
            Ciphertext => Ciphertext,
            Tag        => Tag,
            Plaintext  => Plaintext,
            OK         => OK);
         Bump (S);
      end Open_Record;

   end Aead;

end Tls_Core.Record_Layer;
