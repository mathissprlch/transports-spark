package body Tls_Core.Gcm_Core
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use Interfaces;

   ---------------------------------------------------------------------
   --  Spec_Build_Mac_Data — only spec function not expression-defined.
   --  Constructed pointwise to match Spec_Build_Mac_Data_Byte_At so
   --  the imperative Build_Mac_Data Post discharges by structural
   --  equality to a single byte-equality quantifier.
   ---------------------------------------------------------------------

   function Spec_Build_Mac_Data
     (AAD        : Octet_Array;
      Ciphertext : Octet_Array)
      return Octet_Array
   is
      Total : constant Natural :=
        Spec_Mac_Length (AAD'Length, Ciphertext'Length);
      Result : Octet_Array (1 .. Total) := (others => 0);
   begin
      for I in 1 .. Total loop
         Result (I) := Spec_Build_Mac_Data_Byte_At (AAD, Ciphertext, I);
         pragma Loop_Invariant (Result'First = 1);
         pragma Loop_Invariant (Result'Last = Total);
         pragma Loop_Invariant
           (for all K in 1 .. I =>
              Result (K) =
                Spec_Build_Mac_Data_Byte_At (AAD, Ciphertext, K));
      end loop;
      return Result;
   end Spec_Build_Mac_Data;

   ---------------------------------------------------------------------
   --  INC32
   ---------------------------------------------------------------------

   procedure Increment_Counter (Counter : in out Block_16) is
      Carry   : Unsigned_8 := 1;
      Idx     : Integer := 16;
   begin
      --  AoRTE-clean implementation of NIST SP 800-38D §6.2 inc_32.
      --  Functional Post (Counter = Spec_Inc32 (Counter'Old)) is the
      --  open §0b honest-unproven gap — see CLAUDE.md §0b / the
      --  [VERIFIED — AoRTE] tag in the .ads.
      while Idx >= 13 and then Carry > 0 loop
         pragma Loop_Invariant (Idx in 13 .. 16);
         pragma Loop_Variant (Decreases => Idx);
         declare
            Sum : constant Unsigned_16 :=
              Unsigned_16 (Counter (Idx)) + Unsigned_16 (Carry);
         begin
            Counter (Idx) := Octet (Sum and 16#FF#);
            if Sum >= 256 then
               Carry := 1;
            else
               Carry := 0;
            end if;
         end;
         Idx := Idx - 1;
      end loop;
   end Increment_Counter;

   ---------------------------------------------------------------------
   --  Build_J0
   ---------------------------------------------------------------------

   procedure Build_J0
     (Nonce  : Octet_Array;
      Out_J0 : out Block_16)
   is
   begin
      Out_J0 := (others => 0);
      Out_J0 (1 .. 12) := Nonce;
      Out_J0 (16) := 1;
      --  Out_J0 = Spec_Build_J0 (Nonce) follows from extensional
      --  equality of the 16 bytes after the three assignments above.
      pragma Assert
        (for all I in 1 .. 12 =>
           Out_J0 (I) = Nonce (Nonce'First + (I - 1)));
      pragma Assert
        (for all I in 13 .. 15 => Out_J0 (I) = 0);
      pragma Assert (Out_J0 (16) = 1);
   end Build_J0;

   ---------------------------------------------------------------------
   --  Build_Mac_Data
   ---------------------------------------------------------------------

   procedure Build_Mac_Data
     (AAD        : Octet_Array;
      Ciphertext : Octet_Array;
      Out_Buf    : out Octet_Array;
      Out_Last   : out Natural)
   is
      Aad_Len : constant Natural := AAD'Length;
      Ct_Len  : constant Natural := Ciphertext'Length;
      Pad_A   : constant Natural := Pad_Len (Aad_Len);
      Pad_C   : constant Natural := Pad_Len (Ct_Len);
      Total   : constant Natural := Spec_Mac_Length (Aad_Len, Ct_Len);

      --  Single-loop pointwise build — each iteration writes one
      --  byte at index I and dispatches to the correct source
      --  region. Maintains the invariant
      --      forall K in 1 .. I => Out_Buf (K) =
      --        Spec_Build_Mac_Data_Byte_At (AAD, Ciphertext, K)
      --  by mirroring exactly the if-elsif chain of
      --  Spec_Build_Mac_Data_Byte_At.
   begin
      Out_Buf := (others => 0);
      for I in 1 .. Total loop
         if I <= Aad_Len then
            Out_Buf (I) := AAD (AAD'First + (I - 1));
         elsif I <= Aad_Len + Pad_A then
            Out_Buf (I) := 0;
         elsif I <= Aad_Len + Pad_A + Ct_Len then
            Out_Buf (I) :=
              Ciphertext
                (Ciphertext'First + (I - Aad_Len - Pad_A - 1));
         elsif I <= Aad_Len + Pad_A + Ct_Len + Pad_C then
            Out_Buf (I) := 0;
         elsif I <= Aad_Len + Pad_A + Ct_Len + Pad_C + 8 then
            Out_Buf (I) :=
              Spec_U64_BE (Unsigned_64 (Aad_Len) * 8)
                (I - (Aad_Len + Pad_A + Ct_Len + Pad_C));
         else
            Out_Buf (I) :=
              Spec_U64_BE (Unsigned_64 (Ct_Len) * 8)
                (I - (Aad_Len + Pad_A + Ct_Len + Pad_C + 8));
         end if;
         pragma Loop_Invariant
           (for all K in 1 .. I =>
              Out_Buf (K) =
                Spec_Build_Mac_Data_Byte_At (AAD, Ciphertext, K));
         pragma Loop_Invariant
           (for all K in I + 1 .. Out_Buf'Last => Out_Buf (K) = 0);
      end loop;
      Out_Last := Total;
   end Build_Mac_Data;

   ---------------------------------------------------------------------
   --  Ghash_Mul — GF(2^128) bit-by-bit multiply.
   ---------------------------------------------------------------------

   procedure Ghash_Mul (X : in out Block_16; Y : Block_16) is
      V    : Block_16 := X;
      Z    : Block_16 := (others => 0);
      Msb  : Octet;
      Bit  : Natural;
   begin
      --  AoRTE-clean implementation of NIST SP 800-38D §6.3
      --  Algorithm 1. Functional Post (X = Spec_GF128_Mul (X'Old, Y))
      --  is the open §0b honest-unproven gap — see CLAUDE.md §0b /
      --  the [VERIFIED — AoRTE] tag in the .ads. The body's
      --  structural correspondence to Spec_GF128_Mul_From is exact,
      --  but the inductive invariant
      --      Spec_GF128_Mul_From (V, Z, Y, K) =
      --        Spec_GF128_Mul (V_init, Y)
      --  does not pull through gnatprove's recursive expression
      --  function unfolding without `pragma Annotate (GNATprove,
      --  Inline_For_Proof)` (forbidden per §0d.6). Closing this gap
      --  requires either a non-recursive equational reformulation
      --  of Spec_GF128_Mul or explicit lemma chains à la HACL\*
      --  `Vale.AES.GHash_BE`. Tracked as separate session work.
      for I in 1 .. 16 loop
         for J in reverse 0 .. 7 loop
            Bit := Natural
              ((Shift_Right (Unsigned_8 (Y (I)), J)) and Unsigned_8'(1));
            if Bit = 1 then
               for L in 1 .. 16 loop
                  Z (L) := Z (L) xor V (L);
               end loop;
            end if;
            Msb := V (16) and 16#01#;
            for L in reverse 2 .. 16 loop
               V (L) := Octet (Shift_Right (Unsigned_8 (V (L)), 1))
                          or (Octet (Shift_Left
                                       (Unsigned_8 (V (L - 1)) and 16#01#,
                                        7)));
            end loop;
            V (1) := Octet (Shift_Right (Unsigned_8 (V (1)), 1));
            if Msb = 1 then
               V (1) := V (1) xor 16#E1#;
            end if;
         end loop;
      end loop;
      X := Z;
   end Ghash_Mul;

   ---------------------------------------------------------------------
   --  Ghash — full-message accumulator.
   --
   --  Body uses the bit-by-bit Ghash_Mul (not the 4-bit table)
   --  because the table-multiply equivalence to `Spec_GF128_Mul`
   --  requires a separate equivalence proof not yet ported (the
   --  HACL\* `Vale.AES.GHash_BE` table-correctness proof is over
   --  polynomial reasoning; porting it into SPARK is a separate
   --  session). Performance impact on the worst-case TLS record
   --  (~33326 bytes input) is bounded: bit-by-bit is ~16x slower per
   --  block but still completes in microseconds. The 4-bit table
   --  primitive remains in `Tls_Core.Ghash_Table` and may be
   --  re-routed once the equivalence proof closes (open functional
   --  correctness gap per CLAUDE.md §0b).
   ---------------------------------------------------------------------

   procedure Ghash
     (H     : Block_16;
      Data  : Octet_Array;
      Out_X : in out Block_16)
   is
      Cursor : Natural := 0;
      Block  : Block_16;
   begin
      while Cursor + 16 <= Data'Length loop
         pragma Loop_Invariant (Cursor in 0 .. Data'Length);
         pragma Loop_Invariant (Cursor mod 16 = 0);
         pragma Loop_Invariant (Cursor + 16 <= 33326);
         pragma Loop_Variant (Decreases => Data'Length - Cursor);
         for I in 1 .. 16 loop
            pragma Loop_Invariant (Cursor + 16 <= Data'Length);
            Block (I) := Data (Data'First + Cursor + I - 1);
         end loop;
         for I in 1 .. 16 loop
            Out_X (I) := Out_X (I) xor Block (I);
         end loop;
         Ghash_Mul (Out_X, H);
         Cursor := Cursor + 16;
      end loop;
      if Cursor < Data'Length then
         Block := (others => 0);
         declare
            Tail : constant Natural := Data'Length - Cursor;
         begin
            pragma Assert (Tail in 1 .. 15);
            for I in 1 .. Tail loop
               pragma Loop_Invariant (Cursor + Tail <= Data'Length);
               pragma Loop_Invariant (Cursor < Data'Length);
               Block (I) := Data (Data'First + Cursor + I - 1);
            end loop;
         end;
         for I in 1 .. 16 loop
            Out_X (I) := Out_X (I) xor Block (I);
         end loop;
         Ghash_Mul (Out_X, H);
      end if;
      --  AoRTE-only on the functional Post: discharging
      --  Out_X = Spec_GHash_Fold (H, Data, Out_X'Old) requires a
      --  per-block invariant of shape
      --    Spec_GHash_Fold (H, Data, Out_X'Old) =
      --      Spec_GHash_Fold (H, Data (cursor + 16 .. last), Out_X)
      --  that gnatprove cannot pull through automatically because
      --  Spec_GHash_Fold's slicing recursion requires unfolding it
      --  by Cursor. Honest-unproven §0b gap; the AEAD test vectors
      --  (NIST CAVP) cover correctness empirically.
      null;
   end Ghash;

   ---------------------------------------------------------------------
   --  Aes_Ctr_Pkg — generic counter-mode encrypt.
   ---------------------------------------------------------------------

   package body Aes_Ctr_Pkg is

      function Spec_Aes_Ctr
        (RK    : Round_Keys;
         J     : Block_16;
         Input : Octet_Array)
         return Octet_Array
      is
         Take      : Natural;
         Stream    : constant Block_16 := Spec_Encrypt_Block (RK, J);
         Result    : Octet_Array (1 .. Input'Length) := (others => 0);
      begin
         if Input'Length = 0 then
            return Result;
         end if;
         Take :=
           (if Input'Length >= 16 then 16 else Input'Length);
         for I in 1 .. Take loop
            Result (I) :=
              Input (Input'First + (I - 1)) xor Stream (I);
            pragma Loop_Invariant (Take in 1 .. 16);
            pragma Loop_Invariant (Result'Length = Input'Length);
            pragma Loop_Invariant (Result'First = 1);
         end loop;
         if Input'Length <= 16 then
            return Result;
         end if;
         declare
            Tail : constant Octet_Array :=
              Spec_Aes_Ctr
                (RK,
                 Spec_Inc32 (J),
                 Input (Input'First + 16 .. Input'Last));
         begin
            for I in 1 .. Tail'Length loop
               Result (16 + I) := Tail (I);
               pragma Loop_Invariant (Tail'Length = Input'Length - 16);
            end loop;
         end;
         return Result;
      end Spec_Aes_Ctr;

      procedure Aes_Ctr
        (RK        : Round_Keys;
         Initial_J : Block_16;
         Input     : Octet_Array;
         Output    : out Octet_Array)
      is
         Counter : Block_16 := Initial_J;
         Stream  : Block_16;
         Cursor  : Natural := 0;
      begin
         Output := (others => 0);
         while Cursor < Input'Length loop
            pragma Loop_Variant (Decreases => Input'Length - Cursor);
            pragma Loop_Invariant (Cursor in 0 .. Input'Length);
            Encrypt_Block (RK, Counter, Stream);
            declare
               Take : constant Natural :=
                 Natural'Min (16, Input'Length - Cursor);
            begin
               for I in 1 .. Take loop
                  Output (Output'First + Cursor + I - 1) :=
                    Input (Input'First + Cursor + I - 1) xor Stream (I);
               end loop;
               Cursor := Cursor + Take;
            end;
            Increment_Counter (Counter);
         end loop;
         --  AoRTE-only on the functional Post: discharging
         --  Output = Spec_Aes_Ctr (RK, Initial_J, Input) requires a
         --  per-block invariant tying (Counter, Cursor) to the
         --  recursive structure of Spec_Aes_Ctr (specifically that
         --  Counter = Spec_Inc32^k (Initial_J) at iteration k). The
         --  invariant is straightforward but its discharge depends
         --  on the formal generic Post (Encrypt_Block matches
         --  Spec_Encrypt_Block) — see CLAUDE.md §0b for the AES
         --  spec gap. Honest-unproven §0b gap.
         null;
      end Aes_Ctr;

   end Aes_Ctr_Pkg;

end Tls_Core.Gcm_Core;
