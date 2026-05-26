package body Tls_Core.Rsa_Pss
  with SPARK_Mode
is

   use Interfaces;
   use type Tls_Core.Sha256.Hash_State;
   use type Tls_Core.Sha384.Hash_State;

   ---------------------------------------------------------------------
   --  EM_Length / em_Bits constants (RFC 8017 §9.1).
   --
   --  For a 2048-bit RSA modulus, modBits = 2048, so
   --      emBits = modBits - 1 = 2047
   --      emLen  = ceil (emBits / 8) = 256
   --
   --  After OS2IP / I2OSP at the EMSA boundary, EM is exactly 256
   --  bytes — i.e., a Bigint. The "high 8*emLen - emBits = 1 bit
   --  of EM[0]" must be zero.
   --
   --  EM_Length / EM_High_Mask are exposed in the package spec so
   --  the spec ghost (Spec_DB_Zero_2047) and the imperative body
   --  share one definition.
   ---------------------------------------------------------------------

   ---------------------------------------------------------------------
   --  Spec ports — ported from HACL* specs/Spec.RSAPSS.fst.
   --  These are real (executable) SPARK functions referenced by the
   --  Posts on Emsa_Pss_Verify_*. The imperative entry points call
   --  them directly, so the functional Posts discharge by
   --  construction (mirror of Sha256.Hash → Spec_SHA256).
   ---------------------------------------------------------------------

   ---------------------------------------------------------------------
   --  Hash-determinism congruence lemmas (null bodies — SMT discharges
   --  the Post directly from Pre X = Y if Spec_SHA's body is treated as
   --  a pure function with UF congruence). If null fails, body is
   --  expanded with inductive structural asserts.
   ---------------------------------------------------------------------

   --  Inductive congruence on the recursive Spec_W message schedule.
   procedure Lemma_W_Cong_Sha256
     (B1, B2 : Tls_Core.Sha256.Block; I : Natural)
   with
     Ghost,
     Global             => null,
     Pre                => B1 = B2 and then I <= 63,
     Post               =>
       Tls_Core.Sha256.Spec_W_SHA256 (B1, I)
       = Tls_Core.Sha256.Spec_W_SHA256 (B2, I),
     Subprogram_Variant => (Decreases => I);

   procedure Lemma_W_Cong_Sha256
     (B1, B2 : Tls_Core.Sha256.Block; I : Natural)
   is
   begin
      if I > 15 then
         Lemma_W_Cong_Sha256 (B1, B2, I - 2);
         Lemma_W_Cong_Sha256 (B1, B2, I - 7);
         Lemma_W_Cong_Sha256 (B1, B2, I - 15);
         Lemma_W_Cong_Sha256 (B1, B2, I - 16);
      end if;
   end Lemma_W_Cong_Sha256;

   procedure Lemma_W_Cong_Sha384
     (B1, B2 : Tls_Core.Sha384.Block; I : Natural)
   with
     Ghost,
     Global             => null,
     Pre                => B1 = B2 and then I <= 79,
     Post               =>
       Tls_Core.Sha384.Spec_W_SHA384 (B1, I)
       = Tls_Core.Sha384.Spec_W_SHA384 (B2, I),
     Subprogram_Variant => (Decreases => I);

   procedure Lemma_W_Cong_Sha384
     (B1, B2 : Tls_Core.Sha384.Block; I : Natural)
   is
   begin
      if I > 15 then
         Lemma_W_Cong_Sha384 (B1, B2, I - 2);
         Lemma_W_Cong_Sha384 (B1, B2, I - 7);
         Lemma_W_Cong_Sha384 (B1, B2, I - 15);
         Lemma_W_Cong_Sha384 (B1, B2, I - 16);
      end if;
   end Lemma_W_Cong_Sha384;

   --  Inductive congruence on the recursive Spec_Shuffle fold. Same
   --  template as Lemma_Hash_Blocks_Cong — recursive lemma with
   --  Subprogram_Variant on N drives gnatprove's induction.
   procedure Lemma_Shuffle_Cong_Sha256
     (S1, S2 : Tls_Core.Sha256.Hash_State;
      B1, B2 : Tls_Core.Sha256.Block;
      N      : Natural)
   with
     Ghost,
     Global             => null,
     Pre                =>
       S1 = S2 and then B1 = B2 and then N <= 64,
     Post               =>
       Tls_Core.Sha256.Spec_Shuffle_SHA256 (S1, B1, N)
       = Tls_Core.Sha256.Spec_Shuffle_SHA256 (S2, B2, N),
     Subprogram_Variant => (Decreases => N);

   procedure Lemma_Shuffle_Cong_Sha256
     (S1, S2 : Tls_Core.Sha256.Hash_State;
      B1, B2 : Tls_Core.Sha256.Block;
      N      : Natural)
   is
   begin
      if N /= 0 then
         Lemma_Shuffle_Cong_Sha256 (S1, S2, B1, B2, N - 1);
         Lemma_W_Cong_Sha256 (B1, B2, N - 1);
      end if;
   end Lemma_Shuffle_Cong_Sha256;

   procedure Lemma_Shuffle_Cong_Sha384
     (S1, S2 : Tls_Core.Sha384.Hash_State;
      B1, B2 : Tls_Core.Sha384.Block;
      N      : Natural)
   with
     Ghost,
     Global             => null,
     Pre                =>
       S1 = S2 and then B1 = B2 and then N <= 80,
     Post               =>
       Tls_Core.Sha384.Spec_Shuffle_SHA384 (S1, B1, N)
       = Tls_Core.Sha384.Spec_Shuffle_SHA384 (S2, B2, N),
     Subprogram_Variant => (Decreases => N);

   procedure Lemma_Shuffle_Cong_Sha384
     (S1, S2 : Tls_Core.Sha384.Hash_State;
      B1, B2 : Tls_Core.Sha384.Block;
      N      : Natural)
   is
   begin
      if N /= 0 then
         Lemma_Shuffle_Cong_Sha384 (S1, S2, B1, B2, N - 1);
         Lemma_W_Cong_Sha384 (B1, B2, N - 1);
      end if;
   end Lemma_Shuffle_Cong_Sha384;

   --  Leaf congruence on Update_Block_Spec — calls Shuffle cong via
   --  the lemma above so SMT has the induction step ready.
   procedure Lemma_Update_Block_Cong_Sha256
     (S1, S2 : Tls_Core.Sha256.Hash_State; B1, B2 : Tls_Core.Sha256.Block)
   with
     Ghost,
     Global => null,
     Pre    => S1 = S2 and then B1 = B2,
     Post   =>
       Tls_Core.Sha256.Update_Block_Spec (S1, B1)
       = Tls_Core.Sha256.Update_Block_Spec (S2, B2);

   procedure Lemma_Update_Block_Cong_Sha256
     (S1, S2 : Tls_Core.Sha256.Hash_State; B1, B2 : Tls_Core.Sha256.Block)
   is
   begin
      Lemma_Shuffle_Cong_Sha256 (S1, S2, B1, B2, 64);
   end Lemma_Update_Block_Cong_Sha256;

   procedure Lemma_Update_Block_Cong_Sha384
     (S1, S2 : Tls_Core.Sha384.Hash_State; B1, B2 : Tls_Core.Sha384.Block)
   with
     Ghost,
     Global => null,
     Pre    => S1 = S2 and then B1 = B2,
     Post   =>
       Tls_Core.Sha384.Update_Block_Spec (S1, B1)
       = Tls_Core.Sha384.Update_Block_Spec (S2, B2);

   procedure Lemma_Update_Block_Cong_Sha384
     (S1, S2 : Tls_Core.Sha384.Hash_State; B1, B2 : Tls_Core.Sha384.Block)
   is
   begin
      Lemma_Shuffle_Cong_Sha384 (S1, S2, B1, B2, 80);
   end Lemma_Update_Block_Cong_Sha384;

   --  Inductive congruence on the recursive Spec_Hash_Blocks fold.
   --  gnatprove SMT does not auto-instantiate the induction principle,
   --  so we write it as a null-body lemma with a recursive call: the
   --  Subprogram_Variant on N drives gnatprove's induction.
   procedure Lemma_Hash_Blocks_Cong_Sha256
     (S0 : Tls_Core.Sha256.Hash_State; Px, Py : Octet_Array; N : Natural)
   with
     Ghost,
     Global             => null,
     Pre                =>
       Px'First = 1
       and then Py'First = 1
       and then Px'Length = Py'Length
       and then N <= Natural'Last / 64
       and then N * 64 <= Px'Length
       and then Px = Py,
     Post               =>
       Tls_Core.Sha256.Spec_Hash_Blocks (S0, Px, N)
       = Tls_Core.Sha256.Spec_Hash_Blocks (S0, Py, N),
     Subprogram_Variant => (Decreases => N);

   procedure Lemma_Hash_Blocks_Cong_Sha256
     (S0 : Tls_Core.Sha256.Hash_State; Px, Py : Octet_Array; N : Natural)
   is
   begin
      if N /= 0 then
         Lemma_Hash_Blocks_Cong_Sha256 (S0, Px, Py, N - 1);
         Lemma_Update_Block_Cong_Sha256
           (Tls_Core.Sha256.Spec_Hash_Blocks (S0, Px, N - 1),
            Tls_Core.Sha256.Spec_Hash_Blocks (S0, Py, N - 1),
            Tls_Core.Sha256.Block_At (Px, N - 1),
            Tls_Core.Sha256.Block_At (Py, N - 1));
      end if;
   end Lemma_Hash_Blocks_Cong_Sha256;

   procedure Lemma_Hash_Blocks_Cong_Sha384
     (S0 : Tls_Core.Sha384.Hash_State; Px, Py : Octet_Array; N : Natural)
   with
     Ghost,
     Global             => null,
     Pre                =>
       Px'First = 1
       and then Py'First = 1
       and then Px'Length = Py'Length
       and then N <= Natural'Last / 128
       and then N * 128 <= Px'Length
       and then Px = Py,
     Post               =>
       Tls_Core.Sha384.Spec_Hash_Blocks (S0, Px, N)
       = Tls_Core.Sha384.Spec_Hash_Blocks (S0, Py, N),
     Subprogram_Variant => (Decreases => N);

   procedure Lemma_Hash_Blocks_Cong_Sha384
     (S0 : Tls_Core.Sha384.Hash_State; Px, Py : Octet_Array; N : Natural)
   is
   begin
      if N /= 0 then
         Lemma_Hash_Blocks_Cong_Sha384 (S0, Px, Py, N - 1);
         Lemma_Update_Block_Cong_Sha384
           (Tls_Core.Sha384.Spec_Hash_Blocks (S0, Px, N - 1),
            Tls_Core.Sha384.Spec_Hash_Blocks (S0, Py, N - 1),
            Tls_Core.Sha384.Block_At (Px, N - 1),
            Tls_Core.Sha384.Block_At (Py, N - 1));
      end if;
   end Lemma_Hash_Blocks_Cong_Sha384;

   procedure Lemma_Sha256_Cong (X, Y : Octet_Array) is
      Px : constant Octet_Array := Tls_Core.Sha256.Pad_SHA256 (X);
      Py : constant Octet_Array := Tls_Core.Sha256.Pad_SHA256 (Y);
      Nx : constant Natural := Px'Length / 64;
   begin
      --  Pad_SHA256 is a pointwise expression function over
      --  Spec_Pad_Byte_SHA256, which depends only on Input's bytes;
      --  per-byte X = Y propagates byte-wise to Pad, giving Px = Py.
      pragma Assert
        (for all K in 1 .. Px'Length => Px (K) = Py (K));
      pragma Assert (Px = Py);
      Lemma_Hash_Blocks_Cong_Sha256
        (Tls_Core.Sha256.Initial_State_SHA256, Px, Py, Nx);
   end Lemma_Sha256_Cong;

   procedure Lemma_Sha384_Cong (X, Y : Octet_Array) is
      Px : constant Octet_Array := Tls_Core.Sha384.Pad_SHA384 (X);
      Py : constant Octet_Array := Tls_Core.Sha384.Pad_SHA384 (Y);
      Nx : constant Natural := Px'Length / 128;
   begin
      pragma Assert
        (for all K in 1 .. Px'Length => Px (K) = Py (K));
      pragma Assert (Px = Py);
      Lemma_Hash_Blocks_Cong_Sha384
        (Tls_Core.Sha384.Initial_State_SHA384, Px, Py, Nx);
   end Lemma_Sha384_Cong;

   ---------------------------------------------------------------------
   --  Lemma_MGF1_Cong_Sha256 — inductive byte-wise mask equality.
   --
   --  Per-iteration: compute Counter in Ada (no symbolic division),
   --  call Lemma_Sha256_Cong on the per-counter Buf inputs, and rely
   --  on MGF1's defining per-byte Post + Block expression-function
   --  inlining + UF congruence to discharge the per-byte invariant
   --  advance from `forall J in 1..I-1` to `forall J in 1..I`.
   ---------------------------------------------------------------------

   procedure Lemma_MGF1_Cong_Sha256
     (Seed_X, Seed_Y : Octet_Array; Mask_Len : Natural)
   is
   begin
      for I in 1 .. Mask_Len loop
         pragma Loop_Invariant
           (for all J in 1 .. I - 1 =>
              Spec_MGF1_Sha256 (Seed_X, Mask_Len) (J)
              = Spec_MGF1_Sha256 (Seed_Y, Mask_Len) (J));
         declare
            C     : constant Interfaces.Unsigned_32 :=
              Interfaces.Unsigned_32 ((I - 1) / 32);
            Buf_X : constant Octet_Array :=
              Spec_MGF1_Sha256_Buf (Seed_X, C);
            Buf_Y : constant Octet_Array :=
              Spec_MGF1_Sha256_Buf (Seed_Y, C);
         begin
            --  Bridge Seed byte equality + Buf defining Post to Buf
            --  byte equality.
            pragma Assert
              (for all J in 1 .. Buf_X'Length => Buf_X (J) = Buf_Y (J));
            Lemma_Sha256_Cong (Buf_X, Buf_Y);
            --  Post-lemma: SHA(Buf_X) = SHA(Buf_Y).
            --  Block expression-function: Block(Seed, C) = SHA(Buf(Seed, C)).
            --  MGF1 defining Post at I: MGF1(Seed, ML)(I) = Block(Seed, C)(K)
            --  where K = (I-1) mod 32 + 1.
            --  Chain through UF cong on (_)(K).
            pragma Assert
              (Spec_MGF1_Sha256 (Seed_X, Mask_Len) (I)
               = Spec_MGF1_Sha256 (Seed_Y, Mask_Len) (I));
         end;
      end loop;
   end Lemma_MGF1_Cong_Sha256;

   procedure Lemma_MGF1_Cong_Sha384
     (Seed_X, Seed_Y : Octet_Array; Mask_Len : Natural)
   is
   begin
      for I in 1 .. Mask_Len loop
         pragma Loop_Invariant
           (for all J in 1 .. I - 1 =>
              Spec_MGF1_Sha384 (Seed_X, Mask_Len) (J)
              = Spec_MGF1_Sha384 (Seed_Y, Mask_Len) (J));
         declare
            C     : constant Interfaces.Unsigned_32 :=
              Interfaces.Unsigned_32 ((I - 1) / 48);
            Buf_X : constant Octet_Array :=
              Spec_MGF1_Sha384_Buf (Seed_X, C);
            Buf_Y : constant Octet_Array :=
              Spec_MGF1_Sha384_Buf (Seed_Y, C);
         begin
            pragma Assert
              (for all J in 1 .. Buf_X'Length => Buf_X (J) = Buf_Y (J));
            Lemma_Sha384_Cong (Buf_X, Buf_Y);
            pragma Assert
              (Spec_MGF1_Sha384 (Seed_X, Mask_Len) (I)
               = Spec_MGF1_Sha384 (Seed_Y, Mask_Len) (I));
         end;
      end loop;
   end Lemma_MGF1_Cong_Sha384;

   procedure Lemma_M_Prime_Cong_Sha256
     (Message     : Octet_Array;
      EM_X, EM_Y  : Bigint)
   is
   begin
      for I in 1 .. 72 loop
         pragma Loop_Invariant
           (for all J in 1 .. I - 1 =>
              Spec_PSS_M_Prime_Sha256 (Message, EM_X) (J)
              = Spec_PSS_M_Prime_Sha256 (Message, EM_Y) (J));
         --  Concrete I; case-split against the three Post conjuncts.
         if I <= 8 then
            --  Both = 0 by Post conjunct 1.
            pragma Assert
              (Spec_PSS_M_Prime_Sha256 (Message, EM_X) (I) = 0);
            pragma Assert
              (Spec_PSS_M_Prime_Sha256 (Message, EM_Y) (I) = 0);
         elsif I <= 40 then
            --  Both = SHA(Message)(I-8) by Post conjunct 2; message-only.
            pragma Assert
              (Spec_PSS_M_Prime_Sha256 (Message, EM_X) (I)
               = Tls_Core.Sha256.Spec_SHA256 (Message) (I - 8));
            pragma Assert
              (Spec_PSS_M_Prime_Sha256 (Message, EM_Y) (I)
               = Tls_Core.Sha256.Spec_SHA256 (Message) (I - 8));
         else
            --  Both = Salt(EM_*)(I-40) by Post conjunct 3; Salt cong Pre.
            pragma Assert
              (Spec_PSS_M_Prime_Sha256 (Message, EM_X) (I)
               = Spec_PSS_Salt_Sha256 (EM_X) (I - 40));
            pragma Assert
              (Spec_PSS_M_Prime_Sha256 (Message, EM_Y) (I)
               = Spec_PSS_Salt_Sha256 (EM_Y) (I - 40));
         end if;
      end loop;
   end Lemma_M_Prime_Cong_Sha256;

   procedure Lemma_M_Prime_Cong_Sha384
     (Message     : Octet_Array;
      EM_X, EM_Y  : Bigint)
   is
   begin
      for I in 1 .. 104 loop
         pragma Loop_Invariant
           (for all J in 1 .. I - 1 =>
              Spec_PSS_M_Prime_Sha384 (Message, EM_X) (J)
              = Spec_PSS_M_Prime_Sha384 (Message, EM_Y) (J));
         if I <= 8 then
            pragma Assert
              (Spec_PSS_M_Prime_Sha384 (Message, EM_X) (I) = 0);
            pragma Assert
              (Spec_PSS_M_Prime_Sha384 (Message, EM_Y) (I) = 0);
         elsif I <= 56 then
            pragma Assert
              (Spec_PSS_M_Prime_Sha384 (Message, EM_X) (I)
               = Tls_Core.Sha384.Spec_SHA384 (Message) (I - 8));
            pragma Assert
              (Spec_PSS_M_Prime_Sha384 (Message, EM_Y) (I)
               = Tls_Core.Sha384.Spec_SHA384 (Message) (I - 8));
         else
            pragma Assert
              (Spec_PSS_M_Prime_Sha384 (Message, EM_X) (I)
               = Spec_PSS_Salt_Sha384 (EM_X) (I - 56));
            pragma Assert
              (Spec_PSS_M_Prime_Sha384 (Message, EM_Y) (I)
               = Spec_PSS_Salt_Sha384 (EM_Y) (I - 56));
         end if;
      end loop;
   end Lemma_M_Prime_Cong_Sha384;

   --  Body chains the proven sub-cong lemmas (MGF1 / M_Prime / SHA)
   --  plus per-byte equality facts. Each step is a localised SMT
   --  obligation that fits within level=2's instantiation budget.
   procedure Lemma_Pss_Verify_Cong_Sha256
     (Message : Octet_Array; EM_X, EM_Y : Bigint)
   is
   begin
      --  EM byte-equality from EM_X = EM_Y.
      pragma Assert
        (for all I in 1 .. EM_Length => EM_X (I) = EM_Y (I));
      --  EM_Tail byte-equality (bytes 224..255 of EM).
      pragma Assert
        (for all I in 1 .. 32 =>
           EM_Tail_Sha256 (EM_X) (I) = EM_Tail_Sha256 (EM_Y) (I));
      --  MGF1 byte cong via the proven inductive lemma.
      Lemma_MGF1_Cong_Sha256
        (EM_Tail_Sha256 (EM_X), EM_Tail_Sha256 (EM_Y), 223);
      --  DB byte cong follows from EM byte cong + MGF1 byte cong.
      pragma Assert
        (for all I in 1 .. 223 =>
           Spec_PSS_DB_Sha256 (EM_X) (I) = Spec_PSS_DB_Sha256 (EM_Y) (I));
      --  Salt byte cong (Salt = DB(192..223)).
      pragma Assert
        (for all I in 1 .. 32 =>
           Spec_PSS_Salt_Sha256 (EM_X) (I)
           = Spec_PSS_Salt_Sha256 (EM_Y) (I));
      --  M_Prime byte cong via the dedicated lemma.
      Lemma_M_Prime_Cong_Sha256 (Message, EM_X, EM_Y);
      --  SHA(M_Prime) cong.
      Lemma_Sha256_Cong
        (Spec_PSS_M_Prime_Sha256 (Message, EM_X),
         Spec_PSS_M_Prime_Sha256 (Message, EM_Y));
      --  SHA(M_Prime) byte cong.
      pragma Assert
        (for all I in 1 .. 32 =>
           Tls_Core.Sha256.Spec_SHA256
             (Spec_PSS_M_Prime_Sha256 (Message, EM_X)) (I)
           = Tls_Core.Sha256.Spec_SHA256
               (Spec_PSS_M_Prime_Sha256 (Message, EM_Y)) (I));
   end Lemma_Pss_Verify_Cong_Sha256;

   procedure Lemma_Pss_Verify_Cong_Sha384
     (Message : Octet_Array; EM_X, EM_Y : Bigint)
   is
   begin
      pragma Assert
        (for all I in 1 .. EM_Length => EM_X (I) = EM_Y (I));
      pragma Assert
        (for all I in 1 .. 48 =>
           EM_Tail_Sha384 (EM_X) (I) = EM_Tail_Sha384 (EM_Y) (I));
      Lemma_MGF1_Cong_Sha384
        (EM_Tail_Sha384 (EM_X), EM_Tail_Sha384 (EM_Y), 207);
      pragma Assert
        (for all I in 1 .. 207 =>
           Spec_PSS_DB_Sha384 (EM_X) (I) = Spec_PSS_DB_Sha384 (EM_Y) (I));
      pragma Assert
        (for all I in 1 .. 48 =>
           Spec_PSS_Salt_Sha384 (EM_X) (I)
           = Spec_PSS_Salt_Sha384 (EM_Y) (I));
      Lemma_M_Prime_Cong_Sha384 (Message, EM_X, EM_Y);
      Lemma_Sha384_Cong
        (Spec_PSS_M_Prime_Sha384 (Message, EM_X),
         Spec_PSS_M_Prime_Sha384 (Message, EM_Y));
      pragma Assert
        (for all I in 1 .. 48 =>
           Tls_Core.Sha384.Spec_SHA384
             (Spec_PSS_M_Prime_Sha384 (Message, EM_X)) (I)
           = Tls_Core.Sha384.Spec_SHA384
               (Spec_PSS_M_Prime_Sha384 (Message, EM_Y)) (I));
   end Lemma_Pss_Verify_Cong_Sha384;

   ---------------------------------------------------------------------
   --  Spec_MGF1_Sha256_Buf / Block — defining-Post chain leaves for
   --  MGF1 congruence.
   ---------------------------------------------------------------------

   function Spec_MGF1_Sha256_Buf
     (Seed : Octet_Array; Counter : Unsigned_32) return Octet_Array
   is
      R : Octet_Array (1 .. Seed'Length + 4) := [others => 0];
   begin
      for I in 1 .. Seed'Length loop
         R (I) := Seed (I);
         pragma Loop_Invariant
           (for all K in 1 .. I => R (K) = Seed (K));
      end loop;
      R (Seed'Length + 1) := Octet (Shift_Right (Counter, 24) and 16#FF#);
      R (Seed'Length + 2) := Octet (Shift_Right (Counter, 16) and 16#FF#);
      R (Seed'Length + 3) := Octet (Shift_Right (Counter, 8) and 16#FF#);
      R (Seed'Length + 4) := Octet (Counter and 16#FF#);
      return R;
   end Spec_MGF1_Sha256_Buf;

   function Spec_MGF1_Sha384_Buf
     (Seed : Octet_Array; Counter : Unsigned_32) return Octet_Array
   is
      R : Octet_Array (1 .. Seed'Length + 4) := [others => 0];
   begin
      for I in 1 .. Seed'Length loop
         R (I) := Seed (I);
         pragma Loop_Invariant
           (for all K in 1 .. I => R (K) = Seed (K));
      end loop;
      R (Seed'Length + 1) := Octet (Shift_Right (Counter, 24) and 16#FF#);
      R (Seed'Length + 2) := Octet (Shift_Right (Counter, 16) and 16#FF#);
      R (Seed'Length + 3) := Octet (Shift_Right (Counter, 8) and 16#FF#);
      R (Seed'Length + 4) := Octet (Counter and 16#FF#);
      return R;
   end Spec_MGF1_Sha384_Buf;

   --  Spec_MGF1_Sha256_Block, Spec_MGF1_Sha384_Block, Spec_MGF1_Sha256,
   --  Spec_MGF1_Sha384 are all expression functions in the .ads (so
   --  gnatprove inlines them for proof — congruence threads).

   ---------------------------------------------------------------------
   --  Spec_DB_Zero_2047 — Spec.RSAPSS.fst:97-104 specialized.
   --  For our fixed emBits=2047, msBits=7 ⇒ mask the top bit.
   ---------------------------------------------------------------------

   function Spec_DB_Zero_2047 (DB : Octet_Array) return Octet_Array is
      --  Pre guarantees DB'First = 1, so DB'Last = DB'Length.
      R : Octet_Array (1 .. DB'Length) := [others => 0];
   begin
      R (1) := DB (1) and EM_High_Mask;
      for I in 2 .. DB'Length loop
         R (I) := DB (I);
         pragma Loop_Invariant (R (1) = (DB (1) and EM_High_Mask));
         pragma Loop_Invariant (for all K in 2 .. I => R (K) = DB (K));
      end loop;
      return R;
   end Spec_DB_Zero_2047;

   ---------------------------------------------------------------------
   --  PSS-Verify decomposition helpers (v0.6 §0e closure).
   ---------------------------------------------------------------------

   function EM_Tail_Sha256 (EM : Bigint) return Octet_Array is
      R : Octet_Array (1 .. 32) := [others => 0];
   begin
      for I in 1 .. 32 loop
         R (I) := EM (223 + I);
         pragma Loop_Invariant
           (for all K in 1 .. I => R (K) = EM (223 + K));
      end loop;
      return R;
   end EM_Tail_Sha256;

   function EM_Tail_Sha384 (EM : Bigint) return Octet_Array is
      R : Octet_Array (1 .. 48) := [others => 0];
   begin
      for I in 1 .. 48 loop
         R (I) := EM (207 + I);
         pragma Loop_Invariant
           (for all K in 1 .. I => R (K) = EM (207 + K));
      end loop;
      return R;
   end EM_Tail_Sha384;

   function Spec_PSS_DB_Sha256 (EM : Bigint) return Octet_Array is
      H_Bytes : constant Octet_Array (1 .. 32) := EM_Tail_Sha256 (EM);
      Db_Mask : constant Octet_Array (1 .. 223) :=
        Spec_MGF1_Sha256 (H_Bytes, 223);
      R       : Octet_Array (1 .. 223) := [others => 0];
   begin
      R (1) := (EM (1) xor Db_Mask (1)) and EM_High_Mask;
      for I in 2 .. 223 loop
         R (I) := EM (I) xor Db_Mask (I);
         pragma Loop_Invariant
           (R (1) = ((EM (1) xor Db_Mask (1)) and EM_High_Mask));
         pragma Loop_Invariant
           (for all K in 2 .. I => R (K) = (EM (K) xor Db_Mask (K)));
      end loop;
      return R;
   end Spec_PSS_DB_Sha256;

   function Spec_PSS_DB_Sha384 (EM : Bigint) return Octet_Array is
      H_Bytes : constant Octet_Array (1 .. 48) := EM_Tail_Sha384 (EM);
      Db_Mask : constant Octet_Array (1 .. 207) :=
        Spec_MGF1_Sha384 (H_Bytes, 207);
      R       : Octet_Array (1 .. 207) := [others => 0];
   begin
      R (1) := (EM (1) xor Db_Mask (1)) and EM_High_Mask;
      for I in 2 .. 207 loop
         R (I) := EM (I) xor Db_Mask (I);
         pragma Loop_Invariant
           (R (1) = ((EM (1) xor Db_Mask (1)) and EM_High_Mask));
         pragma Loop_Invariant
           (for all K in 2 .. I => R (K) = (EM (K) xor Db_Mask (K)));
      end loop;
      return R;
   end Spec_PSS_DB_Sha384;

   function Spec_PSS_Salt_Sha256 (EM : Bigint) return Octet_Array is
      DB : constant Octet_Array (1 .. 223) := Spec_PSS_DB_Sha256 (EM);
      R  : Octet_Array (1 .. 32) := [others => 0];
   begin
      for I in 1 .. 32 loop
         R (I) := DB (191 + I);
         pragma Loop_Invariant
           (for all K in 1 .. I => R (K) = DB (191 + K));
      end loop;
      return R;
   end Spec_PSS_Salt_Sha256;

   function Spec_PSS_Salt_Sha384 (EM : Bigint) return Octet_Array is
      DB : constant Octet_Array (1 .. 207) := Spec_PSS_DB_Sha384 (EM);
      R  : Octet_Array (1 .. 48) := [others => 0];
   begin
      for I in 1 .. 48 loop
         R (I) := DB (159 + I);
         pragma Loop_Invariant
           (for all K in 1 .. I => R (K) = DB (159 + K));
      end loop;
      return R;
   end Spec_PSS_Salt_Sha384;

   function Spec_PSS_M_Prime_Sha256
     (Message : Octet_Array; EM : Bigint) return Octet_Array
   is
      M_Hash : constant Tls_Core.Sha256.Digest :=
        Tls_Core.Sha256.Spec_SHA256 (Message);
      Salt   : constant Octet_Array (1 .. 32) :=
        Spec_PSS_Salt_Sha256 (EM);
      R      : Octet_Array (1 .. 72) := [others => 0];
   begin
      for I in 1 .. 32 loop
         R (8 + I) := M_Hash (I);
         pragma Loop_Invariant
           (for all K in 1 .. 8 => R (K) = 0);
         pragma Loop_Invariant
           (for all K in 1 .. I => R (8 + K) = M_Hash (K));
      end loop;
      for I in 1 .. 32 loop
         R (8 + 32 + I) := Salt (I);
         pragma Loop_Invariant
           (for all K in 1 .. 8 => R (K) = 0);
         pragma Loop_Invariant
           (for all K in 1 .. 32 => R (8 + K) = M_Hash (K));
         pragma Loop_Invariant
           (for all K in 1 .. I => R (8 + 32 + K) = Salt (K));
      end loop;
      return R;
   end Spec_PSS_M_Prime_Sha256;

   function Spec_PSS_M_Prime_Sha384
     (Message : Octet_Array; EM : Bigint) return Octet_Array
   is
      M_Hash : constant Tls_Core.Sha384.Digest :=
        Tls_Core.Sha384.Spec_SHA384 (Message);
      Salt   : constant Octet_Array (1 .. 48) :=
        Spec_PSS_Salt_Sha384 (EM);
      R      : Octet_Array (1 .. 104) := [others => 0];
   begin
      for I in 1 .. 48 loop
         R (8 + I) := M_Hash (I);
         pragma Loop_Invariant
           (for all K in 1 .. 8 => R (K) = 0);
         pragma Loop_Invariant
           (for all K in 1 .. I => R (8 + K) = M_Hash (K));
      end loop;
      for I in 1 .. 48 loop
         R (8 + 48 + I) := Salt (I);
         pragma Loop_Invariant
           (for all K in 1 .. 8 => R (K) = 0);
         pragma Loop_Invariant
           (for all K in 1 .. 48 => R (8 + K) = M_Hash (K));
         pragma Loop_Invariant
           (for all K in 1 .. I => R (8 + 48 + K) = Salt (K));
      end loop;
      return R;
   end Spec_PSS_M_Prime_Sha384;

   ---------------------------------------------------------------------
   --  Spec_Pss_Verify_Sha256 — Spec.RSAPSS.fst:200-212 + 160-187,
   --  specialized to emBits=2047, hLen=sLen=32.
   --
   --  Steps mirror RFC 8017 §9.1.2:
   --   2. emLen >= hLen + sLen + 2  (256 >= 66 ✓)
   --   3. trailer EM[emLen-1] = 0xBC
   --   3'. (HACL pss_verify) top byte sanity: em[0] & 0x80 = 0
   --       (i.e., em[0] high bit is zero — encodes the emBits mask).
   --   4. maskedDB = EM[0..223), H = EM[223..255)  (0-based)
   --   5. dbMask = MGF1 (H, 223)
   --   6. DB = maskedDB XOR dbMask
   --   7. DB = db_zero (DB, emBits)
   --   8. DB[0..190) all zeros, DB[190] = 0x01     (PS pad)
   --   9. salt = DB[191..223)
   --  10. M' = 0x00 x 8 || mHash || salt
   --  11. H' = SHA256 (M')
   --  12. consistent iff H' = H.
   ---------------------------------------------------------------------

   function Spec_Pss_Verify_Sha256
     (Message : Octet_Array; EM : Bigint) return Boolean
   is
      --  Body shape mirrors the .ads defining Post: a conjunction of
      --  five named checks tying back to helper functions (each with
      --  its own defining Post). Step numbering = RFC 8017 §9.1.2.
      DB      : constant Octet_Array (1 .. 223) := Spec_PSS_DB_Sha256 (EM);
      M_Prime : constant Octet_Array (1 .. 72) :=
        Spec_PSS_M_Prime_Sha256 (Message, EM);
      H_Prime : constant Tls_Core.Sha256.Digest :=
        Tls_Core.Sha256.Spec_SHA256 (M_Prime);
      H       : constant Octet_Array (1 .. 32) := EM_Tail_Sha256 (EM);
      PS_OK   : Boolean := True;
      Hash_OK : Boolean := True;
   begin
      --  Step 3: trailer.
      if EM (EM_Length) /= 16#BC# then
         return False;
      end if;

      --  Step 3' (HACL): em high bit must be zero.
      if (EM (1) and 16#80#) /= 0 then
         return False;
      end if;

      --  Step 8: PS check — DB (1 .. 190) all zero.
      for I in 1 .. 190 loop
         if DB (I) /= 0 then
            PS_OK := False;
         end if;
         pragma Loop_Invariant
           (PS_OK = (for all K in 1 .. I => DB (K) = 0));
      end loop;
      if not PS_OK then
         return False;
      end if;

      --  Step 8 cont: DB (191) = 0x01.
      if DB (191) /= 16#01# then
         return False;
      end if;

      --  Steps 9–12: salt (in DB), M' (M_Prime), H' (H_Prime),
      --  compare H' = H pointwise.
      for I in 1 .. 32 loop
         if H_Prime (I) /= H (I) then
            Hash_OK := False;
         end if;
         pragma Loop_Invariant
           (Hash_OK = (for all K in 1 .. I => H_Prime (K) = H (K)));
      end loop;

      return Hash_OK;
   end Spec_Pss_Verify_Sha256;

   ---------------------------------------------------------------------
   --  Spec_Pss_Verify_Sha384 — same structure, hLen=sLen=48.
   ---------------------------------------------------------------------

   function Spec_Pss_Verify_Sha384
     (Message : Octet_Array; EM : Bigint) return Boolean
   is
      --  Same shape as Spec_Pss_Verify_Sha256 with H_Len = S_Len = 48,
      --  DB_Len = 207, PS_Len = 158.
      DB      : constant Octet_Array (1 .. 207) := Spec_PSS_DB_Sha384 (EM);
      M_Prime : constant Octet_Array (1 .. 104) :=
        Spec_PSS_M_Prime_Sha384 (Message, EM);
      H_Prime : constant Tls_Core.Sha384.Digest :=
        Tls_Core.Sha384.Spec_SHA384 (M_Prime);
      H       : constant Octet_Array (1 .. 48) := EM_Tail_Sha384 (EM);
      PS_OK   : Boolean := True;
      Hash_OK : Boolean := True;
   begin
      if EM (EM_Length) /= 16#BC# then
         return False;
      end if;

      if (EM (1) and 16#80#) /= 0 then
         return False;
      end if;

      for I in 1 .. 158 loop
         if DB (I) /= 0 then
            PS_OK := False;
         end if;
         pragma Loop_Invariant
           (PS_OK = (for all K in 1 .. I => DB (K) = 0));
      end loop;
      if not PS_OK then
         return False;
      end if;

      if DB (159) /= 16#01# then
         return False;
      end if;

      for I in 1 .. 48 loop
         if H_Prime (I) /= H (I) then
            Hash_OK := False;
         end if;
         pragma Loop_Invariant
           (Hash_OK = (for all K in 1 .. I => H_Prime (K) = H (K)));
      end loop;

      return Hash_OK;
   end Spec_Pss_Verify_Sha384;

   ---------------------------------------------------------------------
   --  Public Emsa_Pss_Verify entry points — thin wrappers around the
   --  spec, so the Post `OK = Spec_Pss_Verify_Sha*(Message, EM)`
   --  discharges by construction (mirror of Sha256.Hash →
   --  Spec_SHA256). [VERIFIED — PLATINUM]
   ---------------------------------------------------------------------

   procedure Emsa_Pss_Verify_Sha256
     (Message : Octet_Array; EM : Bigint; OK : out Boolean) is
   begin
      OK := Spec_Pss_Verify_Sha256 (Message, EM);
   end Emsa_Pss_Verify_Sha256;

   procedure Emsa_Pss_Verify_Sha384
     (Message : Octet_Array; EM : Bigint; OK : out Boolean) is
   begin
      OK := Spec_Pss_Verify_Sha384 (Message, EM);
   end Emsa_Pss_Verify_Sha384;

   ---------------------------------------------------------------------
   --  EMSA-PSS-ENCODE (RFC 8017 §9.1.1) for round-trip self-tests.
   --  AoRTE-only — encode side is not in v0.5 platinum scope (verify
   --  is the headline; encoding is here for the round-trip test).
   --
   --  Steps:
   --    1. mHash = Hash (M).
   --    2. If emLen < hLen + sLen + 2 — encoding error.
   --    3. Generate salt (caller supplies it).
   --    4. M' = 0x00 x 8 || mHash || salt.
   --    5. H = Hash (M').
   --    6. PS = (emLen - sLen - hLen - 2) zero bytes.
   --    7. DB = PS || 0x01 || salt.    (length = emLen - hLen - 1)
   --    8. dbMask = MGF1 (H, emLen - hLen - 1).
   --    9. maskedDB = DB XOR dbMask.
   --   10. Set the leftmost (8*emLen - emBits) bits of maskedDB to 0.
   --   11. EM = maskedDB || H || 0xBC.
   ---------------------------------------------------------------------

   procedure Encode_Sha256
     (Message : Octet_Array;
      Salt    : Octet_Array;
      Out_EM  : out Bigint;
      OK      : out Boolean)
   is
      H_Len   : constant Natural := 32;
      S_Len   : constant Natural := 32;
      DB_Len  : constant Natural := EM_Length - H_Len - 1;
      M_Hash  : Tls_Core.Sha256.Digest;
      M_Prime : Octet_Array (1 .. 8 + H_Len + S_Len) := [others => 0];
      H_Bytes : Tls_Core.Sha256.Digest;
      DB      : Octet_Array (1 .. DB_Len) := [others => 0];
      Db_Mask : Octet_Array (1 .. DB_Len);
      PS_Len  : constant Natural := EM_Length - S_Len - H_Len - 2;
   begin
      Out_EM := [others => 0];
      pragma Assert (Salt'Length = S_Len);

      Tls_Core.Sha256.Hash (Message, M_Hash);

      --  M' = 8 zero bytes || mHash || salt.
      --  M_Prime is already zeroed at declaration; only fill the
      --  non-zero tail (positions 9 .. 72).
      for I in 1 .. H_Len loop
         M_Prime (8 + I) := M_Hash (I);
      end loop;
      for I in 0 .. S_Len - 1 loop
         M_Prime (9 + H_Len + I) := Salt (Salt'First + I);
      end loop;
      Tls_Core.Sha256.Hash (M_Prime, H_Bytes);

      --  DB = 0x00 .. 0x00 || 0x01 || salt.
      --  DB is already zeroed; just place the 0x01 separator and salt.
      DB (PS_Len + 1) := 16#01#;
      for I in 0 .. S_Len - 1 loop
         DB (PS_Len + 2 + I) := Salt (Salt'First + I);
      end loop;

      Db_Mask := Spec_MGF1_Sha256 (H_Bytes, DB_Len);

      for I in 1 .. DB_Len loop
         DB (I) := DB (I) xor Db_Mask (I);
      end loop;

      --  Zero top bit of DB(1) per emBits=2047.
      DB (1) := DB (1) and EM_High_Mask;

      --  EM = maskedDB || H || 0xBC.
      for I in 1 .. DB_Len loop
         Out_EM (I) := DB (I);
      end loop;
      for I in 1 .. H_Len loop
         Out_EM (DB_Len + I) := H_Bytes (I);
      end loop;
      Out_EM (EM_Length) := 16#BC#;
      OK := True;
   end Encode_Sha256;

   procedure Encode_Sha384
     (Message : Octet_Array;
      Salt    : Octet_Array;
      Out_EM  : out Bigint;
      OK      : out Boolean)
   is
      H_Len   : constant Natural := 48;
      S_Len   : constant Natural := 48;
      DB_Len  : constant Natural := EM_Length - H_Len - 1;
      M_Hash  : Tls_Core.Sha384.Digest;
      M_Prime : Octet_Array (1 .. 8 + H_Len + S_Len) := [others => 0];
      H_Bytes : Tls_Core.Sha384.Digest;
      DB      : Octet_Array (1 .. DB_Len) := [others => 0];
      Db_Mask : Octet_Array (1 .. DB_Len);
      PS_Len  : constant Natural := EM_Length - S_Len - H_Len - 2;
   begin
      Out_EM := [others => 0];
      pragma Assert (Salt'Length = S_Len);

      Tls_Core.Sha384.Hash (Message, M_Hash);

      for I in 1 .. H_Len loop
         M_Prime (8 + I) := M_Hash (I);
      end loop;
      for I in 0 .. S_Len - 1 loop
         M_Prime (9 + H_Len + I) := Salt (Salt'First + I);
      end loop;
      Tls_Core.Sha384.Hash (M_Prime, H_Bytes);

      DB (PS_Len + 1) := 16#01#;
      for I in 0 .. S_Len - 1 loop
         DB (PS_Len + 2 + I) := Salt (Salt'First + I);
      end loop;

      Db_Mask := Spec_MGF1_Sha384 (H_Bytes, DB_Len);

      for I in 1 .. DB_Len loop
         DB (I) := DB (I) xor Db_Mask (I);
      end loop;

      DB (1) := DB (1) and EM_High_Mask;

      for I in 1 .. DB_Len loop
         Out_EM (I) := DB (I);
      end loop;
      for I in 1 .. H_Len loop
         Out_EM (DB_Len + I) := H_Bytes (I);
      end loop;
      Out_EM (EM_Length) := 16#BC#;
      OK := True;
   end Encode_Sha384;

   ---------------------------------------------------------------------
   --  RSASSA-PSS-VERIFY (RFC 8017 §8.1.2):
   --    1. Length check: signature is k = emLen octets (here 256).
   --    2. m := signature^E mod N         (RSAVP1 §5.2.2;
   --                                        AoRTE-only)
   --    3. EMSA-PSS-VERIFY (M, EM=m, emBits)  (PLATINUM via
   --                                        Emsa_Pss_Verify_Sha*)
   ---------------------------------------------------------------------

   procedure Verify_Sha256
     (N         : Bigint;
      E         : Bigint;
      Message   : Octet_Array;
      Signature : Bigint;
      OK        : out Boolean)
   is
      M : Bigint;
   begin
      Tls_Core.Bignum_2048.Mod_Exp (Signature, E, N, M);
      Tls_Core.Bignum_2048.Lemma_Bigint_Roundtrip (M);
      --  Bring SHA-256 determinism (UF congruence on equal byte inputs)
      --  into scope so the M_Prime byte-equality from M = Spec_Em can
      --  carry through SHA256(M_Prime). Outer M_Prime SHA + each MGF1
      --  block-counter SHA must be in scope.
      declare
         Spec_Em : constant Bigint :=
           Tls_Core.Bignum_2048.Spec_Em_From_Pubkey_Sig (N, E, Signature)
           with Ghost;
      begin
         --  MGF1 byte-wise mask equality from Seed byte equality —
         --  inductive lemma walks every byte, calling Lemma_Sha256_Cong
         --  at the correctly-computed counter per byte. Loop_Invariant
         --  inside the lemma accumulates per-byte equality.
         Lemma_MGF1_Cong_Sha256
           (EM_Tail_Sha256 (M), EM_Tail_Sha256 (Spec_Em), 223);
         pragma Assert
           (for all I in 1 .. 223 =>
              Spec_PSS_DB_Sha256 (M) (I) = Spec_PSS_DB_Sha256 (Spec_Em) (I));
         pragma Assert
           (for all I in 1 .. 32 =>
              Spec_PSS_Salt_Sha256 (M) (I)
              = Spec_PSS_Salt_Sha256 (Spec_Em) (I));
         --  Bridge: byte-wise M_Prime equality via inductive lemma.
         --  Loop-invariant accumulates per-byte equality with
         --  case-analysis on I against the three Post conjuncts
         --  (zero prefix / SHA(Message) middle / Salt suffix).
         Lemma_M_Prime_Cong_Sha256 (Message, M, Spec_Em);
         Lemma_Sha256_Cong
           (Spec_PSS_M_Prime_Sha256 (Message, M),
            Spec_PSS_M_Prime_Sha256 (Message, Spec_Em));
         --  Bridge byte-wise hash equality to full-array equality so
         --  the Hash_Match conjunct in Spec_Pss_Verify_Sha256's defining
         --  Post evaluates the same on both sides.
         pragma Assert
           (for all I in 1 .. 32 =>
              Tls_Core.Sha256.Spec_SHA256
                (Spec_PSS_M_Prime_Sha256 (Message, M)) (I)
              = Tls_Core.Sha256.Spec_SHA256
                  (Spec_PSS_M_Prime_Sha256 (Message, Spec_Em)) (I));
         pragma Assert
           (for all I in 1 .. 32 =>
              EM_Tail_Sha256 (M) (I) = EM_Tail_Sha256 (Spec_Em) (I));
         --  M = Spec_Em via Mod_Exp Post + Lemma_Bigint_Roundtrip;
         --  then UF congruence on Spec_Pss_Verify via the dedicated
         --  null-body lemma (level=2 doesn't unfold the full defining
         --  Post in a single shot; the lemma keeps the goal small).
         pragma Assert (M = Spec_Em);
         Lemma_Pss_Verify_Cong_Sha256 (Message, M, Spec_Em);
      end;
      Emsa_Pss_Verify_Sha256 (Message, M, OK);
   end Verify_Sha256;

   procedure Verify_Sha384
     (N         : Bigint;
      E         : Bigint;
      Message   : Octet_Array;
      Signature : Bigint;
      OK        : out Boolean)
   is
      M : Bigint;
   begin
      Tls_Core.Bignum_2048.Mod_Exp (Signature, E, N, M);
      Tls_Core.Bignum_2048.Lemma_Bigint_Roundtrip (M);
      declare
         Spec_Em : constant Bigint :=
           Tls_Core.Bignum_2048.Spec_Em_From_Pubkey_Sig (N, E, Signature)
           with Ghost;
      begin
         Lemma_MGF1_Cong_Sha384
           (EM_Tail_Sha384 (M), EM_Tail_Sha384 (Spec_Em), 207);
         pragma Assert
           (for all I in 1 .. 207 =>
              Spec_PSS_DB_Sha384 (M) (I) = Spec_PSS_DB_Sha384 (Spec_Em) (I));
         pragma Assert
           (for all I in 1 .. 48 =>
              Spec_PSS_Salt_Sha384 (M) (I)
              = Spec_PSS_Salt_Sha384 (Spec_Em) (I));
         Lemma_M_Prime_Cong_Sha384 (Message, M, Spec_Em);
         Lemma_Sha384_Cong
           (Spec_PSS_M_Prime_Sha384 (Message, M),
            Spec_PSS_M_Prime_Sha384 (Message, Spec_Em));
         pragma Assert
           (for all I in 1 .. 48 =>
              Tls_Core.Sha384.Spec_SHA384
                (Spec_PSS_M_Prime_Sha384 (Message, M)) (I)
              = Tls_Core.Sha384.Spec_SHA384
                  (Spec_PSS_M_Prime_Sha384 (Message, Spec_Em)) (I));
         pragma Assert
           (for all I in 1 .. 48 =>
              EM_Tail_Sha384 (M) (I) = EM_Tail_Sha384 (Spec_Em) (I));
         pragma Assert (M = Spec_Em);
         Lemma_Pss_Verify_Cong_Sha384 (Message, M, Spec_Em);
      end;
      Emsa_Pss_Verify_Sha384 (Message, M, OK);
   end Verify_Sha384;

end Tls_Core.Rsa_Pss;
