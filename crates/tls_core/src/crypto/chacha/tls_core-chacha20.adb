package body Tls_Core.Chacha20
  with SPARK_Mode
is

   use Interfaces;

   ---------------------------------------------------------------------
   --  Read four bytes LE → Word (RFC 8439 uses little-endian).
   ---------------------------------------------------------------------

   function LE_Word (B : Octet_Array; Offset : Positive) return Word
   is (Word (B (Offset))
       or Shift_Left (Word (B (Offset + 1)), 8)
       or Shift_Left (Word (B (Offset + 2)), 16)
       or Shift_Left (Word (B (Offset + 3)), 24))
   with
     Pre =>
       Offset <= Positive'Last - 3
       and then B'First <= Offset
       and then Offset + 3 <= B'Last;

   ---------------------------------------------------------------------
   --  ROTL — bitwise left rotation.
   ---------------------------------------------------------------------

   function ROTL (X : Word; N : Natural) return Word
   is (Shift_Left (X, N) or Shift_Right (X, 32 - N))
   with Pre => N in 1 .. 31;

   ---------------------------------------------------------------------
   --  Quarter-round: RFC 8439 §2.1.
   ---------------------------------------------------------------------

   type State_Array is array (0 .. 15) of Word;

   procedure Quarter_Round (S : in out State_Array; A, B, C, D : Natural)
   with Pre => A <= 15 and B <= 15 and C <= 15 and D <= 15;

   procedure Quarter_Round (S : in out State_Array; A, B, C, D : Natural) is
   begin
      S (A) := S (A) + S (B);
      S (D) := ROTL (S (D) xor S (A), 16);
      S (C) := S (C) + S (D);
      S (B) := ROTL (S (B) xor S (C), 12);
      S (A) := S (A) + S (B);
      S (D) := ROTL (S (D) xor S (A), 8);
      S (C) := S (C) + S (D);
      S (B) := ROTL (S (B) xor S (C), 7);
   end Quarter_Round;

   ---------------------------------------------------------------------
   --  Write Word → four bytes LE.
   ---------------------------------------------------------------------

   pragma Unevaluated_Use_Of_Old (Allow);

   procedure Put_LE_Word (B : in out Octet_Array; Offset : Positive; W : Word)
   with
     Pre  =>
       Offset <= Positive'Last - 3
       and then B'First <= Offset
       and then Offset + 3 <= B'Last,
     Post =>
       B'First = B'First'Old
       and then B'Last = B'Last'Old
       and then B (Offset) = Octet (W and 16#FF#)
       and then B (Offset + 1) = Octet (Shift_Right (W, 8) and 16#FF#)
       and then B (Offset + 2) = Octet (Shift_Right (W, 16) and 16#FF#)
       and then B (Offset + 3) = Octet (Shift_Right (W, 24) and 16#FF#)
       and then (for all I in B'Range =>
                   (if I < Offset or else I > Offset + 3
                    then B (I) = B'Old (I)));
   procedure Put_LE_Word (B : in out Octet_Array; Offset : Positive; W : Word)
   is
   begin
      B (Offset) := Octet (W and 16#FF#);
      B (Offset + 1) := Octet (Shift_Right (W, 8) and 16#FF#);
      B (Offset + 2) := Octet (Shift_Right (W, 16) and 16#FF#);
      B (Offset + 3) := Octet (Shift_Right (W, 24) and 16#FF#);
   end Put_LE_Word;

   ---------------------------------------------------------------------
   --  Setup: build the initial 16-word ChaCha20 state from
   --  constants + key + counter + nonce.
   --  Mirrors HACL*  specs/Spec.Chacha20.fst : setup / chacha20_init.
   ---------------------------------------------------------------------

   --  Expression function: gnatprove auto-inlines the aggregate at
   --  every call site, so two calls with equal arguments are
   --  syntactically equal expressions.
   function Build_Initial_State
     (Key : Key_Array; Nonce : Nonce_Array; Counter : Word) return State_Array
   is ([0  => 16#6170_7865#,
        1  => 16#3320_646E#,
        2  => 16#7962_2D32#,
        3  => 16#6B20_6574#,
        4  => LE_Word (Key, 1),
        5  => LE_Word (Key, 5),
        6  => LE_Word (Key, 9),
        7  => LE_Word (Key, 13),
        8  => LE_Word (Key, 17),
        9  => LE_Word (Key, 21),
        10 => LE_Word (Key, 25),
        11 => LE_Word (Key, 29),
        12 => Counter,
        13 => LE_Word (Nonce, 1),
        14 => LE_Word (Nonce, 5),
        15 => LE_Word (Nonce, 9)]);

   ---------------------------------------------------------------------
   --  Run the 20 rounds (10 double-rounds) on the initial state.
   --  Mirrors HACL*  Spec.Chacha20.fst : rounds / column_round /
   --  diagonal_round / double_round.
   ---------------------------------------------------------------------

   ---------------------------------------------------------------------
   --  Run_Rounds_Fn — pure functional 20-round shuffle. Takes a state
   --  by value, returns the post-rounds state. This is the single
   --  "rounds" definition that both the imperative Block path and
   --  the ghost Spec_Block_Bytes path call, ensuring that any
   --  equality between them holds by construction.
   ---------------------------------------------------------------------

   function Run_Rounds_Fn (S0 : State_Array) return State_Array is
      S : State_Array := S0;
   begin
      for R in 1 .. 10 loop
         --  Column rounds.
         Quarter_Round (S, 0, 4, 8, 12);
         Quarter_Round (S, 1, 5, 9, 13);
         Quarter_Round (S, 2, 6, 10, 14);
         Quarter_Round (S, 3, 7, 11, 15);
         --  Diagonal rounds.
         Quarter_Round (S, 0, 5, 10, 15);
         Quarter_Round (S, 1, 6, 11, 12);
         Quarter_Round (S, 2, 7, 8, 13);
         Quarter_Round (S, 3, 4, 9, 14);
      end loop;
      return S;
   end Run_Rounds_Fn;

   --  Expression-function wrapper. Both Block (imperative) and
   --  Spec_Block_State (ghost) call this, so equality between the
   --  two derivations is by construction.
   function Spec_Rounds (S : State_Array) return State_Array
   is (Run_Rounds_Fn (S));

   ---------------------------------------------------------------------
   --  Spec_Block_State: reproduce HACL*'s chacha20_core.
   --     init  = setup K N Ctr
   --     core  = init + rounds(init)
   --  We keep the same shape: build initial state, run rounds, add
   --  initial state back element-wise.
   ---------------------------------------------------------------------

   ---------------------------------------------------------------------
   --  Spec_State_Word: body declaration for the .ads ghost. Defined
   --  as the I-th limb of the post-mix state.
   ---------------------------------------------------------------------

   function Spec_State_Word
     (Key : Key_Array; Nonce : Nonce_Array; Counter : Word; I : Natural)
      return Word
   is (Spec_Rounds (Build_Initial_State (Key, Nonce, Counter)) (I)
       + Build_Initial_State (Key, Nonce, Counter) (I));

   ---------------------------------------------------------------------
   --  Spec_Block_Bytes: serialize the 16-word state little-endian
   --  to 64 bytes. Mirrors HACL*  uints_to_bytes_le.
   ---------------------------------------------------------------------

   --  Body of Spec_Block_Bytes — serializes the post-mix state
   --  little-endian, byte-by-byte. The .ads-level Post is the
   --  per-byte equation against Spec_State_Word.
   function Spec_Block_Bytes
     (Key : Key_Array; Nonce : Nonce_Array; Counter : Word) return Block_Array
   is
      Result : Block_Array := [others => 0];
   begin
      for I in 0 .. 15 loop
         declare
            W : constant Word := Spec_State_Word (Key, Nonce, Counter, I);
         begin
            Result (4 * I + 1) := Octet (W and 16#FF#);
            Result (4 * I + 2) := Octet (Shift_Right (W, 8) and 16#FF#);
            Result (4 * I + 3) := Octet (Shift_Right (W, 16) and 16#FF#);
            Result (4 * I + 4) := Octet (Shift_Right (W, 24) and 16#FF#);
         end;
         pragma
           Loop_Invariant
             (for all J in 0 .. I =>
                Result (4 * J + 1)
                = Octet (Spec_State_Word (Key, Nonce, Counter, J) and 16#FF#)
                and then Result (4 * J + 2)
                         = Octet
                             (Shift_Right
                                (Spec_State_Word (Key, Nonce, Counter, J), 8)
                              and 16#FF#)
                and then Result (4 * J + 3)
                         = Octet
                             (Shift_Right
                                (Spec_State_Word (Key, Nonce, Counter, J), 16)
                              and 16#FF#)
                and then Result (4 * J + 4)
                         = Octet
                             (Shift_Right
                                (Spec_State_Word (Key, Nonce, Counter, J), 24)
                              and 16#FF#));
      end loop;
      return Result;
   end Spec_Block_Bytes;

   ---------------------------------------------------------------------
   --  Spec_Chacha20: byte-by-byte, indexed. Mirrors HACL*'s
   --     chacha20_encrypt_bytes = init >> map_blocks
   --
   --  Equivalent to the recursive map_blocks formulation, but
   --  written as a single non-recursive loop. The byte at position
   --  J of the output is plaintext-byte-J XOR keystream-byte at
   --  the corresponding (counter, in-block-offset) — exactly what
   --  the imperative Encrypt computes byte-for-byte. This shared
   --  byte-level structure makes the equivalence proof direct.
   --
   --  Concretely, for output byte index J (1-based):
   --      block_idx   = (J - 1) / Block_Length     0-based
   --      in_block    = (J - 1) mod Block_Length + 1  1..64
   --      out_byte    = Input (Input'First + J - 1)
   --                     xor Spec_Block_Bytes
   --                           (Key, Nonce,
   --                            Counter + Word (block_idx)) (in_block)
   ---------------------------------------------------------------------

   function Spec_Chacha20
     (Key     : Key_Array;
      Nonce   : Nonce_Array;
      Counter : Word;
      Input   : Octet_Array) return Octet_Array
   is
      Result : Octet_Array (1 .. Input'Length) := [others => 0];
   begin
      if Input'Length = 0 then
         return Result;
      end if;

      for J in 1 .. Input'Length loop
         Result (J) :=
           Input (Input'First + J - 1)
           xor Spec_Block_Bytes
                 (Key, Nonce, Counter + Word ((J - 1) / Block_Length))
                    (((J - 1) mod Block_Length) + 1);
         pragma
           Loop_Invariant
             (for all K in 1 .. J =>
                Result (K)
                = (Input (Input'First + K - 1)
                   xor Spec_Block_Bytes
                         (Key, Nonce, Counter + Word ((K - 1) / Block_Length))
                            (((K - 1) mod Block_Length) + 1)));
      end loop;
      return Result;
   end Spec_Chacha20;

   ---------------------------------------------------------------------
   --  Block — RFC 8439 §2.3.1, imperative.
   ---------------------------------------------------------------------

   procedure Block
     (Key       : Key_Array;
      Nonce     : Nonce_Array;
      Counter   : Word;
      Out_Block : out Block_Array)
   is
      Initial : constant State_Array :=
        Build_Initial_State (Key, Nonce, Counter);
      --  Use Spec_Rounds — same expression function as the ghost
      --  Spec_Block_Bytes path goes through. By construction, then,
      --  State (I) + Initial (I) = Spec_State_Word (Key, Nonce, Counter, I).
      State   : constant State_Array := Spec_Rounds (Initial);
   begin
      Out_Block := [others => 0];

      for I in State'Range loop
         declare
            W : constant Word := State (I) + Initial (I);
         begin
            --  Stage equality through the expression-function body so
            --  SMT sees W = Spec_State_Word at this loop iteration.
            pragma
              Assert
                (Spec_State_Word (Key, Nonce, Counter, I)
                   = Spec_Rounds (Build_Initial_State (Key, Nonce, Counter))
                       (I)
                     + Build_Initial_State (Key, Nonce, Counter) (I));
            pragma
              Assert (Build_Initial_State (Key, Nonce, Counter) = Initial);
            pragma
              Assert
                (Spec_Rounds (Build_Initial_State (Key, Nonce, Counter))
                   = Spec_Rounds (Initial));
            pragma Assert (Spec_Rounds (Initial) = State);
            pragma Assert (W = Spec_State_Word (Key, Nonce, Counter, I));
            Put_LE_Word (Out_Block, 4 * I + 1, W);
            --  Strong loop invariant: Out_Block matches Spec_Block_Bytes
            --  byte-for-byte across the linear-index range already
            --  written, so the procedure Post is the loop invariant
            --  at exit (no further bridging needed).
            pragma
              Loop_Invariant
                (for all K in 1 .. 4 * (I + 1) =>
                   Out_Block (K) = Spec_Block_Bytes (Key, Nonce, Counter) (K));
         end;
      end loop;

      --  At exit I = 15, so the loop invariant covers K in 1..64,
      --  which is exactly Block_Array'Range = the procedure Post.
      pragma
        Assert
          (for all I in Block_Array'Range =>
             Out_Block (I) = Spec_Block_Bytes (Key, Nonce, Counter) (I));
   end Block;

   ---------------------------------------------------------------------
   --  Encrypt — XOR plaintext with keystream blocks, mirrors
   --  HACL*  chacha20_encrypt_bytes = init >> map_blocks.
   ---------------------------------------------------------------------

   procedure Encrypt
     (Key             : Key_Array;
      Nonce           : Nonce_Array;
      Initial_Counter : Word;
      Input           : Octet_Array;
      Output          : out Octet_Array)
   is
      Stream  : Block_Array;
      Counter : Word := Initial_Counter;
      Cursor  : Natural := 0;

      --  Ghost: at every loop iteration, Output's processed prefix
      --  equals Spec_Chacha20 applied to Input's processed prefix.
   begin
      Output := [others => 0];

      --  Special-case empty Input: Output is the empty array, which
      --  by definition equals Spec_Chacha20 (..., empty).
      if Input'Length = 0 then
         pragma Assert (Output'Length = 0);
         pragma Assert (Output = Spec_Chacha20 (Key, Nonce, Counter, Input));
         return;
      end if;

      while Cursor < Input'Length loop
         pragma Loop_Invariant (Cursor in 0 .. Input'Length);
         pragma Loop_Invariant (Cursor mod Block_Length = 0);
         pragma
           Loop_Invariant
             (Counter = Initial_Counter + Word (Cursor / Block_Length));
         --  Byte-by-byte spec equality up to the bytes processed
         --  so far. Same indexing pattern as Spec_Chacha20's Post
         --  so SMT pattern-matches directly.
         pragma
           Loop_Invariant
             (for all K in 1 .. Cursor =>
                Output (Output'First + K - 1)
                = (Input (Input'First + K - 1)
                   xor Spec_Block_Bytes
                         (Key,
                          Nonce,
                          Initial_Counter + Word ((K - 1) / Block_Length))
                            (((K - 1) mod Block_Length) + 1)));
         pragma Loop_Variant (Decreases => Input'Length - Cursor);

         Block
           (Key       => Key,
            Nonce     => Nonce,
            Counter   => Counter,
            Out_Block => Stream);

         declare
            Take       : constant Natural :=
              Natural'Min (Block_Length, Input'Length - Cursor);
            Old_Cursor : constant Natural := Cursor
            with Ghost;
            Old_Output : constant Octet_Array := Output
            with Ghost;
         begin
            for I in 1 .. Take loop
               Output (Output'First + Cursor + I - 1) :=
                 Input (Input'First + Cursor + I - 1) xor Stream (I);
               --  Bytes just written equal the spec's by-byte XOR.
               pragma
                 Loop_Invariant
                   (for all J in 1 .. I =>
                      Output (Output'First + Old_Cursor + J - 1)
                      = (Input (Input'First + Old_Cursor + J - 1)
                         xor Stream (J)));
               --  Bytes outside the [Old_Cursor + 1 .. Old_Cursor + I]
               --  window retain their pre-loop values.
               pragma
                 Loop_Invariant
                   (for all K in Output'Range =>
                      (if K < Output'First + Old_Cursor
                         or K > Output'First + Old_Cursor + I - 1
                       then Output (K) = Old_Output (K)));
            end loop;
            Cursor := Cursor + Take;
         end;
         Counter := Counter + 1;
      end loop;

      pragma Assert (Cursor = Input'Length);
      --  Final equality: the loop invariant gives byte-by-byte equality
      --  of Output and the same byte expression that Spec_Chacha20's
      --  Post says equals Spec_Chacha20'Result. Lengths match, so
      --  array equality follows.
      declare
         Spec_Out : constant Octet_Array :=
           Spec_Chacha20 (Key, Nonce, Initial_Counter, Input)
         with Ghost;
      begin
         pragma Assert (Spec_Out'Length = Output'Length);
         pragma
           Assert
             (for all K in 1 .. Input'Length =>
                Output (Output'First + K - 1) = Spec_Out (K));
         pragma Assert (Output = Spec_Out);
      end;
   end Encrypt;

end Tls_Core.Chacha20;
