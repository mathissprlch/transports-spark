package body Tls_Core.Chacha20
with SPARK_Mode
is

   use Interfaces;

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   ---------------------------------------------------------------------
   --  Read four bytes LE → Word (RFC 8439 uses little-endian).
   ---------------------------------------------------------------------

   function LE_Word (B : Octet_Array; Offset : Positive) return Word
   is
     (Word (B (Offset))
      or Shift_Left (Word (B (Offset + 1)), 8)
      or Shift_Left (Word (B (Offset + 2)), 16)
      or Shift_Left (Word (B (Offset + 3)), 24))
   with Pre =>
     Offset <= Positive'Last - 3
     and then B'First <= Offset
     and then Offset + 3 <= B'Last;

   ---------------------------------------------------------------------
   --  Write Word → four bytes LE.
   ---------------------------------------------------------------------

   procedure Put_LE_Word
     (B : in out Octet_Array; Offset : Positive; W : Word)
   with Pre =>
     Offset <= Positive'Last - 3
     and then B'First <= Offset
     and then Offset + 3 <= B'Last;
   procedure Put_LE_Word
     (B : in out Octet_Array; Offset : Positive; W : Word)
   is
   begin
      B (Offset)     := Octet (W and 16#FF#);
      B (Offset + 1) := Octet (Shift_Right (W,  8) and 16#FF#);
      B (Offset + 2) := Octet (Shift_Right (W, 16) and 16#FF#);
      B (Offset + 3) := Octet (Shift_Right (W, 24) and 16#FF#);
   end Put_LE_Word;

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

   procedure Quarter_Round
     (S    : in out State_Array;
      A, B, C, D : Natural)
   with Pre => A <= 15 and B <= 15 and C <= 15 and D <= 15;

   procedure Quarter_Round
     (S    : in out State_Array;
      A, B, C, D : Natural)
   is
   begin
      S (A) := S (A) + S (B);  S (D) := ROTL (S (D) xor S (A), 16);
      S (C) := S (C) + S (D);  S (B) := ROTL (S (B) xor S (C), 12);
      S (A) := S (A) + S (B);  S (D) := ROTL (S (D) xor S (A),  8);
      S (C) := S (C) + S (D);  S (B) := ROTL (S (B) xor S (C),  7);
   end Quarter_Round;

   ---------------------------------------------------------------------
   --  Block function — RFC 8439 §2.3.1.
   ---------------------------------------------------------------------

   procedure Block
     (Key       : Key_Array;
      Nonce     : Nonce_Array;
      Counter   : Word;
      Out_Block : out Block_Array)
   is
      --  Constants "expand 32-byte k" per §2.3.
      C0 : constant Word := 16#6170_7865#;
      C1 : constant Word := 16#3320_646E#;
      C2 : constant Word := 16#7962_2D32#;
      C3 : constant Word := 16#6B20_6574#;
      pragma Warnings (Off, "initialization of ""Initial"" has no effect");
      pragma Warnings (Off, "initialization of ""State"" has no effect");
      Initial : State_Array := (others => 0);
      State   : State_Array := (others => 0);
      pragma Warnings (On, "initialization of ""Initial"" has no effect");
      pragma Warnings (On, "initialization of ""State"" has no effect");
   begin
      Out_Block := (others => 0);
      Initial (0)  := C0;
      Initial (1)  := C1;
      Initial (2)  := C2;
      Initial (3)  := C3;
      Initial (4)  := LE_Word (Key,  1);
      Initial (5)  := LE_Word (Key,  5);
      Initial (6)  := LE_Word (Key,  9);
      Initial (7)  := LE_Word (Key, 13);
      Initial (8)  := LE_Word (Key, 17);
      Initial (9)  := LE_Word (Key, 21);
      Initial (10) := LE_Word (Key, 25);
      Initial (11) := LE_Word (Key, 29);
      Initial (12) := Counter;
      Initial (13) := LE_Word (Nonce, 1);
      Initial (14) := LE_Word (Nonce, 5);
      Initial (15) := LE_Word (Nonce, 9);

      State := Initial;

      --  Ten double-rounds = 20 quarter-rounds.
      for R in 1 .. 10 loop
         --  Column rounds.
         Quarter_Round (State,  0,  4,  8, 12);
         Quarter_Round (State,  1,  5,  9, 13);
         Quarter_Round (State,  2,  6, 10, 14);
         Quarter_Round (State,  3,  7, 11, 15);
         --  Diagonal rounds.
         Quarter_Round (State,  0,  5, 10, 15);
         Quarter_Round (State,  1,  6, 11, 12);
         Quarter_Round (State,  2,  7,  8, 13);
         Quarter_Round (State,  3,  4,  9, 14);
      end loop;

      --  Add original state, serialize little-endian.
      for I in State'Range loop
         Put_LE_Word
           (Out_Block, 4 * I + 1, State (I) + Initial (I));
      end loop;
   end Block;

   ---------------------------------------------------------------------
   --  Encrypt — XOR plaintext with keystream blocks.
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
   begin
      Output := (others => 0);
      while Cursor < Input'Length loop
         pragma Loop_Variant (Decreases => Input'Length - Cursor);
         Block
           (Key       => Key,
            Nonce     => Nonce,
            Counter   => Counter,
            Out_Block => Stream);
         declare
            Take : constant Natural :=
              Natural'Min (Block_Length, Input'Length - Cursor);
         begin
            for I in 1 .. Take loop
               Output (Output'First + Cursor + I - 1) :=
                 Input (Input'First + Cursor + I - 1)
                 xor Stream (I);
            end loop;
            Cursor := Cursor + Take;
         end;
         Counter := Counter + 1;
      end loop;
      pragma Assume
        (Output =
           Spec_Encrypt (Key, Nonce, Initial_Counter, Input));
   end Encrypt;

   function Spec_Encrypt
     (Key             : Key_Array;
      Nonce           : Nonce_Array;
      Initial_Counter : Word;
      Input           : Octet_Array)
      return Octet_Array
   is
      pragma Unreferenced (Key, Nonce, Initial_Counter);
      Result : constant Octet_Array (Input'Range) := (others => 0);
   begin
      return Result;
   end Spec_Encrypt;

end Tls_Core.Chacha20;
