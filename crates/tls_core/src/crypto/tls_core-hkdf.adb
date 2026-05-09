
package body Tls_Core.Hkdf
is
   pragma SPARK_Mode (On);

   ---------------------------------------------------------------------
   --  Build_Info_Bytes
   --
   --  Hand-written, contracts visible. Spec lists every byte the
   --  output must carry; the loop bodies fill those bytes one by
   --  one and gnatprove discharges the all-quantified post.
   ---------------------------------------------------------------------

   procedure Build_Info_Bytes
     (Length  : Interfaces.Unsigned_16;
      Label   : Octet_Array;
      Context : Octet_Array;
      Output  : out Octet_Array;
      Last    : out Natural)
   is
      use Interfaces;

      --  Cursor offsets where each region begins, all relative to
      --  Output'First = 1. Naming them out makes the loop
      --  invariants below readable and the post-condition match.
      Prefix_Off  : constant Positive := 4;
      Label_Off   : constant Positive :=
        Prefix_Off + Tls13_Prefix'Length;
      Ctx_Len_Off : constant Positive := Label_Off + Label'Length;
      Ctx_Off     : constant Positive := Ctx_Len_Off + 1;
   begin
      --  Initialize all bytes to zero up-front. Subsequent writes
      --  overwrite the regions we own. This pattern keeps gnatprove's
      --  initialization analysis happy without a Relaxed_Initialization
      --  aspect (unsupported on parameters in this toolchain build).
      Output := (others => 0);

      --  u16 BE Length.
      Output (1) := Octet (Length / 256);
      Output (2) := Octet (Length mod 256);

      --  Labelled-name length octet.
      Output (3) :=
        Octet (Tls13_Prefix'Length + Label'Length);

      --  Literal "tls13 " — slice assignment so gnatprove sees
      --  the all-quantified equality directly.
      Output (Prefix_Off .. Prefix_Off + Tls13_Prefix'Length - 1) :=
        Tls13_Prefix;

      --  Caller-supplied Label.
      for I in 1 .. Label'Length loop
         Output (Label_Off + I - 1) :=
           Label (Label'First + I - 1);
         pragma Loop_Invariant
           (Output (1) = Octet (Length / 256)
            and then Output (2) = Octet (Length mod 256)
            and then Output (3) =
              Octet (Tls13_Prefix'Length + Label'Length)
            and then
              (for all J in 1 .. Tls13_Prefix'Length =>
                 Output (Prefix_Off + J - 1) = Tls13_Prefix (J))
            and then
              (for all J in 1 .. I =>
                 Output (Label_Off + J - 1)
                 = Label (Label'First + J - 1)));
      end loop;

      --  Context length octet.
      Output (Ctx_Len_Off) := Octet (Context'Length);

      --  Context bytes.
      for I in 1 .. Context'Length loop
         Output (Ctx_Off + I - 1) :=
           Context (Context'First + I - 1);
         pragma Loop_Invariant
           (Output (1) = Octet (Length / 256)
            and then Output (2) = Octet (Length mod 256)
            and then Output (3) =
              Octet (Tls13_Prefix'Length + Label'Length)
            and then
              (for all J in 1 .. Tls13_Prefix'Length =>
                 Output (Prefix_Off + J - 1) = Tls13_Prefix (J))
            and then
              (for all J in 1 .. Label'Length =>
                 Output (Label_Off + J - 1)
                 = Label (Label'First + J - 1))
            and then Output (Ctx_Len_Off) = Octet (Context'Length)
            and then
              (for all J in 1 .. I =>
                 Output (Ctx_Off + J - 1)
                 = Context (Context'First + J - 1)));
      end loop;

      Last := Output'Last;
   end Build_Info_Bytes;

   ---------------------------------------------------------------------
   --  Built_Info_Bytes — pure functional twin of Build_Info_Bytes.
   --
   --  Allocates a fresh Octet_Array sized to Info_Size and runs the
   --  same imperative construction as Build_Info_Bytes, returning
   --  the resulting array. Same wire shape (RFC 8446 §7.1).
   ---------------------------------------------------------------------

   function Built_Info_Bytes
     (Length  : Natural;
      Label   : Octet_Array;
      Context : Octet_Array) return Octet_Array
   is
      use Interfaces;

      Result : Octet_Array
        (1 .. Info_Size (Label'Length, Context'Length)) := (others => 0);

      Prefix_Off  : constant Positive := 4;
      Label_Off   : constant Positive :=
        Prefix_Off + Tls13_Prefix'Length;
      Ctx_Len_Off : constant Positive := Label_Off + Label'Length;
      Ctx_Off     : constant Positive := Ctx_Len_Off + 1;

      L_U16 : constant Unsigned_16 := Unsigned_16 (Length);
   begin
      Result (1) := Octet (L_U16 / 256);
      Result (2) := Octet (L_U16 mod 256);
      Result (3) := Octet (Tls13_Prefix'Length + Label'Length);

      Result (Prefix_Off .. Prefix_Off + Tls13_Prefix'Length - 1) :=
        Tls13_Prefix;

      for I in 1 .. Label'Length loop
         Result (Label_Off + I - 1) := Label (Label'First + I - 1);
         pragma Loop_Invariant
           (Result (1) = Octet (L_U16 / 256)
            and then Result (2) = Octet (L_U16 mod 256)
            and then Result (3) =
              Octet (Tls13_Prefix'Length + Label'Length)
            and then
              (for all J in 1 .. Tls13_Prefix'Length =>
                 Result (Prefix_Off + J - 1) = Tls13_Prefix (J))
            and then
              (for all J in 1 .. I =>
                 Result (Label_Off + J - 1)
                 = Label (Label'First + J - 1)));
      end loop;

      Result (Ctx_Len_Off) := Octet (Context'Length);

      for I in 1 .. Context'Length loop
         Result (Ctx_Off + I - 1) := Context (Context'First + I - 1);
         pragma Loop_Invariant
           (Result (1) = Octet (L_U16 / 256)
            and then Result (2) = Octet (L_U16 mod 256)
            and then Result (3) =
              Octet (Tls13_Prefix'Length + Label'Length)
            and then
              (for all J in 1 .. Tls13_Prefix'Length =>
                 Result (Prefix_Off + J - 1) = Tls13_Prefix (J))
            and then
              (for all J in 1 .. Label'Length =>
                 Result (Label_Off + J - 1)
                 = Label (Label'First + J - 1))
            and then Result (Ctx_Len_Off) = Octet (Context'Length)
            and then
              (for all J in 1 .. I =>
                 Result (Ctx_Off + J - 1)
                 = Context (Context'First + J - 1)));
      end loop;

      return Result;
   end Built_Info_Bytes;

   ---------------------------------------------------------------------
   --  Expand_Label — composition: build §7.1 info, hand to HMAC.
   --
   --  We build the info bytes via Built_Info_Bytes (a function — its
   --  return value is referentially transparent so the Post can name
   --  it), then call the formal Hmac_Expand. Hmac_Expand's Post pins
   --  Output to Spec_Hmac_Expand at that info; the resulting Post on
   --  Expand_Label discharges by congruence.
   ---------------------------------------------------------------------

   procedure Expand_Label
     (Secret  : Octet_Array;
      Label   : Octet_Array;
      Context : Octet_Array;
      Output  : out Octet_Array)
   is
      Info : constant Octet_Array :=
        Built_Info_Bytes (Output'Length, Label, Context);
   begin
      Hmac_Expand
        (Prk    => Secret,
         Info   => Info,
         Output => Output);
   end Expand_Label;

end Tls_Core.Hkdf;
