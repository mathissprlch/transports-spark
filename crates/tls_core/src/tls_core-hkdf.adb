with RFLX.Hkdf;
with RFLX.Hkdf.Label;
with RFLX.RFLX_Types;

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
   --  Build_Info_Bytes_Via_Rflx — same wire output, via the
   --  RecordFlux-generated `Hkdf::Label` serializer. Cross-check
   --  oracle for Build_Info_Bytes; not in the SPARK boundary
   --  because RFLX runtime context types carry their own
   --  ownership reasoning we don't yet replicate here.
   ---------------------------------------------------------------------

   procedure Build_Info_Bytes_Via_Rflx
     (Length  : Interfaces.Unsigned_16;
      Label   : Octet_Array;
      Context : Octet_Array;
      Buffer  : in out RFLX.RFLX_Builtin_Types.Bytes_Ptr;
      Last    : out Natural)
   is
      pragma SPARK_Mode (Off);
      Ctx        : RFLX.Hkdf.Label.Context;
      Lbl_Bytes  : RFLX.RFLX_Types.Bytes
        (1 .. RFLX.RFLX_Types.Index
                (Tls13_Prefix'Length + Label'Length));
      Ctx_Bytes  : RFLX.RFLX_Types.Bytes
        (1 .. RFLX.RFLX_Types.Index
                (Natural'Max (Context'Length, 1)));
      Last_Bit   : RFLX.RFLX_Types.Bit_Length;
   begin
      --  Pack the labelled name = "tls13 " + Label.
      for I in Tls13_Prefix'Range loop
         Lbl_Bytes (RFLX.RFLX_Types.Index (I)) :=
           RFLX.RFLX_Types.Byte (Tls13_Prefix (I));
      end loop;
      for I in 1 .. Label'Length loop
         Lbl_Bytes
           (RFLX.RFLX_Types.Index (Tls13_Prefix'Length + I)) :=
             RFLX.RFLX_Types.Byte (Label (Label'First + I - 1));
      end loop;

      --  And the context.
      for I in 1 .. Context'Length loop
         Ctx_Bytes (RFLX.RFLX_Types.Index (I)) :=
           RFLX.RFLX_Types.Byte (Context (Context'First + I - 1));
      end loop;

      RFLX.Hkdf.Label.Initialize (Ctx, Buffer);
      RFLX.Hkdf.Label.Set_Length
        (Ctx, RFLX.Hkdf.Length_U16 (Length));
      RFLX.Hkdf.Label.Set_Label_Len
        (Ctx,
         RFLX.Hkdf.Label_Length
           (Tls13_Prefix'Length + Label'Length));
      RFLX.Hkdf.Label.Set_Label_Bytes (Ctx, Lbl_Bytes);
      RFLX.Hkdf.Label.Set_Context_Len
        (Ctx, RFLX.Hkdf.Context_Length (Context'Length));
      if Context'Length = 0 then
         RFLX.Hkdf.Label.Set_Context_Bytes_Empty (Ctx);
      else
         RFLX.Hkdf.Label.Set_Context_Bytes
           (Ctx, Ctx_Bytes (1 .. RFLX.RFLX_Types.Index (Context'Length)));
      end if;
      Last_Bit := RFLX.Hkdf.Label.Message_Last (Ctx);
      Last := Natural (RFLX.RFLX_Types.To_Index (Last_Bit));
      RFLX.Hkdf.Label.Take_Buffer (Ctx, Buffer);
   end Build_Info_Bytes_Via_Rflx;

   ---------------------------------------------------------------------
   --  Expand_Label — composition: build §7.1 info, hand to HMAC.
   ---------------------------------------------------------------------

   procedure Expand_Label
     (Secret  : Octet_Array;
      Label   : Octet_Array;
      Context : Octet_Array;
      Output  : out Octet_Array)
   is
      Info  : Octet_Array
        (1 .. Info_Size (Label'Length, Context'Length));
      Ignored : Natural;
   begin
      Build_Info_Bytes
        (Length  => Interfaces.Unsigned_16 (Output'Length),
         Label   => Label,
         Context => Context,
         Output  => Info,
         Last    => Ignored);
      Hmac_Expand
        (Prk    => Secret,
         Info   => Info,
         Output => Output);
   end Expand_Label;

end Tls_Core.Hkdf;
