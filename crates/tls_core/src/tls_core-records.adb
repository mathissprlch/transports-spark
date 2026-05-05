with RFLX.Record_Layer.Plaintext;
with RFLX.RFLX_Types;
with RFLX.RFLX_Types.Operators; use RFLX.RFLX_Types.Operators;

package body Tls_Core.Records
with SPARK_Mode => Off
is

   use type RFLX.RFLX_Types.Bit_Length;

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   --  Mirror of Content_Type ←→ RFLX.Record_Layer.Content_Type.
   function To_Rflx_Type
     (T : Content_Type) return RFLX.Record_Layer.Content_Type
   is (case T is
         when Invalid            => RFLX.Record_Layer.Invalid,
         when Change_Cipher_Spec => RFLX.Record_Layer.Change_Cipher_Spec,
         when Alert              => RFLX.Record_Layer.Alert,
         when Handshake          => RFLX.Record_Layer.Handshake,
         when Application_Data   => RFLX.Record_Layer.Application_Data);

   function From_Rflx_Type
     (T : RFLX.Record_Layer.Content_Type) return Content_Type
   is (case T is
         when RFLX.Record_Layer.Invalid            => Invalid,
         when RFLX.Record_Layer.Change_Cipher_Spec => Change_Cipher_Spec,
         when RFLX.Record_Layer.Alert              => Alert,
         when RFLX.Record_Layer.Handshake          => Handshake,
         when RFLX.Record_Layer.Application_Data   => Application_Data);

   procedure Encode
     (Buffer    : in out RFLX.RFLX_Builtin_Types.Bytes_Ptr;
      Last      : out Natural;
      Type_Of   : Content_Type;
      Fragment  : Octet_Array)
   is
      Ctx     : RFLX.Record_Layer.Plaintext.Context;
      Payload : RFLX.RFLX_Types.Bytes
        (1 .. RFLX.RFLX_Types.Index'Max
                (1, RFLX.RFLX_Types.Index (Fragment'Length)));
   begin
      for I in 1 .. Fragment'Length loop
         Payload (RFLX.RFLX_Types.Index (I)) :=
           RFLX.RFLX_Types.Byte (Fragment (Fragment'First + I - 1));
      end loop;

      RFLX.Record_Layer.Plaintext.Initialize (Ctx, Buffer);
      RFLX.Record_Layer.Plaintext.Set_Type_Field
        (Ctx, To_Rflx_Type (Type_Of));
      RFLX.Record_Layer.Plaintext.Set_Legacy_Version (Ctx, 16#0303#);
      RFLX.Record_Layer.Plaintext.Set_Length
        (Ctx, RFLX.Record_Layer.Length_U16 (Fragment'Length));
      if Fragment'Length = 0 then
         RFLX.Record_Layer.Plaintext.Set_Fragment_Empty (Ctx);
      else
         RFLX.Record_Layer.Plaintext.Set_Fragment
           (Ctx,
            Payload (1 .. RFLX.RFLX_Types.Index (Fragment'Length)));
      end if;
      Last := Natural
        (RFLX.RFLX_Types.To_Index
           (RFLX.Record_Layer.Plaintext.Message_Last (Ctx)));
      RFLX.Record_Layer.Plaintext.Take_Buffer (Ctx, Buffer);
   end Encode;

   procedure Decode
     (Buffer         : in out RFLX.RFLX_Builtin_Types.Bytes_Ptr;
      Last           : Natural;
      OK             : out Boolean;
      Type_Of        : out Content_Type;
      Fragment_First : out Natural;
      Fragment_Last  : out Natural)
   is
      Ctx : RFLX.Record_Layer.Plaintext.Context;
   begin
      OK := False;
      Type_Of := Invalid;
      Fragment_First := 0;
      Fragment_Last := 0;
      RFLX.Record_Layer.Plaintext.Initialize
        (Ctx, Buffer,
         Written_Last =>
           RFLX.RFLX_Types.Bit_Length (Last) *
             RFLX.RFLX_Types.Bit_Length'(8));
      RFLX.Record_Layer.Plaintext.Verify_Message (Ctx);
      if RFLX.Record_Layer.Plaintext.Well_Formed_Message (Ctx) then
         Type_Of :=
           From_Rflx_Type
             (RFLX.Record_Layer.Plaintext.Get_Type_Field (Ctx));
         declare
            Frag_Bits : constant RFLX.RFLX_Types.Bit_Length :=
              RFLX.Record_Layer.Plaintext.Field_Size
                (Ctx, RFLX.Record_Layer.Plaintext.F_Fragment);
            Frag_Bytes : constant Natural :=
              Natural (RFLX.RFLX_Types.To_Length (Frag_Bits));
         begin
            --  Bytes 1..5 are the fixed header (type+version+length).
            Fragment_First := 6;
            Fragment_Last  := 5 + Frag_Bytes;
         end;
         OK := True;
      end if;
      RFLX.Record_Layer.Plaintext.Take_Buffer (Ctx, Buffer);
   end Decode;

end Tls_Core.Records;
