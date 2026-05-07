with RFLX.Hkdf;
with RFLX.Hkdf.Label;
with RFLX.RFLX_Types;

package body Test_Rflx_Oracles
is

   --  "tls13 " prefix that HKDF-Expand-Label prepends to Label.
   Tls13_Prefix : constant Tls_Core.Octet_Array (1 .. 6) :=
     (16#74#, 16#6C#, 16#73#, 16#31#, 16#33#, 16#20#);

   procedure Build_Info_Bytes_Via_Rflx
     (Length  : Interfaces.Unsigned_16;
      Label   : Tls_Core.Octet_Array;
      Context : Tls_Core.Octet_Array;
      Buffer  : in out RFLX.RFLX_Builtin_Types.Bytes_Ptr;
      Last    : out Natural)
   is
      Ctx        : RFLX.Hkdf.Label.Context;
      Lbl_Bytes  : RFLX.RFLX_Types.Bytes
        (1 .. RFLX.RFLX_Types.Index
                (Tls13_Prefix'Length + Label'Length));
      Ctx_Bytes  : RFLX.RFLX_Types.Bytes
        (1 .. RFLX.RFLX_Types.Index
                (Natural'Max (Context'Length, 1)));
      Last_Bit   : RFLX.RFLX_Types.Bit_Length;
   begin
      for I in Tls13_Prefix'Range loop
         Lbl_Bytes (RFLX.RFLX_Types.Index (I)) :=
           RFLX.RFLX_Types.Byte (Tls13_Prefix (I));
      end loop;
      for I in 1 .. Label'Length loop
         Lbl_Bytes
           (RFLX.RFLX_Types.Index (Tls13_Prefix'Length + I)) :=
             RFLX.RFLX_Types.Byte (Label (Label'First + I - 1));
      end loop;

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

end Test_Rflx_Oracles;
