with RFLX.RFLX_Builtin_Types;

package body Grpc_Core.Framing
with SPARK_Mode
is

   use type RFLX.RFLX_Types.Index;
   use type RFLX.RFLX_Builtin_Types.Byte;

   subtype U8 is RFLX.RFLX_Types.Byte;

   procedure Encode
     (Buffer       : in out RFLX.RFLX_Types.Bytes;
      Message      : RFLX.RFLX_Types.Bytes;
      Output_Last  : out RFLX.RFLX_Types.Index;
      Output_OK    : out Boolean)
   is
      Len : constant Natural := Message'Length;
      F   : constant RFLX.RFLX_Types.Index := Buffer'First;
   begin
      Buffer (F)     := 0;  --  C = 0 (uncompressed)
      Buffer (F + 1) := U8 ((Len / 16777216) mod 256);
      Buffer (F + 2) := U8 ((Len / 65536) mod 256);
      Buffer (F + 3) := U8 ((Len / 256) mod 256);
      Buffer (F + 4) := U8 (Len mod 256);
      if Len > 0 then
         Buffer (F + 5 .. F + 4 + RFLX.RFLX_Types.Index (Len)) :=
           Message;
      end if;
      Output_Last := F + 4 + RFLX.RFLX_Types.Index (Len);
      Output_OK   := True;
   end Encode;

   procedure Decode
     (Input            : RFLX.RFLX_Types.Bytes;
      Message          : in out RFLX.RFLX_Types.Bytes;
      Message_Length   : out RFLX.RFLX_Types.Length;
      Compressed_Flag  : out Boolean;
      Output_OK        : out Boolean)
   is
      F   : constant RFLX.RFLX_Types.Index := Input'First;
      Len : constant Natural :=
        Natural (Input (F + 1)) * 16777216
        + Natural (Input (F + 2)) * 65536
        + Natural (Input (F + 3)) * 256
        + Natural (Input (F + 4));
   begin
      Compressed_Flag := Input (F) /= 0;
      Output_OK       := False;
      Message_Length  := 0;

      if Len > Input'Length - 5 then
         return;  --  declared length exceeds available input
      end if;
      if Len > Message'Length then
         return;  --  caller's buffer too small
      end if;
      if Len > 0 then
         Message (Message'First ..
                    Message'First + RFLX.RFLX_Types.Index (Len) - 1) :=
           Input (F + 5 .. F + 4 + RFLX.RFLX_Types.Index (Len));
      end if;
      Message_Length := RFLX.RFLX_Types.Length (Len);
      Output_OK      := True;
   end Decode;

end Grpc_Core.Framing;
