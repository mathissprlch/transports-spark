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
      F : constant RFLX.RFLX_Types.Index := Input'First;
      --  Compute the 32-bit BE length in a 64-bit accumulator. Earlier
      --  iteration used Natural for the intermediate; on this target
      --  Natural is 32-bit signed, so byte (>= 0x80) * 16777216
      --  overflowed Natural'Last (~2.15B) in 50% of random inputs.
      --  Iteration-01 fuzz log:
      --    grpc_core-framing.adb:43 overflow check failed (2,500,064/5M)
      --  Long_Long_Integer is at least 64-bit on every supported
      --  GNAT target.
      Len64 : constant Long_Long_Integer :=
        Long_Long_Integer (Input (F + 1)) * 16777216
        + Long_Long_Integer (Input (F + 2)) * 65536
        + Long_Long_Integer (Input (F + 3)) * 256
        + Long_Long_Integer (Input (F + 4));
   begin
      Compressed_Flag := Input (F) /= 0;
      Output_OK       := False;
      Message_Length  := 0;

      --  Even with a 64-bit accumulator we cap the message at the
      --  caller-provided Message buffer; oversize lengths become
      --  Output_OK = False rather than a partial copy.
      if Len64 > Long_Long_Integer (Input'Length) - 5 then
         return;  --  declared length exceeds available input
      end if;
      if Len64 > Long_Long_Integer (Message'Length) then
         return;  --  caller's buffer too small
      end if;
      declare
         Len : constant Natural := Natural (Len64);
      begin
         if Len > 0 then
            Message (Message'First ..
                       Message'First + RFLX.RFLX_Types.Index (Len) - 1) :=
              Input (F + 5 .. F + 4 + RFLX.RFLX_Types.Index (Len));
         end if;
         Message_Length := RFLX.RFLX_Types.Length (Len);
      end;
      Output_OK := True;
   end Decode;

end Grpc_Core.Framing;
