package body Tls_Core.Alert
  with SPARK_Mode
is

   ---------------------------------------------------------------------
   --  Encode
   ---------------------------------------------------------------------

   procedure Encode (A : Alert; Out_Bytes : out Alert_Bytes) is
   begin
      Out_Bytes := (A.Level, A.Description);
   end Encode;

   ---------------------------------------------------------------------
   --  Decode
   ---------------------------------------------------------------------

   procedure Decode (In_Bytes : Octet_Array; A : out Alert; OK : out Boolean)
   is
   begin
      A := (Level => 0, Description => 0);
      if In_Bytes'Length /= 2 then
         OK := False;
         return;
      end if;
      A.Level := In_Bytes (In_Bytes'First);
      A.Description := In_Bytes (In_Bytes'First + 1);
      OK := True;
   end Decode;

end Tls_Core.Alert;
