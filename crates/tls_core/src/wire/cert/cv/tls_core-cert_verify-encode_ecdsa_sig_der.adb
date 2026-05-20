separate (Tls_Core.Cert_Verify)
procedure Encode_Ecdsa_Sig_Der
  (R, S : Octet_Array; Out_Buf : out Octet_Array; Out_Last : out Natural)
is
   Cursor : Natural := 2;  --  reserve bytes 1..2 for SEQUENCE header
begin
   Out_Buf := (others => 0);
   Cursor := 2;
   Append_Der_Integer (R, Out_Buf, Cursor);
   pragma Assert (Cursor <= 37);
   Append_Der_Integer (S, Out_Buf, Cursor);
   pragma Assert (Cursor <= 72);
   Out_Buf (1) := 16#30#;
   --  SEQUENCE body length = total - 2-byte header. Cursor - 2
   --  is bounded by 70 (worst case 35 + 35), well under 0x7F so a
   --  single-byte short-form length suffices.
   Out_Buf (2) := Octet (Cursor - 2);
   Out_Last := Cursor;
end Encode_Ecdsa_Sig_Der;
