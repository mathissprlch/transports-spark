separate (Tls_Core.Cert_Verify)
   procedure Build_Signed_Content
     (Side            : Cert_Verify_Side;
      Transcript_Hash : Octet_Array;
      Out_Buf         : out Octet_Array;
      Out_Last        : out Natural)
   is
   begin
      Out_Buf := (others => 0);
      --  64 spaces.
      for I in 1 .. 64 loop
         Out_Buf (I) := 16#20#;
      end loop;
      --  Side-specific prefix.
      case Side is
         when Server =>
            Out_Buf (65 .. 65 + 32) := Server_Prefix;
         when Client =>
            Out_Buf (65 .. 65 + 32) := Client_Prefix;
      end case;
      --  Separator 0x00.
      Out_Buf (98) := 16#00#;
      --  Transcript hash.
      for I in 1 .. Transcript_Hash'Length loop
         Out_Buf (98 + I) :=
           Transcript_Hash (Transcript_Hash'First + I - 1);
      end loop;
      Out_Last := 98 + Transcript_Hash'Length;
   end Build_Signed_Content;
