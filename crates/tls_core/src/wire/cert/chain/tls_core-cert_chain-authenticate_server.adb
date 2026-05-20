separate (Tls_Core.Cert_Chain)
procedure Authenticate_Server
  (All_Certs       : Octet_Array;
   Chain_In        : Chain;
   Trust           : Trust_Store;
   Hostname        : Octet_Array;
   Sig_Scheme      : Interfaces.Unsigned_16;
   Sig_Body        : Octet_Array;
   Transcript_Hash : Octet_Array;
   Result          : out Validation_Result)
is
   Leaf_Parsed  : Tls_Core.Cert.Parsed_Cert;
   Chain_Result : Validation_Result;
begin
   --  (a) Validate the chain.
   Validate_Chain
     (All_Certs   => All_Certs,
      Chain_In    => Chain_In,
      Trust       => Trust,
      Result      => Chain_Result,
      Leaf_Parsed => Leaf_Parsed);
   if Chain_Result /= OK_Validated then
      Result := Chain_Result;
      return;
   end if;

   --  (b) Optional SAN match. Stage the SAN body into a fixed
   --  1024-byte buffer (RFC 5280 doesn't fix an upper bound but
   --  sane real-world certs never exceed 1024 bytes of SAN body).
   if Hostname'Length > 0 then
      if not Leaf_Parsed.San_Present then
         Result := Bad_Signature;
         return;
      end if;
      if Leaf_Parsed.San_First in All_Certs'Range
        and then Leaf_Parsed.San_Last in All_Certs'Range
        and then Leaf_Parsed.San_First <= Leaf_Parsed.San_Last
      then
         declare
            San_Buf : Octet_Array (1 .. 1024) := (others => 0);
            San_Len : constant Natural :=
              Leaf_Parsed.San_Last - Leaf_Parsed.San_First + 1;
         begin
            if San_Len = 0 or else San_Len > 1024 then
               Result := Bad_Cert_Format;
               return;
            end if;
            for K in 0 .. San_Len - 1 loop
               San_Buf (1 + K) := All_Certs (Leaf_Parsed.San_First + K);
            end loop;
            if not Tls_Core.Cert.Match_DNS_SAN
                     (San_Buf (1 .. San_Len), Hostname)
            then
               Result := Bad_Signature;
               return;
            end if;
         end;
      else
         Result := Bad_Cert_Format;
         return;
      end if;
   end if;

   --  (c) CertificateVerify signature. Stage the leaf DER into a
   --  16K fixed buffer the same way Validate_Chain does, then
   --  re-parse so Verify_Cert_Verify gets indices local to that
   --  buffer's coordinate frame (Buf'First = 1).
   declare
      Signed_Buf  : Octet_Array (1 .. 64 + 33 + 1 + 64);
      Signed_Last : Natural;

      Leaf_Ent : constant Chain_Entry := Chain_In.Entries (1);
      Leaf_Buf : Octet_Array (1 .. 16384) := (others => 0);
      Leaf_Len : constant Natural := Leaf_Ent.Last - Leaf_Ent.First + 1;

      Leaf_P_Local : Tls_Core.Cert.Parsed_Cert;
      Leaf_OK      : Boolean;

      CV_OK : Boolean;
   begin
      if Transcript_Hash'Length not in 1 .. 64 then
         Result := Bad_Signature;
         return;
      end if;
      if Leaf_Len < 16 or else Leaf_Len > 16384 then
         Result := Bad_Cert_Format;
         return;
      end if;
      for K in 0 .. Leaf_Len - 1 loop
         Leaf_Buf (1 + K) := All_Certs (Leaf_Ent.First + K);
      end loop;

      Tls_Core.Cert_Verify.Build_Signed_Content
        (Side            => Tls_Core.Cert_Verify.Server,
         Transcript_Hash => Transcript_Hash,
         Out_Buf         => Signed_Buf,
         Out_Last        => Signed_Last);

      Tls_Core.Cert.Parse (Leaf_Buf (1 .. Leaf_Len), Leaf_P_Local, Leaf_OK);
      if not Leaf_OK then
         Result := Bad_Cert_Format;
         return;
      end if;

      if Sig_Body'Length not in 1 .. 1024 then
         Result := Bad_Signature;
         return;
      end if;

      Verify_Cert_Verify
        (Leaf_Der       => Leaf_Buf (1 .. Leaf_Len),
         Leaf_Parsed    => Leaf_P_Local,
         Sig_Scheme     => Sig_Scheme,
         Signed_Content => Signed_Buf (1 .. Signed_Last),
         Signature      => Sig_Body,
         OK             => CV_OK);
      if CV_OK then
         Result := OK_Validated;
      else
         Result := Bad_Signature;
      end if;
   end;
end Authenticate_Server;
