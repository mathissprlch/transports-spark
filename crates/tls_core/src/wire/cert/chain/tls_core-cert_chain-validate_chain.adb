separate (Tls_Core.Cert_Chain)
procedure Validate_Chain
  (All_Certs   : Octet_Array;
   Chain_In    : Chain;
   Trust       : Trust_Store;
   Result      : out Validation_Result;
   Leaf_Parsed : out Tls_Core.Cert.Parsed_Cert)
is
   Parsed_Chain : array (1 .. Max_Chain_Depth) of Tls_Core.Cert.Parsed_Cert;
begin
   Result := Bad_Cert_Format;
   Leaf_Parsed :=
     (Tbs_First     => 0,
      Tbs_Last      => 0,
      Spki_First    => 0,
      Spki_Last     => 0,
      Sig_Alg       => Tls_Core.Cert.Unknown,
      Sig_First     => 0,
      Sig_Last      => 0,
      Issuer_First  => 0,
      Issuer_Last   => 0,
      Subject_First => 0,
      Subject_Last  => 0,
      San_Present   => False,
      San_First     => 0,
      San_Last      => 0);

   if Chain_In.Count = 0 then
      return;
   end if;

   --  Step 1: parse every entry. Any malformed cert => Bad_Cert_Format.
   for I in 1 .. Chain_In.Count loop
      pragma Loop_Invariant (Chain_In.Count in 1 .. Max_Chain_Depth);
      pragma
        Loop_Invariant
          (for all J in 1 .. I - 1 =>
             Parsed_Chain (J).Tbs_First
             in Chain_In.Entries (J).First .. Chain_In.Entries (J).Last
             and then Parsed_Chain (J).Tbs_Last
                      in Chain_In.Entries (J).First
                       .. Chain_In.Entries (J).Last
             and then Parsed_Chain (J).Tbs_First <= Parsed_Chain (J).Tbs_Last
             and then Parsed_Chain (J).Sig_First
                      in Chain_In.Entries (J).First
                       .. Chain_In.Entries (J).Last
             and then Parsed_Chain (J).Sig_Last
                      in Chain_In.Entries (J).First
                       .. Chain_In.Entries (J).Last
             and then Parsed_Chain (J).Sig_First <= Parsed_Chain (J).Sig_Last
             and then Parsed_Chain (J).Spki_First
                      in Chain_In.Entries (J).First
                       .. Chain_In.Entries (J).Last
             and then Parsed_Chain (J).Spki_Last
                      in Chain_In.Entries (J).First
                       .. Chain_In.Entries (J).Last
             and then Parsed_Chain (J).Spki_First
                      <= Parsed_Chain (J).Spki_Last);
      declare
         Ent       : constant Chain_Entry := Chain_In.Entries (I);
         Slice_Len : constant Natural := Ent.Last - Ent.First + 1;
         Slice_Buf : Octet_Array (1 .. 16384) := [others => 0];
         P         : Tls_Core.Cert.Parsed_Cert;
         P_OK      : Boolean;
      begin
         if Slice_Len < 16 or else Slice_Len > 16384 then
            Result := Bad_Cert_Format;
            return;
         end if;
         for K in 0 .. Slice_Len - 1 loop
            Slice_Buf (1 + K) := All_Certs (Ent.First + K);
         end loop;
         Tls_Core.Cert.Parse (Slice_Buf (1 .. Slice_Len), P, P_OK);
         if not P_OK then
            Result := Bad_Cert_Format;
            return;
         end if;
         --  Translate the parsed indices from Slice's local frame
         --  (Slice'First = 1) back to All_Certs absolute frame.
         --  Cert.Parse Post says every index lies in 1 .. Slice_Len
         --  when OK; after the offset translation each index lies
         --  in Ent.First .. Ent.Last ⊆ All_Certs'Range.
         declare
            Off : constant Integer := Ent.First - 1;
         begin
            P.Tbs_First := P.Tbs_First + Off;
            P.Tbs_Last := P.Tbs_Last + Off;
            P.Spki_First := P.Spki_First + Off;
            P.Spki_Last := P.Spki_Last + Off;
            P.Sig_First := P.Sig_First + Off;
            P.Sig_Last := P.Sig_Last + Off;
            P.Issuer_First := P.Issuer_First + Off;
            P.Issuer_Last := P.Issuer_Last + Off;
            P.Subject_First := P.Subject_First + Off;
            P.Subject_Last := P.Subject_Last + Off;
            if P.San_Present then
               P.San_First := P.San_First + Off;
               P.San_Last := P.San_Last + Off;
            end if;
         end;
         Parsed_Chain (I) := P;
      end;
   end loop;
   Leaf_Parsed := Parsed_Chain (1);

   --  Step 2: verify intra-chain links. Each TBS / Sig / SPKI
   --  region is staged into a 1024-byte fixed buffer (~enough for
   --  4K-RSA SPKIs, ECDSA TBSes are <2K). The variable-bound
   --  slice pattern is rejected by SPARK flow analysis (subtype
   --  constraint with variable input), so we copy + slice with a
   --  static-sized buffer instead.
   if Chain_In.Count >= 2 then
      for I in 1 .. Chain_In.Count - 1 loop
         pragma Loop_Invariant (Chain_In.Count in 1 .. Max_Chain_Depth);
         declare
            Child    : constant Tls_Core.Cert.Parsed_Cert := Parsed_Chain (I);
            Parent   : constant Tls_Core.Cert.Parsed_Cert :=
              Parsed_Chain (I + 1);
            TBS_Buf  : Octet_Array (1 .. 16384) := [others => 0];
            Sig_Buf  : Octet_Array (1 .. 512) := [others => 0];
            Spki_Buf : Octet_Array (1 .. 1024) := [others => 0];
            TBS_Len  : constant Natural :=
              Child.Tbs_Last - Child.Tbs_First + 1;
            Sig_Len  : constant Natural :=
              Child.Sig_Last - Child.Sig_First + 1;
            Spki_Len : constant Natural :=
              Parent.Spki_Last - Parent.Spki_First + 1;
            Link_OK  : Boolean := False;
         begin
            if Child.Sig_Alg = Tls_Core.Cert.Unknown then
               Result := Unsupported_Sig_Alg;
               return;
            end if;
            if TBS_Len not in 1 .. 16384
              or else Sig_Len not in 1 .. 512
              or else Spki_Len not in 16 .. 1024
            then
               Result := Bad_Cert_Format;
               return;
            end if;
            for K in 0 .. TBS_Len - 1 loop
               TBS_Buf (1 + K) := All_Certs (Child.Tbs_First + K);
            end loop;
            for K in 0 .. Sig_Len - 1 loop
               Sig_Buf (1 + K) := All_Certs (Child.Sig_First + K);
            end loop;
            for K in 0 .. Spki_Len - 1 loop
               Spki_Buf (1 + K) := All_Certs (Parent.Spki_First + K);
            end loop;
            Verify_Signed_TBS
              (TBS_Bytes => TBS_Buf (1 .. TBS_Len),
               Sig_Bytes => Sig_Buf (1 .. Sig_Len),
               Sig_Alg   => Child.Sig_Alg,
               Spki_Buf  => Spki_Buf (1 .. Spki_Len),
               OK        => Link_OK);
            if not Link_OK then
               Result := Bad_Signature;
               return;
            end if;
         end;
      end loop;
   end if;

   --  Step 3: terminate against trust store. Top of chain is at
   --  index Chain_In.Count; verify its TBS signature against any
   --  trust-store root's SPKI.
   declare
      Top         : constant Tls_Core.Cert.Parsed_Cert :=
        Parsed_Chain (Chain_In.Count);
      Top_TBS_Buf : Octet_Array (1 .. 16384) := [others => 0];
      Top_Sig_Buf : Octet_Array (1 .. 512) := [others => 0];
      Top_TBS_Len : constant Natural := Top.Tbs_Last - Top.Tbs_First + 1;
      Top_Sig_Len : constant Natural := Top.Sig_Last - Top.Sig_First + 1;
   begin
      if Top.Sig_Alg = Tls_Core.Cert.Unknown then
         Result := Unsupported_Sig_Alg;
         return;
      end if;
      if Top_TBS_Len not in 1 .. 16384 or else Top_Sig_Len not in 1 .. 512 then
         Result := Bad_Cert_Format;
         return;
      end if;
      for K in 0 .. Top_TBS_Len - 1 loop
         Top_TBS_Buf (1 + K) := All_Certs (Top.Tbs_First + K);
      end loop;
      for K in 0 .. Top_Sig_Len - 1 loop
         Top_Sig_Buf (1 + K) := All_Certs (Top.Sig_First + K);
      end loop;
      if Trust.Count = 0 then
         Result := Unknown_CA;
         return;
      end if;
      for J in 1 .. Trust.Count loop
         pragma Loop_Invariant (Trust.Count in 0 .. Max_Trust_Roots);
         declare
            Ent      : constant Trust_Entry := Trust.Entries (J);
            Root_Buf : Octet_Array (1 .. 16384) := [others => 0];
            Root_Len : constant Natural := Ent.Last - Ent.First + 1;
            Root_P   : Tls_Core.Cert.Parsed_Cert;
            Root_OK  : Boolean;
         begin
            if Root_Len in 16 .. 16384 then
               for K in 0 .. Root_Len - 1 loop
                  Root_Buf (1 + K) := All_Certs (Ent.First + K);
               end loop;
               Tls_Core.Cert.Parse (Root_Buf (1 .. Root_Len), Root_P, Root_OK);
               if Root_OK then
                  declare
                     Spki_Buf : Octet_Array (1 .. 1024) := [others => 0];
                     Spki_Len : constant Natural :=
                       Root_P.Spki_Last - Root_P.Spki_First + 1;
                     Link_OK  : Boolean := False;
                  begin
                     if Spki_Len in 16 .. 1024 then
                        for K in 0 .. Spki_Len - 1 loop
                           Spki_Buf (1 + K) :=
                             Root_Buf (Root_P.Spki_First + K);
                        end loop;
                        Verify_Signed_TBS
                          (TBS_Bytes => Top_TBS_Buf (1 .. Top_TBS_Len),
                           Sig_Bytes => Top_Sig_Buf (1 .. Top_Sig_Len),
                           Sig_Alg   => Top.Sig_Alg,
                           Spki_Buf  => Spki_Buf (1 .. Spki_Len),
                           OK        => Link_OK);
                        if Link_OK then
                           Result := OK_Validated;
                           return;
                        end if;
                     end if;
                  end;
               end if;
            end if;
         end;
      end loop;
      Result := Unknown_CA;
   end;
end Validate_Chain;
