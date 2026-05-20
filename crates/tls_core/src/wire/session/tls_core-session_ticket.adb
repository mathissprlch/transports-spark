with Tls_Core.Hkdf;
with Tls_Core.Hkdf_Sha256;

package body Tls_Core.Session_Ticket
  with SPARK_Mode
is


   ---------------------------------------------------------------------
   --  HKDF-Expand-Label, SHA-256-pinned. Same instantiation pattern
   --  used by Tls_Core.Tls13_Driver and Tls_Core.Key_Update.
   ---------------------------------------------------------------------

   procedure Hkdf_Expand_Label_Sha256 is new
     Tls_Core.Hkdf.Expand_Label
       (Hash_Length      => Tls_Core.Sha256.Hash_Length,
        Max_Info         => 512,
        Spec_Hmac_Expand => Tls_Core.Hkdf_Sha256.Spec_HKDF_Expand,
        Hmac_Expand      => Tls_Core.Hkdf_Sha256.Hmac_Expand);

   ---------------------------------------------------------------------
   --  Encode_Body — RFC 8446 §4.6.1 wire packing.
   ---------------------------------------------------------------------

   procedure Encode_Body
     (Lifetime     : U32;
      Age_Add      : U32;
      Ticket_Nonce : Octet_Array;
      Ticket       : Octet_Array;
      Out_Buf      : out Octet_Array;
      Out_Last     : out Natural)
   is
      P : Natural := 0;
   begin
      Out_Buf := [others => 0];

      --  uint32 ticket_lifetime (BE).
      Out_Buf (1) := Octet ((Lifetime / 2**24) mod 256);
      Out_Buf (2) := Octet ((Lifetime / 2**16) mod 256);
      Out_Buf (3) := Octet ((Lifetime / 2**8) mod 256);
      Out_Buf (4) := Octet (Lifetime mod 256);

      --  uint32 ticket_age_add (BE).
      Out_Buf (5) := Octet ((Age_Add / 2**24) mod 256);
      Out_Buf (6) := Octet ((Age_Add / 2**16) mod 256);
      Out_Buf (7) := Octet ((Age_Add / 2**8) mod 256);
      Out_Buf (8) := Octet (Age_Add mod 256);

      P := 8;

      --  opaque ticket_nonce<0..255>: 1-byte length + bytes.
      Out_Buf (P + 1) := Octet (Ticket_Nonce'Length);
      P := P + 1;
      if Ticket_Nonce'Length > 0 then
         Out_Buf (P + 1 .. P + Ticket_Nonce'Length) := Ticket_Nonce;
         P := P + Ticket_Nonce'Length;
      end if;

      --  opaque ticket<1..2^16-1>: 2-byte length + bytes.
      Out_Buf (P + 1) := Octet ((Ticket'Length / 256) mod 256);
      Out_Buf (P + 2) := Octet (Ticket'Length mod 256);
      P := P + 2;
      Out_Buf (P + 1 .. P + Ticket'Length) := Ticket;
      P := P + Ticket'Length;

      --  Extension extensions<0..2^16-2>: empty list (v0.5 — no
      --  early_data extension; see package comment).
      Out_Buf (P + 1) := 0;
      Out_Buf (P + 2) := 0;
      P := P + 2;

      Out_Last := P;
   end Encode_Body;

   ---------------------------------------------------------------------
   --  Decode_Body — RFC 8446 §4.6.1 wire parsing.
   --
   --  Layout (per RFC):
   --
   --    bytes 1..4    : ticket_lifetime (u32 BE)
   --    bytes 5..8    : ticket_age_add  (u32 BE)
   --    byte  9       : nonce_length    (u8)
   --    bytes ..      : ticket_nonce    (nonce_length bytes)
   --    bytes ..      : ticket_length   (u16 BE)
   --    bytes ..      : ticket          (ticket_length bytes)
   --    bytes ..      : extensions_len  (u16 BE)
   --    bytes ..      : extensions      (extensions_len bytes)
   ---------------------------------------------------------------------

   procedure Decode_Body
     (In_Buf       : Octet_Array;
      Lifetime     : out U32;
      Age_Add      : out U32;
      Nonce_First  : out Natural;
      Nonce_Last   : out Integer;
      Ticket_First : out Natural;
      Ticket_Last  : out Integer;
      OK           : out Boolean)
   is
      P  : Natural;
      Nl : Natural;  --  nonce length
      Tl : Natural;  --  ticket length
      El : Natural;  --  extensions length
   begin
      Lifetime := 0;
      Age_Add := 0;
      Nonce_First := In_Buf'First;
      Nonce_Last := In_Buf'First - 1;
      Ticket_First := In_Buf'First;
      Ticket_Last := In_Buf'First;
      OK := False;

      --  Need at least 4 + 4 + 1 + 0 + 2 + 1 + 2 = 14 bytes.
      if In_Buf'Length < 14 then
         return;
      end if;

      Lifetime :=
        U32 (In_Buf (In_Buf'First))
        * 2**24
        + U32 (In_Buf (In_Buf'First + 1)) * 2**16
        + U32 (In_Buf (In_Buf'First + 2)) * 2**8
        + U32 (In_Buf (In_Buf'First + 3));

      Age_Add :=
        U32 (In_Buf (In_Buf'First + 4))
        * 2**24
        + U32 (In_Buf (In_Buf'First + 5)) * 2**16
        + U32 (In_Buf (In_Buf'First + 6)) * 2**8
        + U32 (In_Buf (In_Buf'First + 7));

      P := In_Buf'First + 8;  --  start of nonce-length octet

      Nl := Natural (In_Buf (P));
      if Nl > Max_Ticket_Nonce_Length then
         return;
      end if;
      --  After the nonce-length byte we need at least Nl bytes of
      --  nonce + 2 bytes of ticket-length + 1 byte of ticket + 2
      --  bytes of extensions-length = Nl + 5.
      if P > In_Buf'Last - (Nl + 5) then
         return;
      end if;

      if Nl = 0 then
         Nonce_First := P + 1;     --  empty range encoded as F..F-1
         Nonce_Last := P;
      else
         Nonce_First := P + 1;
         Nonce_Last := P + Nl;
      end if;
      P := P + 1 + Nl;

      Tl := Natural (In_Buf (P)) * 256 + Natural (In_Buf (P + 1));
      if Tl < 1 or else Tl > Max_Ticket_Length then
         return;
      end if;
      --  After the 2-byte ticket-length we need Tl bytes of ticket
      --  + 2 bytes of extensions-length = Tl + 2.
      if P + 1 > In_Buf'Last - (Tl + 2) then
         return;
      end if;

      Ticket_First := P + 2;
      Ticket_Last := P + 1 + Tl;
      P := P + 2 + Tl;

      El := Natural (In_Buf (P)) * 256 + Natural (In_Buf (P + 1));
      if El > Max_Nst_Extensions_Length then
         return;
      end if;
      --  Extensions block must consume the remainder exactly.
      if P + 1 + El /= In_Buf'Last then
         return;
      end if;

      OK := True;
   end Decode_Body;

   ---------------------------------------------------------------------
   --  Derive_Resumption_Master_Secret_Sha256 — RFC 8446 §7.1.
   --
   --  resumption_master_secret =
   --      Derive-Secret(Master_Secret, "res master",
   --                    ClientHello..client Finished)
   --
   --  Derive-Secret(Secret, Label, Messages) =
   --      HKDF-Expand-Label(Secret, Label, Hash(Messages), Hash.length)
   --
   --  Caller passes in the SHA-256 transcript-hash directly (cheaper
   --  than rehashing the whole CH..CF byte stream), matching the
   --  Hkdf_Expand_Label call shape.
   ---------------------------------------------------------------------

   procedure Derive_Resumption_Master_Secret_Sha256
     (Master_Secret     : Tls_Core.Key_Schedule.Secret;
      Transcript_Hash   : Tls_Core.Sha256.Digest;
      Resumption_Secret : out Tls_Core.Key_Schedule.Secret) is
   begin
      Hkdf_Expand_Label_Sha256
        (Secret  => Master_Secret,
         Label   => Res_Master_Label,
         Context => Transcript_Hash,
         Output  => Resumption_Secret);
   end Derive_Resumption_Master_Secret_Sha256;

   ---------------------------------------------------------------------
   --  Derive_Psk_From_Ticket_Sha256 — RFC 8446 §4.6.1.
   ---------------------------------------------------------------------

   procedure Derive_Psk_From_Ticket_Sha256
     (Resumption_Secret : Tls_Core.Key_Schedule.Secret;
      Ticket_Nonce      : Octet_Array;
      Psk               : out Tls_Core.Key_Schedule.Secret) is
   begin
      Hkdf_Expand_Label_Sha256
        (Secret  => Resumption_Secret,
         Label   => Resumption_Label,
         Context => Ticket_Nonce,
         Output  => Psk);
   end Derive_Psk_From_Ticket_Sha256;

end Tls_Core.Session_Ticket;
