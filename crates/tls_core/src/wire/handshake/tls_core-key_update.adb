with Tls_Core.Hkdf;
with Tls_Core.Hkdf_Sha256;
with Tls_Core.Hkdf_Label_Sha384;

package body Tls_Core.Key_Update
  with SPARK_Mode
is


   --  Wrap the SHA-256 Expand_Label here (matches the pattern in
   --  Tls_Core.Traffic_Keys). For SHA-384 we re-use the existing
   --  Tls_Core.Hkdf_Label_Sha384.Expand_Label instance.
   procedure Hkdf_Expand_Label_Sha256 is new
     Tls_Core.Hkdf.Expand_Label
       (Hash_Length      => 32,
        Max_Info         => 512,
        Spec_Hmac_Expand => Tls_Core.Hkdf_Sha256.Spec_HKDF_Expand,
        Hmac_Expand      => Tls_Core.Hkdf_Sha256.Hmac_Expand);

   --  RFC 8446 §7.2 / §7.1: the bytes of the literal label string
   --  "traffic upd" (no Tls13_Prefix — Hkdf.Expand_Label adds it).
   Traffic_Upd_Label : constant Octet_Array (1 .. 11) :=
     [Character'Pos ('t'),
      Character'Pos ('r'),
      Character'Pos ('a'),
      Character'Pos ('f'),
      Character'Pos ('f'),
      Character'Pos ('i'),
      Character'Pos ('c'),
      Character'Pos (' '),
      Character'Pos ('u'),
      Character'Pos ('p'),
      Character'Pos ('d')];

   Empty_Ctx : constant Octet_Array (1 .. 0) := [others => 0];

   ---------------------------------------------------------------------
   --  Encode
   ---------------------------------------------------------------------

   procedure Encode
     (Request_Update : Octet;
      Out_Buf        : out Octet_Array;
      Out_Last       : out Natural) is
   begin
      Out_Buf := [others => 0];
      Out_Buf (1) := Hs_Type_Key_Update;   --  msg_type = 0x18
      Out_Buf (2) := 0;                    --  u24 length high
      Out_Buf (3) := 0;
      Out_Buf (4) := 1;                    --  u24 length low (= 1)
      Out_Buf (5) := Request_Update;
      Out_Last := Wire_Size;
   end Encode;

   ---------------------------------------------------------------------
   --  Decode
   ---------------------------------------------------------------------

   procedure Decode
     (In_Buf : Octet_Array; Request_Update : out Octet; OK : out Boolean) is
   begin
      Request_Update := 0;
      OK := False;
      if In_Buf'Length /= Wire_Size then
         return;
      end if;
      if In_Buf (In_Buf'First) /= Hs_Type_Key_Update
        or else In_Buf (In_Buf'First + 1) /= 0
        or else In_Buf (In_Buf'First + 2) /= 0
        or else In_Buf (In_Buf'First + 3) /= 1
      then
         return;
      end if;
      declare
         Payload : constant Octet := In_Buf (In_Buf'First + 4);
      begin
         if Payload /= Update_Not_Requested
           and then Payload /= Update_Requested
         then
            return;
         end if;
         Request_Update := Payload;
         OK := True;
      end;
   end Decode;

   ---------------------------------------------------------------------
   --  Derive_Next_Sha256
   ---------------------------------------------------------------------

   procedure Derive_Next_Sha256
     (Current : Tls_Core.Key_Schedule.Secret;
      Next    : out Tls_Core.Key_Schedule.Secret) is
   begin
      Hkdf_Expand_Label_Sha256
        (Secret  => Current,
         Label   => Traffic_Upd_Label,
         Context => Empty_Ctx,
         Output  => Next);
   end Derive_Next_Sha256;

   ---------------------------------------------------------------------
   --  Derive_Next_Sha384
   ---------------------------------------------------------------------

   procedure Derive_Next_Sha384
     (Current : Tls_Core.Key_Schedule_Sha384.Secret;
      Next    : out Tls_Core.Key_Schedule_Sha384.Secret) is
   begin
      Tls_Core.Hkdf_Label_Sha384.Expand_Label
        (Secret  => Current,
         Label   => Traffic_Upd_Label,
         Context => Empty_Ctx,
         Output  => Next);
   end Derive_Next_Sha384;

end Tls_Core.Key_Update;
