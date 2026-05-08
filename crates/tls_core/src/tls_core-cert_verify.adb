package body Tls_Core.Cert_Verify
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use Interfaces;
   use type Tls_Core.Octet;

   --  RFC 8446 §4.4.3 — fixed prefix bytes for the CertVerify
   --  signed content. 64 spaces, then either the server or client
   --  string, then a single 0x00 separator, then the transcript
   --  hash.
   Server_Prefix : constant Octet_Array (1 .. 33) :=
     (16#54#, 16#4C#, 16#53#, 16#20#, 16#31#, 16#2E#, 16#33#, 16#2C#,
      16#20#, 16#73#, 16#65#, 16#72#, 16#76#, 16#65#, 16#72#, 16#20#,
      16#43#, 16#65#, 16#72#, 16#74#, 16#69#, 16#66#, 16#69#, 16#63#,
      16#61#, 16#74#, 16#65#, 16#56#, 16#65#, 16#72#, 16#69#, 16#66#,
      16#79#);
   --  "TLS 1.3, server CertificateVerify"

   Client_Prefix : constant Octet_Array (1 .. 33) :=
     (16#54#, 16#4C#, 16#53#, 16#20#, 16#31#, 16#2E#, 16#33#, 16#2C#,
      16#20#, 16#63#, 16#6C#, 16#69#, 16#65#, 16#6E#, 16#74#, 16#20#,
      16#43#, 16#65#, 16#72#, 16#74#, 16#69#, 16#66#, 16#69#, 16#63#,
      16#61#, 16#74#, 16#65#, 16#56#, 16#65#, 16#72#, 16#69#, 16#66#,
      16#79#);
   --  "TLS 1.3, client CertificateVerify"

   procedure Put_U16
     (Out_Buf : in out Octet_Array;
      Cursor  : in out Natural;
      V       : Unsigned_16)
   with
     Pre =>
       Out_Buf'First = 1
       and then Out_Buf'Last < Integer'Last - 16
       and then Cursor <= Out_Buf'Length - 2,
     Post => Cursor = Cursor'Old + 2;
   procedure Put_U16
     (Out_Buf : in out Octet_Array;
      Cursor  : in out Natural;
      V       : Unsigned_16)
   is
   begin
      Out_Buf (Cursor + 1) := Octet (Shift_Right (V, 8) and 16#FF#);
      Out_Buf (Cursor + 2) := Octet (V and 16#FF#);
      Cursor := Cursor + 2;
   end Put_U16;

   procedure Put_U24
     (Out_Buf : in out Octet_Array;
      Cursor  : in out Natural;
      V       : Natural)
   with
     Pre =>
       Out_Buf'First = 1
       and then V in 0 .. 16#FFFFFF#
       and then Out_Buf'Last < Integer'Last - 16
       and then Cursor <= Out_Buf'Length - 3,
     Post => Cursor = Cursor'Old + 3;
   procedure Put_U24
     (Out_Buf : in out Octet_Array;
      Cursor  : in out Natural;
      V       : Natural)
   is
   begin
      Out_Buf (Cursor + 1) := Octet ((V / 16#10000#) mod 256);
      Out_Buf (Cursor + 2) := Octet ((V / 16#100#) mod 256);
      Out_Buf (Cursor + 3) := Octet (V mod 256);
      Cursor := Cursor + 3;
   end Put_U24;

   procedure Encode_Body_Single
     (Cert_Data : Octet_Array;
      Out_Buf   : out Octet_Array;
      Out_Last  : out Natural)
   is
      Cursor : Natural := 0;
      Cert_List_Body_Len : constant Natural := 3 + Cert_Data'Length + 2;
   begin
      Out_Buf := (others => 0);
      --  request_context length = 0.
      Out_Buf (Cursor + 1) := 0;
      Cursor := Cursor + 1;
      --  certificate_list u24 length.
      Put_U24 (Out_Buf, Cursor, Cert_List_Body_Len);
      --  cert_data u24 length.
      Put_U24 (Out_Buf, Cursor, Cert_Data'Length);
      --  cert_data bytes.
      for I in 1 .. Cert_Data'Length loop
         Out_Buf (Cursor + I) := Cert_Data (Cert_Data'First + I - 1);
      end loop;
      Cursor := Cursor + Cert_Data'Length;
      --  extensions u16 length = 0.
      Put_U16 (Out_Buf, Cursor, 0);
      Out_Last := Cursor;
   end Encode_Body_Single;

   procedure Decode_Body_Single
     (Buf        : Octet_Array;
      OK         : out Boolean;
      Cert_First : out Natural;
      Cert_Last  : out Natural)
   is
      Cursor : Natural := 0;
   begin
      OK := False;
      Cert_First := 0;
      Cert_Last  := 0;
      if Buf'Length < 1 + 3 + 3 + 1 + 2 then
         return;
      end if;
      --  request_context: must be empty (length byte = 0)
      if Buf (Buf'First) /= 0 then
         return;
      end if;
      Cursor := 1;
      --  certificate_list u24 length
      declare
         List_Len : constant Natural :=
           Natural (Buf (Buf'First + Cursor)) * 16#10000#
           + Natural (Buf (Buf'First + Cursor + 1)) * 16#100#
           + Natural (Buf (Buf'First + Cursor + 2));
      begin
         Cursor := Cursor + 3;
         if 1 + 3 + List_Len /= Buf'Length then
            return;
         end if;
         if List_Len < 3 + 1 + 2 then
            return;
         end if;
         --  Single CertificateEntry: u24 cert_data_len, then bytes,
         --  then u16 extensions_len.
         declare
            Cert_Len : constant Natural :=
              Natural (Buf (Buf'First + Cursor)) * 16#10000#
              + Natural (Buf (Buf'First + Cursor + 1)) * 16#100#
              + Natural (Buf (Buf'First + Cursor + 2));
         begin
            Cursor := Cursor + 3;
            if Cert_Len = 0 then
               return;
            end if;
            if Cursor + Cert_Len + 2 > Buf'Length then
               return;
            end if;
            Cert_First := Buf'First + Cursor;
            Cert_Last  := Buf'First + Cursor + Cert_Len - 1;
            Cursor := Cursor + Cert_Len;
            --  extensions u16 length — we accept zero only.
            declare
               Ext_Len : constant Natural :=
                 Natural (Buf (Buf'First + Cursor)) * 256
                 + Natural (Buf (Buf'First + Cursor + 1));
            begin
               if Ext_Len /= 0 then
                  return;  --  v0.5: no per-cert extensions
               end if;
               Cursor := Cursor + 2;
            end;
            --  Must consume exactly the list_len.  Cursor counts
            --  the 1-byte request_context_len plus the 3-byte
            --  list_len_u24 field plus the list body itself; the
            --  list body alone is List_Len bytes, so Cursor - 4
            --  must equal List_Len.
            if Cursor - 4 /= List_Len then
               return;
            end if;
         end;
      end;
      OK := True;
   end Decode_Body_Single;

   procedure Encode_Body
     (Sig_Scheme : Unsigned_16;
      Signature  : Octet_Array;
      Out_Buf    : out Octet_Array;
      Out_Last   : out Natural)
   is
      Cursor : Natural := 0;
   begin
      Out_Buf := (others => 0);
      Put_U16 (Out_Buf, Cursor, Sig_Scheme);
      Put_U16 (Out_Buf, Cursor, Unsigned_16 (Signature'Length));
      for I in 1 .. Signature'Length loop
         Out_Buf (Cursor + I) := Signature (Signature'First + I - 1);
      end loop;
      Cursor := Cursor + Signature'Length;
      Out_Last := Cursor;
   end Encode_Body;

   procedure Decode_Body
     (Buf        : Octet_Array;
      OK         : out Boolean;
      Sig_Scheme : out Unsigned_16;
      Sig_First  : out Natural;
      Sig_Last   : out Natural)
   is
   begin
      OK := False;
      Sig_Scheme := 0;
      Sig_First := 0;
      Sig_Last  := 0;
      if Buf'Length < 4 then
         return;
      end if;
      Sig_Scheme :=
        Unsigned_16 (Buf (Buf'First)) * 256
        + Unsigned_16 (Buf (Buf'First + 1));
      declare
         Sig_Len : constant Natural :=
           Natural (Buf (Buf'First + 2)) * 256
           + Natural (Buf (Buf'First + 3));
      begin
         if 4 + Sig_Len /= Buf'Length then
            return;
         end if;
         if Sig_Len = 0 then
            return;
         end if;
         Sig_First := Buf'First + 4;
         Sig_Last  := Buf'First + 4 + Sig_Len - 1;
         OK := True;
      end;
   end Decode_Body;

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

   ---------------------------------------------------------------------
   --  Encode_Ecdsa_Sig_Der
   ---------------------------------------------------------------------

   procedure Encode_Ecdsa_Sig_Der
     (R, S     : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   is
      Cursor : Natural := 2;  --  reserve bytes 1..2 for SEQUENCE header

      procedure Append_Integer (Value : Octet_Array)
      with
        Pre =>
          Value'Length = 32
          and then Value'First = 1
          and then Cursor in 2 .. Out_Buf'Length - 35,
        Post =>
          Cursor in Cursor'Old + 3 .. Cursor'Old + 35;

      procedure Append_Integer (Value : Octet_Array) is
         First_Nonzero : Natural := 1;
         Need_Pad      : Boolean;
         Body_Len      : Natural;
      begin
         while First_Nonzero <= 32
           and then Value (First_Nonzero) = 0
         loop
            pragma Loop_Invariant (First_Nonzero in 1 .. 32);
            First_Nonzero := First_Nonzero + 1;
         end loop;
         if First_Nonzero > 32 then
            --  All zeros: emit INTEGER 0x00 (tag + len 1 + 0x00).
            Cursor := Cursor + 1;
            Out_Buf (Cursor) := 16#02#;
            Cursor := Cursor + 1;
            Out_Buf (Cursor) := 16#01#;
            Cursor := Cursor + 1;
            Out_Buf (Cursor) := 16#00#;
            return;
         end if;
         Need_Pad := (Value (First_Nonzero) and 16#80#) /= 0;
         Body_Len :=
           (32 - First_Nonzero + 1) + (if Need_Pad then 1 else 0);
         Cursor := Cursor + 1;
         Out_Buf (Cursor) := 16#02#;
         Cursor := Cursor + 1;
         Out_Buf (Cursor) := Octet (Body_Len);
         if Need_Pad then
            Cursor := Cursor + 1;
            Out_Buf (Cursor) := 16#00#;
         end if;
         for I in First_Nonzero .. 32 loop
            pragma Loop_Invariant
              (I in First_Nonzero .. 32
               and then Cursor < Out_Buf'Length);
            Cursor := Cursor + 1;
            Out_Buf (Cursor) := Value (I);
         end loop;
      end Append_Integer;

   begin
      Out_Buf := (others => 0);
      Cursor := 2;
      Append_Integer (R);
      Append_Integer (S);
      Out_Buf (1) := 16#30#;
      --  SEQUENCE body length = total - 2-byte header. Cursor - 2
      --  is bounded by 70 (worst case 35 + 35), well under 0x7F so a
      --  single-byte short-form length suffices.
      Out_Buf (2) := Octet (Cursor - 2);
      Out_Last := Cursor;
   end Encode_Ecdsa_Sig_Der;

end Tls_Core.Cert_Verify;
