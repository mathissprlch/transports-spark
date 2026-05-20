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
     (16#54#,
      16#4C#,
      16#53#,
      16#20#,
      16#31#,
      16#2E#,
      16#33#,
      16#2C#,
      16#20#,
      16#73#,
      16#65#,
      16#72#,
      16#76#,
      16#65#,
      16#72#,
      16#20#,
      16#43#,
      16#65#,
      16#72#,
      16#74#,
      16#69#,
      16#66#,
      16#69#,
      16#63#,
      16#61#,
      16#74#,
      16#65#,
      16#56#,
      16#65#,
      16#72#,
      16#69#,
      16#66#,
      16#79#);
   --  "TLS 1.3, server CertificateVerify"

   Client_Prefix : constant Octet_Array (1 .. 33) :=
     (16#54#,
      16#4C#,
      16#53#,
      16#20#,
      16#31#,
      16#2E#,
      16#33#,
      16#2C#,
      16#20#,
      16#63#,
      16#6C#,
      16#69#,
      16#65#,
      16#6E#,
      16#74#,
      16#20#,
      16#43#,
      16#65#,
      16#72#,
      16#74#,
      16#69#,
      16#66#,
      16#69#,
      16#63#,
      16#61#,
      16#74#,
      16#65#,
      16#56#,
      16#65#,
      16#72#,
      16#69#,
      16#66#,
      16#79#);
   --  "TLS 1.3, client CertificateVerify"

   procedure Put_U16
     (Out_Buf : in out Octet_Array; Cursor : in out Natural; V : Unsigned_16)
   with
     Pre  =>
       Out_Buf'First = 1
       and then Out_Buf'Last < Integer'Last - 16
       and then Cursor <= Out_Buf'Length - 2,
     Post => Cursor = Cursor'Old + 2;
   procedure Put_U16
     (Out_Buf : in out Octet_Array; Cursor : in out Natural; V : Unsigned_16)
   is
   begin
      Out_Buf (Cursor + 1) := Octet (Shift_Right (V, 8) and 16#FF#);
      Out_Buf (Cursor + 2) := Octet (V and 16#FF#);
      Cursor := Cursor + 2;
   end Put_U16;

   procedure Put_U24
     (Out_Buf : in out Octet_Array; Cursor : in out Natural; V : Natural)
   with
     Pre  =>
       Out_Buf'First = 1
       and then V in 0 .. 16#FFFFFF#
       and then Out_Buf'Last < Integer'Last - 16
       and then Cursor <= Out_Buf'Length - 3,
     Post => Cursor = Cursor'Old + 3;
   procedure Put_U24
     (Out_Buf : in out Octet_Array; Cursor : in out Natural; V : Natural) is
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
   is separate;

   procedure Decode_Body_Single
     (Buf        : Octet_Array;
      OK         : out Boolean;
      Cert_First : out Natural;
      Cert_Last  : out Natural)
   is separate;

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
   is separate;

   procedure Build_Signed_Content
     (Side            : Cert_Verify_Side;
      Transcript_Hash : Octet_Array;
      Out_Buf         : out Octet_Array;
      Out_Last        : out Natural)
   is separate;

   ---------------------------------------------------------------------
   --  Encode_Ecdsa_Sig_Der
   ---------------------------------------------------------------------

   --  DER-encode one 32-byte big-endian integer into Out_Buf at
   --  Cursor, advancing Cursor by 3..35 bytes. Lifted out of
   --  Encode_Ecdsa_Sig_Der's nested scope so the per-call Pre/Post
   --  pass to gnatprove without depending on enclosing-variable
   --  invariants.
   procedure Append_Der_Integer
     (Value   : Octet_Array;
      Out_Buf : in out Octet_Array;
      Cursor  : in out Natural)
   with
     Pre  =>
       Value'Length = 32
       and then Value'First = 1
       and then Out_Buf'First = 1
       and then Out_Buf'Last <= Integer'Last - 35
       and then Cursor in 0 .. Out_Buf'Length - 35,
     Post => Cursor in Cursor'Old + 3 .. Cursor'Old + 35;

   procedure Append_Der_Integer
     (Value   : Octet_Array;
      Out_Buf : in out Octet_Array;
      Cursor  : in out Natural)
   is separate;

   procedure Encode_Ecdsa_Sig_Der
     (R, S : Octet_Array; Out_Buf : out Octet_Array; Out_Last : out Natural)
   is separate;

end Tls_Core.Cert_Verify;
