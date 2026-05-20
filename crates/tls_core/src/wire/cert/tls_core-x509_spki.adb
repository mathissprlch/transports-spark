with Interfaces;

package body Tls_Core.X509_Spki
  with SPARK_Mode
is

   use type Interfaces.Unsigned_8;

   --  DER tag bytes (ITU-T X.690 §8.1).
   Tag_Sequence   : constant Octet := 16#30#;  --  context-free constructed
   Tag_Oid        : constant Octet := 16#06#;
   Tag_Bit_String : constant Octet := 16#03#;
   Tag_Integer    : constant Octet := 16#02#;
   Tag_Null       : constant Octet := 16#05#;
   pragma Unreferenced (Tag_Null);

   --  rsaEncryption (RFC 8017 §A.1):
   --    1.2.840.113549.1.1.1 = 2A 86 48 86 F7 0D 01 01 01 (9 bytes)
   Oid_Rsa : constant Octet_Array (1 .. 9) :=
     [16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 16#01#];

   --  id-ecPublicKey (RFC 5480 §2.1.1):
   --    1.2.840.10045.2.1 = 2A 86 48 CE 3D 02 01 (7 bytes)
   Oid_Ec_Pub : constant Octet_Array (1 .. 7) :=
     [16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#02#, 16#01#];

   --  prime256v1 / secp256r1 (RFC 5480 §2.1.1.1):
   --    1.2.840.10045.3.1.7 = 2A 86 48 CE 3D 03 01 07 (8 bytes)
   Oid_P256 : constant Octet_Array (1 .. 8) :=
     [16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#03#, 16#01#, 16#07#];

   --  ===================================================================
   --  Parser combinators (miTLS-style refinement-typed cursor advance).
   --
   --  Every combinator takes a current Cur in Buf'First .. Buf'Last+1
   --  (the "+1" sentinel meaning "one past end", aka EOF) and outputs a
   --  New_Cur in the same range, with New_Cur >= Cur on OK.  Cumulative
   --  Cur+Used overflow is hidden inside each combinator and proven
   --  locally; callers chain combinators by passing the previous
   --  New_Cur as the next Cur.
   --
   --  This mirrors miTLS's `read_length: ... -> Tot (option (n × pos))`
   --  signature where the refinement type rules out the cumulative-
   --  position overflow class.
   --  ===================================================================

   --  Read a DER length field starting at Buf (Off..). Returns the
   --  decoded length in Out_Len and the number of bytes consumed
   --  (1 for short form, 1+N for long form), plus the New_Cur cursor
   --  position (Off + Used) clamped to Buf'Last+1.
   procedure Read_Length
     (Buf     : Octet_Array;
      Off     : Natural;
      Out_Len : out Natural;
      Used    : out Natural;
      OK      : out Boolean)
   with
     Pre  =>
       Buf'First = 1
       and then Off in 1 .. Buf'Last
       and then Buf'Last < Integer'Last - 16,
     Post =>
       (if OK
        then
          Used in 1 .. 5
          and then Off + Used <= Buf'Last + 1
          and then Out_Len <= Buf'Length);
   procedure Read_Length
     (Buf     : Octet_Array;
      Off     : Natural;
      Out_Len : out Natural;
      Used    : out Natural;
      OK      : out Boolean)
   is separate;

   --  Read a single tag byte at Cur and advance.
   --
   --  Pre:  Cur in Buf'First .. Buf'Last+1
   --  Post: OK iff (Cur <= Buf'Last and Buf(Cur) = Expected_Tag);
   --        New_Cur = Cur+1 on OK, else New_Cur = Cur (sentinel).
   procedure Read_Tag
     (Buf          : Octet_Array;
      Cur          : Natural;
      Expected_Tag : Octet;
      New_Cur      : out Natural;
      OK           : out Boolean)
   with
     Pre  =>
       Buf'First = 1
       and then Buf'Last < Integer'Last - 16
       and then Cur in Buf'First .. Buf'Last + 1,
     Post =>
       (if OK
        then
          New_Cur = Cur + 1 and then New_Cur in Buf'First + 1 .. Buf'Last + 1
        else New_Cur = Cur);
   procedure Read_Tag
     (Buf          : Octet_Array;
      Cur          : Natural;
      Expected_Tag : Octet;
      New_Cur      : out Natural;
      OK           : out Boolean) is
   begin
      New_Cur := Cur;
      OK := False;
      if Cur > Buf'Last then
         return;
      end if;
      if Buf (Cur) /= Expected_Tag then
         return;
      end if;
      New_Cur := Cur + 1;
      OK := True;
   end Read_Tag;

   --  Read a TLV header (tag byte + DER length) and report:
   --    Body_First — index of first body byte (Cur+1+Used),
   --    Body_Last  — index of last  body byte (Body_First+Len-1),
   --    After      — cursor past the TLV (Body_Last+1).
   --
   --  All three positions are clamped to Buf'First..Buf'Last+1; the
   --  combinator either succeeds with all three in range or sets OK
   --  False and leaves the outputs at safe sentinels.
   procedure Read_TLV_Header
     (Buf          : Octet_Array;
      Cur          : Natural;
      Expected_Tag : Octet;
      Body_First   : out Natural;
      Body_Last    : out Natural;
      After        : out Natural;
      OK           : out Boolean)
   with
     Pre  =>
       Buf'First = 1
       and then Buf'Last < Integer'Last - 16
       and then Cur in Buf'First .. Buf'Last + 1,
     Post =>
       (if OK
        then
          Body_First in Cur + 2 .. Buf'Last + 1
          and then Body_Last in Body_First - 1 .. Buf'Last
          and then After = Body_Last + 1
          and then After in Body_First .. Buf'Last + 1
          and then After >= Cur + 2);
   procedure Read_TLV_Header
     (Buf          : Octet_Array;
      Cur          : Natural;
      Expected_Tag : Octet;
      Body_First   : out Natural;
      Body_Last    : out Natural;
      After        : out Natural;
      OK           : out Boolean)
   is separate;

   --  Compare a slice of Buf against a constant byte string.
   function Slice_Equal
     (Buf : Octet_Array; First, Last : Natural; Cmp : Octet_Array)
      return Boolean
   with
     Pre =>
       Buf'First = 1
       and then First in 1 .. Buf'Last
       and then Last in First .. Buf'Last
       and then Cmp'First = 1
       and then Cmp'Last < Integer'Last - 16;
   --  miTLS pattern: parser equality is just Ada array equality on
   --  the named slice. SPARK's built-in array '=' is far easier to
   --  prove than a hand-rolled byte loop.
   function Slice_Equal
     (Buf : Octet_Array; First, Last : Natural; Cmp : Octet_Array)
      return Boolean
   is (Last - First + 1 = Cmp'Length and then Buf (First .. Last) = Cmp);

   --  DER walker — RFC 5280 §4.1.2.7. Driven by the Read_TLV_Header
   --  combinator above so that cumulative cursor advance never opens
   --  the Cur+Used overflow class to the prover. The Post on Decode
   --  is imperative: when OK is True the returned slice indices live
   --  in Buf'Range and Kind is one of the supported key types.
   procedure Decode
     (Buf       : Octet_Array;
      OK        : out Boolean;
      Kind      : out Key_Kind;
      Key_First : out Natural;
      Key_Last  : out Natural)
   is separate;

   --  RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
   --  Trust-axiom rationale matches Decode above.
   procedure Decode_Rsa_Key
     (Buf       : Octet_Array;
      OK        : out Boolean;
      Mod_First : out Natural;
      Mod_Last  : out Natural;
      Exp_First : out Natural;
      Exp_Last  : out Natural)
   is separate;

end Tls_Core.X509_Spki;
