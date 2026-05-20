with Interfaces;

package body Tls_Core.X509_Spki
with SPARK_Mode
is

   use type Interfaces.Unsigned_8;
   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

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
     (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#,
      16#01#);

   --  id-ecPublicKey (RFC 5480 §2.1.1):
   --    1.2.840.10045.2.1 = 2A 86 48 CE 3D 02 01 (7 bytes)
   Oid_Ec_Pub : constant Octet_Array (1 .. 7) :=
     (16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#02#, 16#01#);

   --  prime256v1 / secp256r1 (RFC 5480 §2.1.1.1):
   --    1.2.840.10045.3.1.7 = 2A 86 48 CE 3D 03 01 07 (8 bytes)
   Oid_P256 : constant Octet_Array (1 .. 8) :=
     (16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#03#, 16#01#, 16#07#);

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
     (Buf      : Octet_Array;
      Off      : Natural;
      Out_Len  : out Natural;
      Used     : out Natural;
      OK       : out Boolean)
   with
     Pre  => Buf'First = 1
             and then Off in 1 .. Buf'Last
             and then Buf'Last < Integer'Last - 16,
     Post => (if OK then
                 Used in 1 .. 5
                 and then Off + Used <= Buf'Last + 1
                 and then Out_Len <= Buf'Length);
   procedure Read_Length
     (Buf      : Octet_Array;
      Off      : Natural;
      Out_Len  : out Natural;
      Used     : out Natural;
      OK       : out Boolean)
   is
      B0 : constant Octet := Buf (Off);
   begin
      Out_Len := 0;
      Used    := 0;
      OK      := False;
      if B0 < 16#80# then
         if Natural (B0) > Buf'Length then
            return;  --  short-form length exceeds buffer; reject.
         end if;
         Out_Len := Natural (B0);
         Used    := 1;
         OK      := True;
         return;
      end if;
      declare
         N : constant Natural := Natural (B0) - 16#80#;
         Acc : Natural := 0;
      begin
         if N = 0 or else N > 4 then
            return;  --  indefinite-length (0) and absurd (>4) are
                     --  not supported in DER profiles.
         end if;
         if Off + N > Buf'Last then
            return;
         end if;
         for I in 1 .. N loop
            if Acc > Natural'Last / 256 then
               return;
            end if;
            pragma Assert (Acc <= Natural'Last / 256);
            Acc := Acc * 256 + Natural (Buf (Off + I));
         end loop;
         --  Final clamp to Buf'Length: the encoded length must fit
         --  within the buffer for the parser to be useful.
         if Acc > Buf'Length then
            return;
         end if;
         Out_Len := Acc;
         Used    := 1 + N;
         OK      := True;
      end;
   end Read_Length;

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
     Pre  => Buf'First = 1
             and then Buf'Last < Integer'Last - 16
             and then Cur in Buf'First .. Buf'Last + 1,
     Post => (if OK then
                 New_Cur = Cur + 1
                 and then New_Cur in Buf'First + 1 .. Buf'Last + 1
              else
                 New_Cur = Cur);
   procedure Read_Tag
     (Buf          : Octet_Array;
      Cur          : Natural;
      Expected_Tag : Octet;
      New_Cur      : out Natural;
      OK           : out Boolean)
   is
   begin
      New_Cur := Cur;
      OK      := False;
      if Cur > Buf'Last then
         return;
      end if;
      if Buf (Cur) /= Expected_Tag then
         return;
      end if;
      New_Cur := Cur + 1;
      OK      := True;
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
     Pre  => Buf'First = 1
             and then Buf'Last < Integer'Last - 16
             and then Cur in Buf'First .. Buf'Last + 1,
     Post => (if OK then
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
   is
      Tag_Cur : Natural;
      Tag_OK  : Boolean;
      Len     : Natural;
      Used    : Natural;
      Len_OK  : Boolean;
   begin
      Body_First := Cur;
      Body_Last  := Cur;
      After      := Cur;
      OK         := False;

      Read_Tag (Buf, Cur, Expected_Tag, Tag_Cur, Tag_OK);
      if not Tag_OK then
         return;
      end if;
      --  Tag_Cur = Cur + 1, in Buf'First+1 .. Buf'Last+1
      if Tag_Cur > Buf'Last then
         return;
      end if;
      --  Tag_Cur in 1 .. Buf'Last
      Read_Length (Buf, Tag_Cur, Len, Used, Len_OK);
      if not Len_OK then
         return;
      end if;
      --  Read_Length post: Used in 1..5, Tag_Cur+Used <= Buf'Last+1,
      --  Len <= Buf'Length.
      pragma Assert (Tag_Cur + Used <= Buf'Last + 1);
      pragma Assert (Len <= Buf'Length);

      declare
         BF : constant Natural := Tag_Cur + Used;
         --  BF in Tag_Cur+1 .. Buf'Last+1
         --     = Cur+2     .. Buf'Last+1
      begin
         pragma Assert (BF in Cur + 2 .. Buf'Last + 1);
         --  Need: BF + Len - 1 <= Buf'Last and BF + Len <= Buf'Last+1
         --  We have BF <= Buf'Last+1 and Len <= Buf'Length =
         --  Buf'Last - Buf'First + 1 = Buf'Last (since Buf'First=1).
         --  But that's not enough — need BF + Len - 1 <= Buf'Last.
         --  Read_Length only constrains Len <= Buf'Length, not the
         --  cumulative position.  So we have to range-check here.
         if Len > Buf'Last - BF + 1 then
            --  Body would run past end of buffer.
            return;
         end if;
         --  Now BF + Len <= Buf'Last + 1, all positions safe.
         pragma Assert (BF + Len <= Buf'Last + 1);
         Body_First := BF;
         if Len = 0 then
            Body_Last := BF - 1;  --  empty body convention
            After     := BF;
         else
            Body_Last := BF + Len - 1;
            After     := BF + Len;
         end if;
         OK := True;
      end;
   end Read_TLV_Header;

   --  Compare a slice of Buf against a constant byte string.
   function Slice_Equal
     (Buf : Octet_Array; First, Last : Natural; Cmp : Octet_Array)
      return Boolean
   with Pre => Buf'First = 1
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
   is (Last - First + 1 = Cmp'Length
       and then Buf (First .. Last) = Cmp);

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
   is
      Step_OK : Boolean;

      --  Outer SubjectPublicKeyInfo SEQUENCE.  We only consume the
      --  body-first cursor (header has been parsed away); body-last
      --  and after-cursor are unused but Read_TLV_Header signature
      --  keeps them named for symmetry.
      Outer_BF : Natural;
      Outer_BL : Natural;
      Outer_AF : Natural;

      --  Algorithm SEQUENCE (lives inside outer body)
      Alg_BF : Natural;
      Alg_BL : Natural;  --  also "Alg_End": last byte of algorithm body
      Alg_AF : Natural;  --  cursor where the BIT STRING starts

      --  Algorithm OID
      Oid_BF : Natural;
      Oid_BL : Natural;
      Oid_AF : Natural;

      --  BIT STRING (lives at Alg_AF inside outer body)
      Bs_BF : Natural;
      Bs_BL : Natural;
      Bs_AF : Natural;
   begin
      OK := False;
      Kind := Unknown;
      Key_First := 0;
      Key_Last  := 0;

      --  SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }
      Read_TLV_Header
        (Buf, Buf'First, Tag_Sequence,
         Outer_BF, Outer_BL, Outer_AF, Step_OK);
      if not Step_OK then
         return;
      end if;
      --  Outer_BF in Buf'First+2 .. Buf'Last+1 (cursor past header)

      --  AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters }
      Read_TLV_Header
        (Buf, Outer_BF, Tag_Sequence,
         Alg_BF, Alg_BL, Alg_AF, Step_OK);
      if not Step_OK then
         return;
      end if;
      --  Alg_BF .. Alg_BL is the algorithm-id body; Alg_AF is the
      --  cursor past it (i.e., where the BIT STRING starts).

      --  algorithm OID
      Read_TLV_Header
        (Buf, Alg_BF, Tag_Oid,
         Oid_BF, Oid_BL, Oid_AF, Step_OK);
      if not Step_OK then
         return;
      end if;
      --  Oid_BL must lie within the algorithm body.
      if Oid_BL > Alg_BL then
         return;
      end if;

      if Oid_BF <= Oid_BL
        and then Slice_Equal (Buf, Oid_BF, Oid_BL, Oid_Rsa)
      then
         Kind := Rsa;
         --  No need to inspect parameters; RFC 8017 says NULL.
      elsif Oid_BF <= Oid_BL
        and then Slice_Equal (Buf, Oid_BF, Oid_BL, Oid_Ec_Pub)
      then
         --  Need parameters carrying the prime256v1 OID.
         declare
            Params_Cur : constant Natural := Oid_AF;
            Curve_BF : Natural;
            Curve_BL : Natural;
            Curve_AF : Natural;
            Sub_OK : Boolean;
         begin
            if Params_Cur > Alg_BL then
               --  Parameters absent — required for ecPublicKey.
               return;
            end if;
            --  Params_Cur in 1 .. Alg_BL <= Buf'Last so it's a valid
            --  cursor for Read_TLV_Header.
            pragma Assert (Params_Cur in Buf'First .. Buf'Last + 1);
            Read_TLV_Header
              (Buf, Params_Cur, Tag_Oid,
               Curve_BF, Curve_BL, Curve_AF, Sub_OK);
            if not Sub_OK then
               return;
            end if;
            if Curve_BL > Alg_BL then
               return;
            end if;
            if Curve_BF <= Curve_BL
              and then Slice_Equal
                         (Buf, Curve_BF, Curve_BL, Oid_P256)
            then
               Kind := Ecdsa_P256;
            else
               return;
            end if;
         end;
      else
         return;
      end if;

      --  subjectPublicKey BIT STRING — lives at cursor Alg_AF.
      Read_TLV_Header
        (Buf, Alg_AF, Tag_Bit_String,
         Bs_BF, Bs_BL, Bs_AF, Step_OK);
      if not Step_OK then
         OK := False;
         Kind := Unknown;
         return;
      end if;
      --  Need at least one byte of content (the unused-bits header).
      if Bs_BF > Bs_BL then
         OK := False;
         Kind := Unknown;
         return;
      end if;
      --  Bs_BF in 1..Buf'Last by Read_TLV_Header post + Bs_BF<=Bs_BL.
      pragma Assert (Bs_BF in Buf'First .. Buf'Last);
      if Buf (Bs_BF) /= 0 then
         OK := False;
         Kind := Unknown;
         return;
      end if;
      --  Key contents follow the unused-bits byte.
      if Bs_BF >= Bs_BL then
         --  empty key body — degenerate; reject.
         OK := False;
         Kind := Unknown;
         return;
      end if;
      --  Bs_BF < Bs_BL <= Buf'Last, so Bs_BF + 1 <= Bs_BL is a valid
      --  index in Buf'Range. Key_First <= Key_Last.
      Key_First := Bs_BF + 1;
      Key_Last  := Bs_BL;
      OK := True;
   end Decode;

   --  RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
   --  Trust-axiom rationale matches Decode above.
   procedure Decode_Rsa_Key
     (Buf       : Octet_Array;
      OK        : out Boolean;
      Mod_First : out Natural;
      Mod_Last  : out Natural;
      Exp_First : out Natural;
      Exp_Last  : out Natural)
   is
      Step_OK : Boolean;

      --  Outer RSAPublicKey SEQUENCE
      Outer_BF : Natural;
      Outer_BL : Natural;
      Outer_AF : Natural;

      --  modulus INTEGER
      Mod_BF : Natural;
      Mod_BL : Natural;
      Mod_AF : Natural;

      --  publicExponent INTEGER
      Exp_BF : Natural;
      Exp_BL : Natural;
      Exp_AF : Natural;
   begin
      OK := False;
      Mod_First := 0;
      Mod_Last  := 0;
      Exp_First := 0;
      Exp_Last  := 0;

      --  RSAPublicKey ::= SEQUENCE
      Read_TLV_Header
        (Buf, Buf'First, Tag_Sequence,
         Outer_BF, Outer_BL, Outer_AF, Step_OK);
      if not Step_OK then
         return;
      end if;

      --  modulus INTEGER (must lie inside outer body)
      Read_TLV_Header
        (Buf, Outer_BF, Tag_Integer,
         Mod_BF, Mod_BL, Mod_AF, Step_OK);
      if not Step_OK then
         return;
      end if;
      if Mod_BL > Outer_BL or else Mod_BF > Mod_BL then
         return;
      end if;

      --  publicExponent INTEGER (must follow modulus inside outer body)
      Read_TLV_Header
        (Buf, Mod_AF, Tag_Integer,
         Exp_BF, Exp_BL, Exp_AF, Step_OK);
      if not Step_OK then
         return;
      end if;
      if Exp_BL > Outer_BL or else Exp_BF > Exp_BL then
         return;
      end if;

      --  DER INTEGER values for X.509 are big-endian, possibly with
      --  a leading 0x00 sign byte to disambiguate from negative.
      --  Caller is responsible for stripping that if it cares.
      Mod_First := Mod_BF;
      Mod_Last  := Mod_BL;
      Exp_First := Exp_BF;
      Exp_Last  := Exp_BL;
      OK := True;
   end Decode_Rsa_Key;

end Tls_Core.X509_Spki;
