--  Tls_Core.Hkdf — RFC 8446 §7.1 HKDF-Expand-Label.
--
--  Source: RFC 8446 §7.1 (Key Schedule).
--
--      HKDF-Expand-Label(Secret, Label, Context, Length) =
--          HKDF-Expand(Secret, HkdfLabel, Length)
--
--      struct {
--          uint16 length = Length;
--          opaque label<7..255>   = "tls13 " + Label;
--          opaque context<0..255> = Context;
--      } HkdfLabel;
--
--  miTLS reference (project-everest/mitls-fstar):
--    src/parsers/MiTLS.Parsers.HKDF.rfc          (TLS-PL HkdfLabel)
--    src/tls/MiTLS.HKDF.fst                      (`format`,
--                                                  `expand_label`)
--
--  miTLS proves nothing beyond memory-safety on `expand_label`
--  itself; the functional postcondition rides on
--  `EverCrypt.HKDF.expand` (HACL\*) which provides
--  `t == expand_spec prk info len`. Our split is the same:
--
--    * `Build_Info_Bytes` (this package) carries the
--      §7.1-encoding postcondition, refining the miTLS
--      `assume length tls13_prefix = 6` into a discharged Ada
--      lemma and the `assume length label_bytes >= 7` into a
--      precondition derived from `Label'Length >= 1`.
--    * `Hmac_Expand` is a generic formal whose contracts mirror
--      the `expand_spec` axiom HACL\* discharges in F\*; once we
--      have a SPARK HMAC-SHA-256, we instantiate against it.
--
--  See ../docs/v0.5-tls-plan.md for the slicing rationale.


package Tls_Core.Hkdf
with SPARK_Mode
is

   use type Tls_Core.Octet;
   use type Interfaces.Unsigned_16;

   --  The literal six-byte ASCII prefix per RFC 8446 §7.1.
   Tls13_Prefix : constant Octet_Array (1 .. 6) :=
     (Character'Pos ('t'), Character'Pos ('l'),
      Character'Pos ('s'), Character'Pos ('1'),
      Character'Pos ('3'), Character'Pos (' '));

   --  Wire size of the HkdfLabel struct for given Label / Context
   --  byte counts. Two bytes for the u16 length field, one byte
   --  for each opaque length octet, plus the labelled name
   --  (Tls13_Prefix + Label) and the context bytes. Bounds match
   --  the HkdfLabel struct's TLS-PL widths (Label_Length <= 249,
   --  Context_Length <= 255).
   function Info_Size
     (Label_Length   : Natural;
      Context_Length : Natural)
      return Natural
   is (2 + 1 + Tls13_Prefix'Length + Label_Length
       + 1 + Context_Length)
   with
     Pre  => Label_Length <= 249 and then Context_Length <= 255,
     Post => Info_Size'Result =
               2 + 1 + Tls13_Prefix'Length + Label_Length
               + 1 + Context_Length;

   --  Build the HkdfLabel byte sequence in `Output` per §7.1.
   --
   --  Output(1..2)        = u16 BE Length
   --  Output(3)           = 6 + Label'Length
   --  Output(4..9)        = Tls13_Prefix
   --  Output(10..)        = Label
   --  Output(...)         = Context'Length
   --  Output(...)         = Context
   --
   --  The §7.1 ranges (label<7..255>, context<0..255>) are
   --  encoded as preconditions on Label'Length and
   --  Context'Length. The miTLS `assume length label_bytes >= 7`
   --  is then discharged automatically: 6 + Label'Length >= 7
   --  whenever Label'Length >= 1.
   procedure Build_Info_Bytes
     (Length  : Interfaces.Unsigned_16;
      Label   : Octet_Array;
      Context : Octet_Array;
      Output  : out Octet_Array;
      Last    : out Natural)
   with
     Pre  =>
       Label'Length in 1 .. 249             --  ⇒ 7 <= label_bytes <= 255
       and then Context'Length in 0 .. 255
       and then Output'Length =
         Info_Size (Label'Length, Context'Length)
       and then Output'First = 1
       --  Bound caller's index ranges so the loop accesses below
       --  cannot overflow Integer, even on 32-bit machines.
       and then Label'Last < Integer'Last - 256
       and then Context'Last < Integer'Last - 256,
     Post =>
       Last = Output'Last
       --  u16 BE Length.
       and then Output (1) =
         Octet (Length / Interfaces.Unsigned_16'(256))
       and then Output (2) =
         Octet (Length mod Interfaces.Unsigned_16'(256))
       --  Labelled-name length octet = "tls13 " + Label.
       and then Output (3) = Octet (Tls13_Prefix'Length + Label'Length)
       --  "tls13 " literal sits immediately after.
       and then (for all I in 1 .. Tls13_Prefix'Length =>
                   Output (3 + I) = Tls13_Prefix (I))
       --  Then the caller-supplied Label.
       and then (for all I in 1 .. Label'Length =>
                   Output (3 + Tls13_Prefix'Length + I)
                     = Label (Label'First + I - 1))
       --  Context length octet, then Context bytes.
       and then Output
                  (3 + Tls13_Prefix'Length + Label'Length + 1)
                = Octet (Context'Length)
       and then (for all I in 1 .. Context'Length =>
                   Output
                     (3 + Tls13_Prefix'Length + Label'Length + 1 + I)
                   = Context (Context'First + I - 1));

   --  HKDF-Expand-Label proper. The wrapper:
   --    1. Builds the info bytes with Build_Info_Bytes.
   --    2. Hands them to the generic `Hmac_Expand` primitive.
   --
   --  Hash_Length is the hash function's output size in octets
   --  (32 for SHA-256, 48 for SHA-384). RFC 5869 caps the
   --  expanded output at 255 * HashLen.
   generic
      Hash_Length : Positive;
      Max_Info    : Positive := 256;  --  ceiling on Info_Size,
                                      --  picked to fit common
                                      --  Label / Context shapes.
      --  Caller is responsible for proving Hmac_Expand satisfies
      --  RFC 5869 §2.3. Ours is the wrapper-with-lemmas pattern:
      --  Hmac_Expand stands in for HACL\*'s `EverCrypt.HKDF.expand`,
      --  whose F\* postcondition is `t == expand_spec prk info len`.
      --  When we have a SPARK HMAC-SHA-256 we will instantiate
      --  this generic against it and the axiom becomes a theorem.
      with procedure Hmac_Expand
        (Prk     : Octet_Array;
         Info    : Octet_Array;
         Output  : out Octet_Array);
   procedure Expand_Label
     (Secret  : Octet_Array;
      Label   : Octet_Array;
      Context : Octet_Array;
      Output  : out Octet_Array)
   with
     Pre =>
       Secret'Length = Hash_Length
       and then Label'Length in 1 .. 249
       and then Context'Length in 0 .. 255
       and then Output'Length in 1 .. 255 * Hash_Length
       and then Info_Size (Label'Length, Context'Length) <= Max_Info
       and then Label'Last < Integer'Last - 256
       and then Context'Last < Integer'Last - 256
       and then Secret'Last < Integer'Last - 1024
       and then Output'Last < Integer'Last - 1024
       --  Hmac_Expand instantiations call Sha256.Hash transitively;
       --  the HACL*-ported functional Post requires 1-based input.
       and then Secret'First = 1;

end Tls_Core.Hkdf;
