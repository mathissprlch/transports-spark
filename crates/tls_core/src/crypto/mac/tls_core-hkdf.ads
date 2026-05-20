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
--  See ../../docs/wrapper-pattern.md for the RFLX + SPARK-Post
--  approach this primitive follows.

package Tls_Core.Hkdf
  with SPARK_Mode
is

   use type Tls_Core.Octet;
   use type Interfaces.Unsigned_16;

   --  The literal six-byte ASCII prefix per RFC 8446 §7.1.
   Tls13_Prefix : constant Octet_Array (1 .. 6) :=
     [Character'Pos ('t'),
      Character'Pos ('l'),
      Character'Pos ('s'),
      Character'Pos ('1'),
      Character'Pos ('3'),
      Character'Pos (' ')];

   --  Wire size of the HkdfLabel struct for given Label / Context
   --  byte counts. Two bytes for the u16 length field, one byte
   --  for each opaque length octet, plus the labelled name
   --  (Tls13_Prefix + Label) and the context bytes. Bounds match
   --  the HkdfLabel struct's TLS-PL widths (Label_Length <= 249,
   --  Context_Length <= 255).
   function Info_Size
     (Label_Length : Natural; Context_Length : Natural) return Natural
   is (2 + 1 + Tls13_Prefix'Length + Label_Length + 1 + Context_Length)
   with
     Pre  => Label_Length <= 249 and then Context_Length <= 255,
     Post =>
       Info_Size'Result
       = 2 + 1 + Tls13_Prefix'Length + Label_Length + 1 + Context_Length;

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
       and then Output'Length = Info_Size (Label'Length, Context'Length)
       and then Output'First = 1
       --  Bound caller's index ranges so the loop accesses below
       --  cannot overflow Integer, even on 32-bit machines.
       and then Label'Last < Integer'Last - 256
       and then Context'Last < Integer'Last - 256,
     Post =>
       Last
       = Output'Last
         --  u16 BE Length.
       and then Output (1) = Octet (Length / Interfaces.Unsigned_16'(256))
       and then Output (2) = Octet (Length mod Interfaces.Unsigned_16'(256))
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
       and then Output (3 + Tls13_Prefix'Length + Label'Length + 1)
                = Octet (Context'Length)
       and then (for all I in 1 .. Context'Length =>
                   Output (3 + Tls13_Prefix'Length + Label'Length + 1 + I)
                   = Context (Context'First + I - 1));

   ---------------------------------------------------------------------
   --  Built_Info_Bytes — pure functional version of Build_Info_Bytes.
   --
   --  Returns the §7.1-encoded HkdfLabel as an Octet_Array (rather
   --  than writing into an out parameter). Used by the Expand_Label
   --  Post so the contract is a single referentially-transparent
   --  expression. Same wire shape as Build_Info_Bytes; see the Post
   --  there for byte-by-byte contract.
   ---------------------------------------------------------------------
   function Built_Info_Bytes
     (Length : Natural; Label : Octet_Array; Context : Octet_Array)
      return Octet_Array
   with
     Pre  =>
       Length <= 255 * 64
       and then Label'Length in 1 .. 249
       and then Context'Length in 0 .. 255
       and then Label'Last < Integer'Last - 256
       and then Context'Last < Integer'Last - 256,
     Post =>
       Built_Info_Bytes'Result'First = 1
       and then Built_Info_Bytes'Result'Length
                = Info_Size (Label'Length, Context'Length);

   --------------------------------------------------------------------
   --  [VERIFIED — PLATINUM]  HKDF-Expand-Label (RFC 8446 §7.1)
   --
   --  Standard:    RFC 8446 §7.1 (HKDF-Expand-Label)
   --  Spec mirror: HACL* specs/Spec.HKDF.fst : expand
   --               (RFC 8446 §7.1 wraps it with a structured info
   --                field; see Build_Info_Bytes Post for the §7.1
   --                wire layout).
   --  Functional:  Output equals applying Spec_Hmac_Expand to the
   --               §7.1-encoded HkdfLabel info.
   --  Proven at:   gnatprove --level=2 (audit-clean)
   --
   --  HKDF-Expand-Label proper. The wrapper:
   --    1. Builds the info bytes with Build_Info_Bytes.
   --    2. Hands them to the generic `Hmac_Expand` primitive.
   --
   --  Hash_Length is the hash function's output size in octets
   --  (32 for SHA-256, 48 for SHA-384). RFC 5869 caps the
   --  expanded output at 255 * HashLen.
   --
   --  HACL\* spec port (docs/conventions.md §0c): the Post on Expand_Label
   --  references Spec_Hmac_Expand, the generic-formal ghost the
   --  caller threads through. For our concrete instantiations
   --  (Tls_Core.Hkdf_Sha256.Spec_HKDF_Expand /
   --   Tls_Core.Hkdf_Sha384.Spec_HKDF_Expand) Spec_Hmac_Expand is a
   --  real executable HACL* port (see docs/conventions.md §0d clause 4 — no
   --  stub ghosts). Combined with the §7.1 wire-construction Post on
   --  Build_Info_Bytes, the Expand_Label Post is the RFC 8446 §7.1
   --  functional theorem.
   --------------------------------------------------------------------
   generic
      Hash_Length : Positive;
      Max_Info : Positive := 256;  --  ceiling on Info_Size,
      --  picked to fit common
      --  Label / Context shapes.

      --  Spec ghost the caller threads in. For SHA-256 instantiations
      --  this is Tls_Core.Hkdf_Sha256.Spec_HKDF_Expand (a real
      --  executable HACL* port — see §0d clause 4).
      with
        function Spec_Hmac_Expand
          (Prk  : Tls_Core.Octet_Array;
           Info : Tls_Core.Octet_Array;
           L    : Positive) return Tls_Core.Octet_Array;

      --  The actual Expand procedure. Its Post pins it to
      --  Spec_Hmac_Expand pointwise; see
      --  Tls_Core.Hkdf_Sha256.Hmac_Expand and
      --  Tls_Core.Hkdf_Sha384.Hmac_Expand for instances whose Post
      --  matches this signature.
      with
        procedure Hmac_Expand
          (Prk    : Tls_Core.Octet_Array;
           Info   : Tls_Core.Octet_Array;
           Output : out Tls_Core.Octet_Array)
        with
          Pre  =>
            Prk'Length = Hash_Length
            and then Output'Length in 1 .. 255 * Hash_Length
            and then Info'Length <= 1024
            and then Prk'Last < Integer'Last - 1024
            and then Info'Last < Integer'Last - 1024
            and then Output'Last < Integer'Last - 1024,
          Post =>
            (for all I in 1 .. Output'Length =>
               Output (Output'First + I - 1)
               = Spec_Hmac_Expand (Prk, Info, Output'Length)
                   (Spec_Hmac_Expand (Prk, Info, Output'Length)'First
                    + I
                    - 1));
   procedure Expand_Label
     (Secret  : Octet_Array;
      Label   : Octet_Array;
      Context : Octet_Array;
      Output  : out Octet_Array)
   with
     Pre  =>
       Secret'Length = Hash_Length
       and then Label'Length in 1 .. 249
       and then Context'Length in 0 .. 255
       and then Output'Length in 1 .. 255 * Hash_Length
       and then Info_Size (Label'Length, Context'Length) <= Max_Info
       and then Label'Last < Integer'Last - 256
       and then Context'Last < Integer'Last - 256
       and then Secret'Last < Integer'Last - 1024
       and then Output'Last < Integer'Last - 1024,
     Post =>
       --  Functional contract: each output byte equals the byte of
       --  Spec_Hmac_Expand applied to (Secret, §7.1-encoded info,
       --  Output'Length). The Build_Info_Bytes Post pins the
       --  §7.1-encoded info to the RFC 8446 wire shape; the
       --  Hmac_Expand Post pins the expand to the HACL\* spec.
       (for all I in 1 .. Output'Length =>
          Output (Output'First + I - 1)
          = Spec_Hmac_Expand
              (Secret,
               Built_Info_Bytes (Output'Length, Label, Context),
               Output'Length)
                 (Spec_Hmac_Expand
                    (Secret,
                     Built_Info_Bytes (Output'Length, Label, Context),
                     Output'Length)'First
                  + I
                  - 1));

end Tls_Core.Hkdf;
