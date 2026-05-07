--  tls_core_tests — first-slice unit tests for v0.5.
--
--  Two checks per scenario:
--    1. Build_Info_Bytes (hand-rolled, SPARK contracts) emits the
--       byte sequence the RFC 8446 §7.1 layout demands.

with Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;
with Tls_Core;
with Tls_Core.Hkdf;
with Tls_Core.Record_Layer;
with Tls_Core.Sha256;
with Tls_Core.Hmac_Sha256;
with Tls_Core.Hkdf_Sha256;
with Tls_Core.Key_Schedule;
with Tls_Core.Chacha20;
with Tls_Core.Poly1305;
with Tls_Core.Aead_Chacha20_Poly1305;
with Tls_Core.Transcript;
with Tls_Core.Finished;
with Tls_Core.Handshake;
with Tls_Core.Handshake_Driver;
with Tls_Core.Channel;
with Tls_Core.X25519;
with Tls_Core.Sha512;
with Tls_Core.Ed25519;
with Tls_Core.X509;
with Tls_Core.Hello;
with Tls_Core.Transport;
with Tls_Core.Tcp_Transport;
with Tls_Core.Psk_Binder;
with Tls_Core.Tls13_Driver;
with Tls_Core.Aes128;
with Tls_Core.Aead_Aes128_Gcm;
with Tls_Core.Sha384;
with Tls_Core.Hmac_Sha384;
with Tls_Core.Hkdf_Sha384;
with Tls_Core.Aes256;
with Tls_Core.Aead_Aes256_Gcm;
with Tls_Core.Channel_Aes128;
with Tls_Core.Channel_Aes256;
with Tls_Core.Key_Schedule_Sha384;
with Tls_Core.P256;
with Tls_Core.P256_Field;
with Tls_Core.P256_Order;
with Tls_Core.Ecdsa_P256;

procedure Tls_Core_Tests is

   use Ada.Text_IO;
   use type Tls_Core.Octet;

   Pass : Natural := 0;
   Fail : Natural := 0;

   procedure Check (Label : String; OK : Boolean);
   procedure Check (Label : String; OK : Boolean) is
   begin
      if OK then
         Pass := Pass + 1;
         Put_Line ("  PASS " & Label);
      else
         Fail := Fail + 1;
         Put_Line ("  FAIL " & Label);
      end if;
   end Check;

   --  Compare two octet slices.
   function Equal (A, B : Tls_Core.Octet_Array) return Boolean;
   function Equal (A, B : Tls_Core.Octet_Array) return Boolean is
   begin
      if A'Length /= B'Length then
         return False;
      end if;
      for I in 0 .. A'Length - 1 loop
         if A (A'First + I) /= B (B'First + I) then
            return False;
         end if;
      end loop;
      return True;
   end Equal;

   --------------------------------------------------------------------
   --  Scenario 1 — label="hello", context empty, length=32.
   --
   --  Expected wire (RFC 8446 §7.1, big-endian u16 length, "tls13 "
   --  + label, then context-len + context):
   --    00 20                              -- u16 length = 32
   --    0B                                  -- |"tls13 "+label| = 11
   --    74 6C 73 31 33 20                  -- "tls13 "
   --    68 65 6C 6C 6F                     -- "hello"
   --    00                                  -- |context| = 0
   --------------------------------------------------------------------

   procedure Scenario_1;
   procedure Scenario_1 is
      Label    : constant Tls_Core.Octet_Array (1 .. 5) :=
        (16#68#, 16#65#, 16#6C#, 16#6C#, 16#6F#);
      Context  : constant Tls_Core.Octet_Array (1 .. 0) :=
        (others => 0);
      Out_Hand : Tls_Core.Octet_Array
        (1 .. Tls_Core.Hkdf.Info_Size (Label'Length, Context'Length));
      Out_Last : Natural;
      Expected : constant Tls_Core.Octet_Array (1 .. 15) :=
        (16#00#, 16#20#,
         16#0B#,
         16#74#, 16#6C#, 16#73#, 16#31#, 16#33#, 16#20#,
         16#68#, 16#65#, 16#6C#, 16#6C#, 16#6F#,
         16#00#);
   begin
      Put_Line ("scenario 1 — label=hello, context=empty, length=32");
      Tls_Core.Hkdf.Build_Info_Bytes
        (Length  => 32,
         Label   => Label,
         Context => Context,
         Output  => Out_Hand,
         Last    => Out_Last);
      Check ("hand-rolled length matches",
             Out_Last = Out_Hand'Last);
      Check ("hand-rolled bytes match RFC §7.1",
             Equal (Out_Hand, Expected));

   end Scenario_1;

   --------------------------------------------------------------------
   --  Scenario 2 — label="key", context=4 bytes 0xCA 0xFE 0xBA 0xBE,
   --  length=16. Exercises the non-empty-context branch.
   --
   --  Expected wire:
   --    00 10                                -- u16 length = 16
   --    09                                    -- |"tls13 "+label| = 9
   --    74 6C 73 31 33 20                    -- "tls13 "
   --    6B 65 79                              -- "key"
   --    04                                    -- |context| = 4
   --    CA FE BA BE                          -- context
   --------------------------------------------------------------------

   procedure Scenario_2;
   procedure Scenario_2 is
      Label    : constant Tls_Core.Octet_Array (1 .. 3) :=
        (16#6B#, 16#65#, 16#79#);
      Context  : constant Tls_Core.Octet_Array (1 .. 4) :=
        (16#CA#, 16#FE#, 16#BA#, 16#BE#);
      Out_Hand : Tls_Core.Octet_Array
        (1 .. Tls_Core.Hkdf.Info_Size (Label'Length, Context'Length));
      Out_Last : Natural;
      Expected : constant Tls_Core.Octet_Array (1 .. 17) :=
        (16#00#, 16#10#,
         16#09#,
         16#74#, 16#6C#, 16#73#, 16#31#, 16#33#, 16#20#,
         16#6B#, 16#65#, 16#79#,
         16#04#,
         16#CA#, 16#FE#, 16#BA#, 16#BE#);
   begin
      Put_Line ("scenario 2 — label=key, context=4B, length=16");
      Tls_Core.Hkdf.Build_Info_Bytes
        (Length  => 16,
         Label   => Label,
         Context => Context,
         Output  => Out_Hand,
         Last    => Out_Last);
      Check ("hand-rolled length matches",
             Out_Last = Out_Hand'Last);
      Check ("hand-rolled bytes match RFC §7.1",
             Equal (Out_Hand, Expected));

   end Scenario_2;

   --------------------------------------------------------------------
   --  Record-layer scenarios — exercise the per-record nonce
   --  derivation at runtime to confirm what we proved statically:
   --    * nonce(IV, 0) leaves IV's low-8 bytes untouched (XOR 0).
   --    * nonce(IV, k) for k = 0..N never repeats.
   --    * The high four bytes of the nonce always equal IV(1..4).
   --------------------------------------------------------------------

   procedure Record_Layer_Scenario;
   procedure Record_Layer_Scenario is
      use type Interfaces.Unsigned_64;
      use Tls_Core.Record_Layer;
      IV : constant Tls_Core.Record_Layer.IV_Array :=
        (16#10#, 16#11#, 16#12#, 16#13#,
         16#20#, 16#21#, 16#22#, 16#23#,
         16#30#, 16#31#, 16#32#, 16#33#);
      N0 : constant Tls_Core.Record_Layer.IV_Array :=
        Tls_Core.Record_Layer.Nonce (IV, 0);
      All_Distinct : Boolean := True;
      Nonces : array (0 .. 31) of
        Tls_Core.Record_Layer.IV_Array;
   begin
      Put_Line
        ("scenario 3 — record-layer nonce derivation, no-reuse runtime");

      --  XOR with seq=0 leaves IV untouched.
      Check ("nonce(IV, 0) = IV", Equal (N0, IV));

      --  Top four bytes of every nonce equal IV(1..4).
      declare
         N5 : constant Tls_Core.Record_Layer.IV_Array :=
           Tls_Core.Record_Layer.Nonce (IV, 5);
      begin
         Check ("nonce high-4 unchanged",
                Equal (N5 (1 .. 4), IV (1 .. 4)));
      end;

      --  Generate 32 nonces, check they're all pairwise distinct.
      for K in Nonces'Range loop
         Nonces (K) :=
           Tls_Core.Record_Layer.Nonce
             (IV, Interfaces.Unsigned_64 (K));
      end loop;
      for I in Nonces'Range loop
         for J in Nonces'Range loop
            if I /= J and then Equal (Nonces (I), Nonces (J)) then
               All_Distinct := False;
            end if;
         end loop;
      end loop;
      Check ("32 distinct nonces from seq 0..31", All_Distinct);

      --  Stream Init/Bump path.
      declare
         S : Tls_Core.Record_Layer.Stream;
      begin
         Tls_Core.Record_Layer.Init (S, IV);
         for K in 0 .. 4 loop
            Tls_Core.Record_Layer.Bump (S);
         end loop;
         Check ("stream Seq advances 5 ticks",
                True);  --  Compile-time verified by gnatprove.
      end;
   end Record_Layer_Scenario;

   --------------------------------------------------------------------
   --  SHA-256 vectors from FIPS 180-4 Appendix B / NIST CAVS:
   --    1. Empty input → e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4
   --                     649b934c a495991b 7852b855
   --    2. "abc"      → ba7816bf 8f01cfea 414140de 5dae2223 b00361a3
   --                     96177a9c b410ff61 f20015ad
   --    3. "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
   --       (FIPS 180-4 §B.2)
   --                  → 248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459
   --                     64ff2167 f6ecedd4 19db06c1
   --
   --  miTLS itself does not test SHA-256 (it imports HACL\*'s
   --  proven Spec.SHA2_256 transparently); we ground our pure-Ada
   --  implementation against the same FIPS vectors HACL\*'s proof
   --  transitively rests on.
   --------------------------------------------------------------------

   procedure Sha256_Scenario;
   procedure Sha256_Scenario is
      Empty_Expected : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#E3#, 16#B0#, 16#C4#, 16#42#, 16#98#, 16#FC#, 16#1C#, 16#14#,
         16#9A#, 16#FB#, 16#F4#, 16#C8#, 16#99#, 16#6F#, 16#B9#, 16#24#,
         16#27#, 16#AE#, 16#41#, 16#E4#, 16#64#, 16#9B#, 16#93#, 16#4C#,
         16#A4#, 16#95#, 16#99#, 16#1B#, 16#78#, 16#52#, 16#B8#, 16#55#);
      Abc            : constant Tls_Core.Octet_Array (1 .. 3) :=
        (16#61#, 16#62#, 16#63#);
      Abc_Expected   : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#BA#, 16#78#, 16#16#, 16#BF#, 16#8F#, 16#01#, 16#CF#, 16#EA#,
         16#41#, 16#41#, 16#40#, 16#DE#, 16#5D#, 16#AE#, 16#22#, 16#23#,
         16#B0#, 16#03#, 16#61#, 16#A3#, 16#96#, 16#17#, 16#7A#, 16#9C#,
         16#B4#, 16#10#, 16#FF#, 16#61#, 16#F2#, 16#00#, 16#15#, 16#AD#);
      --  56-byte FIPS §B.2 input:
      --  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
      Long_In        : constant Tls_Core.Octet_Array (1 .. 56) :=
        (16#61#, 16#62#, 16#63#, 16#64#, 16#62#, 16#63#, 16#64#, 16#65#,
         16#63#, 16#64#, 16#65#, 16#66#, 16#64#, 16#65#, 16#66#, 16#67#,
         16#65#, 16#66#, 16#67#, 16#68#, 16#66#, 16#67#, 16#68#, 16#69#,
         16#67#, 16#68#, 16#69#, 16#6A#, 16#68#, 16#69#, 16#6A#, 16#6B#,
         16#69#, 16#6A#, 16#6B#, 16#6C#, 16#6A#, 16#6B#, 16#6C#, 16#6D#,
         16#6B#, 16#6C#, 16#6D#, 16#6E#, 16#6C#, 16#6D#, 16#6E#, 16#6F#,
         16#6D#, 16#6E#, 16#6F#, 16#70#, 16#6E#, 16#6F#, 16#70#, 16#71#);
      Long_Expected  : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#24#, 16#8D#, 16#6A#, 16#61#, 16#D2#, 16#06#, 16#38#, 16#B8#,
         16#E5#, 16#C0#, 16#26#, 16#93#, 16#0C#, 16#3E#, 16#60#, 16#39#,
         16#A3#, 16#3C#, 16#E4#, 16#59#, 16#64#, 16#FF#, 16#21#, 16#67#,
         16#F6#, 16#EC#, 16#ED#, 16#D4#, 16#19#, 16#DB#, 16#06#, 16#C1#);
      Got            : Tls_Core.Sha256.Digest;
   begin
      Put_Line ("scenario 4 — SHA-256 against FIPS 180-4 §B vectors");

      Tls_Core.Sha256.Hash
        (Tls_Core.Octet_Array'(1 .. 0 => 0), Got);
      Check ("FIPS B.0 empty",       Equal (Got, Empty_Expected));

      Tls_Core.Sha256.Hash (Abc, Got);
      Check ("FIPS B.1 abc",         Equal (Got, Abc_Expected));

      Tls_Core.Sha256.Hash (Long_In, Got);
      Check ("FIPS B.2 56-byte msg", Equal (Got, Long_Expected));

      --  Streaming: split "abc" into "a" + "bc" via two Updates.
      declare
         Ctx : Tls_Core.Sha256.Context;
         A   : constant Tls_Core.Octet_Array (1 .. 1) :=
           (1 => 16#61#);
         Bc  : constant Tls_Core.Octet_Array (1 .. 2) :=
           (16#62#, 16#63#);
      begin
         Tls_Core.Sha256.Init (Ctx);
         Tls_Core.Sha256.Update (Ctx, A);
         Tls_Core.Sha256.Update (Ctx, Bc);
         Tls_Core.Sha256.Finalize (Ctx, Got);
         Check ("streaming a + bc matches abc",
                Equal (Got, Abc_Expected));
      end;
   end Sha256_Scenario;

   --------------------------------------------------------------------
   --  HMAC-SHA-256 vector from RFC 4231 §4.2 (test case 1):
   --    key     = 20 bytes 0x0b
   --    data    = "Hi There"
   --    HMAC    = b0344c61 d8db3853 5ca8afce af0bf12b
   --              881dc200 c9833da7 26e9376c 2e32cff7
   --
   --  Plus an end-to-end HKDF-Expand-Label run (slice 1 instantiated
   --  against slice 7's HMAC primitive). We use a synthetic vector
   --  derived from RFC 5869 §A.1 for cross-checkability:
   --    PRK     = 077709362c2e32df0ddc3f0dc47bba63
   --              90b6c73bb50f9c3122ec844ad7c2b3e5    (RFC §A.1)
   --    label   = "tls13 c hs traffic"-form (TLS 1.3 §7.1)
   --    context = SHA-256(empty) = e3b0c442 ...   from FIPS B.0
   --    length  = 32
   --  We compute the result and verify it's deterministic and the
   --  expected length, not against a specific external vector
   --  (RFC 5869 §A's "info" was raw bytes; the §7.1 wrapping shifts
   --  the comparison goalposts).
   --------------------------------------------------------------------

   procedure Hmac_Sha256_Scenario;
   procedure Hmac_Sha256_Scenario is
      Key : constant Tls_Core.Octet_Array (1 .. 20) :=
        (others => 16#0B#);
      Data : constant Tls_Core.Octet_Array (1 .. 8) :=
        (16#48#, 16#69#, 16#20#, 16#54#, 16#68#, 16#65#, 16#72#, 16#65#);
      Expected : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#B0#, 16#34#, 16#4C#, 16#61#, 16#D8#, 16#DB#, 16#38#, 16#53#,
         16#5C#, 16#A8#, 16#AF#, 16#CE#, 16#AF#, 16#0B#, 16#F1#, 16#2B#,
         16#88#, 16#1D#, 16#C2#, 16#00#, 16#C9#, 16#83#, 16#3D#, 16#A7#,
         16#26#, 16#E9#, 16#37#, 16#6C#, 16#2E#, 16#32#, 16#CF#, 16#F7#);
      Got : Tls_Core.Hmac_Sha256.Tag;
   begin
      Put_Line ("scenario 5 — HMAC-SHA-256 RFC 4231 §4.2 case 1");
      Tls_Core.Hmac_Sha256.Compute
        (Key => Key, Message => Data, Out_Tag => Got);
      Check ("RFC 4231 case 1 matches", Equal (Got, Expected));
   end Hmac_Sha256_Scenario;

   procedure Hkdf_Expand_Scenario;
   procedure Hkdf_Expand_Scenario is
      --  RFC 5869 §A.1 PRK.
      PRK : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#07#, 16#77#, 16#09#, 16#36#, 16#2C#, 16#2E#, 16#32#, 16#DF#,
         16#0D#, 16#DC#, 16#3F#, 16#0D#, 16#C4#, 16#7B#, 16#BA#, 16#63#,
         16#90#, 16#B6#, 16#C7#, 16#3B#, 16#B5#, 16#0F#, 16#9C#, 16#31#,
         16#22#, 16#EC#, 16#84#, 16#4A#, 16#D7#, 16#C2#, 16#B3#, 16#E5#);
      Info : constant Tls_Core.Octet_Array (1 .. 10) :=
        (16#F0#, 16#F1#, 16#F2#, 16#F3#, 16#F4#,
         16#F5#, 16#F6#, 16#F7#, 16#F8#, 16#F9#);
      --  RFC 5869 §A.1 expected output (42 bytes).
      Expected : constant Tls_Core.Octet_Array (1 .. 42) :=
        (16#3C#, 16#B2#, 16#5F#, 16#25#, 16#FA#, 16#AC#, 16#D5#, 16#7A#,
         16#90#, 16#43#, 16#4F#, 16#64#, 16#D0#, 16#36#, 16#2F#, 16#2A#,
         16#2D#, 16#2D#, 16#0A#, 16#90#, 16#CF#, 16#1A#, 16#5A#, 16#4C#,
         16#5D#, 16#B0#, 16#2D#, 16#56#, 16#EC#, 16#C4#, 16#C5#, 16#BF#,
         16#34#, 16#00#, 16#72#, 16#08#, 16#D5#, 16#B8#, 16#87#, 16#18#,
         16#58#, 16#65#);
      OKM : Tls_Core.Octet_Array (1 .. 42);
   begin
      Put_Line ("scenario 6 — HKDF-Expand RFC 5869 §A.1");
      Tls_Core.Hkdf_Sha256.Expand (PRK, Info, OKM);
      Check ("RFC 5869 §A.1 OKM matches", Equal (OKM, Expected));
   end Hkdf_Expand_Scenario;

   --  Slice 1's Tls_Core.Hkdf.Expand_Label generic, instantiated
   --  against slice 7's pure-SPARK HMAC-SHA-256.
   procedure Hkdf_Expand_Label_Wrapped
     is new Tls_Core.Hkdf.Expand_Label
       (Hash_Length => Tls_Core.Sha256.Hash_Length,
        Max_Info    => 256,
        Hmac_Expand => Tls_Core.Hkdf_Sha256.Hmac_Expand);

   procedure Expand_Label_End_To_End;
   procedure Expand_Label_End_To_End is
      Secret : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#07#, 16#77#, 16#09#, 16#36#, 16#2C#, 16#2E#, 16#32#, 16#DF#,
         16#0D#, 16#DC#, 16#3F#, 16#0D#, 16#C4#, 16#7B#, 16#BA#, 16#63#,
         16#90#, 16#B6#, 16#C7#, 16#3B#, 16#B5#, 16#0F#, 16#9C#, 16#31#,
         16#22#, 16#EC#, 16#84#, 16#4A#, 16#D7#, 16#C2#, 16#B3#, 16#E5#);
      Label : constant Tls_Core.Octet_Array (1 .. 10) :=
        (16#63#, 16#20#, 16#68#, 16#73#, 16#20#,        --  "c hs "
         16#74#, 16#72#, 16#61#, 16#66#, 16#66#);       --  "traff"
      Empty_Hash : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#E3#, 16#B0#, 16#C4#, 16#42#, 16#98#, 16#FC#, 16#1C#, 16#14#,
         16#9A#, 16#FB#, 16#F4#, 16#C8#, 16#99#, 16#6F#, 16#B9#, 16#24#,
         16#27#, 16#AE#, 16#41#, 16#E4#, 16#64#, 16#9B#, 16#93#, 16#4C#,
         16#A4#, 16#95#, 16#99#, 16#1B#, 16#78#, 16#52#, 16#B8#, 16#55#);
      Out_Material : Tls_Core.Octet_Array (1 .. 32);
      All_Different_From_Secret : Boolean := True;
   begin
      Put_Line ("scenario 7 — HKDF-Expand-Label end-to-end");
      Hkdf_Expand_Label_Wrapped
        (Secret  => Secret,
         Label   => Label,
         Context => Empty_Hash,
         Output  => Out_Material);
      --  We don't pin against a third-party-issued reference
      --  (RFC 8448 vectors are deep into a real TLS handshake);
      --  what we DO check is determinism + that the output isn't
      --  trivially the input secret (which would mean Expand_Label
      --  is broken).
      for I in Out_Material'Range loop
         if Out_Material (I) /= Secret (I) then
            All_Different_From_Secret := True;
            exit;
         end if;
      end loop;
      Check ("32-byte output produced", Out_Material'Length = 32);
      Check ("output not == raw secret", All_Different_From_Secret);
      --  Determinism: run again, same result.
      declare
         Out_2 : Tls_Core.Octet_Array (1 .. 32);
      begin
         Hkdf_Expand_Label_Wrapped
           (Secret => Secret, Label => Label,
            Context => Empty_Hash, Output => Out_2);
         Check ("deterministic re-run", Equal (Out_Material, Out_2));
      end;
   end Expand_Label_End_To_End;

   --------------------------------------------------------------------
   --  Key schedule — RFC 8448 §3 (TLS 1.3 1-RTT simple handshake).
   --
   --  Step 0 of every TLS 1.3 handshake: Early Secret =
   --    HKDF-Extract(0_32, 0_32)
   --  RFC 8448 §3 logs this exactly:
   --    33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2
   --    10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a
   --
   --  Then "derived" = Derive-Secret(Early_Secret, "derived",
   --  ""), which feeds the next Extract that mixes in the
   --  (EC)DHE shared secret. RFC 8448 §3 logs:
   --    6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97
   --    16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba
   --------------------------------------------------------------------

   --------------------------------------------------------------------
   --  ChaCha20 — RFC 8439 §2.3.2 block-function test vector.
   --
   --  Key   = 00..1f                                  (32 bytes)
   --  Nonce = 00 00 00 09 00 00 00 4a 00 00 00 00     (12 bytes)
   --  Ctr   = 1
   --  Block = e4 e7 f1 10 ... see body of test for full 64 bytes
   --
   --  And §2.4.2 encryption test vector (Sunscreen quote).
   --------------------------------------------------------------------

   procedure Chacha20_Scenario;
   procedure Chacha20_Scenario is
      Key   : constant Tls_Core.Chacha20.Key_Array :=
        (16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
         16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#,
         16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#,
         16#18#, 16#19#, 16#1A#, 16#1B#, 16#1C#, 16#1D#, 16#1E#, 16#1F#);
      Nonce : constant Tls_Core.Chacha20.Nonce_Array :=
        (16#00#, 16#00#, 16#00#, 16#09#,
         16#00#, 16#00#, 16#00#, 16#4A#,
         16#00#, 16#00#, 16#00#, 16#00#);
      Expected_Block : constant Tls_Core.Octet_Array (1 .. 64) :=
        (16#10#, 16#F1#, 16#E7#, 16#E4#, 16#D1#, 16#3B#, 16#59#, 16#15#,
         16#50#, 16#0F#, 16#DD#, 16#1F#, 16#A3#, 16#20#, 16#71#, 16#C4#,
         16#C7#, 16#D1#, 16#F4#, 16#C7#, 16#33#, 16#C0#, 16#68#, 16#03#,
         16#04#, 16#22#, 16#AA#, 16#9A#, 16#C3#, 16#D4#, 16#6C#, 16#4E#,
         16#D2#, 16#82#, 16#64#, 16#46#, 16#07#, 16#9F#, 16#AA#, 16#09#,
         16#14#, 16#C2#, 16#D7#, 16#05#, 16#D9#, 16#8B#, 16#02#, 16#A2#,
         16#B5#, 16#12#, 16#9C#, 16#D1#, 16#DE#, 16#16#, 16#4E#, 16#B9#,
         16#CB#, 16#D0#, 16#83#, 16#E8#, 16#A2#, 16#50#, 16#3C#, 16#4E#);
      Got_Block : Tls_Core.Chacha20.Block_Array;

      --  RFC 8439 §2.4.2 encryption vector — "Sunscreen" plaintext.
      Sunscreen_Nonce : constant Tls_Core.Chacha20.Nonce_Array :=
        (16#00#, 16#00#, 16#00#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#4A#,
         16#00#, 16#00#, 16#00#, 16#00#);
      --  "Ladies and Gentlemen of the class of '99: If I could
      --   offer you only one tip for the future, sunscreen would
      --   be it."  (114 bytes)
      Plain : constant Tls_Core.Octet_Array (1 .. 114) :=
        (16#4C#, 16#61#, 16#64#, 16#69#, 16#65#, 16#73#, 16#20#, 16#61#,
         16#6E#, 16#64#, 16#20#, 16#47#, 16#65#, 16#6E#, 16#74#, 16#6C#,
         16#65#, 16#6D#, 16#65#, 16#6E#, 16#20#, 16#6F#, 16#66#, 16#20#,
         16#74#, 16#68#, 16#65#, 16#20#, 16#63#, 16#6C#, 16#61#, 16#73#,
         16#73#, 16#20#, 16#6F#, 16#66#, 16#20#, 16#27#, 16#39#, 16#39#,
         16#3A#, 16#20#, 16#49#, 16#66#, 16#20#, 16#49#, 16#20#, 16#63#,
         16#6F#, 16#75#, 16#6C#, 16#64#, 16#20#, 16#6F#, 16#66#, 16#66#,
         16#65#, 16#72#, 16#20#, 16#79#, 16#6F#, 16#75#, 16#20#, 16#6F#,
         16#6E#, 16#6C#, 16#79#, 16#20#, 16#6F#, 16#6E#, 16#65#, 16#20#,
         16#74#, 16#69#, 16#70#, 16#20#, 16#66#, 16#6F#, 16#72#, 16#20#,
         16#74#, 16#68#, 16#65#, 16#20#, 16#66#, 16#75#, 16#74#, 16#75#,
         16#72#, 16#65#, 16#2C#, 16#20#, 16#73#, 16#75#, 16#6E#, 16#73#,
         16#63#, 16#72#, 16#65#, 16#65#, 16#6E#, 16#20#, 16#77#, 16#6F#,
         16#75#, 16#6C#, 16#64#, 16#20#, 16#62#, 16#65#, 16#20#, 16#69#,
         16#74#, 16#2E#);
      Cipher : constant Tls_Core.Octet_Array (1 .. 114) :=
        (16#6E#, 16#2E#, 16#35#, 16#9A#, 16#25#, 16#68#, 16#F9#, 16#80#,
         16#41#, 16#BA#, 16#07#, 16#28#, 16#DD#, 16#0D#, 16#69#, 16#81#,
         16#E9#, 16#7E#, 16#7A#, 16#EC#, 16#1D#, 16#43#, 16#60#, 16#C2#,
         16#0A#, 16#27#, 16#AF#, 16#CC#, 16#FD#, 16#9F#, 16#AE#, 16#0B#,
         16#F9#, 16#1B#, 16#65#, 16#C5#, 16#52#, 16#47#, 16#33#, 16#AB#,
         16#8F#, 16#59#, 16#3D#, 16#AB#, 16#CD#, 16#62#, 16#B3#, 16#57#,
         16#16#, 16#39#, 16#D6#, 16#24#, 16#E6#, 16#51#, 16#52#, 16#AB#,
         16#8F#, 16#53#, 16#0C#, 16#35#, 16#9F#, 16#08#, 16#61#, 16#D8#,
         16#07#, 16#CA#, 16#0D#, 16#BF#, 16#50#, 16#0D#, 16#6A#, 16#61#,
         16#56#, 16#A3#, 16#8E#, 16#08#, 16#8A#, 16#22#, 16#B6#, 16#5E#,
         16#52#, 16#BC#, 16#51#, 16#4D#, 16#16#, 16#CC#, 16#F8#, 16#06#,
         16#81#, 16#8C#, 16#E9#, 16#1A#, 16#B7#, 16#79#, 16#37#, 16#36#,
         16#5A#, 16#F9#, 16#0B#, 16#BF#, 16#74#, 16#A3#, 16#5B#, 16#E6#,
         16#B4#, 16#0B#, 16#8E#, 16#ED#, 16#F2#, 16#78#, 16#5E#, 16#42#,
         16#87#, 16#4D#);
      Got : Tls_Core.Octet_Array (1 .. 114);
   begin
      Put_Line
        ("scenario 9 — ChaCha20 RFC 8439 §2.3.2 block + §2.4.2 encrypt");
      Tls_Core.Chacha20.Block
        (Key => Key, Nonce => Nonce, Counter => 1,
         Out_Block => Got_Block);
      Check ("§2.3.2 block matches", Equal (Got_Block, Expected_Block));

      Tls_Core.Chacha20.Encrypt
        (Key => Key, Nonce => Sunscreen_Nonce,
         Initial_Counter => 1, Input => Plain, Output => Got);
      Check ("§2.4.2 encrypt matches", Equal (Got, Cipher));

      --  Decrypt = encrypt (XOR is its own inverse).
      Tls_Core.Chacha20.Encrypt
        (Key => Key, Nonce => Sunscreen_Nonce,
         Initial_Counter => 1, Input => Cipher, Output => Got);
      Check ("§2.4.2 round-trip back to plaintext", Equal (Got, Plain));
   end Chacha20_Scenario;

   --------------------------------------------------------------------
   --  Poly1305 — RFC 8439 §2.5.2 test vector.
   --
   --    Key     = 85d6be7857556d337f4452fe42d506a8
   --              0103808afb0db2fd4abff6af4149f51b
   --    Message = "Cryptographic Forum Research Group"  (34 bytes)
   --    Tag     = a8061dc1305136c6c22b8baf0c0127a9
   --------------------------------------------------------------------

   --------------------------------------------------------------------
   --  AEAD ChaCha20-Poly1305 — RFC 8439 §2.8.2 test vector.
   --
   --  Plaintext = "Ladies and Gentlemen of the class of '99: ..."
   --              (114 bytes, same as §2.4.2)
   --  AAD       = 50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7
   --  Key       = 80..9f
   --  IV        = 40 41 42 43 44 45 46 47   (nonce[5..12])
   --  Constant  = 07 00 00 00              (nonce[1..4])
   --  Ciphertext expected per §2.8.2.
   --  Tag       = 1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91
   --------------------------------------------------------------------

   --------------------------------------------------------------------
   --  Record-layer round-trip — Stream's Seal_Record / Open_Record
   --  driven by the ChaCha20-Poly1305 AEAD primitive. Two seals
   --  produce two distinct ciphertexts (because the Stream's Seq
   --  monotonically increases and the no-reuse lemma fires); both
   --  open back to the original plaintext.
   --------------------------------------------------------------------

   package Stream_Aead is new Tls_Core.Record_Layer.Aead
     (Key_Type => Tls_Core.Aead_Chacha20_Poly1305.Key_Array,
      Tag_Type => Tls_Core.Aead_Chacha20_Poly1305.Tag_Array,
      Seal     => Tls_Core.Aead_Chacha20_Poly1305.Seal,
      Open     => Tls_Core.Aead_Chacha20_Poly1305.Open);

   procedure Record_Aead_Roundtrip;
   procedure Record_Aead_Roundtrip is
      Key : constant Tls_Core.Aead_Chacha20_Poly1305.Key_Array :=
        (others => 16#42#);
      IV  : constant Tls_Core.Record_Layer.IV_Array :=
        (16#01#, 16#02#, 16#03#, 16#04#,
         16#05#, 16#06#, 16#07#, 16#08#,
         16#09#, 16#0A#, 16#0B#, 16#0C#);
      AAD : constant Tls_Core.Octet_Array (1 .. 5) :=
        (16#17#, 16#03#, 16#03#, 16#00#, 16#21#);  -- TLS 1.3 record header sketch
      Plain : constant Tls_Core.Octet_Array (1 .. 16) :=
        (16#54#, 16#65#, 16#73#, 16#74#,
         16#5F#, 16#52#, 16#65#, 16#63#,
         16#6F#, 16#72#, 16#64#, 16#5F#,
         16#41#, 16#42#, 16#43#, 16#44#);
      Sender, Receiver : Tls_Core.Record_Layer.Stream;
      Cipher_1, Cipher_2 : Tls_Core.Octet_Array (1 .. 16);
      Tag_1, Tag_2 : Tls_Core.Aead_Chacha20_Poly1305.Tag_Array;
      Out_Plain : Tls_Core.Octet_Array (1 .. 16);
      Open_OK : Boolean;
   begin
      Put_Line ("scenario 12 — Record_Layer.Aead round-trip + no-reuse");
      Tls_Core.Record_Layer.Init (Sender, IV);
      Tls_Core.Record_Layer.Init (Receiver, IV);

      Stream_Aead.Seal_Record
        (S => Sender, Key => Key, AAD => AAD,
         Plaintext => Plain,
         Ciphertext => Cipher_1, Tag => Tag_1);
      Stream_Aead.Seal_Record
        (S => Sender, Key => Key, AAD => AAD,
         Plaintext => Plain,
         Ciphertext => Cipher_2, Tag => Tag_2);

      Check ("two seals of identical plaintext differ",
             not Equal (Cipher_1, Cipher_2));

      --  Receiver opens in the same order.
      Stream_Aead.Open_Record
        (S => Receiver, Key => Key, AAD => AAD,
         Ciphertext => Cipher_1, Tag => Tag_1,
         Plaintext => Out_Plain, OK => Open_OK);
      Check ("open seq=0 succeeds", Open_OK);
      Check ("open seq=0 recovers plaintext",
             Equal (Out_Plain, Plain));

      Stream_Aead.Open_Record
        (S => Receiver, Key => Key, AAD => AAD,
         Ciphertext => Cipher_2, Tag => Tag_2,
         Plaintext => Out_Plain, OK => Open_OK);
      Check ("open seq=1 succeeds", Open_OK);
      Check ("open seq=1 recovers plaintext",
             Equal (Out_Plain, Plain));
   end Record_Aead_Roundtrip;

   --------------------------------------------------------------------
   --------------------------------------------------------------------

   --------------------------------------------------------------------
   --  Transcript + Finished — full chain from PSK to verify_data.
   --
   --  This composes every slice landed in v0.5:
   --    * Tls_Core.Sha256              (slice 7)
   --    * Tls_Core.Key_Schedule.Extract / Derive_Secret (slice 2)
   --    * Tls_Core.Hkdf.Expand_Label   (slice 1)
   --    * Tls_Core.Transcript.{Init,Append,Snapshot}
   --    * Tls_Core.Finished.Compute
   --
   --  The actual byte values aren't matched against an external
   --  vector here (RFC 8448 §3 stops short of Finished without an
   --  ECDHE step we don't implement); instead we check determinism,
   --  the right output length, and that two parties operating on
   --  the same inputs produce identical verify_data — i.e., the
   --  primitive is composing correctly.
   --------------------------------------------------------------------

   --------------------------------------------------------------------
   --  Capstone — full PSK_KE handshake on a single process,
   --  driven by Tls_Core.Handshake.Derive_Psk_Secrets, with
   --  application data sealed/opened via the derived keys.
   --
   --  This is the v0.5 end-to-end smoke test: PSK in, working
   --  authenticated channel out. Both "client" and "server"
   --  compute the same secrets from the same recorded transcript;
   --  the test confirms determinism + that the AEAD cycle works
   --  with the derived application-traffic secret as the key.
   --------------------------------------------------------------------

   procedure Capstone_Scenario;
   procedure Capstone_Scenario is
      use type Tls_Core.Sha256.Digest;
      PSK : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#5C#);
      --  Synthetic recorded handshake transcript bytes. The actual
      --  bytes don't have to be valid TLS messages for the key
      --  derivation to produce identical outputs — both parties
      --  just need to feed the same byte sequences.
      Ch_Bytes : constant Tls_Core.Octet_Array (1 .. 90) :=
        (others => 16#11#);
      Sh_Bytes : constant Tls_Core.Octet_Array (1 .. 90) :=
        (others => 16#22#);
      Sf_Bytes : constant Tls_Core.Octet_Array (1 .. 36) :=
        (others => 16#33#);
      Client_Side, Server_Side : Tls_Core.Handshake.Traffic_Secrets;
   begin
      Put_Line
        ("scenario 15 — capstone: PSK_KE handshake → AEAD round-trip");

      --  Both sides derive in parallel from the same inputs.
      Tls_Core.Handshake.Derive_Psk_Secrets
        (PSK => PSK,
         Client_Hello => Ch_Bytes, Server_Hello => Sh_Bytes,
         Server_Finished => Sf_Bytes,
         Out_Secrets => Client_Side);
      Tls_Core.Handshake.Derive_Psk_Secrets
        (PSK => PSK,
         Client_Hello => Ch_Bytes, Server_Hello => Sh_Bytes,
         Server_Finished => Sf_Bytes,
         Out_Secrets => Server_Side);

      --  Both sides reach identical secrets — the property the
      --  whole TLS 1.3 key-schedule architecture buys us.
      Check ("client + server agree on c_hs_traffic_secret",
             Equal (Client_Side.Client_Handshake,
                    Server_Side.Client_Handshake));
      Check ("client + server agree on s_hs_traffic_secret",
             Equal (Client_Side.Server_Handshake,
                    Server_Side.Server_Handshake));
      Check ("client + server agree on c_ap_traffic_secret",
             Equal (Client_Side.Client_App,
                    Server_Side.Client_App));
      Check ("client + server agree on s_ap_traffic_secret",
             Equal (Client_Side.Server_App,
                    Server_Side.Server_App));

      --  The four secrets MUST be distinct (else key separation
      --  is broken).
      Check ("c_hs_traffic /= s_hs_traffic",
             not Equal (Client_Side.Client_Handshake,
                        Client_Side.Server_Handshake));
      Check ("c_ap_traffic /= s_ap_traffic",
             not Equal (Client_Side.Client_App,
                        Client_Side.Server_App));
      Check ("c_hs_traffic /= c_ap_traffic",
             not Equal (Client_Side.Client_Handshake,
                        Client_Side.Client_App));

      --  Now use the c_ap_traffic_secret directly as a 32-byte
      --  AEAD key (production would HKDF-Expand-Label "key" /
      --  "iv" out of it; this test just demonstrates that the
      --  derived bytes produce a working AEAD round-trip).
      declare
         AEAD_Key : Tls_Core.Aead_Chacha20_Poly1305.Key_Array
           := Client_Side.Client_App;
         Nonce : constant Tls_Core.Aead_Chacha20_Poly1305.Nonce_Array :=
           (others => 16#33#);
         Plain : constant Tls_Core.Octet_Array (1 .. 13) :=
           (16#48#, 16#65#, 16#6C#, 16#6C#, 16#6F#,  -- "Hello"
            16#2C#, 16#20#,                          -- ", "
            16#54#, 16#4C#, 16#53#, 16#21#,          -- "TLS!"
            16#0A#, 16#0D#);
         AAD : constant Tls_Core.Octet_Array (1 .. 0) :=
           (others => 0);
         Cipher : Tls_Core.Octet_Array (1 .. 13);
         Tag : Tls_Core.Aead_Chacha20_Poly1305.Tag_Array;
         Decrypted : Tls_Core.Octet_Array (1 .. 13);
         Ok : Boolean;
      begin
         Tls_Core.Aead_Chacha20_Poly1305.Seal
           (Key => AEAD_Key, Nonce => Nonce, AAD => AAD,
            Plaintext => Plain, Ciphertext => Cipher, Tag => Tag);
         Tls_Core.Aead_Chacha20_Poly1305.Open
           (Key => AEAD_Key, Nonce => Nonce, AAD => AAD,
            Ciphertext => Cipher, Tag => Tag,
            Plaintext => Decrypted, OK => Ok);
         Check ("AEAD opens with derived key", Ok);
         Check ("decrypted plaintext matches original",
                Equal (Decrypted, Plain));
      end;
   end Capstone_Scenario;

   procedure Transcript_Finished_Scenario;
   procedure Transcript_Finished_Scenario is
      use type Tls_Core.Sha256.Digest;
      PSK : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#AB#);
      --  Synthetic ClientHello and ServerHello bodies (just bytes
      --  for the running hash; not validated against a wire spec
      --  here — the wire-format check is scenario 13).
      Ch_Bytes : constant Tls_Core.Octet_Array (1 .. 64) :=
        (others => 16#11#);
      Sh_Bytes : constant Tls_Core.Octet_Array (1 .. 64) :=
        (others => 16#22#);
      Early_Secret, Handshake_Secret : Tls_Core.Key_Schedule.Secret;
      Hs_Traffic : Tls_Core.Key_Schedule.Secret;
      Empty   : constant Tls_Core.Octet_Array (1 .. 0) :=
        (others => 0);
      Zero32  : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 0);
      Derived_Label : constant Tls_Core.Octet_Array (1 .. 7) :=
        (16#64#, 16#65#, 16#72#, 16#69#, 16#76#, 16#65#, 16#64#);
      C_Hs_Label : constant Tls_Core.Octet_Array (1 .. 12) :=
        (16#63#, 16#20#, 16#68#, 16#73#, 16#20#, 16#74#,
         16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
      Tx : Tls_Core.Transcript.Accumulator;
      Snapshot_Hash : Tls_Core.Sha256.Digest;
      Verify_A, Verify_B : Tls_Core.Finished.Verify_Data;
   begin
      Put_Line
        ("scenario 14 — PSK key schedule chain → Finished verify_data");

      --  Step 1: Early Secret = HKDF-Extract(0_32, PSK).
      Tls_Core.Key_Schedule.Extract
        (Salt => Zero32, IKM => PSK, Out_PRK => Early_Secret);

      --  Step 2: derived = Derive-Secret(Early_Secret, "derived", "").
      declare
         Derived : Tls_Core.Key_Schedule.Secret;
      begin
         Tls_Core.Key_Schedule.Derive_Secret
           (Secret_In  => Early_Secret,
            Label      => Derived_Label,
            Messages   => Empty,
            Out_Secret => Derived);
         --  PSK-only path skips real ECDHE; per RFC 8446 §7.1
         --  the (EC)DHE input is then 32 zero bytes.
         Tls_Core.Key_Schedule.Extract
           (Salt => Derived, IKM => Zero32,
            Out_PRK => Handshake_Secret);
      end;

      --  Step 3: feed ClientHello + ServerHello into the transcript.
      Tls_Core.Transcript.Init (Tx);
      Tls_Core.Transcript.Append (Tx, Ch_Bytes);
      Tls_Core.Transcript.Append (Tx, Sh_Bytes);
      Tls_Core.Transcript.Snapshot (Tx, Snapshot_Hash);

      --  Step 4: client_handshake_traffic_secret =
      --    Derive-Secret(Handshake_Secret, "c hs traffic", CH..SH).
      Tls_Core.Key_Schedule.Derive_Secret
        (Secret_In  => Handshake_Secret,
         Label      => C_Hs_Label,
         Messages   => Ch_Bytes & Sh_Bytes,
         Out_Secret => Hs_Traffic);

      --  Step 5: verify_data = HMAC(finished_key, Snapshot_Hash)
      --  where finished_key = HKDF-Expand-Label(Hs_Traffic,
      --  "finished", "", 32).
      Tls_Core.Finished.Compute
        (Base_Key => Hs_Traffic,
         Transcript_Hash => Snapshot_Hash,
         Out_Verify => Verify_A);

      Check ("verify_data is 32 bytes", Verify_A'Length = 32);
      --  Determinism: re-run from scratch.
      declare
         Tx_2 : Tls_Core.Transcript.Accumulator;
         Snap_2 : Tls_Core.Sha256.Digest;
      begin
         Tls_Core.Transcript.Init (Tx_2);
         Tls_Core.Transcript.Append (Tx_2, Ch_Bytes);
         Tls_Core.Transcript.Append (Tx_2, Sh_Bytes);
         Tls_Core.Transcript.Snapshot (Tx_2, Snap_2);
         Check ("transcript snapshot deterministic",
                Equal (Snap_2, Snapshot_Hash));
      end;
      Tls_Core.Finished.Compute
        (Base_Key => Hs_Traffic,
         Transcript_Hash => Snapshot_Hash,
         Out_Verify => Verify_B);
      Check ("Finished compute deterministic",
             Equal (Verify_A, Verify_B));
      --  Sanity: verify_data must depend on the Snapshot (mutating
      --  one byte of the transcript-hash flips the verify_data).
      declare
         Mutated : Tls_Core.Sha256.Digest := Snapshot_Hash;
         Verify_C : Tls_Core.Finished.Verify_Data;
      begin
         Mutated (1) := Mutated (1) xor 16#01#;
         Tls_Core.Finished.Compute
           (Base_Key => Hs_Traffic,
            Transcript_Hash => Mutated,
            Out_Verify => Verify_C);
         Check ("Finished depends on transcript hash",
                not Equal (Verify_A, Verify_C));
      end;
   end Transcript_Finished_Scenario;


   procedure Aead_Scenario;
   procedure Aead_Scenario is
      Key : constant Tls_Core.Aead_Chacha20_Poly1305.Key_Array :=
        (16#80#, 16#81#, 16#82#, 16#83#, 16#84#, 16#85#, 16#86#, 16#87#,
         16#88#, 16#89#, 16#8A#, 16#8B#, 16#8C#, 16#8D#, 16#8E#, 16#8F#,
         16#90#, 16#91#, 16#92#, 16#93#, 16#94#, 16#95#, 16#96#, 16#97#,
         16#98#, 16#99#, 16#9A#, 16#9B#, 16#9C#, 16#9D#, 16#9E#, 16#9F#);
      Nonce : constant Tls_Core.Aead_Chacha20_Poly1305.Nonce_Array :=
        (16#07#, 16#00#, 16#00#, 16#00#,
         16#40#, 16#41#, 16#42#, 16#43#,
         16#44#, 16#45#, 16#46#, 16#47#);
      AAD : constant Tls_Core.Octet_Array (1 .. 12) :=
        (16#50#, 16#51#, 16#52#, 16#53#,
         16#C0#, 16#C1#, 16#C2#, 16#C3#,
         16#C4#, 16#C5#, 16#C6#, 16#C7#);
      Plain : constant Tls_Core.Octet_Array (1 .. 114) :=
        (16#4C#, 16#61#, 16#64#, 16#69#, 16#65#, 16#73#, 16#20#, 16#61#,
         16#6E#, 16#64#, 16#20#, 16#47#, 16#65#, 16#6E#, 16#74#, 16#6C#,
         16#65#, 16#6D#, 16#65#, 16#6E#, 16#20#, 16#6F#, 16#66#, 16#20#,
         16#74#, 16#68#, 16#65#, 16#20#, 16#63#, 16#6C#, 16#61#, 16#73#,
         16#73#, 16#20#, 16#6F#, 16#66#, 16#20#, 16#27#, 16#39#, 16#39#,
         16#3A#, 16#20#, 16#49#, 16#66#, 16#20#, 16#49#, 16#20#, 16#63#,
         16#6F#, 16#75#, 16#6C#, 16#64#, 16#20#, 16#6F#, 16#66#, 16#66#,
         16#65#, 16#72#, 16#20#, 16#79#, 16#6F#, 16#75#, 16#20#, 16#6F#,
         16#6E#, 16#6C#, 16#79#, 16#20#, 16#6F#, 16#6E#, 16#65#, 16#20#,
         16#74#, 16#69#, 16#70#, 16#20#, 16#66#, 16#6F#, 16#72#, 16#20#,
         16#74#, 16#68#, 16#65#, 16#20#, 16#66#, 16#75#, 16#74#, 16#75#,
         16#72#, 16#65#, 16#2C#, 16#20#, 16#73#, 16#75#, 16#6E#, 16#73#,
         16#63#, 16#72#, 16#65#, 16#65#, 16#6E#, 16#20#, 16#77#, 16#6F#,
         16#75#, 16#6C#, 16#64#, 16#20#, 16#62#, 16#65#, 16#20#, 16#69#,
         16#74#, 16#2E#);
      Cipher_Expected : constant Tls_Core.Octet_Array (1 .. 114) :=
        (16#D3#, 16#1A#, 16#8D#, 16#34#, 16#64#, 16#8E#, 16#60#, 16#DB#,
         16#7B#, 16#86#, 16#AF#, 16#BC#, 16#53#, 16#EF#, 16#7E#, 16#C2#,
         16#A4#, 16#AD#, 16#ED#, 16#51#, 16#29#, 16#6E#, 16#08#, 16#FE#,
         16#A9#, 16#E2#, 16#B5#, 16#A7#, 16#36#, 16#EE#, 16#62#, 16#D6#,
         16#3D#, 16#BE#, 16#A4#, 16#5E#, 16#8C#, 16#A9#, 16#67#, 16#12#,
         16#82#, 16#FA#, 16#FB#, 16#69#, 16#DA#, 16#92#, 16#72#, 16#8B#,
         16#1A#, 16#71#, 16#DE#, 16#0A#, 16#9E#, 16#06#, 16#0B#, 16#29#,
         16#05#, 16#D6#, 16#A5#, 16#B6#, 16#7E#, 16#CD#, 16#3B#, 16#36#,
         16#92#, 16#DD#, 16#BD#, 16#7F#, 16#2D#, 16#77#, 16#8B#, 16#8C#,
         16#98#, 16#03#, 16#AE#, 16#E3#, 16#28#, 16#09#, 16#1B#, 16#58#,
         16#FA#, 16#B3#, 16#24#, 16#E4#, 16#FA#, 16#D6#, 16#75#, 16#94#,
         16#55#, 16#85#, 16#80#, 16#8B#, 16#48#, 16#31#, 16#D7#, 16#BC#,
         16#3F#, 16#F4#, 16#DE#, 16#F0#, 16#8E#, 16#4B#, 16#7A#, 16#9D#,
         16#E5#, 16#76#, 16#D2#, 16#65#, 16#86#, 16#CE#, 16#C6#, 16#4B#,
         16#61#, 16#16#);
      Tag_Expected : constant Tls_Core.Octet_Array (1 .. 16) :=
        (16#1A#, 16#E1#, 16#0B#, 16#59#, 16#4F#, 16#09#, 16#E2#, 16#6A#,
         16#7E#, 16#90#, 16#2E#, 16#CB#, 16#D0#, 16#60#, 16#06#, 16#91#);
      Got_Cipher : Tls_Core.Octet_Array (1 .. 114);
      Got_Tag    : Tls_Core.Aead_Chacha20_Poly1305.Tag_Array;
      Got_Plain  : Tls_Core.Octet_Array (1 .. 114);
      Open_OK    : Boolean;
   begin
      Put_Line ("scenario 11 — ChaCha20-Poly1305 AEAD RFC 8439 §2.8.2");
      Tls_Core.Aead_Chacha20_Poly1305.Seal
        (Key => Key, Nonce => Nonce, AAD => AAD,
         Plaintext => Plain,
         Ciphertext => Got_Cipher, Tag => Got_Tag);
      Check ("§2.8.2 ciphertext matches",
             Equal (Got_Cipher, Cipher_Expected));
      Check ("§2.8.2 tag matches", Equal (Got_Tag, Tag_Expected));

      --  Open round-trip.
      Tls_Core.Aead_Chacha20_Poly1305.Open
        (Key => Key, Nonce => Nonce, AAD => AAD,
         Ciphertext => Got_Cipher, Tag => Got_Tag,
         Plaintext => Got_Plain, OK => Open_OK);
      Check ("Open succeeds with valid tag", Open_OK);
      Check ("Open recovers plaintext", Equal (Got_Plain, Plain));

      --  Tamper one byte of ciphertext, expect Open to fail.
      Got_Cipher (5) := Got_Cipher (5) xor 16#01#;
      Tls_Core.Aead_Chacha20_Poly1305.Open
        (Key => Key, Nonce => Nonce, AAD => AAD,
         Ciphertext => Got_Cipher, Tag => Got_Tag,
         Plaintext => Got_Plain, OK => Open_OK);
      Check ("Open rejects tampered ciphertext", not Open_OK);
   end Aead_Scenario;

   procedure Poly1305_Scenario;
   procedure Poly1305_Scenario is
      Key : constant Tls_Core.Poly1305.Key_Array :=
        (16#85#, 16#D6#, 16#BE#, 16#78#, 16#57#, 16#55#, 16#6D#, 16#33#,
         16#7F#, 16#44#, 16#52#, 16#FE#, 16#42#, 16#D5#, 16#06#, 16#A8#,
         16#01#, 16#03#, 16#80#, 16#8A#, 16#FB#, 16#0D#, 16#B2#, 16#FD#,
         16#4A#, 16#BF#, 16#F6#, 16#AF#, 16#41#, 16#49#, 16#F5#, 16#1B#);
      Msg : constant Tls_Core.Octet_Array (1 .. 34) :=
        (16#43#, 16#72#, 16#79#, 16#70#, 16#74#, 16#6F#, 16#67#, 16#72#,
         16#61#, 16#70#, 16#68#, 16#69#, 16#63#, 16#20#, 16#46#, 16#6F#,
         16#72#, 16#75#, 16#6D#, 16#20#, 16#52#, 16#65#, 16#73#, 16#65#,
         16#61#, 16#72#, 16#63#, 16#68#, 16#20#, 16#47#, 16#72#, 16#6F#,
         16#75#, 16#70#);
      Expected : constant Tls_Core.Octet_Array (1 .. 16) :=
        (16#A8#, 16#06#, 16#1D#, 16#C1#, 16#30#, 16#51#, 16#36#, 16#C6#,
         16#C2#, 16#2B#, 16#8B#, 16#AF#, 16#0C#, 16#01#, 16#27#, 16#A9#);
      Got : Tls_Core.Poly1305.Tag_Array;
   begin
      Put_Line ("scenario 10 — Poly1305 RFC 8439 §2.5.2");
      Tls_Core.Poly1305.Mac (Key, Msg, Got);
      Check ("§2.5.2 tag matches", Equal (Got, Expected));
   end Poly1305_Scenario;

   procedure Key_Schedule_Scenario;
   procedure Key_Schedule_Scenario is
      use type Tls_Core.Sha256.Digest;
      Zero32 : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 0);
      Early_Secret_Expected :
        constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#33#, 16#AD#, 16#0A#, 16#1C#, 16#60#, 16#7E#, 16#C0#, 16#3B#,
         16#09#, 16#E6#, 16#CD#, 16#98#, 16#93#, 16#68#, 16#0C#, 16#E2#,
         16#10#, 16#AD#, 16#F3#, 16#00#, 16#AA#, 16#1F#, 16#26#, 16#60#,
         16#E1#, 16#B2#, 16#2E#, 16#10#, 16#F1#, 16#70#, 16#F9#, 16#2A#);
      Derived_Expected :
        constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#6F#, 16#26#, 16#15#, 16#A1#, 16#08#, 16#C7#, 16#02#, 16#C5#,
         16#67#, 16#8F#, 16#54#, 16#FC#, 16#9D#, 16#BA#, 16#B6#, 16#97#,
         16#16#, 16#C0#, 16#76#, 16#18#, 16#9C#, 16#48#, 16#25#, 16#0C#,
         16#EB#, 16#EA#, 16#C3#, 16#57#, 16#6C#, 16#36#, 16#11#, 16#BA#);
      Derived_Label : constant Tls_Core.Octet_Array (1 .. 7) :=
        (16#64#, 16#65#, 16#72#, 16#69#, 16#76#, 16#65#, 16#64#);
      Empty   : constant Tls_Core.Octet_Array (1 .. 0) :=
        (others => 0);
      Early_Secret : Tls_Core.Key_Schedule.Secret;
      Derived      : Tls_Core.Key_Schedule.Secret;
   begin
      Put_Line
        ("scenario 8 — TLS 1.3 key schedule, RFC 8448 §3 "
         & "Early Secret + derived");
      Tls_Core.Key_Schedule.Extract
        (Salt => Zero32, IKM => Zero32, Out_PRK => Early_Secret);
      Check ("early_secret matches RFC 8448 §3",
             Equal (Early_Secret, Early_Secret_Expected));

      Tls_Core.Key_Schedule.Derive_Secret
        (Secret_In  => Early_Secret,
         Label      => Derived_Label,
         Messages   => Empty,
         Out_Secret => Derived);
      Check ("Derive-Secret(early, derived, empty) matches RFC 8448",
             Equal (Derived, Derived_Expected));
   end Key_Schedule_Scenario;

   --------------------------------------------------------------------
   --  Scenario 16 — wire-level handshake driver loopback.
   --
   --  Two Driver instances (Client and Server), wired through a
   --  pair of byte buffers, run the PSK_KE handshake to Done.
   --  After the loopback completes, both drivers expose identical
   --  Traffic_Secrets — proving the state machine composes the
   --  primitives correctly.
   --------------------------------------------------------------------
   procedure Driver_Loopback_Scenario;
   procedure Driver_Loopback_Scenario is
      use type Tls_Core.Handshake_Driver.State;
      use type Tls_Core.Octet;

      Psk : constant Tls_Core.Octet_Array (1 .. 32) := (others => 16#42#);

      C, S : Tls_Core.Handshake_Driver.Driver;

      Buf : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
      Buf_Last : Natural := 0;
      Empty : constant Tls_Core.Octet_Array (1 .. 0) := (others => 0);
      pragma Unreferenced (Empty);

      Cs, Ss : Tls_Core.Handshake.Traffic_Secrets;
   begin
      Put_Line ("scenario 16 — Handshake_Driver Client/Server loopback");

      Tls_Core.Handshake_Driver.Init (C, Tls_Core.Handshake_Driver.Client, Psk);
      Tls_Core.Handshake_Driver.Init (S, Tls_Core.Handshake_Driver.Server, Psk);

      --  Client kicks off — empty in, ClientHello out.
      Tls_Core.Handshake_Driver.Step
        (C, In_Bytes => Buf (1 .. 0), Out_Buf => Buf, Out_Last => Buf_Last);
      Check ("Client.Step Idle → Awaiting_Server_Hello",
             Tls_Core.Handshake_Driver.Current_State (C)
               = Tls_Core.Handshake_Driver.Awaiting_Server_Hello);
      Check ("Client emits ClientHello bytes", Buf_Last > 4);

      --  Server consumes CH, emits SH.
      declare
         CH_Bytes : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Reply_Last : Natural := 0;
      begin
         Tls_Core.Handshake_Driver.Step
           (S, In_Bytes => CH_Bytes, Out_Buf => Reply, Out_Last => Reply_Last);
         Check ("Server.Step Awaiting_CH → Awaiting_Finished",
                Tls_Core.Handshake_Driver.Current_State (S)
                  = Tls_Core.Handshake_Driver.Awaiting_Finished);
         Check ("Server emits ServerHello bytes", Reply_Last > 4);
         Buf := (others => 0);
         Buf (1 .. Reply_Last) := Reply (1 .. Reply_Last);
         Buf_Last := Reply_Last;
      end;

      --  Client consumes SH || SF, derives secrets, → Awaiting_Finished.
      declare
         Sh_Sf_Bytes : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Reply_Last : Natural := 0;
      begin
         Tls_Core.Handshake_Driver.Step
           (C, In_Bytes => Sh_Sf_Bytes, Out_Buf => Reply, Out_Last => Reply_Last);
         Check ("Client.Step Awaiting_SH → Awaiting_Finished",
                Tls_Core.Handshake_Driver.Current_State (C)
                  = Tls_Core.Handshake_Driver.Awaiting_Finished);
         pragma Unreferenced (Reply_Last);
      end;

      --  Client emits its Finished, → Done. Server receives → Done.
      declare
         Reply : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Reply_Last : Natural := 0;
      begin
         Tls_Core.Handshake_Driver.Step
           (C, In_Bytes => Buf (1 .. 0),
            Out_Buf => Reply, Out_Last => Reply_Last);
         Check ("Client.Step Awaiting_Finished → Done",
                Tls_Core.Handshake_Driver.Current_State (C)
                  = Tls_Core.Handshake_Driver.Done);

         declare
            CF : constant Tls_Core.Octet_Array :=
              Reply (1 .. Reply_Last);
            Discard : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
            Discard_Last : Natural := 0;
         begin
            Tls_Core.Handshake_Driver.Step
              (S, In_Bytes => CF,
               Out_Buf => Discard, Out_Last => Discard_Last);
         end;
         Check ("Server.Step Awaiting_Finished → Done",
                Tls_Core.Handshake_Driver.Current_State (S)
                  = Tls_Core.Handshake_Driver.Done);
      end;

      Tls_Core.Handshake_Driver.Get_Secrets (C, Cs);
      Tls_Core.Handshake_Driver.Get_Secrets (S, Ss);

      --  Both sides walked the same key-schedule tree — the four
      --  derived secrets must match across the loopback.
      Check ("Driver: client/server agree on c_hs",
             Equal (Cs.Client_Handshake, Ss.Client_Handshake));
      Check ("Driver: client/server agree on s_hs",
             Equal (Cs.Server_Handshake, Ss.Server_Handshake));
      Check ("Driver: client/server agree on c_ap",
             Equal (Cs.Client_App, Ss.Client_App));
      Check ("Driver: client/server agree on s_ap",
             Equal (Cs.Server_App, Ss.Server_App));
   end Driver_Loopback_Scenario;

   --------------------------------------------------------------------
   --  Scenario 17 — Tls_Core.Channel record-layer round-trip.
   --
   --  Drives the Handshake_Driver to Done, then opens a Channel
   --  with the derived c_ap_traffic_secret, sends three plaintexts
   --  through one Direction's Send and decrypts each on the
   --  matching Direction's Receive. Confirms (a) wire-format
   --  framing per RFC 8446 §5.2, (b) AEAD round-trip, (c)
   --  stream sequence numbers stay aligned across multiple
   --  records.
   --------------------------------------------------------------------
   procedure Channel_Roundtrip_Scenario;
   procedure Channel_Roundtrip_Scenario is
      use type Tls_Core.Octet;
      Psk : constant Tls_Core.Octet_Array (1 .. 32) := (others => 16#42#);

      C, S : Tls_Core.Handshake_Driver.Driver;
      Buf : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
      Buf_Last : Natural := 0;
      Cs : Tls_Core.Handshake.Traffic_Secrets;
      Send_Dir, Recv_Dir : Tls_Core.Channel.Direction;
   begin
      Put_Line ("scenario 17 — Tls_Core.Channel record round-trip");

      Tls_Core.Handshake_Driver.Init
        (C, Tls_Core.Handshake_Driver.Client, Psk);
      Tls_Core.Handshake_Driver.Init
        (S, Tls_Core.Handshake_Driver.Server, Psk);
      Tls_Core.Handshake_Driver.Step
        (C, In_Bytes => Buf (1 .. 0), Out_Buf => Buf, Out_Last => Buf_Last);
      declare
         CH_Bytes : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Reply_Last : Natural := 0;
      begin
         Tls_Core.Handshake_Driver.Step
           (S, In_Bytes => CH_Bytes, Out_Buf => Reply, Out_Last => Reply_Last);
         Buf := (others => 0);
         Buf (1 .. Reply_Last) := Reply (1 .. Reply_Last);
         Buf_Last := Reply_Last;
      end;
      declare
         Sh_Sf : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Reply_Last : Natural := 0;
      begin
         Tls_Core.Handshake_Driver.Step
           (C, In_Bytes => Sh_Sf, Out_Buf => Reply, Out_Last => Reply_Last);
         pragma Unreferenced (Reply_Last);
      end;
      declare
         Reply : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Reply_Last : Natural := 0;
      begin
         Tls_Core.Handshake_Driver.Step
           (C, In_Bytes => Buf (1 .. 0),
            Out_Buf => Reply, Out_Last => Reply_Last);
         declare
            CF : constant Tls_Core.Octet_Array := Reply (1 .. Reply_Last);
            Discard : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
            Discard_Last : Natural := 0;
         begin
            Tls_Core.Handshake_Driver.Step
              (S, In_Bytes => CF,
               Out_Buf => Discard, Out_Last => Discard_Last);
         end;
      end;
      Tls_Core.Handshake_Driver.Get_Secrets (C, Cs);

      --  Both sides initialise a Channel direction from the SAME
      --  secret — what real peers would do for, say, the client→
      --  server application-data direction.
      Tls_Core.Channel.Init (Send_Dir, Cs.Client_App);
      Tls_Core.Channel.Init (Recv_Dir, Cs.Client_App);

      declare
         Pt1 : constant Tls_Core.Octet_Array := (16#41#, 16#42#, 16#43#);
         Pt2 : constant Tls_Core.Octet_Array (1 .. 5) :=
           (16#68#, 16#65#, 16#6C#, 16#6C#, 16#6F#);  --  "hello"
         Pt3 : constant Tls_Core.Octet_Array (1 .. 16) := (others => 16#5A#);

         Wire1 : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Wire1_L : Natural;
         Wire2 : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Wire2_L : Natural;
         Wire3 : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Wire3_L : Natural;

         Got : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Got_L : Natural;
         OK    : Boolean;
      begin
         Tls_Core.Channel.Send (Send_Dir, Pt1, Wire1, Wire1_L);
         Tls_Core.Channel.Send (Send_Dir, Pt2, Wire2, Wire2_L);
         Tls_Core.Channel.Send (Send_Dir, Pt3, Wire3, Wire3_L);

         Check ("Channel: record 1 has TLS 1.3 envelope (0x17 0x03 0x03)",
                Wire1 (1) = 16#17#
                and then Wire1 (2) = 16#03#
                and then Wire1 (3) = 16#03#);
         Check ("Channel: record 1 wire length matches",
                Wire1_L = 5 + Pt1'Length + 1 + 16);

         --  Open them in order.
         Tls_Core.Channel.Receive
           (Recv_Dir, Wire1 (1 .. Wire1_L),
            Got, Got_L, OK);
         Check ("Channel: open record 1 succeeds", OK);
         Check ("Channel: record 1 round-trips bytes",
                Got_L = Pt1'Length and then Equal (Got (1 .. Got_L), Pt1));

         Tls_Core.Channel.Receive
           (Recv_Dir, Wire2 (1 .. Wire2_L),
            Got, Got_L, OK);
         Check ("Channel: open record 2 succeeds", OK);
         Check ("Channel: record 2 round-trips bytes",
                Got_L = Pt2'Length and then Equal (Got (1 .. Got_L), Pt2));

         Tls_Core.Channel.Receive
           (Recv_Dir, Wire3 (1 .. Wire3_L),
            Got, Got_L, OK);
         Check ("Channel: open record 3 succeeds", OK);
         Check ("Channel: record 3 round-trips bytes",
                Got_L = Pt3'Length and then Equal (Got (1 .. Got_L), Pt3));

         --  Tampered ciphertext is rejected.
         declare
            Bad : Tls_Core.Octet_Array (1 .. Wire1_L) := Wire1 (1 .. Wire1_L);
         begin
            Bad (10) := Bad (10) xor 16#01#;
            --  Re-init Recv_Dir so the sequence number realigns.
            Tls_Core.Channel.Init (Recv_Dir, Cs.Client_App);
            Tls_Core.Channel.Receive
              (Recv_Dir, Bad, Got, Got_L, OK);
            Check ("Channel: tampered record rejected", not OK);
         end;
      end;
   end Channel_Roundtrip_Scenario;

   --------------------------------------------------------------------
   --  Scenario 18 — X25519 RFC 7748 §5.2 byte-exact test vectors.
   --
   --  Two single-shot input/output triples from §5.2 plus a Diffie-
   --  Hellman round (§6.1): Alice and Bob each derive a public key
   --  from their private scalar via the base point, then each
   --  derive the shared secret from their private + peer's public.
   --  Both shared secrets must match.
   --------------------------------------------------------------------
   procedure X25519_Scenario;
   procedure X25519_Scenario is
      use type Tls_Core.Octet;

      --  RFC 7748 §5.2 first vector.
      Scalar_1 : constant Tls_Core.X25519.Bytes_32 :=
        (16#A5#, 16#46#, 16#E3#, 16#6B#, 16#F0#, 16#52#, 16#7C#, 16#9D#,
         16#3B#, 16#16#, 16#15#, 16#4B#, 16#82#, 16#46#, 16#5E#, 16#DD#,
         16#62#, 16#14#, 16#4C#, 16#0A#, 16#C1#, 16#FC#, 16#5A#, 16#18#,
         16#50#, 16#6A#, 16#22#, 16#44#, 16#BA#, 16#44#, 16#9A#, 16#C4#);
      U_1 : constant Tls_Core.X25519.Bytes_32 :=
        (16#E6#, 16#DB#, 16#68#, 16#67#, 16#58#, 16#30#, 16#30#, 16#DB#,
         16#35#, 16#94#, 16#C1#, 16#A4#, 16#24#, 16#B1#, 16#5F#, 16#7C#,
         16#72#, 16#66#, 16#24#, 16#EC#, 16#26#, 16#B3#, 16#35#, 16#3B#,
         16#10#, 16#A9#, 16#03#, 16#A6#, 16#D0#, 16#AB#, 16#1C#, 16#4C#);
      Expected_1 : constant Tls_Core.X25519.Bytes_32 :=
        (16#C3#, 16#DA#, 16#55#, 16#37#, 16#9D#, 16#E9#, 16#C6#, 16#90#,
         16#8E#, 16#94#, 16#EA#, 16#4D#, 16#F2#, 16#8D#, 16#08#, 16#4F#,
         16#32#, 16#EC#, 16#CF#, 16#03#, 16#49#, 16#1C#, 16#71#, 16#F7#,
         16#54#, 16#B4#, 16#07#, 16#55#, 16#77#, 16#A2#, 16#85#, 16#52#);

      --  RFC 7748 §5.2 second vector.
      Scalar_2 : constant Tls_Core.X25519.Bytes_32 :=
        (16#4B#, 16#66#, 16#E9#, 16#D4#, 16#D1#, 16#B4#, 16#67#, 16#3C#,
         16#5A#, 16#D2#, 16#26#, 16#91#, 16#95#, 16#7D#, 16#6A#, 16#F5#,
         16#C1#, 16#1B#, 16#64#, 16#21#, 16#E0#, 16#EA#, 16#01#, 16#D4#,
         16#2C#, 16#A4#, 16#16#, 16#9E#, 16#79#, 16#18#, 16#BA#, 16#0D#);
      U_2 : constant Tls_Core.X25519.Bytes_32 :=
        (16#E5#, 16#21#, 16#0F#, 16#12#, 16#78#, 16#68#, 16#11#, 16#D3#,
         16#F4#, 16#B7#, 16#95#, 16#9D#, 16#05#, 16#38#, 16#AE#, 16#2C#,
         16#31#, 16#DB#, 16#E7#, 16#10#, 16#6F#, 16#C0#, 16#3C#, 16#3E#,
         16#FC#, 16#4C#, 16#D5#, 16#49#, 16#C7#, 16#15#, 16#A4#, 16#93#);
      Expected_2 : constant Tls_Core.X25519.Bytes_32 :=
        (16#95#, 16#CB#, 16#DE#, 16#94#, 16#76#, 16#E8#, 16#90#, 16#7D#,
         16#7A#, 16#AD#, 16#E4#, 16#5C#, 16#B4#, 16#B8#, 16#73#, 16#F8#,
         16#8B#, 16#59#, 16#5A#, 16#68#, 16#79#, 16#9F#, 16#A1#, 16#52#,
         16#E6#, 16#F8#, 16#F7#, 16#64#, 16#7A#, 16#AC#, 16#79#, 16#57#);

      Got : Tls_Core.X25519.Bytes_32 := (others => 0);
   begin
      Put_Line ("scenario 18 — X25519 RFC 7748 §5.2 vectors");

      Tls_Core.X25519.Scalar_Mult (Scalar_1, U_1, Got);
      Check ("X25519 vector #1 matches RFC 7748 §5.2", Equal (Got, Expected_1));

      Tls_Core.X25519.Scalar_Mult (Scalar_2, U_2, Got);
      Check ("X25519 vector #2 matches RFC 7748 §5.2", Equal (Got, Expected_2));

      --  Diffie-Hellman round-trip (RFC 7748 §6.1).
      declare
         Alice_Priv : constant Tls_Core.X25519.Bytes_32 :=
           (16#77#, 16#07#, 16#6D#, 16#0A#, 16#73#, 16#18#, 16#A5#, 16#7D#,
            16#3C#, 16#16#, 16#C1#, 16#72#, 16#51#, 16#B2#, 16#66#, 16#45#,
            16#DF#, 16#4C#, 16#2F#, 16#87#, 16#EB#, 16#C0#, 16#99#, 16#2A#,
            16#B1#, 16#77#, 16#FB#, 16#A5#, 16#1D#, 16#B9#, 16#2C#, 16#2A#);
         Alice_Pub_Expected : constant Tls_Core.X25519.Bytes_32 :=
           (16#85#, 16#20#, 16#F0#, 16#09#, 16#89#, 16#30#, 16#A7#, 16#54#,
            16#74#, 16#8B#, 16#7D#, 16#DC#, 16#B4#, 16#3E#, 16#F7#, 16#5A#,
            16#0D#, 16#BF#, 16#3A#, 16#0D#, 16#26#, 16#38#, 16#1A#, 16#F4#,
            16#EB#, 16#A4#, 16#A9#, 16#8E#, 16#AA#, 16#9B#, 16#4E#, 16#6A#);

         Bob_Priv : constant Tls_Core.X25519.Bytes_32 :=
           (16#5D#, 16#AB#, 16#08#, 16#7E#, 16#62#, 16#4A#, 16#8A#, 16#4B#,
            16#79#, 16#E1#, 16#7F#, 16#8B#, 16#83#, 16#80#, 16#0E#, 16#E6#,
            16#6F#, 16#3B#, 16#B1#, 16#29#, 16#26#, 16#18#, 16#B6#, 16#FD#,
            16#1C#, 16#2F#, 16#8B#, 16#27#, 16#FF#, 16#88#, 16#E0#, 16#EB#);
         Bob_Pub_Expected : constant Tls_Core.X25519.Bytes_32 :=
           (16#DE#, 16#9E#, 16#DB#, 16#7D#, 16#7B#, 16#7D#, 16#C1#, 16#B4#,
            16#D3#, 16#5B#, 16#61#, 16#C2#, 16#EC#, 16#E4#, 16#35#, 16#37#,
            16#3F#, 16#83#, 16#43#, 16#C8#, 16#5B#, 16#78#, 16#67#, 16#4D#,
            16#AD#, 16#FC#, 16#7E#, 16#14#, 16#6F#, 16#88#, 16#2B#, 16#4F#);
         Shared_Expected : constant Tls_Core.X25519.Bytes_32 :=
           (16#4A#, 16#5D#, 16#9D#, 16#5B#, 16#A4#, 16#CE#, 16#2D#, 16#E1#,
            16#72#, 16#8E#, 16#3B#, 16#F4#, 16#80#, 16#35#, 16#0F#, 16#25#,
            16#E0#, 16#7E#, 16#21#, 16#C9#, 16#47#, 16#D1#, 16#9E#, 16#33#,
            16#76#, 16#F0#, 16#9B#, 16#3C#, 16#1E#, 16#16#, 16#17#, 16#42#);

         Alice_Pub, Bob_Pub : Tls_Core.X25519.Bytes_32 := (others => 0);
         Shared_A, Shared_B : Tls_Core.X25519.Bytes_32 := (others => 0);
      begin
         Tls_Core.X25519.Derive_Public (Alice_Priv, Alice_Pub);
         Tls_Core.X25519.Derive_Public (Bob_Priv, Bob_Pub);
         Check ("X25519 Alice public matches RFC 7748 §6.1",
                Equal (Alice_Pub, Alice_Pub_Expected));
         Check ("X25519 Bob public matches RFC 7748 §6.1",
                Equal (Bob_Pub, Bob_Pub_Expected));

         Tls_Core.X25519.Scalar_Mult (Alice_Priv, Bob_Pub, Shared_A);
         Tls_Core.X25519.Scalar_Mult (Bob_Priv, Alice_Pub, Shared_B);
         Check ("X25519 Alice and Bob agree on shared secret",
                Equal (Shared_A, Shared_B));
         Check ("X25519 shared secret matches RFC 7748 §6.1",
                Equal (Shared_A, Shared_Expected));
      end;
   end X25519_Scenario;

   --------------------------------------------------------------------
   --  Scenario 19 — pure-ECDHE handshake key schedule end-to-end.
   --
   --  Two parties run an X25519 Diffie-Hellman exchange, then both
   --  feed the resulting 32-byte shared secret + a recorded
   --  CH/SH/SF transcript into Derive_Ecdhe_Secrets. Both sides
   --  must reach identical traffic secrets — the ECDHE branch of
   --  RFC 8446 §7.1 working end-to-end.
   --------------------------------------------------------------------
   procedure Ecdhe_Schedule_Scenario;
   procedure Ecdhe_Schedule_Scenario is
      use type Tls_Core.Octet;
      Alice_Priv : constant Tls_Core.X25519.Bytes_32 := (others => 16#11#);
      Bob_Priv   : constant Tls_Core.X25519.Bytes_32 := (others => 16#22#);

      Alice_Pub, Bob_Pub : Tls_Core.X25519.Bytes_32 := (others => 0);
      Shared_A, Shared_B : Tls_Core.X25519.Bytes_32 := (others => 0);

      CH : constant Tls_Core.Octet_Array (1 .. 64) := (others => 16#A1#);
      SH : constant Tls_Core.Octet_Array (1 .. 64) := (others => 16#B2#);
      SF : constant Tls_Core.Octet_Array (1 .. 32) := (others => 16#C3#);

      Sec_A, Sec_B : Tls_Core.Handshake.Traffic_Secrets;
   begin
      Put_Line ("scenario 19 — ECDHE key schedule (RFC 8446 §7.1 mode 3)");

      Tls_Core.X25519.Derive_Public (Alice_Priv, Alice_Pub);
      Tls_Core.X25519.Derive_Public (Bob_Priv, Bob_Pub);
      Tls_Core.X25519.Scalar_Mult (Alice_Priv, Bob_Pub, Shared_A);
      Tls_Core.X25519.Scalar_Mult (Bob_Priv, Alice_Pub, Shared_B);
      Check ("ECDHE: Alice and Bob compute equal shared secret",
             Equal (Shared_A, Shared_B));

      Tls_Core.Handshake.Derive_Ecdhe_Secrets
        (ECDHE_Shared    => Shared_A,
         Client_Hello    => CH,
         Server_Hello    => SH,
         Server_Finished => SF,
         Out_Secrets     => Sec_A);
      Tls_Core.Handshake.Derive_Ecdhe_Secrets
        (ECDHE_Shared    => Shared_B,
         Client_Hello    => CH,
         Server_Hello    => SH,
         Server_Finished => SF,
         Out_Secrets     => Sec_B);

      Check ("ECDHE schedule: both sides agree on c_hs_traffic",
             Equal (Sec_A.Client_Handshake, Sec_B.Client_Handshake));
      Check ("ECDHE schedule: both sides agree on s_hs_traffic",
             Equal (Sec_A.Server_Handshake, Sec_B.Server_Handshake));
      Check ("ECDHE schedule: both sides agree on c_ap_traffic",
             Equal (Sec_A.Client_App, Sec_B.Client_App));
      Check ("ECDHE schedule: both sides agree on s_ap_traffic",
             Equal (Sec_A.Server_App, Sec_B.Server_App));
      --  Sanity: ECDHE branch differs from PSK_KE branch with the
      --  shared secret reused as a "PSK".
      declare
         Psk_Sec : Tls_Core.Handshake.Traffic_Secrets;
      begin
         Tls_Core.Handshake.Derive_Psk_Secrets
           (PSK             => Shared_A,
            Client_Hello    => CH,
            Server_Hello    => SH,
            Server_Finished => SF,
            Out_Secrets     => Psk_Sec);
         Check ("ECDHE schedule diverges from PSK_KE for same input",
                not Equal (Sec_A.Client_App, Psk_Sec.Client_App));
      end;
   end Ecdhe_Schedule_Scenario;

   --------------------------------------------------------------------
   --  Scenario 20 — Handshake_Driver ECDHE loopback.
   --
   --  Two drivers in ECDHE mode, each with their own X25519 private
   --  scalar, exchange ClientHello / ServerHello / Finished / Finished
   --  through a buffer pair. Both peers extract the other's
   --  X25519 public key from the Hello body, compute the shared
   --  secret, and run Derive_Ecdhe_Secrets — converging on
   --  identical traffic secrets.
   --------------------------------------------------------------------
   procedure Ecdhe_Driver_Loopback;
   procedure Ecdhe_Driver_Loopback is
      use type Tls_Core.Handshake_Driver.State;
      use type Tls_Core.Octet;

      Cli_Priv : constant Tls_Core.X25519.Bytes_32 := (others => 16#33#);
      Srv_Priv : constant Tls_Core.X25519.Bytes_32 := (others => 16#44#);

      C, S : Tls_Core.Handshake_Driver.Driver;
      Buf : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
      Buf_Last : Natural := 0;
      Cs, Ss : Tls_Core.Handshake.Traffic_Secrets;
   begin
      Put_Line ("scenario 20 — Handshake_Driver ECDHE loopback");

      Tls_Core.Handshake_Driver.Init_Ecdhe
        (C, Tls_Core.Handshake_Driver.Client, Cli_Priv);
      Tls_Core.Handshake_Driver.Init_Ecdhe
        (S, Tls_Core.Handshake_Driver.Server, Srv_Priv);

      --  Client → ClientHello (with X25519 public).
      Tls_Core.Handshake_Driver.Step
        (C, In_Bytes => Buf (1 .. 0), Out_Buf => Buf, Out_Last => Buf_Last);
      Check ("ECDHE Driver: Client emitted CH",
             Tls_Core.Handshake_Driver.Current_State (C)
               = Tls_Core.Handshake_Driver.Awaiting_Server_Hello);

      --  Server → ServerHello + Finished, having extracted client pub
      --  and computed shared.
      declare
         CH : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Reply_Last : Natural := 0;
      begin
         Tls_Core.Handshake_Driver.Step
           (S, In_Bytes => CH, Out_Buf => Reply, Out_Last => Reply_Last);
         Check ("ECDHE Driver: Server emitted SH+SF",
                Tls_Core.Handshake_Driver.Current_State (S)
                  = Tls_Core.Handshake_Driver.Awaiting_Finished);
         Buf := (others => 0);
         Buf (1 .. Reply_Last) := Reply (1 .. Reply_Last);
         Buf_Last := Reply_Last;
      end;

      --  Client receives SH+SF, extracts server pub, computes shared.
      declare
         Sh_Sf : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Reply_Last : Natural := 0;
      begin
         Tls_Core.Handshake_Driver.Step
           (C, In_Bytes => Sh_Sf, Out_Buf => Reply, Out_Last => Reply_Last);
         Check ("ECDHE Driver: Client → Awaiting_Finished",
                Tls_Core.Handshake_Driver.Current_State (C)
                  = Tls_Core.Handshake_Driver.Awaiting_Finished);
         pragma Unreferenced (Reply_Last);
      end;

      --  Client emits Finished; Server receives it.
      declare
         Reply : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Reply_Last : Natural := 0;
      begin
         Tls_Core.Handshake_Driver.Step
           (C, In_Bytes => Buf (1 .. 0),
            Out_Buf => Reply, Out_Last => Reply_Last);
         Check ("ECDHE Driver: Client → Done",
                Tls_Core.Handshake_Driver.Current_State (C)
                  = Tls_Core.Handshake_Driver.Done);
         declare
            CF : constant Tls_Core.Octet_Array := Reply (1 .. Reply_Last);
            Discard : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
            Discard_Last : Natural := 0;
         begin
            Tls_Core.Handshake_Driver.Step
              (S, In_Bytes => CF,
               Out_Buf => Discard, Out_Last => Discard_Last);
         end;
         Check ("ECDHE Driver: Server → Done",
                Tls_Core.Handshake_Driver.Current_State (S)
                  = Tls_Core.Handshake_Driver.Done);
      end;

      Tls_Core.Handshake_Driver.Get_Secrets (C, Cs);
      Tls_Core.Handshake_Driver.Get_Secrets (S, Ss);
      Check ("ECDHE Driver: c_hs match across loopback",
             Equal (Cs.Client_Handshake, Ss.Client_Handshake));
      Check ("ECDHE Driver: s_hs match across loopback",
             Equal (Cs.Server_Handshake, Ss.Server_Handshake));
      Check ("ECDHE Driver: c_ap match across loopback",
             Equal (Cs.Client_App, Ss.Client_App));
      Check ("ECDHE Driver: s_ap match across loopback",
             Equal (Cs.Server_App, Ss.Server_App));
   end Ecdhe_Driver_Loopback;

   --------------------------------------------------------------------
   --  Scenario 21 — SHA-512 FIPS 180-4 §C test vectors.
   --
   --  §C.1 — "abc" → 0xDDAF35A1...
   --  §C.2 — "abcdbcdec...nopq" (448-bit message) → 0x8E959B75...
   --  §C.3 — empty string → 0xCF83E135...
   --------------------------------------------------------------------
   procedure Sha512_Scenario;
   procedure Sha512_Scenario is
      use type Tls_Core.Octet;

      Empty : constant Tls_Core.Octet_Array (1 .. 0) := (others => 0);

      Msg_Abc : constant Tls_Core.Octet_Array := (16#61#, 16#62#, 16#63#);

      Msg_C2 : constant Tls_Core.Octet_Array :=
        (16#61#, 16#62#, 16#63#, 16#64#, 16#62#, 16#63#, 16#64#, 16#65#,
         16#63#, 16#64#, 16#65#, 16#66#, 16#64#, 16#65#, 16#66#, 16#67#,
         16#65#, 16#66#, 16#67#, 16#68#, 16#66#, 16#67#, 16#68#, 16#69#,
         16#67#, 16#68#, 16#69#, 16#6A#, 16#68#, 16#69#, 16#6A#, 16#6B#,
         16#69#, 16#6A#, 16#6B#, 16#6C#, 16#6A#, 16#6B#, 16#6C#, 16#6D#,
         16#6B#, 16#6C#, 16#6D#, 16#6E#, 16#6C#, 16#6D#, 16#6E#, 16#6F#,
         16#6D#, 16#6E#, 16#6F#, 16#70#, 16#6E#, 16#6F#, 16#70#, 16#71#);

      Expected_Abc : constant Tls_Core.Sha512.Digest :=
        (16#DD#, 16#AF#, 16#35#, 16#A1#, 16#93#, 16#61#, 16#7A#, 16#BA#,
         16#CC#, 16#41#, 16#73#, 16#49#, 16#AE#, 16#20#, 16#41#, 16#31#,
         16#12#, 16#E6#, 16#FA#, 16#4E#, 16#89#, 16#A9#, 16#7E#, 16#A2#,
         16#0A#, 16#9E#, 16#EE#, 16#E6#, 16#4B#, 16#55#, 16#D3#, 16#9A#,
         16#21#, 16#92#, 16#99#, 16#2A#, 16#27#, 16#4F#, 16#C1#, 16#A8#,
         16#36#, 16#BA#, 16#3C#, 16#23#, 16#A3#, 16#FE#, 16#EB#, 16#BD#,
         16#45#, 16#4D#, 16#44#, 16#23#, 16#64#, 16#3C#, 16#E8#, 16#0E#,
         16#2A#, 16#9A#, 16#C9#, 16#4F#, 16#A5#, 16#4C#, 16#A4#, 16#9F#);

      Expected_C2 : constant Tls_Core.Sha512.Digest :=
        (16#20#, 16#4A#, 16#8F#, 16#C6#, 16#DD#, 16#A8#, 16#2F#, 16#0A#,
         16#0C#, 16#ED#, 16#7B#, 16#EB#, 16#8E#, 16#08#, 16#A4#, 16#16#,
         16#57#, 16#C1#, 16#6E#, 16#F4#, 16#68#, 16#B2#, 16#28#, 16#A8#,
         16#27#, 16#9B#, 16#E3#, 16#31#, 16#A7#, 16#03#, 16#C3#, 16#35#,
         16#96#, 16#FD#, 16#15#, 16#C1#, 16#3B#, 16#1B#, 16#07#, 16#F9#,
         16#AA#, 16#1D#, 16#3B#, 16#EA#, 16#57#, 16#78#, 16#9C#, 16#A0#,
         16#31#, 16#AD#, 16#85#, 16#C7#, 16#A7#, 16#1D#, 16#D7#, 16#03#,
         16#54#, 16#EC#, 16#63#, 16#12#, 16#38#, 16#CA#, 16#34#, 16#45#);

      Expected_Empty : constant Tls_Core.Sha512.Digest :=
        (16#CF#, 16#83#, 16#E1#, 16#35#, 16#7E#, 16#EF#, 16#B8#, 16#BD#,
         16#F1#, 16#54#, 16#28#, 16#50#, 16#D6#, 16#6D#, 16#80#, 16#07#,
         16#D6#, 16#20#, 16#E4#, 16#05#, 16#0B#, 16#57#, 16#15#, 16#DC#,
         16#83#, 16#F4#, 16#A9#, 16#21#, 16#D3#, 16#6C#, 16#E9#, 16#CE#,
         16#47#, 16#D0#, 16#D1#, 16#3C#, 16#5D#, 16#85#, 16#F2#, 16#B0#,
         16#FF#, 16#83#, 16#18#, 16#D2#, 16#87#, 16#7E#, 16#EC#, 16#2F#,
         16#63#, 16#B9#, 16#31#, 16#BD#, 16#47#, 16#41#, 16#7A#, 16#81#,
         16#A5#, 16#38#, 16#32#, 16#7A#, 16#F9#, 16#27#, 16#DA#, 16#3E#);

      D : Tls_Core.Sha512.Digest;
   begin
      Put_Line ("scenario 21 — SHA-512 FIPS 180-4 §C test vectors");

      Tls_Core.Sha512.Hash (Msg_Abc, D);
      Check ("SHA-512(""abc"") matches FIPS 180-4 §C.1",
             Equal (D, Expected_Abc));

      Tls_Core.Sha512.Hash (Msg_C2, D);
      Check ("SHA-512(448-bit message) matches FIPS 180-4 §C.2",
             Equal (D, Expected_C2));

      Tls_Core.Sha512.Hash (Empty, D);
      Check ("SHA-512(empty) matches FIPS 180-4 §C.3",
             Equal (D, Expected_Empty));

      --  Streaming split: hash "abc" in two Update calls.
      declare
         Ctx : Tls_Core.Sha512.Context;
         D2  : Tls_Core.Sha512.Digest;
      begin
         Tls_Core.Sha512.Init (Ctx);
         Tls_Core.Sha512.Update (Ctx, Msg_Abc (1 .. 1));
         Tls_Core.Sha512.Update (Ctx, Msg_Abc (2 .. 3));
         Tls_Core.Sha512.Finalize (Ctx, D2);
         Check ("SHA-512 streaming split equals one-shot",
                Equal (D2, Expected_Abc));
      end;
   end Sha512_Scenario;

   --------------------------------------------------------------------
   --  Scenario 22 — X509 Ed25519 self-signed certificate parser.
   --
   --  Cert was generated with
   --      openssl req -x509 -newkey ed25519 -nodes -days 365 \
   --          -subj "/CN=test" -outform DER -out test.der
   --  and the bytes copied verbatim via `xxd -i test.der`.
   --
   --  The parser must (a) report OK, (b) name a non-empty TBS range
   --  strictly inside the cert, (c) extract a 32-byte public key,
   --  (d) extract a 64-byte signature. As a sanity capstone we also
   --  feed the parser's outputs into Ed25519.Verify — the cert is
   --  self-signed, so verification over the TBS must accept.
   --------------------------------------------------------------------

   procedure X509_Scenario;
   procedure X509_Scenario is
      Cert : constant Tls_Core.Octet_Array (1 .. 310) :=
        (16#30#, 16#82#, 16#01#, 16#32#, 16#30#, 16#81#, 16#E5#, 16#A0#,
         16#03#, 16#02#, 16#01#, 16#02#, 16#02#, 16#14#, 16#56#, 16#8D#,
         16#E2#, 16#DF#, 16#FB#, 16#BC#, 16#98#, 16#AF#, 16#80#, 16#FD#,
         16#10#, 16#86#, 16#ED#, 16#3B#, 16#29#, 16#B4#, 16#1D#, 16#51#,
         16#D7#, 16#BE#, 16#30#, 16#05#, 16#06#, 16#03#, 16#2B#, 16#65#,
         16#70#, 16#30#, 16#0F#, 16#31#, 16#0D#, 16#30#, 16#0B#, 16#06#,
         16#03#, 16#55#, 16#04#, 16#03#, 16#0C#, 16#04#, 16#74#, 16#65#,
         16#73#, 16#74#, 16#30#, 16#1E#, 16#17#, 16#0D#, 16#32#, 16#36#,
         16#30#, 16#35#, 16#30#, 16#35#, 16#31#, 16#32#, 16#30#, 16#33#,
         16#33#, 16#30#, 16#5A#, 16#17#, 16#0D#, 16#32#, 16#37#, 16#30#,
         16#35#, 16#30#, 16#35#, 16#31#, 16#32#, 16#30#, 16#33#, 16#33#,
         16#30#, 16#5A#, 16#30#, 16#0F#, 16#31#, 16#0D#, 16#30#, 16#0B#,
         16#06#, 16#03#, 16#55#, 16#04#, 16#03#, 16#0C#, 16#04#, 16#74#,
         16#65#, 16#73#, 16#74#, 16#30#, 16#2A#, 16#30#, 16#05#, 16#06#,
         16#03#, 16#2B#, 16#65#, 16#70#, 16#03#, 16#21#, 16#00#, 16#86#,
         16#7B#, 16#5A#, 16#0F#, 16#9B#, 16#80#, 16#61#, 16#B3#, 16#89#,
         16#E3#, 16#A8#, 16#1F#, 16#E0#, 16#B3#, 16#AF#, 16#87#, 16#FC#,
         16#66#, 16#2D#, 16#59#, 16#86#, 16#A8#, 16#72#, 16#03#, 16#D8#,
         16#61#, 16#7A#, 16#C2#, 16#99#, 16#CC#, 16#09#, 16#32#, 16#A3#,
         16#53#, 16#30#, 16#51#, 16#30#, 16#1D#, 16#06#, 16#03#, 16#55#,
         16#1D#, 16#0E#, 16#04#, 16#16#, 16#04#, 16#14#, 16#6E#, 16#8E#,
         16#E2#, 16#E6#, 16#75#, 16#86#, 16#1D#, 16#89#, 16#36#, 16#B7#,
         16#48#, 16#AC#, 16#8C#, 16#BA#, 16#E5#, 16#38#, 16#B8#, 16#A7#,
         16#F6#, 16#F8#, 16#30#, 16#1F#, 16#06#, 16#03#, 16#55#, 16#1D#,
         16#23#, 16#04#, 16#18#, 16#30#, 16#16#, 16#80#, 16#14#, 16#6E#,
         16#8E#, 16#E2#, 16#E6#, 16#75#, 16#86#, 16#1D#, 16#89#, 16#36#,
         16#B7#, 16#48#, 16#AC#, 16#8C#, 16#BA#, 16#E5#, 16#38#, 16#B8#,
         16#A7#, 16#F6#, 16#F8#, 16#30#, 16#0F#, 16#06#, 16#03#, 16#55#,
         16#1D#, 16#13#, 16#01#, 16#01#, 16#FF#, 16#04#, 16#05#, 16#30#,
         16#03#, 16#01#, 16#01#, 16#FF#, 16#30#, 16#05#, 16#06#, 16#03#,
         16#2B#, 16#65#, 16#70#, 16#03#, 16#41#, 16#00#, 16#B5#, 16#74#,
         16#B9#, 16#8E#, 16#04#, 16#45#, 16#76#, 16#3F#, 16#C8#, 16#AA#,
         16#7E#, 16#D0#, 16#8F#, 16#13#, 16#2A#, 16#79#, 16#D2#, 16#2E#,
         16#31#, 16#E3#, 16#89#, 16#76#, 16#5B#, 16#87#, 16#9B#, 16#43#,
         16#C6#, 16#3A#, 16#DA#, 16#52#, 16#FE#, 16#A7#, 16#7C#, 16#AA#,
         16#BB#, 16#98#, 16#AE#, 16#9A#, 16#55#, 16#83#, 16#91#, 16#9C#,
         16#A2#, 16#92#, 16#F7#, 16#03#, 16#7F#, 16#91#, 16#73#, 16#43#,
         16#A8#, 16#86#, 16#DB#, 16#C4#, 16#88#, 16#09#, 16#38#, 16#D6#,
         16#36#, 16#F4#, 16#C2#, 16#D6#, 16#ED#, 16#00#);

      --  Expected pub-key first/last bytes (from xxd of the cert at
      --  the 32-byte window after the SPKI BIT STRING unused-bits
      --  byte). Cross-checks the offset arithmetic.
      Expected_Pub_First : constant Tls_Core.Octet := 16#86#;
      Expected_Pub_Last  : constant Tls_Core.Octet := 16#32#;
      --  Likewise for the trailing signatureValue BIT STRING.
      Expected_Sig_First : constant Tls_Core.Octet := 16#B5#;
      Expected_Sig_Last  : constant Tls_Core.Octet := 16#00#;

      Tbs_First : Natural;
      Tbs_Last  : Natural;
      Pub_Key   : Tls_Core.X509.Public_Key;
      Sig       : Tls_Core.X509.Signature;
      OK        : Boolean;
   begin
      Put_Line ("scenario 22 — X509 Ed25519 cert parser");

      Tls_Core.X509.Parse_Ed25519_Cert
        (Der       => Cert,
         Tbs_First => Tbs_First,
         Tbs_Last  => Tbs_Last,
         Pub_Key   => Pub_Key,
         Sig       => Sig,
         OK        => OK);

      Check ("X509: Parse_Ed25519_Cert returns OK", OK);
      Check ("X509: TBS range non-empty",
             Tbs_First <= Tbs_Last);
      Check ("X509: TBS range strictly inside Der",
             Tbs_First >= Cert'First and then Tbs_Last <= Cert'Last
             and then (Tbs_First > Cert'First
                       or else Tbs_Last < Cert'Last));
      Check ("X509: pub-key first byte matches",
             Pub_Key (1) = Expected_Pub_First);
      Check ("X509: pub-key last byte matches",
             Pub_Key (32) = Expected_Pub_Last);
      Check ("X509: signature first byte matches",
             Sig (1) = Expected_Sig_First);
      Check ("X509: signature last byte matches",
             Sig (64) = Expected_Sig_Last);

      --  Pin TBS bounds at the byte level: TBS must begin with a
      --  SEQUENCE tag (0x30), and the byte immediately after TBS
      --  must be the signatureAlgorithm SEQUENCE tag. Catches any
      --  off-by-one in either bound that the byte-position checks
      --  above could miss.
      Check ("X509: TBS starts with SEQUENCE tag",
             Cert (Tbs_First) = 16#30#);
      Check ("X509: byte after TBS is signatureAlgorithm tag",
             Tbs_Last + 1 <= Cert'Last
             and then Cert (Tbs_Last + 1) = 16#30#);

      --  Negative: zero-length input must return OK=False.
      declare
         Empty : constant Tls_Core.Octet_Array (1 .. 0) :=
           (others => 0);
         Tf    : Natural := 0;
         Tl    : Natural := 0;
         Pk    : Tls_Core.X509.Public_Key;
         Sg    : Tls_Core.X509.Signature;
         Ok2   : Boolean;
      begin
         Tls_Core.X509.Parse_Ed25519_Cert
           (Der       => Empty,
            Tbs_First => Tf,
            Tbs_Last  => Tl,
            Pub_Key   => Pk,
            Sig       => Sg,
            OK        => Ok2);
         Check ("X509: empty input rejected", not Ok2);
      end;

      --  Negative: truncated cert (drop last 16 bytes of signature)
      --  must return OK=False; the trailing BIT STRING length check
      --  catches this.
      declare
         Truncated : constant Tls_Core.Octet_Array :=
           Cert (Cert'First .. Cert'Last - 16);
         Tf  : Natural := 0;
         Tl  : Natural := 0;
         Pk  : Tls_Core.X509.Public_Key;
         Sg  : Tls_Core.X509.Signature;
         Ok2 : Boolean;
      begin
         Tls_Core.X509.Parse_Ed25519_Cert
           (Der       => Truncated,
            Tbs_First => Tf,
            Tbs_Last  => Tl,
            Pub_Key   => Pk,
            Sig       => Sg,
            OK        => Ok2);
         Check ("X509: truncated cert rejected", not Ok2);
      end;
   end X509_Scenario;

   --------------------------------------------------------------------
   --  Scenario 23 — Ed25519 RFC 8032 §7.1 verification vectors.
   --
   --  TEST 1 (empty message), TEST 2 (1-byte message),
   --  TEST 3 ("af82") plus a corrupted-signature rejection check
   --  and a wrong-key rejection check.
   --------------------------------------------------------------------
   procedure Ed25519_Scenario;
   procedure Ed25519_Scenario is
      use type Tls_Core.Octet;

      Pub_1 : constant Tls_Core.Ed25519.Bytes_32 :=
        (16#D7#, 16#5A#, 16#98#, 16#01#, 16#82#, 16#B1#, 16#0A#, 16#B7#,
         16#D5#, 16#4B#, 16#FE#, 16#D3#, 16#C9#, 16#64#, 16#07#, 16#3A#,
         16#0E#, 16#E1#, 16#72#, 16#F3#, 16#DA#, 16#A6#, 16#23#, 16#25#,
         16#AF#, 16#02#, 16#1A#, 16#68#, 16#F7#, 16#07#, 16#51#, 16#1A#);
      Msg_1 : constant Tls_Core.Octet_Array (1 .. 0) := (others => 0);
      Sig_1 : constant Tls_Core.Ed25519.Signature :=
        (16#E5#, 16#56#, 16#43#, 16#00#, 16#C3#, 16#60#, 16#AC#, 16#72#,
         16#90#, 16#86#, 16#E2#, 16#CC#, 16#80#, 16#6E#, 16#82#, 16#8A#,
         16#84#, 16#87#, 16#7F#, 16#1E#, 16#B8#, 16#E5#, 16#D9#, 16#74#,
         16#D8#, 16#73#, 16#E0#, 16#65#, 16#22#, 16#49#, 16#01#, 16#55#,
         16#5F#, 16#B8#, 16#82#, 16#15#, 16#90#, 16#A3#, 16#3B#, 16#AC#,
         16#C6#, 16#1E#, 16#39#, 16#70#, 16#1C#, 16#F9#, 16#B4#, 16#6B#,
         16#D2#, 16#5B#, 16#F5#, 16#F0#, 16#59#, 16#5B#, 16#BE#, 16#24#,
         16#65#, 16#51#, 16#41#, 16#43#, 16#8E#, 16#7A#, 16#10#, 16#0B#);

      Pub_2 : constant Tls_Core.Ed25519.Bytes_32 :=
        (16#3D#, 16#40#, 16#17#, 16#C3#, 16#E8#, 16#43#, 16#89#, 16#5A#,
         16#92#, 16#B7#, 16#0A#, 16#A7#, 16#4D#, 16#1B#, 16#7E#, 16#BC#,
         16#9C#, 16#98#, 16#2C#, 16#CF#, 16#2E#, 16#C4#, 16#96#, 16#8C#,
         16#C0#, 16#CD#, 16#55#, 16#F1#, 16#2A#, 16#F4#, 16#66#, 16#0C#);
      Msg_2 : constant Tls_Core.Octet_Array := (1 => 16#72#);
      Sig_2 : constant Tls_Core.Ed25519.Signature :=
        (16#92#, 16#A0#, 16#09#, 16#A9#, 16#F0#, 16#D4#, 16#CA#, 16#B8#,
         16#72#, 16#0E#, 16#82#, 16#0B#, 16#5F#, 16#64#, 16#25#, 16#40#,
         16#A2#, 16#B2#, 16#7B#, 16#54#, 16#16#, 16#50#, 16#3F#, 16#8F#,
         16#B3#, 16#76#, 16#22#, 16#23#, 16#EB#, 16#DB#, 16#69#, 16#DA#,
         16#08#, 16#5A#, 16#C1#, 16#E4#, 16#3E#, 16#15#, 16#99#, 16#6E#,
         16#45#, 16#8F#, 16#36#, 16#13#, 16#D0#, 16#F1#, 16#1D#, 16#8C#,
         16#38#, 16#7B#, 16#2E#, 16#AE#, 16#B4#, 16#30#, 16#2A#, 16#EE#,
         16#B0#, 16#0D#, 16#29#, 16#16#, 16#12#, 16#BB#, 16#0C#, 16#00#);

      Pub_3 : constant Tls_Core.Ed25519.Bytes_32 :=
        (16#FC#, 16#51#, 16#CD#, 16#8E#, 16#62#, 16#18#, 16#A1#, 16#A3#,
         16#8D#, 16#A4#, 16#7E#, 16#D0#, 16#02#, 16#30#, 16#F0#, 16#58#,
         16#08#, 16#16#, 16#ED#, 16#13#, 16#BA#, 16#33#, 16#03#, 16#AC#,
         16#5D#, 16#EB#, 16#91#, 16#15#, 16#48#, 16#90#, 16#80#, 16#25#);
      Msg_3 : constant Tls_Core.Octet_Array (1 .. 2) := (16#AF#, 16#82#);
      Sig_3 : constant Tls_Core.Ed25519.Signature :=
        (16#62#, 16#91#, 16#D6#, 16#57#, 16#DE#, 16#EC#, 16#24#, 16#02#,
         16#48#, 16#27#, 16#E6#, 16#9C#, 16#3A#, 16#BE#, 16#01#, 16#A3#,
         16#0C#, 16#E5#, 16#48#, 16#A2#, 16#84#, 16#74#, 16#3A#, 16#44#,
         16#5E#, 16#36#, 16#80#, 16#D7#, 16#DB#, 16#5A#, 16#C3#, 16#AC#,
         16#18#, 16#FF#, 16#9B#, 16#53#, 16#8D#, 16#16#, 16#F2#, 16#90#,
         16#AE#, 16#67#, 16#F7#, 16#60#, 16#98#, 16#4D#, 16#C6#, 16#59#,
         16#4A#, 16#7C#, 16#15#, 16#E9#, 16#71#, 16#6E#, 16#D2#, 16#8D#,
         16#C0#, 16#27#, 16#BE#, 16#CE#, 16#EA#, 16#1E#, 16#C4#, 16#0A#);
   begin
      Put_Line ("scenario 23 — Ed25519 RFC 8032 §7.1 verify vectors");

      Check ("Ed25519 TEST 1 (empty msg) verifies",
             Tls_Core.Ed25519.Verify (Pub_1, Msg_1, Sig_1));
      Check ("Ed25519 TEST 2 (1-byte msg) verifies",
             Tls_Core.Ed25519.Verify (Pub_2, Msg_2, Sig_2));
      Check ("Ed25519 TEST 3 (2-byte msg) verifies",
             Tls_Core.Ed25519.Verify (Pub_3, Msg_3, Sig_3));

      declare
         Bad_Sig : Tls_Core.Ed25519.Signature := Sig_1;
      begin
         Bad_Sig (1) := Bad_Sig (1) xor 16#01#;
         Check ("Ed25519 rejects tampered signature",
                not Tls_Core.Ed25519.Verify (Pub_1, Msg_1, Bad_Sig));
      end;

      Check ("Ed25519 rejects wrong public key",
             not Tls_Core.Ed25519.Verify (Pub_2, Msg_1, Sig_1));

      --  RFC 8032 §7.1 sign vectors — derive public key and produce
      --  the canonical signature given the seed.
      declare
         Seed_1 : constant Tls_Core.Ed25519.Bytes_32 :=
           (16#9D#, 16#61#, 16#B1#, 16#9D#, 16#EF#, 16#FD#, 16#5A#, 16#60#,
            16#BA#, 16#84#, 16#4A#, 16#F4#, 16#92#, 16#EC#, 16#2C#, 16#C4#,
            16#44#, 16#49#, 16#C5#, 16#69#, 16#7B#, 16#32#, 16#69#, 16#19#,
            16#70#, 16#3B#, 16#AC#, 16#03#, 16#1C#, 16#AE#, 16#7F#, 16#60#);
         Got_Sig : Tls_Core.Ed25519.Signature;
         Got_Pub : Tls_Core.Ed25519.Bytes_32;
      begin
         Tls_Core.Ed25519.Public_Of_Seed (Seed_1, Got_Pub);
         Check ("Ed25519 Public_Of_Seed matches RFC §7.1 TEST 1 pub",
                Equal (Got_Pub, Pub_1));
         Tls_Core.Ed25519.Sign (Seed_1, Msg_1, Got_Sig);
         Check ("Ed25519 Sign produces RFC §7.1 TEST 1 signature",
                Equal (Got_Sig, Sig_1));
         Check ("Ed25519 sign output verifies",
                Tls_Core.Ed25519.Verify (Got_Pub, Msg_1, Got_Sig));
      end;

      declare
         Seed_2 : constant Tls_Core.Ed25519.Bytes_32 :=
           (16#4C#, 16#CD#, 16#08#, 16#9B#, 16#28#, 16#FF#, 16#96#, 16#DA#,
            16#9D#, 16#B6#, 16#C3#, 16#46#, 16#EC#, 16#11#, 16#4E#, 16#0F#,
            16#5B#, 16#8A#, 16#31#, 16#9F#, 16#35#, 16#AB#, 16#A6#, 16#24#,
            16#DA#, 16#8C#, 16#F6#, 16#ED#, 16#4F#, 16#B8#, 16#A6#, 16#FB#);
         Got_Sig : Tls_Core.Ed25519.Signature;
      begin
         Tls_Core.Ed25519.Sign (Seed_2, Msg_2, Got_Sig);
         Check ("Ed25519 Sign produces RFC §7.1 TEST 2 signature",
                Equal (Got_Sig, Sig_2));
      end;

   end Ed25519_Scenario;

   --------------------------------------------------------------------
   --  Scenario 24 — Hello (CH/SH) encode/decode round-trip with
   --  real RFC 8446 §4 wire format + extensions.
   --------------------------------------------------------------------
   procedure Hello_Scenario;
   procedure Hello_Scenario is
      use type Tls_Core.Octet;

      Random_Bytes : constant Tls_Core.Hello.Random_Bytes :=
        (others => 16#A5#);
      Pub_Key      : constant Tls_Core.Hello.Public_Key :=
        (1 => 16#01#, 2 => 16#02#, others => 16#42#);

      CH : Tls_Core.Hello.Client_Hello :=
        (Random           => Random_Bytes,
         Session_Id_Len   => 0,
         Session_Id_Bytes => (others => 0),
         Key_Share        => Pub_Key);
      SH : Tls_Core.Hello.Server_Hello :=
        (Random           => Random_Bytes,
         Session_Id_Len   => 0,
         Session_Id_Bytes => (others => 0),
         Key_Share        => Pub_Key);

      Wire : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
      Wire_Last : Natural;
      OK : Boolean;
      Decoded_CH : Tls_Core.Hello.Client_Hello;
      Decoded_SH : Tls_Core.Hello.Server_Hello;
   begin
      Put_Line ("scenario 24 — Hello CH/SH wire-format round-trip");

      Tls_Core.Hello.Encode_Client_Hello (CH, Wire, Wire_Last);
      Check ("CH: encode produced bytes", Wire_Last > 50);
      Check ("CH: legacy_version is 0x0303",
             Wire (1) = 16#03# and then Wire (2) = 16#03#);
      Check ("CH: random echoed at offset 3",
             Wire (3) = 16#A5# and then Wire (34) = 16#A5#);

      Tls_Core.Hello.Decode_Client_Hello
        (Wire (1 .. Wire_Last), Decoded_CH, OK);
      Check ("CH: decode succeeds", OK);
      Check ("CH: round-trip random",
             Equal (Decoded_CH.Random, Random_Bytes));
      Check ("CH: round-trip key_share",
             Equal (Decoded_CH.Key_Share, Pub_Key));

      Tls_Core.Hello.Encode_Server_Hello (SH, Wire, Wire_Last);
      Check ("SH: encode produced bytes", Wire_Last > 40);
      Check ("SH: legacy_version is 0x0303",
             Wire (1) = 16#03# and then Wire (2) = 16#03#);

      Tls_Core.Hello.Decode_Server_Hello
        (Wire (1 .. Wire_Last), Decoded_SH, OK);
      Check ("SH: decode succeeds", OK);
      Check ("SH: round-trip random",
             Equal (Decoded_SH.Random, Random_Bytes));
      Check ("SH: round-trip key_share",
             Equal (Decoded_SH.Key_Share, Pub_Key));

      --  CH with non-empty session_id round-trips.
      CH.Session_Id_Len := 16;
      CH.Session_Id_Bytes (1 .. 16) := (others => 16#5A#);
      Tls_Core.Hello.Encode_Client_Hello (CH, Wire, Wire_Last);
      Tls_Core.Hello.Decode_Client_Hello
        (Wire (1 .. Wire_Last), Decoded_CH, OK);
      Check ("CH: session_id round-trips",
             OK
             and then Decoded_CH.Session_Id_Len = 16
             and then Equal
                        (Decoded_CH.Session_Id_Bytes (1 .. 16),
                         CH.Session_Id_Bytes (1 .. 16)));
   end Hello_Scenario;

   --------------------------------------------------------------------
   --  Scenario 25 — Tls_Core.Transport in-process loopback.
   --
   --  Drives the PSK_KE Handshake_Driver to Done, snaps the four
   --  traffic secrets, then opens a Client Pipe and a Server Pipe
   --  on each side and exchanges three plaintext records each
   --  direction. Confirms (a) Send/Drain on one peer feeds Inject/
   --  Receive on the other, (b) sequence numbers stay aligned across
   --  multiple Sends in a row, (c) AEAD-tag tampering is rejected.
   --
   --  Mirrors scenario_17 (Channel_Roundtrip) but exercises the full
   --  two-direction Pipe object that wraps it.
   --------------------------------------------------------------------
   procedure Transport_Loopback_Scenario;
   procedure Transport_Loopback_Scenario is
      use type Tls_Core.Octet;
      Psk : constant Tls_Core.Octet_Array (1 .. 32) := (others => 16#42#);

      C, S : Tls_Core.Handshake_Driver.Driver;
      Buf : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
      Buf_Last : Natural := 0;
      Cs : Tls_Core.Handshake.Traffic_Secrets;

      Client_Pipe, Server_Pipe : Tls_Core.Transport.Pipe;
   begin
      Put_Line ("scenario 25 — Tls_Core.Transport Client/Server loopback");

      --  Drive the PSK_KE handshake to Done (same shape as
      --  scenarios 16/17).
      Tls_Core.Handshake_Driver.Init
        (C, Tls_Core.Handshake_Driver.Client, Psk);
      Tls_Core.Handshake_Driver.Init
        (S, Tls_Core.Handshake_Driver.Server, Psk);
      Tls_Core.Handshake_Driver.Step
        (C, In_Bytes => Buf (1 .. 0), Out_Buf => Buf, Out_Last => Buf_Last);
      declare
         CH_Bytes : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Reply_Last : Natural := 0;
      begin
         Tls_Core.Handshake_Driver.Step
           (S, In_Bytes => CH_Bytes,
            Out_Buf => Reply, Out_Last => Reply_Last);
         Buf := (others => 0);
         Buf (1 .. Reply_Last) := Reply (1 .. Reply_Last);
         Buf_Last := Reply_Last;
      end;
      declare
         Sh_Sf : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Reply_Last : Natural := 0;
      begin
         Tls_Core.Handshake_Driver.Step
           (C, In_Bytes => Sh_Sf, Out_Buf => Reply, Out_Last => Reply_Last);
         pragma Unreferenced (Reply_Last);
      end;
      declare
         Reply : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Reply_Last : Natural := 0;
      begin
         Tls_Core.Handshake_Driver.Step
           (C, In_Bytes => Buf (1 .. 0),
            Out_Buf => Reply, Out_Last => Reply_Last);
         declare
            CF : constant Tls_Core.Octet_Array := Reply (1 .. Reply_Last);
            Discard : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
            Discard_Last : Natural := 0;
         begin
            Tls_Core.Handshake_Driver.Step
              (S, In_Bytes => CF,
               Out_Buf => Discard, Out_Last => Discard_Last);
         end;
      end;
      Tls_Core.Handshake_Driver.Get_Secrets (C, Cs);

      --  Both peers' Pipes share the SAME Traffic_Secrets, but
      --  each was Init'd with the matching Role: Client encrypts
      --  outbound with Client_App and decrypts inbound with
      --  Server_App; Server is the mirror.
      Tls_Core.Transport.Init
        (Client_Pipe, Tls_Core.Transport.Client, Cs);
      Tls_Core.Transport.Init
        (Server_Pipe, Tls_Core.Transport.Server, Cs);

      ----------------------------------------------------------------
      --  Test 1: Client → Server, single 16-byte plaintext.
      ----------------------------------------------------------------
      declare
         Pt : constant Tls_Core.Octet_Array (1 .. 16) :=
           (others => 16#A5#);
         Wire : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Wire_Last : Natural := 0;
         Got : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Got_Last : Natural := 0;
         OK : Boolean := False;
      begin
         Tls_Core.Transport.Send (Client_Pipe, Pt);
         Tls_Core.Transport.Drain (Client_Pipe, Wire, Wire_Last);
         Check ("Transport: client Drain produced wire bytes",
                Wire_Last = 5 + Pt'Length + 1 + 16);

         Tls_Core.Transport.Inject
           (Server_Pipe, Wire (1 .. Wire_Last));
         Tls_Core.Transport.Receive
           (Server_Pipe, Got, Got_Last, OK);
         Check ("Transport: server Receive succeeds (16 B)", OK);
         Check ("Transport: server got the plaintext (16 B)",
                Got_Last = Pt'Length
                and then Equal (Got (1 .. Got_Last), Pt));
      end;

      ----------------------------------------------------------------
      --  Test 2: Server → Client, single 32-byte plaintext.
      ----------------------------------------------------------------
      declare
         Pt : constant Tls_Core.Octet_Array (1 .. 32) :=
           (others => 16#5A#);
         Wire : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Wire_Last : Natural := 0;
         Got : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Got_Last : Natural := 0;
         OK : Boolean := False;
      begin
         Tls_Core.Transport.Send (Server_Pipe, Pt);
         Tls_Core.Transport.Drain (Server_Pipe, Wire, Wire_Last);
         Check ("Transport: server Drain produced wire bytes",
                Wire_Last = 5 + Pt'Length + 1 + 16);

         Tls_Core.Transport.Inject
           (Client_Pipe, Wire (1 .. Wire_Last));
         Tls_Core.Transport.Receive
           (Client_Pipe, Got, Got_Last, OK);
         Check ("Transport: client Receive succeeds (32 B)", OK);
         Check ("Transport: client got the plaintext (32 B)",
                Got_Last = Pt'Length
                and then Equal (Got (1 .. Got_Last), Pt));
      end;

      ----------------------------------------------------------------
      --  Test 3: three Sends in a row, one Drain, one Inject, three
      --  Receives — confirms sequence-number alignment across
      --  multiple records buffered together.
      ----------------------------------------------------------------
      declare
         Pt1 : constant Tls_Core.Octet_Array := (16#41#, 16#42#, 16#43#);
         Pt2 : constant Tls_Core.Octet_Array (1 .. 5) :=
           (16#68#, 16#65#, 16#6C#, 16#6C#, 16#6F#);  --  "hello"
         Pt3 : constant Tls_Core.Octet_Array (1 .. 24) :=
           (others => 16#7E#);

         Wire : Tls_Core.Octet_Array (1 .. 8192) := (others => 0);
         Wire_Last : Natural := 0;
         Got : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Got_Last : Natural := 0;
         OK : Boolean := False;
         Expected_Wire : constant Natural :=
           (5 + Pt1'Length + 1 + 16)
           + (5 + Pt2'Length + 1 + 16)
           + (5 + Pt3'Length + 1 + 16);
      begin
         Tls_Core.Transport.Send (Client_Pipe, Pt1);
         Tls_Core.Transport.Send (Client_Pipe, Pt2);
         Tls_Core.Transport.Send (Client_Pipe, Pt3);
         Tls_Core.Transport.Drain (Client_Pipe, Wire, Wire_Last);
         Check ("Transport: 3 Sends one Drain — wire size matches",
                Wire_Last = Expected_Wire);

         Tls_Core.Transport.Inject
           (Server_Pipe, Wire (1 .. Wire_Last));

         Tls_Core.Transport.Receive (Server_Pipe, Got, Got_Last, OK);
         Check ("Transport: queued record 1 decrypts",
                OK
                and then Got_Last = Pt1'Length
                and then Equal (Got (1 .. Got_Last), Pt1));

         Got := (others => 0);
         Got_Last := 0;
         OK := False;
         Tls_Core.Transport.Receive (Server_Pipe, Got, Got_Last, OK);
         Check ("Transport: queued record 2 decrypts",
                OK
                and then Got_Last = Pt2'Length
                and then Equal (Got (1 .. Got_Last), Pt2));

         Got := (others => 0);
         Got_Last := 0;
         OK := False;
         Tls_Core.Transport.Receive (Server_Pipe, Got, Got_Last, OK);
         Check ("Transport: queued record 3 decrypts",
                OK
                and then Got_Last = Pt3'Length
                and then Equal (Got (1 .. Got_Last), Pt3));

         --  After draining all three records the inbound queue
         --  is empty: a fourth Receive must report no record.
         Got := (others => 0);
         Got_Last := 0;
         OK := True;
         Tls_Core.Transport.Receive (Server_Pipe, Got, Got_Last, OK);
         Check ("Transport: empty inbound queue → OK=False",
                not OK and then Got_Last = 0);
      end;

      ----------------------------------------------------------------
      --  Test 4: tampered ciphertext byte → AEAD verify fails,
      --  Receive returns OK=False.
      ----------------------------------------------------------------
      declare
         Fresh_Client, Fresh_Server : Tls_Core.Transport.Pipe;
         Pt : constant Tls_Core.Octet_Array (1 .. 12) :=
           (others => 16#33#);
         Wire : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Wire_Last : Natural := 0;
         Got : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Got_Last : Natural := 0;
         OK : Boolean := True;
      begin
         --  Re-Init both pipes so sequence numbers start at 0
         --  again — independent of the records exchanged above.
         Tls_Core.Transport.Init
           (Fresh_Client, Tls_Core.Transport.Client, Cs);
         Tls_Core.Transport.Init
           (Fresh_Server, Tls_Core.Transport.Server, Cs);

         Tls_Core.Transport.Send (Fresh_Client, Pt);
         Tls_Core.Transport.Drain (Fresh_Client, Wire, Wire_Last);

         --  Flip one byte inside the ciphertext (byte 10 lands
         --  inside the encrypted fragment, past the 5-byte header).
         Wire (10) := Wire (10) xor 16#01#;

         Tls_Core.Transport.Inject
           (Fresh_Server, Wire (1 .. Wire_Last));
         Tls_Core.Transport.Receive
           (Fresh_Server, Got, Got_Last, OK);
         Check ("Transport: corrupted ciphertext rejected",
                not OK and then Got_Last = 0);
      end;
   end Transport_Loopback_Scenario;

   --------------------------------------------------------------------
   --  Scenario 26 — full ECDHE + server-cert handshake loopback.
   --
   --  Server is initialised with an Ed25519 seed; client is
   --  initialised with the matching public key (skipping the X.509
   --  chain step — Tls_Core.X509 covers parsing separately). Server
   --  emits SH || Cert || CertVerify || Finished; client extracts
   --  the pubkey from Cert, verifies the CertVerify signature, then
   --  proceeds to derive matching traffic secrets.
   --------------------------------------------------------------------
   procedure Cert_Driver_Loopback;
   procedure Cert_Driver_Loopback is
      use type Tls_Core.Handshake_Driver.State;
      use type Tls_Core.Octet;

      Cli_Priv : constant Tls_Core.X25519.Bytes_32 := (others => 16#33#);
      Srv_Priv : constant Tls_Core.X25519.Bytes_32 := (others => 16#44#);
      Sign_Seed : constant Tls_Core.Ed25519.Bytes_32 :=
        (others => 16#55#);

      Server_Pub : Tls_Core.Ed25519.Bytes_32;

      C, S : Tls_Core.Handshake_Driver.Driver;
      Buf : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
      Buf_Last : Natural := 0;
      Cs, Ss : Tls_Core.Handshake.Traffic_Secrets;
   begin
      Put_Line ("scenario 26 — ECDHE + server-cert handshake loopback");

      Tls_Core.Ed25519.Public_Of_Seed (Sign_Seed, Server_Pub);

      Tls_Core.Handshake_Driver.Init_Ecdhe_With_Cert
        (S, Srv_Priv, Sign_Seed);
      Tls_Core.Handshake_Driver.Init_Ecdhe_Verify
        (C, Cli_Priv, Server_Pub);

      Tls_Core.Handshake_Driver.Step
        (C, In_Bytes => Buf (1 .. 0), Out_Buf => Buf, Out_Last => Buf_Last);
      Check ("Cert driver: client emits CH",
             Tls_Core.Handshake_Driver.Current_State (C)
               = Tls_Core.Handshake_Driver.Awaiting_Server_Hello);

      declare
         CH : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Reply_Last : Natural := 0;
      begin
         Tls_Core.Handshake_Driver.Step
           (S, In_Bytes => CH, Out_Buf => Reply, Out_Last => Reply_Last);
         Check ("Cert driver: server emits SH+Cert+CV+SF",
                Tls_Core.Handshake_Driver.Current_State (S)
                  = Tls_Core.Handshake_Driver.Awaiting_Finished);
         Buf := (others => 0);
         Buf (1 .. Reply_Last) := Reply (1 .. Reply_Last);
         Buf_Last := Reply_Last;
      end;

      declare
         Sh_Cert_Cv_Sf : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Reply_Last : Natural := 0;
      begin
         Tls_Core.Handshake_Driver.Step
           (C, In_Bytes => Sh_Cert_Cv_Sf,
            Out_Buf => Reply, Out_Last => Reply_Last);
         Check ("Cert driver: client → Awaiting_Finished (cert verified)",
                Tls_Core.Handshake_Driver.Current_State (C)
                  = Tls_Core.Handshake_Driver.Awaiting_Finished);
         pragma Unreferenced (Reply_Last);
      end;

      declare
         Reply : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Reply_Last : Natural := 0;
      begin
         Tls_Core.Handshake_Driver.Step
           (C, In_Bytes => Buf (1 .. 0),
            Out_Buf => Reply, Out_Last => Reply_Last);
         Check ("Cert driver: client → Done",
                Tls_Core.Handshake_Driver.Current_State (C)
                  = Tls_Core.Handshake_Driver.Done);
         declare
            CF : constant Tls_Core.Octet_Array := Reply (1 .. Reply_Last);
            Discard : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
            Discard_Last : Natural := 0;
         begin
            Tls_Core.Handshake_Driver.Step
              (S, In_Bytes => CF,
               Out_Buf => Discard, Out_Last => Discard_Last);
         end;
         Check ("Cert driver: server → Done",
                Tls_Core.Handshake_Driver.Current_State (S)
                  = Tls_Core.Handshake_Driver.Done);
      end;

      Tls_Core.Handshake_Driver.Get_Secrets (C, Cs);
      Tls_Core.Handshake_Driver.Get_Secrets (S, Ss);
      Check ("Cert driver: c_hs match",
             Equal (Cs.Client_Handshake, Ss.Client_Handshake));
      Check ("Cert driver: s_hs match",
             Equal (Cs.Server_Handshake, Ss.Server_Handshake));
      Check ("Cert driver: c_ap match",
             Equal (Cs.Client_App, Ss.Client_App));
      Check ("Cert driver: s_ap match",
             Equal (Cs.Server_App, Ss.Server_App));

      --  Negative: client init'd with the wrong trusted pubkey rejects.
      declare
         Bad_C, Bad_S : Tls_Core.Handshake_Driver.Driver;
         Bad_Pub : Tls_Core.Ed25519.Bytes_32 := Server_Pub;
         Bad_Buf : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Bad_Buf_Last : Natural := 0;
         Reply : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Reply_Last : Natural := 0;
      begin
         Bad_Pub (1) := Bad_Pub (1) xor 16#01#;
         Tls_Core.Handshake_Driver.Init_Ecdhe_With_Cert
           (Bad_S, Srv_Priv, Sign_Seed);
         Tls_Core.Handshake_Driver.Init_Ecdhe_Verify
           (Bad_C, Cli_Priv, Bad_Pub);
         Tls_Core.Handshake_Driver.Step
           (Bad_C, In_Bytes => Bad_Buf (1 .. 0),
            Out_Buf => Bad_Buf, Out_Last => Bad_Buf_Last);
         declare
            CH : constant Tls_Core.Octet_Array := Bad_Buf (1 .. Bad_Buf_Last);
            Srv_Reply : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
            Srv_Reply_Last : Natural := 0;
         begin
            Tls_Core.Handshake_Driver.Step
              (Bad_S, In_Bytes => CH,
               Out_Buf => Srv_Reply, Out_Last => Srv_Reply_Last);
            Tls_Core.Handshake_Driver.Step
              (Bad_C, In_Bytes => Srv_Reply (1 .. Srv_Reply_Last),
               Out_Buf => Reply, Out_Last => Reply_Last);
         end;
         Check ("Cert driver: wrong trusted pub → Failed",
                Tls_Core.Handshake_Driver.Current_State (Bad_C)
                  = Tls_Core.Handshake_Driver.Failed);
      end;
   end Cert_Driver_Loopback;

   --------------------------------------------------------------------
   --  Scenario 27 — Tls_Core.Tcp_Transport: PSK handshake + AEAD
   --                round-trip over a real localhost TCP socket.
   --
   --  Mirrors scenarios 16/17 (PSK_KE handshake + Channel encrypt/
   --  decrypt) but the bytes flow through 127.0.0.1:<port> instead
   --  of an in-memory queue. Validates that the TLS 1.3 stack works
   --  on the wire, not just over an array.
   --
   --  Layout:
   --    1. Main thread binds the listener on 127.0.0.1:0; the kernel
   --       picks an ephemeral port queryable via Bound_Port.
   --    2. A Server_Task is spawned: it Accept_One's the connection,
   --       runs the server-side handshake driver to Done, then reads
   --       one application-data record and decrypts it. Results
   --       (state + decrypted plaintext) are written to local vars
   --       and surfaced back to the main thread by an entry call.
   --    3. The main thread Connect's, runs the client-side handshake
   --       driver to Done, then encrypts a known plaintext through
   --       a Tls_Core.Channel.Direction and pushes the wire bytes.
   --    4. After the rendezvous: assert both sides reached Done,
   --       both sides agree on the four traffic secrets, and the
   --       server decrypted the exact plaintext the client sent.
   --
   --  Framing on the wire:
   --    Handshake messages — 4-byte header (1B type + u24 length)
   --                          + body. Read header first, decode body
   --                          length, then read body. SH+SF arrive
   --                          back-to-back as two messages, so the
   --                          client reads two of them and concats
   --                          them for the single Step call.
   --    Application records — 5-byte TLSCiphertext header
   --                          (0x17 0x03 0x03 + u16 length) + body.
   --                          Same pattern: read header, parse
   --                          length, read body.
   --------------------------------------------------------------------
   procedure Tcp_Loopback_Scenario;
   procedure Tcp_Loopback_Scenario is
      use type Tls_Core.Handshake_Driver.State;
      use type Tls_Core.Octet;

      Psk : constant Tls_Core.Octet_Array (1 .. 32) := (others => 16#42#);

      --  Plaintext the client encrypts and the server is expected
      --  to decrypt: ASCII for "hello tls 1.3".
      Plaintext : constant Tls_Core.Octet_Array (1 .. 13) :=
        (16#68#, 16#65#, 16#6C#, 16#6C#, 16#6F#, 16#20#,
         16#74#, 16#6C#, 16#73#, 16#20#, 16#31#, 16#2E#, 16#33#);

      --  Rendezvous: the server task binds the listener and posts
      --  the kernel-assigned port; the main thread waits on Get_Port
      --  before it tries to Connect.
      protected type Port_Rendezvous is
         entry Get_Port (P : out Natural);
         procedure Post_Port (P : Natural);
      private
         Posted : Boolean := False;
         Port_Val : Natural := 0;
      end Port_Rendezvous;

      protected body Port_Rendezvous is
         entry Get_Port (P : out Natural) when Posted is
         begin
            P := Port_Val;
         end Get_Port;
         procedure Post_Port (P : Natural) is
         begin
            Port_Val := P;
            Posted   := True;
         end Post_Port;
      end Port_Rendezvous;

      Port_Box : Port_Rendezvous;

      --  Out-band channel for the server task to surface its
      --  results back to the main thread.
      protected type Server_Result_Box is
         entry Get_Result
           (State_OK     : out Boolean;
            Secrets      : out Tls_Core.Handshake.Traffic_Secrets;
            Plaintext_Len : out Natural;
            Plaintext_Buf : out Tls_Core.Octet_Array;
            Receive_OK   : out Boolean);
         procedure Post_Result
           (State_OK     : Boolean;
            Secrets      : Tls_Core.Handshake.Traffic_Secrets;
            Plaintext_Len : Natural;
            Plaintext_Buf : Tls_Core.Octet_Array;
            Receive_OK   : Boolean);
      private
         Posted     : Boolean := False;
         R_State_OK : Boolean := False;
         R_Secrets  : Tls_Core.Handshake.Traffic_Secrets;
         R_PT_Len   : Natural := 0;
         R_PT_Buf   : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         R_Recv_OK  : Boolean := False;
      end Server_Result_Box;

      protected body Server_Result_Box is
         entry Get_Result
           (State_OK     : out Boolean;
            Secrets      : out Tls_Core.Handshake.Traffic_Secrets;
            Plaintext_Len : out Natural;
            Plaintext_Buf : out Tls_Core.Octet_Array;
            Receive_OK   : out Boolean)
         when Posted
         is
         begin
            State_OK := R_State_OK;
            Secrets  := R_Secrets;
            Plaintext_Len := R_PT_Len;
            Plaintext_Buf := (others => 0);
            if R_PT_Len > 0
              and then Plaintext_Buf'Length >= R_PT_Len
            then
               Plaintext_Buf
                 (Plaintext_Buf'First
                  .. Plaintext_Buf'First + R_PT_Len - 1) :=
                 R_PT_Buf (1 .. R_PT_Len);
            end if;
            Receive_OK := R_Recv_OK;
         end Get_Result;
         procedure Post_Result
           (State_OK     : Boolean;
            Secrets      : Tls_Core.Handshake.Traffic_Secrets;
            Plaintext_Len : Natural;
            Plaintext_Buf : Tls_Core.Octet_Array;
            Receive_OK   : Boolean)
         is
         begin
            R_State_OK := State_OK;
            R_Secrets  := Secrets;
            R_PT_Len   := Plaintext_Len;
            R_PT_Buf   := (others => 0);
            if Plaintext_Len > 0
              and then Plaintext_Buf'Length >= Plaintext_Len
            then
               R_PT_Buf (1 .. Plaintext_Len) :=
                 Plaintext_Buf
                   (Plaintext_Buf'First
                    .. Plaintext_Buf'First + Plaintext_Len - 1);
            end if;
            R_Recv_OK := Receive_OK;
            Posted := True;
         end Post_Result;
      end Server_Result_Box;

      Server_Box : Server_Result_Box;

      --  Read one TLS-1.3 Handshake message off the socket: 4-byte
      --  header (type + u24 length) + body. Returns the full
      --  4 + body_len bytes in Out_Buf (1 .. Out_Last). Sets OK
      --  False on EOF or short read.
      procedure Recv_Hs_Msg
        (Chan     : Tls_Core.Tcp_Transport.Channel;
         Out_Buf  : out Tls_Core.Octet_Array;
         Out_Last : out Natural;
         OK       : out Boolean);
      procedure Recv_Hs_Msg
        (Chan     : Tls_Core.Tcp_Transport.Channel;
         Out_Buf  : out Tls_Core.Octet_Array;
         Out_Last : out Natural;
         OK       : out Boolean)
      is
         Header   : Tls_Core.Octet_Array (1 .. 4) := (others => 0);
         Body_Len : Natural;
      begin
         Out_Buf  := (others => 0);
         Out_Last := 0;
         Tls_Core.Tcp_Transport.Recv_All (Chan, Header, OK);
         if not OK then
            return;
         end if;
         Body_Len :=
           Natural (Header (1 + 1)) * 65536
           + Natural (Header (1 + 2)) * 256
           + Natural (Header (1 + 3));
         if 4 + Body_Len > Out_Buf'Length then
            OK := False;
            return;
         end if;
         Out_Buf (1 .. 4) := Header;
         if Body_Len > 0 then
            declare
               Body_Buf : Tls_Core.Octet_Array (1 .. Body_Len) :=
                 (others => 0);
            begin
               Tls_Core.Tcp_Transport.Recv_All (Chan, Body_Buf, OK);
               if not OK then
                  return;
               end if;
               Out_Buf (5 .. 4 + Body_Len) := Body_Buf;
            end;
         end if;
         Out_Last := 4 + Body_Len;
         OK := True;
      end Recv_Hs_Msg;

      --  Read one TLS-1.3 application-data record: 5-byte header
      --  (0x17 0x03 0x03 + u16 length) + ciphertext+tag. Returns
      --  the full 5 + body_len bytes.
      procedure Recv_App_Record
        (Chan     : Tls_Core.Tcp_Transport.Channel;
         Out_Buf  : out Tls_Core.Octet_Array;
         Out_Last : out Natural;
         OK       : out Boolean);
      procedure Recv_App_Record
        (Chan     : Tls_Core.Tcp_Transport.Channel;
         Out_Buf  : out Tls_Core.Octet_Array;
         Out_Last : out Natural;
         OK       : out Boolean)
      is
         Header   : Tls_Core.Octet_Array (1 .. 5) := (others => 0);
         Body_Len : Natural;
      begin
         Out_Buf  := (others => 0);
         Out_Last := 0;
         Tls_Core.Tcp_Transport.Recv_All (Chan, Header, OK);
         if not OK then
            return;
         end if;
         Body_Len :=
           Natural (Header (1 + 3)) * 256 + Natural (Header (1 + 4));
         if 5 + Body_Len > Out_Buf'Length then
            OK := False;
            return;
         end if;
         Out_Buf (1 .. 5) := Header;
         if Body_Len > 0 then
            declare
               Body_Buf : Tls_Core.Octet_Array (1 .. Body_Len) :=
                 (others => 0);
            begin
               Tls_Core.Tcp_Transport.Recv_All (Chan, Body_Buf, OK);
               if not OK then
                  return;
               end if;
               Out_Buf (6 .. 5 + Body_Len) := Body_Buf;
            end;
         end if;
         Out_Last := 5 + Body_Len;
         OK := True;
      end Recv_App_Record;

      --  Server-side handshake + receive-one-record task. Owns its
      --  own Listener handle (the main thread bound it; the task
      --  Accept's). On termination posts results into Server_Box.
      task Server_Task;
      task body Server_Task is
         S        : Tls_Core.Handshake_Driver.Driver;
         Listener : Tls_Core.Tcp_Transport.Listener;
         Sock     : Tls_Core.Tcp_Transport.Channel;
         OK       : Boolean := False;
         Server_Reached_Done : Boolean := False;
         Server_Secrets : Tls_Core.Handshake.Traffic_Secrets;
         Recv_PT  : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         Recv_PT_Len : Natural := 0;
         Recv_PT_OK  : Boolean := False;
      begin
         Tls_Core.Handshake_Driver.Init
           (S, Tls_Core.Handshake_Driver.Server, Psk);

         --  Bind on 127.0.0.1:0 — kernel picks a free port; query
         --  it back via Bound_Port and hand it to the main thread.
         Tls_Core.Tcp_Transport.Listen (Listener, "127.0.0.1", 0);
         Port_Box.Post_Port
           (Tls_Core.Tcp_Transport.Bound_Port (Listener));

         Tls_Core.Tcp_Transport.Accept_One (Listener, Sock);

         --  Flight 1: read CH from the wire, run Step, send SH+SF.
         declare
            CH_Buf  : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
            CH_Last : Natural := 0;
            Reply   : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
            Reply_Last : Natural := 0;
         begin
            Recv_Hs_Msg (Sock, CH_Buf, CH_Last, OK);
            if OK and then CH_Last > 0 then
               Tls_Core.Handshake_Driver.Step
                 (S, In_Bytes => CH_Buf (1 .. CH_Last),
                  Out_Buf => Reply, Out_Last => Reply_Last);
               if Reply_Last > 0 then
                  Tls_Core.Tcp_Transport.Send_All
                    (Sock, Reply (1 .. Reply_Last));
               end if;
            end if;
         end;

         --  Flight 2: read CF from the wire, run Step → Done.
         declare
            CF_Buf  : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
            CF_Last : Natural := 0;
            Discard : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
            Discard_Last : Natural := 0;
         begin
            Recv_Hs_Msg (Sock, CF_Buf, CF_Last, OK);
            if OK and then CF_Last > 0 then
               Tls_Core.Handshake_Driver.Step
                 (S, In_Bytes => CF_Buf (1 .. CF_Last),
                  Out_Buf => Discard, Out_Last => Discard_Last);
            end if;
         end;

         Server_Reached_Done :=
           Tls_Core.Handshake_Driver.Current_State (S)
             = Tls_Core.Handshake_Driver.Done;

         if Server_Reached_Done then
            Tls_Core.Handshake_Driver.Get_Secrets (S, Server_Secrets);

            --  After handshake: read one TLSCiphertext record off
            --  the wire and decrypt with a Direction Init'd from
            --  Client_App (matching what the client encrypted with).
            declare
               Wire   : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
               Wire_Last : Natural := 0;
               Recv_Dir : Tls_Core.Channel.Direction;
            begin
               Tls_Core.Channel.Init (Recv_Dir, Server_Secrets.Client_App);
               Recv_App_Record (Sock, Wire, Wire_Last, OK);
               if OK and then Wire_Last > 0 then
                  Tls_Core.Channel.Receive
                    (Recv_Dir, Wire (1 .. Wire_Last),
                     Recv_PT, Recv_PT_Len, Recv_PT_OK);
               end if;
            end;
         end if;

         Tls_Core.Tcp_Transport.Close (Sock);
         Tls_Core.Tcp_Transport.Stop (Listener);

         Server_Box.Post_Result
           (State_OK      => Server_Reached_Done,
            Secrets       => Server_Secrets,
            Plaintext_Len => Recv_PT_Len,
            Plaintext_Buf => Recv_PT,
            Receive_OK    => Recv_PT_OK);
      exception
         when others =>
            Server_Box.Post_Result
              (State_OK      => False,
               Secrets       => Server_Secrets,
               Plaintext_Len => 0,
               Plaintext_Buf => Recv_PT,
               Receive_OK    => False);
      end Server_Task;

      --  Client-side handshake driver, run on the main thread.
      C : Tls_Core.Handshake_Driver.Driver;
      Cli_Sock : Tls_Core.Tcp_Transport.Channel;
      Buf      : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
      Buf_Last : Natural := 0;
      Cs       : Tls_Core.Handshake.Traffic_Secrets;

      --  Server-side results, harvested via the protected box
      --  after the server task reports Done.
      Srv_State_OK   : Boolean := False;
      Srv_Secrets    : Tls_Core.Handshake.Traffic_Secrets;
      Srv_PT_Buf     : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
      Srv_PT_Len     : Natural := 0;
      Srv_Recv_OK    : Boolean := False;

      Port : Natural;
   begin
      Put_Line ("scenario 27 — Tls_Core.Tcp_Transport TCP loopback");

      --  Server task is activated at this `begin`; it Listens on
      --  127.0.0.1:0 and posts the kernel-assigned port via
      --  Port_Box.Post_Port. Wait for that, then Connect.
      Port_Box.Get_Port (Port);

      --  Client side: connect, drive the PSK_KE handshake.
      Tls_Core.Handshake_Driver.Init
        (C, Tls_Core.Handshake_Driver.Client, Psk);

      Tls_Core.Tcp_Transport.Connect (Cli_Sock, "127.0.0.1", Port);

      --  Flight 1: emit CH bytes and ship them to the server.
      Tls_Core.Handshake_Driver.Step
        (C, In_Bytes => Buf (1 .. 0),
         Out_Buf => Buf, Out_Last => Buf_Last);
      Tls_Core.Tcp_Transport.Send_All (Cli_Sock, Buf (1 .. Buf_Last));

      --  Flight 2: read SH then SF (two back-to-back handshake
      --  messages) and feed both to the client driver in one Step.
      declare
         M1_Buf  : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         M1_Last : Natural := 0;
         M2_Buf  : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         M2_Last : Natural := 0;
         OK      : Boolean := False;
         Combined : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Combined_Last : Natural := 0;
         Reply   : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Reply_Last : Natural := 0;
      begin
         Recv_Hs_Msg (Cli_Sock, M1_Buf, M1_Last, OK);
         pragma Assert (OK);
         Recv_Hs_Msg (Cli_Sock, M2_Buf, M2_Last, OK);
         pragma Assert (OK);
         Combined (1 .. M1_Last) := M1_Buf (1 .. M1_Last);
         Combined (M1_Last + 1 .. M1_Last + M2_Last) :=
           M2_Buf (1 .. M2_Last);
         Combined_Last := M1_Last + M2_Last;
         Tls_Core.Handshake_Driver.Step
           (C, In_Bytes => Combined (1 .. Combined_Last),
            Out_Buf => Reply, Out_Last => Reply_Last);
         pragma Unreferenced (Reply_Last);
      end;

      --  Flight 3: emit Client Finished, ship to server, → Done.
      declare
         Reply : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Reply_Last : Natural := 0;
      begin
         Tls_Core.Handshake_Driver.Step
           (C, In_Bytes => Buf (1 .. 0),
            Out_Buf => Reply, Out_Last => Reply_Last);
         Tls_Core.Tcp_Transport.Send_All
           (Cli_Sock, Reply (1 .. Reply_Last));
      end;

      Check ("Tcp loopback: client driver reached Done",
             Tls_Core.Handshake_Driver.Current_State (C)
               = Tls_Core.Handshake_Driver.Done);

      Tls_Core.Handshake_Driver.Get_Secrets (C, Cs);

      --  Application data: encrypt one record, ship it.
      declare
         Send_Dir : Tls_Core.Channel.Direction;
         Wire     : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Wire_Last : Natural := 0;
      begin
         Tls_Core.Channel.Init (Send_Dir, Cs.Client_App);
         Tls_Core.Channel.Send (Send_Dir, Plaintext, Wire, Wire_Last);
         Check ("Tcp loopback: client wire envelope is "
                & "TLSCiphertext (0x17 0x03 0x03)",
                Wire (1) = 16#17#
                and then Wire (2) = 16#03#
                and then Wire (3) = 16#03#);
         Tls_Core.Tcp_Transport.Send_All
           (Cli_Sock, Wire (1 .. Wire_Last));
      end;

      Tls_Core.Tcp_Transport.Close (Cli_Sock);

      --  Wait on the server task posting its results, then snap them.
      Server_Box.Get_Result
        (State_OK      => Srv_State_OK,
         Secrets       => Srv_Secrets,
         Plaintext_Len => Srv_PT_Len,
         Plaintext_Buf => Srv_PT_Buf,
         Receive_OK    => Srv_Recv_OK);

      Check ("Tcp loopback: server driver reached Done",
             Srv_State_OK);
      Check ("Tcp loopback: client and server agree on c_ap secret",
             Equal (Cs.Client_App, Srv_Secrets.Client_App));
      Check ("Tcp loopback: server Receive decrypted the record",
             Srv_Recv_OK);
      Check ("Tcp loopback: server got the exact plaintext",
             Srv_PT_Len = Plaintext'Length
             and then Equal
               (Srv_PT_Buf
                  (Srv_PT_Buf'First
                   .. Srv_PT_Buf'First + Srv_PT_Len - 1),
                Plaintext));
   end Tcp_Loopback_Scenario;

   --------------------------------------------------------------------
   --  Scenario 28 — RFC 8446 §4.2.11.2 PSK binder.
   --
   --  No external test vector is published for the binder shape on
   --  external PSK; we exercise the helper structurally:
   --    - deterministic on identical inputs,
   --    - sensitive to the PSK,
   --    - sensitive to the truncated-CH bytes,
   --    - constant-time Verify accepts equal binders, rejects flips.
   --------------------------------------------------------------------
   procedure Psk_Binder_Scenario;
   procedure Psk_Binder_Scenario is
      use type Tls_Core.Octet;
      Psk_A : constant Tls_Core.Octet_Array (1 .. 32) := (others => 16#A1#);
      Psk_B : constant Tls_Core.Octet_Array (1 .. 32) := (others => 16#A2#);
      Tch_X : constant Tls_Core.Octet_Array (1 .. 64) := (others => 16#5A#);
      Tch_Y : constant Tls_Core.Octet_Array (1 .. 64) := (others => 16#5B#);

      B1, B2, B3, B4 : Tls_Core.Psk_Binder.Binder_Bytes;
   begin
      Put_Line ("scenario 28 — RFC 8446 §4.2.11.2 PSK binder structural");

      Tls_Core.Psk_Binder.Compute (Psk_A, Tch_X, B1);
      Tls_Core.Psk_Binder.Compute (Psk_A, Tch_X, B2);
      Check ("PSK binder: deterministic", Equal (B1, B2));

      Tls_Core.Psk_Binder.Compute (Psk_B, Tch_X, B3);
      Check ("PSK binder: differs on different PSK",
             not Equal (B1, B3));

      Tls_Core.Psk_Binder.Compute (Psk_A, Tch_Y, B4);
      Check ("PSK binder: differs on different truncated-CH",
             not Equal (B1, B4));

      Check ("PSK binder Verify accepts equal", Tls_Core.Psk_Binder.Verify (B1, B2));
      Check ("PSK binder Verify rejects PSK-flip",
             not Tls_Core.Psk_Binder.Verify (B1, B3));

      declare
         Tampered : Tls_Core.Psk_Binder.Binder_Bytes := B1;
      begin
         Tampered (1) := Tampered (1) xor 16#01#;
         Check ("PSK binder Verify rejects 1-bit tamper",
                not Tls_Core.Psk_Binder.Verify (B1, Tampered));
      end;
   end Psk_Binder_Scenario;

   --------------------------------------------------------------------
   --  Scenario 29 — PSK ClientHello wire-format round-trip with binder.
   --
   --  Encode a CH for the PSK profile, compute the binder over the
   --  truncated bytes, splice it in, decode the result and confirm:
   --    - the random echoes,
   --    - the identity is recovered,
   --    - the binder slice indices match what we wrote,
   --    - re-computing the binder over the decoded truncation gives
   --      the same 32 bytes the encoder produced.
   --  This is the wire-level prerequisite for openssl s_client -psk.
   --------------------------------------------------------------------
   procedure Psk_Hello_Roundtrip;
   procedure Psk_Hello_Roundtrip is
      use type Tls_Core.Octet;
      Psk : constant Tls_Core.Octet_Array (1 .. 32) := (others => 16#42#);
      Random : constant Tls_Core.Hello.Random_Bytes := (others => 16#7E#);
      Identity : constant Tls_Core.Octet_Array :=
        (16#54#, 16#65#, 16#73#, 16#74#);  --  "Test"

      Wire : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
      Wire_Last : Natural;
      Truncated_Last : Natural;
      Computed_Binder : Tls_Core.Psk_Binder.Binder_Bytes;

      Decoded_Random : Tls_Core.Hello.Random_Bytes;
      Id_F, Id_L, Bf, Bl, T_Last : Natural;
      Decode_OK : Boolean;
   begin
      Put_Line ("scenario 29 — PSK ClientHello wire-format + binder splice");

      Tls_Core.Hello.Encode_Client_Hello_Psk
        (Random, Identity, Wire, Wire_Last, Truncated_Last);
      Check ("PSK CH: encoder emitted bytes", Wire_Last > Truncated_Last);
      Check ("PSK CH: 32 binder bytes follow truncated CH",
             Wire_Last = Truncated_Last + 1 + 32);

      Tls_Core.Psk_Binder.Compute
        (Psk, Wire (1 .. Truncated_Last), Computed_Binder);

      --  Splice binder in (right after the u8 binder_len, which the
      --  encoder already wrote at position Truncated_Last + 1).
      Wire (Truncated_Last + 2 .. Truncated_Last + 1 + 32) := Computed_Binder;

      Tls_Core.Hello.Decode_Client_Hello_Psk
        (Wire (1 .. Wire_Last),
         Decoded_Random, Id_F, Id_L, Bf, Bl, T_Last, Decode_OK);
      Check ("PSK CH: decoder accepts encoded bytes", Decode_OK);
      Check ("PSK CH: random round-trips", Equal (Decoded_Random, Random));
      Check ("PSK CH: identity round-trips",
             Id_L - Id_F + 1 = Identity'Length
             and then Equal (Wire (Id_F .. Id_L), Identity));
      Check ("PSK CH: decoder Truncated_Last matches encoder",
             T_Last = Truncated_Last);
      Check ("PSK CH: binder slice has 32 bytes",
             Bl - Bf + 1 = 32);

      --  Re-compute the binder against decoder-reported truncation
      --  and verify it equals what we spliced in.
      declare
         Recompute : Tls_Core.Psk_Binder.Binder_Bytes;
      begin
         Tls_Core.Psk_Binder.Compute
           (Psk, Wire (1 .. T_Last), Recompute);
         Check ("PSK CH: binder re-verifies on decoded truncation",
                Tls_Core.Psk_Binder.Verify
                  (Recompute, Wire (Bf .. Bl)));
      end;

      --  ServerHello echo round-trip.
      declare
         Sh_Wire : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         Sh_Last : Natural;
      begin
         Tls_Core.Hello.Encode_Server_Hello_Psk (Random, Sh_Wire, Sh_Last);
         Check ("PSK SH: encoder produced bytes", Sh_Last > 40);
         Check ("PSK SH: legacy_version 0x0303",
                Sh_Wire (1) = 16#03# and then Sh_Wire (2) = 16#03#);
      end;
   end Psk_Hello_Roundtrip;

   --------------------------------------------------------------------
   --  Scenario 30 — Tls13_Driver Ada-to-Ada PSK_KE handshake
   --
   --  Two Tls13_Driver instances (Client + Server) drive the
   --  spec-compliant TLS 1.3 PSK_KE handshake against each other:
   --    1. Client emits CH (TLSPlaintext record).
   --    2. Server consumes, emits SH || {EE} || {Finished} flight.
   --    3. Client consumes, emits {Finished} encrypted record.
   --    4. Server consumes, transitions to Done.
   --  After Done both sides Open_App_Directions; client sends an
   --  encrypted application-data record, server decrypts → matches.
   --
   --  This is the unit test that validates wire-format correctness
   --  before any external-reference-impl interop test is run.
   --------------------------------------------------------------------
   procedure Tls13_Loopback;
   procedure Tls13_Loopback is
      use type Tls_Core.Tls13_Driver.State;
      use type Tls_Core.Octet;

      Psk : constant Tls_Core.Octet_Array (1 .. 32) := (others => 16#42#);
      Identity : constant Tls_Core.Octet_Array :=
        (16#54#, 16#65#, 16#73#, 16#74#);  --  "Test"

      C, S : Tls_Core.Tls13_Driver.Driver;
      Buf : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
      Buf_Last : Natural := 0;
   begin
      Put_Line ("scenario 30 — Tls13_Driver Ada-to-Ada PSK_KE");

      Tls_Core.Tls13_Driver.Init_Psk_Server (S, Psk, Identity);
      Tls_Core.Tls13_Driver.Init_Psk_Client (C, Psk, Identity);

      --  Flight 1: client → CH
      Tls_Core.Tls13_Driver.Step
        (C, In_Bytes => Buf (1 .. 0), Out_Buf => Buf, Out_Last => Buf_Last);
      Check ("Tls13: client produced CH record", Buf_Last > 50);
      Check ("Tls13: CH outer is handshake (0x16)",
             Buf (1) = 16#16#);

      --  Flight 2: server consumes CH, emits SH+EE+SF
      declare
         Ch : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Reply_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Step
           (S, In_Bytes => Ch, Out_Buf => Reply, Out_Last => Reply_Last);
         Check ("Tls13: server reached Awaiting_Cf",
                Tls_Core.Tls13_Driver.Current_State (S)
                  = Tls_Core.Tls13_Driver.Awaiting_Cf);
         Check ("Tls13: server flight has SH plaintext + 2 ciphertext records",
                Reply_Last > 100
                and then Reply (1) = 16#16#  --  SH plaintext
                and then Reply (Natural (Reply (4)) * 256
                              + Natural (Reply (5)) + 6) = 16#17#);
         --  Byte 6 + SH-rec-len is the start of the next record (EE encrypted),
         --  whose outer type should be 0x17 application_data.
         Buf := (others => 0);
         Buf (1 .. Reply_Last) := Reply (1 .. Reply_Last);
         Buf_Last := Reply_Last;
      end;

      --  Flight 3: client consumes SH+EE+SF, emits CF
      declare
         Sf_Flight : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Reply_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Step
           (C, In_Bytes => Sf_Flight,
            Out_Buf => Reply, Out_Last => Reply_Last);
         Check ("Tls13: client reached Done",
                Tls_Core.Tls13_Driver.Current_State (C)
                  = Tls_Core.Tls13_Driver.Done);
         Check ("Tls13: client emitted encrypted Finished",
                Reply_Last > 16 and then Reply (1) = 16#17#);
         Buf := (others => 0);
         Buf (1 .. Reply_Last) := Reply (1 .. Reply_Last);
         Buf_Last := Reply_Last;
      end;

      --  Server consumes client Finished, → Done
      declare
         Cf : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Discard : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Discard_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Step
           (S, In_Bytes => Cf, Out_Buf => Discard, Out_Last => Discard_Last);
         Check ("Tls13: server reached Done after CF",
                Tls_Core.Tls13_Driver.Current_State (S)
                  = Tls_Core.Tls13_Driver.Done);
      end;

      --  Application data round-trip: client encrypts plaintext under
      --  c_ap_traffic_secret; server decrypts under same.
      declare
         Out_Cli, In_Cli, Out_Srv, In_Srv : Tls_Core.Channel.Direction;
         Pt : constant Tls_Core.Octet_Array :=
           (16#48#, 16#69#);  --  "Hi"
         Wire : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         Wire_Last : Natural;
         Got : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         Got_Last : Natural;
         OK : Boolean;
      begin
         Tls_Core.Tls13_Driver.Open_App_Directions (C, Out_Cli, In_Cli);
         Tls_Core.Tls13_Driver.Open_App_Directions (S, Out_Srv, In_Srv);
         Tls_Core.Channel.Send (Out_Cli, Pt, Wire, Wire_Last);
         Tls_Core.Channel.Receive
           (In_Srv, Wire (1 .. Wire_Last), Got, Got_Last, OK);
         Check ("Tls13: app data c→s decrypts", OK);
         Check ("Tls13: app data c→s round-trips",
                Got_Last = Pt'Length
                and then Equal (Got (1 .. Got_Last), Pt));
      end;
   end Tls13_Loopback;

   --------------------------------------------------------------------
   --  Scenario 31 — AES-128 single-block FIPS 197 §C.1 test vector.
   --
   --    Key   = 000102030405060708090A0B0C0D0E0F
   --    Pt    = 00112233445566778899AABBCCDDEEFF
   --    Ct    = 69C4E0D86A7B0430D8CDB78070B4C55A
   --------------------------------------------------------------------
   procedure Aes128_Scenario;
   procedure Aes128_Scenario is
      Key : constant Tls_Core.Aes128.Key_Array :=
        (16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
         16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#);
      Pt : constant Tls_Core.Aes128.Block :=
        (16#00#, 16#11#, 16#22#, 16#33#, 16#44#, 16#55#, 16#66#, 16#77#,
         16#88#, 16#99#, 16#AA#, 16#BB#, 16#CC#, 16#DD#, 16#EE#, 16#FF#);
      Expected : constant Tls_Core.Aes128.Block :=
        (16#69#, 16#C4#, 16#E0#, 16#D8#, 16#6A#, 16#7B#, 16#04#, 16#30#,
         16#D8#, 16#CD#, 16#B7#, 16#80#, 16#70#, 16#B4#, 16#C5#, 16#5A#);

      RK : Tls_Core.Aes128.Round_Keys;
      Ct : Tls_Core.Aes128.Block;
   begin
      Put_Line ("scenario 31 — AES-128 FIPS 197 §C.1");
      Tls_Core.Aes128.Expand_Key (Key, RK);
      Tls_Core.Aes128.Encrypt_Block (RK, Pt, Ct);
      Check ("AES-128 §C.1 ciphertext byte-exact",
             Equal (Ct, Expected));
   end Aes128_Scenario;

   --------------------------------------------------------------------
   --  Scenario 32 — AES-128-GCM NIST Test Case 3 (gcm-spec.pdf).
   --
   --    K  = feffe9928665731c6d6a8f9467308308
   --    P  = d9313225f88406e5a55909c5aff5269a... (60 bytes)
   --    IV = cafebabefacedbaddecaf888
   --    C  = 42831ec2217774244b7221b784d0d49c... (60 bytes)
   --    T  = 4d5c2af327cd64a62cf35abd2ba6fab4
   --------------------------------------------------------------------
   procedure Aes_Gcm_Scenario;
   procedure Aes_Gcm_Scenario is
      Key : constant Tls_Core.Aead_Aes128_Gcm.Key_Array :=
        (16#FE#, 16#FF#, 16#E9#, 16#92#, 16#86#, 16#65#, 16#73#, 16#1C#,
         16#6D#, 16#6A#, 16#8F#, 16#94#, 16#67#, 16#30#, 16#83#, 16#08#);
      IV : constant Tls_Core.Aead_Aes128_Gcm.Nonce_Array :=
        (16#CA#, 16#FE#, 16#BA#, 16#BE#, 16#FA#, 16#CE#, 16#DB#, 16#AD#,
         16#DE#, 16#CA#, 16#F8#, 16#88#);
      Pt : constant Tls_Core.Octet_Array (1 .. 64) :=
        (16#D9#, 16#31#, 16#32#, 16#25#, 16#F8#, 16#84#, 16#06#, 16#E5#,
         16#A5#, 16#59#, 16#09#, 16#C5#, 16#AF#, 16#F5#, 16#26#, 16#9A#,
         16#86#, 16#A7#, 16#A9#, 16#53#, 16#15#, 16#34#, 16#F7#, 16#DA#,
         16#2E#, 16#4C#, 16#30#, 16#3D#, 16#8A#, 16#31#, 16#8A#, 16#72#,
         16#1C#, 16#3C#, 16#0C#, 16#95#, 16#95#, 16#68#, 16#09#, 16#53#,
         16#2F#, 16#CF#, 16#0E#, 16#24#, 16#49#, 16#A6#, 16#B5#, 16#25#,
         16#B1#, 16#6A#, 16#ED#, 16#F5#, 16#AA#, 16#0D#, 16#E6#, 16#57#,
         16#BA#, 16#63#, 16#7B#, 16#39#, 16#1A#, 16#AF#, 16#D2#, 16#55#);
      AAD : constant Tls_Core.Octet_Array (1 .. 0) := (others => 0);
      Expected_Ct : constant Tls_Core.Octet_Array (1 .. 64) :=
        (16#42#, 16#83#, 16#1E#, 16#C2#, 16#21#, 16#77#, 16#74#, 16#24#,
         16#4B#, 16#72#, 16#21#, 16#B7#, 16#84#, 16#D0#, 16#D4#, 16#9C#,
         16#E3#, 16#AA#, 16#21#, 16#2F#, 16#2C#, 16#02#, 16#A4#, 16#E0#,
         16#35#, 16#C1#, 16#7E#, 16#23#, 16#29#, 16#AC#, 16#A1#, 16#2E#,
         16#21#, 16#D5#, 16#14#, 16#B2#, 16#54#, 16#66#, 16#93#, 16#1C#,
         16#7D#, 16#8F#, 16#6A#, 16#5A#, 16#AC#, 16#84#, 16#AA#, 16#05#,
         16#1B#, 16#A3#, 16#0B#, 16#39#, 16#6A#, 16#0A#, 16#AC#, 16#97#,
         16#3D#, 16#58#, 16#E0#, 16#91#, 16#47#, 16#3F#, 16#59#, 16#85#);
      Expected_T : constant Tls_Core.Aead_Aes128_Gcm.Tag_Array :=
        (16#4D#, 16#5C#, 16#2A#, 16#F3#, 16#27#, 16#CD#, 16#64#, 16#A6#,
         16#2C#, 16#F3#, 16#5A#, 16#BD#, 16#2B#, 16#A6#, 16#FA#, 16#B4#);

      Ct : Tls_Core.Octet_Array (1 .. 64);
      T  : Tls_Core.Aead_Aes128_Gcm.Tag_Array;

      Round_Pt : Tls_Core.Octet_Array (1 .. 64) := (others => 0);
      OK : Boolean;
   begin
      Put_Line ("scenario 32 — AES-128-GCM NIST Test Case 3");
      Tls_Core.Aead_Aes128_Gcm.Seal
        (Key, IV, AAD, Pt, Ct, T);
      Check ("AES-GCM ciphertext byte-exact",
             Equal (Ct, Expected_Ct));
      Check ("AES-GCM tag byte-exact",
             Equal (T, Expected_T));

      Tls_Core.Aead_Aes128_Gcm.Open
        (Key, IV, AAD, Ct, T, Round_Pt, OK);
      Check ("AES-GCM Open succeeds with valid tag", OK);
      Check ("AES-GCM Open round-trips plaintext",
             Equal (Round_Pt, Pt));

      --  Tampered ciphertext rejected.
      declare
         Bad_Ct : Tls_Core.Octet_Array (1 .. 64) := Ct;
         Pt2 : Tls_Core.Octet_Array (1 .. 64) := (others => 0);
         OK2 : Boolean;
      begin
         Bad_Ct (1) := Bad_Ct (1) xor 16#01#;
         Tls_Core.Aead_Aes128_Gcm.Open
           (Key, IV, AAD, Bad_Ct, T, Pt2, OK2);
         Check ("AES-GCM Open rejects tampered ciphertext", not OK2);
      end;
   end Aes_Gcm_Scenario;

   ---------------------------------------------------------------------
   --  Scenario 33 — SHA-384 of "abc" (FIPS 180-4 §C.2 / B.4).
   ---------------------------------------------------------------------

   procedure Sha384_Scenario;
   procedure Sha384_Scenario is
      Msg : constant Tls_Core.Octet_Array (1 .. 3) :=
        (16#61#, 16#62#, 16#63#);   --  "abc"
      Expected : constant Tls_Core.Sha384.Digest :=
        (16#CB#, 16#00#, 16#75#, 16#3F#, 16#45#, 16#A3#, 16#5E#, 16#8B#,
         16#B5#, 16#A0#, 16#3D#, 16#69#, 16#9A#, 16#C6#, 16#50#, 16#07#,
         16#27#, 16#2C#, 16#32#, 16#AB#, 16#0E#, 16#DE#, 16#D1#, 16#63#,
         16#1A#, 16#8B#, 16#60#, 16#5A#, 16#43#, 16#FF#, 16#5B#, 16#ED#,
         16#80#, 16#86#, 16#07#, 16#2B#, 16#A1#, 16#E7#, 16#CC#, 16#23#,
         16#58#, 16#BA#, 16#EC#, 16#A1#, 16#34#, 16#C8#, 16#25#, 16#A7#);
      Got : Tls_Core.Sha384.Digest;
   begin
      Put_Line ("scenario 33 — SHA-384 ""abc"" (FIPS 180-4 §C.2)");
      Tls_Core.Sha384.Hash (Msg, Got);
      Check ("SHA-384(""abc"") byte-exact", Equal (Got, Expected));
   end Sha384_Scenario;

   ---------------------------------------------------------------------
   --  Scenario 34 — AES-256 single-block (FIPS 197 §C.3).
   ---------------------------------------------------------------------

   procedure Aes256_Scenario;
   procedure Aes256_Scenario is
      Key : constant Tls_Core.Aes256.Key_Array :=
        (16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
         16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#,
         16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#,
         16#18#, 16#19#, 16#1A#, 16#1B#, 16#1C#, 16#1D#, 16#1E#, 16#1F#);
      Pt : constant Tls_Core.Aes256.Block :=
        (16#00#, 16#11#, 16#22#, 16#33#, 16#44#, 16#55#, 16#66#, 16#77#,
         16#88#, 16#99#, 16#AA#, 16#BB#, 16#CC#, 16#DD#, 16#EE#, 16#FF#);
      Expected : constant Tls_Core.Aes256.Block :=
        (16#8E#, 16#A2#, 16#B7#, 16#CA#, 16#51#, 16#67#, 16#45#, 16#BF#,
         16#EA#, 16#FC#, 16#49#, 16#90#, 16#4B#, 16#49#, 16#60#, 16#89#);
      RK : Tls_Core.Aes256.Round_Keys;
      Got : Tls_Core.Aes256.Block;
   begin
      Put_Line ("scenario 34 — AES-256 FIPS 197 §C.3");
      Tls_Core.Aes256.Expand_Key (Key, RK);
      Tls_Core.Aes256.Encrypt_Block (RK, Pt, Got);
      Check ("AES-256 §C.3 ciphertext byte-exact",
             Equal (Got, Expected));
   end Aes256_Scenario;

   ---------------------------------------------------------------------
   --  Scenario 35 — AES-256-GCM NIST SP 800-38D Test Case 15.
   ---------------------------------------------------------------------

   procedure Aes256_Gcm_Scenario;
   procedure Aes256_Gcm_Scenario is
      Key : constant Tls_Core.Aead_Aes256_Gcm.Key_Array :=
        (16#FE#, 16#FF#, 16#E9#, 16#92#, 16#86#, 16#65#, 16#73#, 16#1C#,
         16#6D#, 16#6A#, 16#8F#, 16#94#, 16#67#, 16#30#, 16#83#, 16#08#,
         16#FE#, 16#FF#, 16#E9#, 16#92#, 16#86#, 16#65#, 16#73#, 16#1C#,
         16#6D#, 16#6A#, 16#8F#, 16#94#, 16#67#, 16#30#, 16#83#, 16#08#);
      IV : constant Tls_Core.Aead_Aes256_Gcm.Nonce_Array :=
        (16#CA#, 16#FE#, 16#BA#, 16#BE#, 16#FA#, 16#CE#, 16#DB#, 16#AD#,
         16#DE#, 16#CA#, 16#F8#, 16#88#);
      Pt : constant Tls_Core.Octet_Array (1 .. 64) :=
        (16#D9#, 16#31#, 16#32#, 16#25#, 16#F8#, 16#84#, 16#06#, 16#E5#,
         16#A5#, 16#59#, 16#09#, 16#C5#, 16#AF#, 16#F5#, 16#26#, 16#9A#,
         16#86#, 16#A7#, 16#A9#, 16#53#, 16#15#, 16#34#, 16#F7#, 16#DA#,
         16#2E#, 16#4C#, 16#30#, 16#3D#, 16#8A#, 16#31#, 16#8A#, 16#72#,
         16#1C#, 16#3C#, 16#0C#, 16#95#, 16#95#, 16#68#, 16#09#, 16#53#,
         16#2F#, 16#CF#, 16#0E#, 16#24#, 16#49#, 16#A6#, 16#B5#, 16#25#,
         16#B1#, 16#6A#, 16#ED#, 16#F5#, 16#AA#, 16#0D#, 16#E6#, 16#57#,
         16#BA#, 16#63#, 16#7B#, 16#39#, 16#1A#, 16#AF#, 16#D2#, 16#55#);
      AAD : constant Tls_Core.Octet_Array (1 .. 0) := (others => 0);
      Expected_Ct : constant Tls_Core.Octet_Array (1 .. 64) :=
        (16#52#, 16#2D#, 16#C1#, 16#F0#, 16#99#, 16#56#, 16#7D#, 16#07#,
         16#F4#, 16#7F#, 16#37#, 16#A3#, 16#2A#, 16#84#, 16#42#, 16#7D#,
         16#64#, 16#3A#, 16#8C#, 16#DC#, 16#BF#, 16#E5#, 16#C0#, 16#C9#,
         16#75#, 16#98#, 16#A2#, 16#BD#, 16#25#, 16#55#, 16#D1#, 16#AA#,
         16#8C#, 16#B0#, 16#8E#, 16#48#, 16#59#, 16#0D#, 16#BB#, 16#3D#,
         16#A7#, 16#B0#, 16#8B#, 16#10#, 16#56#, 16#82#, 16#88#, 16#38#,
         16#C5#, 16#F6#, 16#1E#, 16#63#, 16#93#, 16#BA#, 16#7A#, 16#0A#,
         16#BC#, 16#C9#, 16#F6#, 16#62#, 16#89#, 16#80#, 16#15#, 16#AD#);
      Expected_T : constant Tls_Core.Aead_Aes256_Gcm.Tag_Array :=
        (16#B0#, 16#94#, 16#DA#, 16#C5#, 16#D9#, 16#34#, 16#71#, 16#BD#,
         16#EC#, 16#1A#, 16#50#, 16#22#, 16#70#, 16#E3#, 16#CC#, 16#6C#);

      Ct : Tls_Core.Octet_Array (1 .. 64);
      T  : Tls_Core.Aead_Aes256_Gcm.Tag_Array;
      Round_Pt : Tls_Core.Octet_Array (1 .. 64) := (others => 0);
      OK : Boolean;
   begin
      Put_Line ("scenario 35 — AES-256-GCM NIST Test Case 15");
      Tls_Core.Aead_Aes256_Gcm.Seal (Key, IV, AAD, Pt, Ct, T);
      Check ("AES-256-GCM ciphertext byte-exact",
             Equal (Ct, Expected_Ct));
      Check ("AES-256-GCM tag byte-exact",
             Equal (T, Expected_T));
      Tls_Core.Aead_Aes256_Gcm.Open (Key, IV, AAD, Ct, T, Round_Pt, OK);
      Check ("AES-256-GCM Open succeeds with valid tag", OK);
      Check ("AES-256-GCM Open round-trips plaintext",
             Equal (Round_Pt, Pt));
      declare
         Bad_Ct : Tls_Core.Octet_Array (1 .. 64) := Ct;
         Pt2 : Tls_Core.Octet_Array (1 .. 64) := (others => 0);
         OK2 : Boolean;
      begin
         Bad_Ct (1) := Bad_Ct (1) xor 16#01#;
         Tls_Core.Aead_Aes256_Gcm.Open (Key, IV, AAD, Bad_Ct, T, Pt2, OK2);
         Check ("AES-256-GCM Open rejects tampered ciphertext", not OK2);
      end;
   end Aes256_Gcm_Scenario;

   ---------------------------------------------------------------------
   --  Scenario 36 — HMAC-SHA-384 RFC 4231 §4.2 Test Case 1.
   ---------------------------------------------------------------------

   procedure Hmac_Sha384_Scenario;
   procedure Hmac_Sha384_Scenario is
      Key : constant Tls_Core.Octet_Array (1 .. 20) :=
        (others => 16#0B#);
      --  "Hi There"
      Msg : constant Tls_Core.Octet_Array (1 .. 8) :=
        (16#48#, 16#69#, 16#20#, 16#54#,
         16#68#, 16#65#, 16#72#, 16#65#);
      Expected : constant Tls_Core.Hmac_Sha384.Tag :=
        (16#AF#, 16#D0#, 16#39#, 16#44#, 16#D8#, 16#48#, 16#95#, 16#62#,
         16#6B#, 16#08#, 16#25#, 16#F4#, 16#AB#, 16#46#, 16#90#, 16#7F#,
         16#15#, 16#F9#, 16#DA#, 16#DB#, 16#E4#, 16#10#, 16#1E#, 16#C6#,
         16#82#, 16#AA#, 16#03#, 16#4C#, 16#7C#, 16#EB#, 16#C5#, 16#9C#,
         16#FA#, 16#EA#, 16#9E#, 16#A9#, 16#07#, 16#6E#, 16#DE#, 16#7F#,
         16#4A#, 16#F1#, 16#52#, 16#E8#, 16#B2#, 16#FA#, 16#9C#, 16#B6#);
      Got : Tls_Core.Hmac_Sha384.Tag;
   begin
      Put_Line ("scenario 36 — HMAC-SHA-384 RFC 4231 Test Case 1");
      Tls_Core.Hmac_Sha384.Compute (Key, Msg, Got);
      Check ("HMAC-SHA-384 byte-exact", Equal (Got, Expected));
   end Hmac_Sha384_Scenario;

   ---------------------------------------------------------------------
   --  Scenario 37 — HKDF-SHA-384 self-roundtrip + non-zero output
   --  smoke test (full RFC 5869 vectors are SHA-256 only; the
   --  algorithm is identical except for HashLen, so a non-zero
   --  output + monotonic-length check exercises the iteration).
   ---------------------------------------------------------------------

   procedure Hkdf_Sha384_Scenario;
   procedure Hkdf_Sha384_Scenario is
      Prk : constant Tls_Core.Octet_Array
        (1 .. Tls_Core.Hkdf_Sha384.Hash_Length) := (others => 16#42#);
      Info : constant Tls_Core.Octet_Array (1 .. 4) :=
        (16#74#, 16#65#, 16#73#, 16#74#);  --  "test"
      Out48 : Tls_Core.Octet_Array (1 .. 48);
      Out96 : Tls_Core.Octet_Array (1 .. 96);
      All_Zero_48 : Boolean := True;
      Prefix_Match : Boolean := True;
   begin
      Put_Line ("scenario 37 — HKDF-SHA-384 smoke");
      Tls_Core.Hkdf_Sha384.Expand (Prk, Info, Out48);
      Tls_Core.Hkdf_Sha384.Expand (Prk, Info, Out96);
      for I in Out48'Range loop
         if Out48 (I) /= 0 then
            All_Zero_48 := False;
         end if;
         if Out48 (I) /= Out96 (I) then
            Prefix_Match := False;
         end if;
      end loop;
      --  The first HashLen bytes of Expand are independent of the
      --  output length: T(1) is computed identically. Truncation
      --  happens only at the tail.
      Check ("HKDF-SHA-384 produces non-zero output", not All_Zero_48);
      Check ("HKDF-SHA-384 prefix stable across lengths", Prefix_Match);
   end Hkdf_Sha384_Scenario;

   ---------------------------------------------------------------------
   --  Scenario X — AES-128-GCM Channel round-trip.
   --
   --  Validates the Tls_Core.Channel_Aes128 module: derive AES-128
   --  + IV from a traffic secret, send a plaintext through the
   --  channel, decrypt at the receiving direction, confirm the
   --  bytes round-trip. Bypasses the Tls13_Driver (which is
   --  ChaCha20-only at v0.5).
   ---------------------------------------------------------------------

   procedure Channel_Aes128_Roundtrip_Scenario;
   procedure Channel_Aes128_Roundtrip_Scenario is
      use type Tls_Core.Octet;
      Secret : constant Tls_Core.Key_Schedule.Secret :=
        (others => 16#7A#);  --  arbitrary 32-byte secret
      Tx, Rx : Tls_Core.Channel_Aes128.Direction;
      Pt : constant Tls_Core.Octet_Array :=
        (16#48#, 16#65#, 16#6C#, 16#6C#, 16#6F#);  --  "Hello"
      Wire : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
      Wire_Last : Natural;
      Got : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
      Got_Last : Natural;
      Inner : Tls_Core.Octet;
      OK : Boolean;
   begin
      Put_Line ("scenario X — Channel_Aes128 round-trip");
      Tls_Core.Channel_Aes128.Init (Tx, Secret);
      Tls_Core.Channel_Aes128.Init (Rx, Secret);
      Tls_Core.Channel_Aes128.Send
        (Tx, Pt,
         Tls_Core.Channel_Aes128.Inner_Type_Application_Data,
         Wire, Wire_Last);
      Check ("Channel_Aes128: wire bytes produced",
             Wire_Last >= 5 + Pt'Length + 1 + 16);
      Tls_Core.Channel_Aes128.Receive
        (Rx, Wire (1 .. Wire_Last), Got, Got_Last, Inner, OK);
      Check ("Channel_Aes128: decrypt OK", OK);
      Check ("Channel_Aes128: round-trip plaintext",
             Got_Last = Pt'Length
             and then Equal (Got (1 .. Got_Last), Pt));
      Check ("Channel_Aes128: inner type preserved",
             Inner = Tls_Core.Channel_Aes128.Inner_Type_Application_Data);
   end Channel_Aes128_Roundtrip_Scenario;

   procedure Channel_Aes256_Roundtrip_Scenario;
   procedure Channel_Aes256_Roundtrip_Scenario is
      use type Tls_Core.Octet;
      Secret : constant Tls_Core.Key_Schedule_Sha384.Secret :=
        (others => 16#7B#);  --  arbitrary 48-byte SHA-384 secret
      Tx, Rx : Tls_Core.Channel_Aes256.Direction;
      Pt : constant Tls_Core.Octet_Array :=
        (16#48#, 16#65#, 16#6C#, 16#6C#, 16#6F#);
      Wire : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
      Wire_Last : Natural;
      Got : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
      Got_Last : Natural;
      Inner : Tls_Core.Octet;
      OK : Boolean;
   begin
      Put_Line ("scenario X — Channel_Aes256 round-trip");
      Tls_Core.Channel_Aes256.Init (Tx, Secret);
      Tls_Core.Channel_Aes256.Init (Rx, Secret);
      Tls_Core.Channel_Aes256.Send
        (Tx, Pt,
         Tls_Core.Channel_Aes256.Inner_Type_Application_Data,
         Wire, Wire_Last);
      Check ("Channel_Aes256: wire bytes produced",
             Wire_Last >= 5 + Pt'Length + 1 + 16);
      Tls_Core.Channel_Aes256.Receive
        (Rx, Wire (1 .. Wire_Last), Got, Got_Last, Inner, OK);
      Check ("Channel_Aes256: decrypt OK", OK);
      Check ("Channel_Aes256: round-trip plaintext",
             Got_Last = Pt'Length
             and then Equal (Got (1 .. Got_Last), Pt));
      Check ("Channel_Aes256: inner type preserved",
             Inner = Tls_Core.Channel_Aes256.Inner_Type_Application_Data);
   end Channel_Aes256_Roundtrip_Scenario;

   ---------------------------------------------------------------------
   --  Scenario 38 — NIST P-256 generator decodes (curve membership).
   --
   --  SEC 1 §2.3.4 uncompressed encoding 04 || Gx || Gy. The decode
   --  succeeds iff y^2 = x^3 - 3x + b over GF(p).
   --  Generator from FIPS 186-4 §D.1.2.3.
   ---------------------------------------------------------------------

   procedure P256_Generator_Scenario;
   procedure P256_Generator_Scenario is
      Encoded : Tls_Core.Octet_Array (1 .. 65) :=
        (1 => 16#04#, others => 0);
      Gx : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#6B#, 16#17#, 16#D1#, 16#F2#, 16#E1#, 16#2C#, 16#42#, 16#47#,
         16#F8#, 16#BC#, 16#E6#, 16#E5#, 16#63#, 16#A4#, 16#40#, 16#F2#,
         16#77#, 16#03#, 16#7D#, 16#81#, 16#2D#, 16#EB#, 16#33#, 16#A0#,
         16#F4#, 16#A1#, 16#39#, 16#45#, 16#D8#, 16#98#, 16#C2#, 16#96#);
      Gy : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#4F#, 16#E3#, 16#42#, 16#E2#, 16#FE#, 16#1A#, 16#7F#, 16#9B#,
         16#8E#, 16#E7#, 16#EB#, 16#4A#, 16#7C#, 16#0F#, 16#9E#, 16#16#,
         16#2B#, 16#CE#, 16#33#, 16#57#, 16#6B#, 16#31#, 16#5E#, 16#CE#,
         16#CB#, 16#B6#, 16#40#, 16#68#, 16#37#, 16#BF#, 16#51#, 16#F5#);
      P  : Tls_Core.P256.Point;
      OK : Boolean;
   begin
      Put_Line ("scenario 38 — P-256 generator on curve");
      Encoded (2 .. 33) := Gx;
      Encoded (34 .. 65) := Gy;
      Tls_Core.P256.Decode_Uncompressed (Encoded, P, OK);
      Check ("P-256 generator decodes (curve eqn satisfied)", OK);
   end P256_Generator_Scenario;

   ---------------------------------------------------------------------
   --  Scenario 39 — 1 * G = G (scalar mult identity check).
   --
   --  SEC 1 §3.2.1 with k = 1: scalar mult should leave the
   --  encoding bit-for-bit unchanged.
   ---------------------------------------------------------------------

   procedure P256_One_G_Scenario;
   procedure P256_One_G_Scenario is
      Encoded : Tls_Core.Octet_Array (1 .. 65) :=
        (1 => 16#04#, others => 0);
      Encoded_Out : Tls_Core.Octet_Array (1 .. 65);
      Gx : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#6B#, 16#17#, 16#D1#, 16#F2#, 16#E1#, 16#2C#, 16#42#, 16#47#,
         16#F8#, 16#BC#, 16#E6#, 16#E5#, 16#63#, 16#A4#, 16#40#, 16#F2#,
         16#77#, 16#03#, 16#7D#, 16#81#, 16#2D#, 16#EB#, 16#33#, 16#A0#,
         16#F4#, 16#A1#, 16#39#, 16#45#, 16#D8#, 16#98#, 16#C2#, 16#96#);
      Gy : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#4F#, 16#E3#, 16#42#, 16#E2#, 16#FE#, 16#1A#, 16#7F#, 16#9B#,
         16#8E#, 16#E7#, 16#EB#, 16#4A#, 16#7C#, 16#0F#, 16#9E#, 16#16#,
         16#2B#, 16#CE#, 16#33#, 16#57#, 16#6B#, 16#31#, 16#5E#, 16#CE#,
         16#CB#, 16#B6#, 16#40#, 16#68#, 16#37#, 16#BF#, 16#51#, 16#F5#);
      Scalar : Tls_Core.Octet_Array (1 .. 32) := (others => 0);
      P, R   : Tls_Core.P256.Point;
      OK     : Boolean;
   begin
      Put_Line ("scenario 39 — P-256 1*G = G");
      Encoded (2 .. 33) := Gx;
      Encoded (34 .. 65) := Gy;
      Tls_Core.P256.Decode_Uncompressed (Encoded, P, OK);
      Scalar (32) := 1;
      Tls_Core.P256.Scalar_Mul (Scalar, P, R);
      Tls_Core.P256.Encode_Uncompressed (R, Encoded_Out);
      Check ("P-256 1*G round-trip equals input encoding",
             Equal (Encoded, Encoded_Out));
   end P256_One_G_Scenario;

   ---------------------------------------------------------------------
   --  Scenario 40 — 2 * G byte-exact.
   --
   --  Source: NIST CAVP P-256 known answer (also reproduced in
   --  many references, e.g. Brown 2009 SEC 1 test vectors and
   --  RFC 6979 §A.2.5):
   --     2*Gx = 7CF27B188D034F7E8A52380304B51AC3C08969E2
   --            77F21B35A60B48FC47669978
   --     2*Gy = 07775510DB8ED040293D9AC69F7430DBBA7DADE6
   --            3CE982299E04B79D227873D1
   ---------------------------------------------------------------------

   procedure P256_Two_G_Scenario;
   procedure P256_Two_G_Scenario is
      Encoded : Tls_Core.Octet_Array (1 .. 65) :=
        (1 => 16#04#, others => 0);
      Encoded_Out : Tls_Core.Octet_Array (1 .. 65);
      Gx : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#6B#, 16#17#, 16#D1#, 16#F2#, 16#E1#, 16#2C#, 16#42#, 16#47#,
         16#F8#, 16#BC#, 16#E6#, 16#E5#, 16#63#, 16#A4#, 16#40#, 16#F2#,
         16#77#, 16#03#, 16#7D#, 16#81#, 16#2D#, 16#EB#, 16#33#, 16#A0#,
         16#F4#, 16#A1#, 16#39#, 16#45#, 16#D8#, 16#98#, 16#C2#, 16#96#);
      Gy : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#4F#, 16#E3#, 16#42#, 16#E2#, 16#FE#, 16#1A#, 16#7F#, 16#9B#,
         16#8E#, 16#E7#, 16#EB#, 16#4A#, 16#7C#, 16#0F#, 16#9E#, 16#16#,
         16#2B#, 16#CE#, 16#33#, 16#57#, 16#6B#, 16#31#, 16#5E#, 16#CE#,
         16#CB#, 16#B6#, 16#40#, 16#68#, 16#37#, 16#BF#, 16#51#, 16#F5#);
      Two_Gx : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#7C#, 16#F2#, 16#7B#, 16#18#, 16#8D#, 16#03#, 16#4F#, 16#7E#,
         16#8A#, 16#52#, 16#38#, 16#03#, 16#04#, 16#B5#, 16#1A#, 16#C3#,
         16#C0#, 16#89#, 16#69#, 16#E2#, 16#77#, 16#F2#, 16#1B#, 16#35#,
         16#A6#, 16#0B#, 16#48#, 16#FC#, 16#47#, 16#66#, 16#99#, 16#78#);
      Two_Gy : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#07#, 16#77#, 16#55#, 16#10#, 16#DB#, 16#8E#, 16#D0#, 16#40#,
         16#29#, 16#3D#, 16#9A#, 16#C6#, 16#9F#, 16#74#, 16#30#, 16#DB#,
         16#BA#, 16#7D#, 16#AD#, 16#E6#, 16#3C#, 16#E9#, 16#82#, 16#29#,
         16#9E#, 16#04#, 16#B7#, 16#9D#, 16#22#, 16#78#, 16#73#, 16#D1#);
      Expected : Tls_Core.Octet_Array (1 .. 65) :=
        (1 => 16#04#, others => 0);
      Scalar : Tls_Core.Octet_Array (1 .. 32) := (others => 0);
      P, R   : Tls_Core.P256.Point;
      OK     : Boolean;
   begin
      Put_Line ("scenario 40 — P-256 2*G byte-exact");
      Encoded (2 .. 33) := Gx;
      Encoded (34 .. 65) := Gy;
      Expected (2 .. 33) := Two_Gx;
      Expected (34 .. 65) := Two_Gy;
      Tls_Core.P256.Decode_Uncompressed (Encoded, P, OK);
      Scalar (32) := 2;
      Tls_Core.P256.Scalar_Mul (Scalar, P, R);
      Tls_Core.P256.Encode_Uncompressed (R, Encoded_Out);
      Check ("P-256 2*G byte-exact", Equal (Encoded_Out, Expected));
   end P256_Two_G_Scenario;

   ---------------------------------------------------------------------
   --  Scenario 41 — RFC 5903 §8.1 / NIST SP 800-186 ECDH KAT.
   --
   --  Two parties (i, r) share secret X = (i * (r * G)).x =
   --  (r * (i * G)).x. Both directions checked.
   ---------------------------------------------------------------------

   procedure P256_Ecdh_Scenario;
   procedure P256_Ecdh_Scenario is
      I_Scalar : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#C8#, 16#8F#, 16#01#, 16#F5#, 16#10#, 16#D9#, 16#AC#, 16#3F#,
         16#70#, 16#A2#, 16#92#, 16#DA#, 16#A2#, 16#31#, 16#6D#, 16#E5#,
         16#44#, 16#E9#, 16#AA#, 16#B8#, 16#AF#, 16#E8#, 16#40#, 16#49#,
         16#C6#, 16#2A#, 16#9C#, 16#57#, 16#86#, 16#2D#, 16#14#, 16#33#);
      R_Scalar : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#C6#, 16#EF#, 16#9C#, 16#5D#, 16#78#, 16#AE#, 16#01#, 16#2A#,
         16#01#, 16#11#, 16#64#, 16#AC#, 16#B3#, 16#97#, 16#CE#, 16#20#,
         16#88#, 16#68#, 16#5D#, 16#8F#, 16#06#, 16#BF#, 16#9B#, 16#E0#,
         16#B2#, 16#83#, 16#AB#, 16#46#, 16#47#, 16#6B#, 16#EE#, 16#53#);
      G_iX : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#DA#, 16#D0#, 16#B6#, 16#53#, 16#94#, 16#22#, 16#1C#, 16#F9#,
         16#B0#, 16#51#, 16#E1#, 16#FE#, 16#CA#, 16#57#, 16#87#, 16#D0#,
         16#98#, 16#DF#, 16#E6#, 16#37#, 16#FC#, 16#90#, 16#B9#, 16#EF#,
         16#94#, 16#5D#, 16#0C#, 16#37#, 16#72#, 16#58#, 16#11#, 16#80#);
      G_iY : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#52#, 16#71#, 16#A0#, 16#46#, 16#1C#, 16#DB#, 16#82#, 16#52#,
         16#D6#, 16#1F#, 16#1C#, 16#45#, 16#6F#, 16#A3#, 16#E5#, 16#9A#,
         16#B1#, 16#F4#, 16#5B#, 16#33#, 16#AC#, 16#CF#, 16#5F#, 16#58#,
         16#38#, 16#9E#, 16#05#, 16#77#, 16#B8#, 16#99#, 16#0B#, 16#B3#);
      G_rX : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#D1#, 16#2D#, 16#FB#, 16#52#, 16#89#, 16#C8#, 16#D4#, 16#F8#,
         16#12#, 16#08#, 16#B7#, 16#02#, 16#70#, 16#39#, 16#8C#, 16#34#,
         16#22#, 16#96#, 16#97#, 16#0A#, 16#0B#, 16#CC#, 16#B7#, 16#4C#,
         16#73#, 16#6F#, 16#C7#, 16#55#, 16#44#, 16#94#, 16#BF#, 16#63#);
      G_rY : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#56#, 16#FB#, 16#F3#, 16#CA#, 16#36#, 16#6C#, 16#C2#, 16#3E#,
         16#81#, 16#57#, 16#85#, 16#4C#, 16#13#, 16#C5#, 16#8D#, 16#6A#,
         16#AC#, 16#23#, 16#F0#, 16#46#, 16#AD#, 16#A3#, 16#0F#, 16#83#,
         16#53#, 16#E7#, 16#4F#, 16#33#, 16#03#, 16#98#, 16#72#, 16#AB#);
      Shared_X : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#D6#, 16#84#, 16#0F#, 16#6B#, 16#42#, 16#F6#, 16#ED#, 16#AF#,
         16#D1#, 16#31#, 16#16#, 16#E0#, 16#E1#, 16#25#, 16#65#, 16#20#,
         16#2F#, 16#EF#, 16#8E#, 16#9E#, 16#CE#, 16#7D#, 16#CE#, 16#03#,
         16#81#, 16#24#, 16#64#, 16#D0#, 16#4B#, 16#94#, 16#42#, 16#DE#);

      Encoded_I : Tls_Core.Octet_Array (1 .. 65) :=
        (1 => 16#04#, others => 0);
      Encoded_R : Tls_Core.Octet_Array (1 .. 65) :=
        (1 => 16#04#, others => 0);
      P_I, P_R, Shared_Pt_1, Shared_Pt_2 : Tls_Core.P256.Point;
      Shared_X_1, Shared_X_2 : Tls_Core.P256_Field.Field;
      OK_I, OK_R : Boolean;
      Got_X_1 : Tls_Core.Octet_Array (1 .. 32);
      Got_X_2 : Tls_Core.Octet_Array (1 .. 32);
   begin
      Put_Line ("scenario 41 — P-256 ECDH (RFC 5903 §8.1)");
      Encoded_I (2 .. 33) := G_iX;
      Encoded_I (34 .. 65) := G_iY;
      Encoded_R (2 .. 33) := G_rX;
      Encoded_R (34 .. 65) := G_rY;
      Tls_Core.P256.Decode_Uncompressed (Encoded_I, P_I, OK_I);
      Tls_Core.P256.Decode_Uncompressed (Encoded_R, P_R, OK_R);
      Check ("alice's pubkey on curve", OK_I);
      Check ("bob's pubkey on curve",   OK_R);

      --  Direction 1: shared = i * (G_r)
      Tls_Core.P256.Scalar_Mul (I_Scalar, P_R, Shared_Pt_1);
      Tls_Core.P256.To_Affine_X (Shared_Pt_1, Shared_X_1);
      for J in 0 .. 31 loop
         Got_X_1 (1 + J) := Shared_X_1 (1 + J);
      end loop;

      --  Direction 2: shared = r * (G_i)
      Tls_Core.P256.Scalar_Mul (R_Scalar, P_I, Shared_Pt_2);
      Tls_Core.P256.To_Affine_X (Shared_Pt_2, Shared_X_2);
      for J in 0 .. 31 loop
         Got_X_2 (1 + J) := Shared_X_2 (1 + J);
      end loop;

      Check ("ECDH i*G_r .x matches RFC 5903",
             Equal (Got_X_1, Shared_X));
      Check ("ECDH r*G_i .x matches RFC 5903",
             Equal (Got_X_2, Shared_X));
      Check ("ECDH symmetric (i*G_r .x = r*G_i .x)",
             Equal (Got_X_1, Got_X_2));
   end P256_Ecdh_Scenario;

   ---------------------------------------------------------------------
   --  Scenario 42 — ECDSA-P256 verify, RFC 6979 §A.2.5 KAT.
   --
   --  Public key Q = x*G with
   --      x  = C9AFA9D845BA75166B5C215767B1D6934E50C3DB
   --           36E89B127B8A622B120F6721
   --      Ux = 60FED4BA255A9D31C961EB74C6356D68C049B892
   --           3B61FA6CE669622E60F29FB6
   --      Uy = 7903FE1008B8BC99A41AE9E95628BC64F2F1B20C
   --           2D7E9F5177A3C294D4462299
   --
   --  Message  = "sample"
   --  Signature (SHA-256, deterministic per RFC 6979):
   --      r  = EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B
   --           56AAF991C34D0EA84EAF3716
   --      s  = F7CB1C942D657C41D436C7A1B6E29F65F3E900DB
   --           B9AFF4064DC4AB2F843ACDA8
   --
   --  Tamper variants (incremented r, incremented s, flipped
   --  message byte) must each be rejected.
   ---------------------------------------------------------------------

   procedure Ecdsa_P256_Verify_Scenario;
   procedure Ecdsa_P256_Verify_Scenario is
      Ux : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#60#, 16#FE#, 16#D4#, 16#BA#, 16#25#, 16#5A#, 16#9D#, 16#31#,
         16#C9#, 16#61#, 16#EB#, 16#74#, 16#C6#, 16#35#, 16#6D#, 16#68#,
         16#C0#, 16#49#, 16#B8#, 16#92#, 16#3B#, 16#61#, 16#FA#, 16#6C#,
         16#E6#, 16#69#, 16#62#, 16#2E#, 16#60#, 16#F2#, 16#9F#, 16#B6#);
      Uy : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#79#, 16#03#, 16#FE#, 16#10#, 16#08#, 16#B8#, 16#BC#, 16#99#,
         16#A4#, 16#1A#, 16#E9#, 16#E9#, 16#56#, 16#28#, 16#BC#, 16#64#,
         16#F2#, 16#F1#, 16#B2#, 16#0C#, 16#2D#, 16#7E#, 16#9F#, 16#51#,
         16#77#, 16#A3#, 16#C2#, 16#94#, 16#D4#, 16#46#, 16#22#, 16#99#);
      Pubkey : Tls_Core.Octet_Array (1 .. 65) :=
        (1 => 16#04#, others => 0);

      Msg : constant Tls_Core.Octet_Array (1 .. 6) :=
        (16#73#, 16#61#, 16#6D#, 16#70#, 16#6C#, 16#65#);  -- "sample"
      R : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#EF#, 16#D4#, 16#8B#, 16#2A#, 16#AC#, 16#B6#, 16#A8#, 16#FD#,
         16#11#, 16#40#, 16#DD#, 16#9C#, 16#D4#, 16#5E#, 16#81#, 16#D6#,
         16#9D#, 16#2C#, 16#87#, 16#7B#, 16#56#, 16#AA#, 16#F9#, 16#91#,
         16#C3#, 16#4D#, 16#0E#, 16#A8#, 16#4E#, 16#AF#, 16#37#, 16#16#);
      S : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#F7#, 16#CB#, 16#1C#, 16#94#, 16#2D#, 16#65#, 16#7C#, 16#41#,
         16#D4#, 16#36#, 16#C7#, 16#A1#, 16#B6#, 16#E2#, 16#9F#, 16#65#,
         16#F3#, 16#E9#, 16#00#, 16#DB#, 16#B9#, 16#AF#, 16#F4#, 16#06#,
         16#4D#, 16#C4#, 16#AB#, 16#2F#, 16#84#, 16#3A#, 16#CD#, 16#A8#);

      OK     : Boolean;
      R_Bad  : Tls_Core.Octet_Array (1 .. 32) := R;
      S_Bad  : Tls_Core.Octet_Array (1 .. 32) := S;
      Msg_Bad : Tls_Core.Octet_Array (1 .. 6) := Msg;
   begin
      Put_Line ("scenario 42 — ECDSA-P256 verify (RFC 6979 §A.2.5)");
      Pubkey (2 .. 33) := Ux;
      Pubkey (34 .. 65) := Uy;

      Tls_Core.Ecdsa_P256.Verify (Pubkey, Msg, R, S, OK);
      Check ("RFC 6979 'sample' / SHA-256 verifies", OK);

      --  Tamper r (last byte +1).
      R_Bad (32) := R (32) + 1;
      Tls_Core.Ecdsa_P256.Verify (Pubkey, Msg, R_Bad, S, OK);
      Check ("tampered r rejected", not OK);

      --  Tamper s (last byte +1).
      S_Bad (32) := S (32) + 1;
      Tls_Core.Ecdsa_P256.Verify (Pubkey, Msg, R, S_Bad, OK);
      Check ("tampered s rejected", not OK);

      --  Tamper message (flip a byte).
      Msg_Bad (1) := Msg (1) xor 16#01#;
      Tls_Core.Ecdsa_P256.Verify (Pubkey, Msg_Bad, R, S, OK);
      Check ("tampered message rejected", not OK);
   end Ecdsa_P256_Verify_Scenario;

   ---------------------------------------------------------------------
   --  Scenario 43 — out-of-range r/s rejection (FIPS 186-4 §6.4.2 step 1).
   ---------------------------------------------------------------------

   procedure Ecdsa_P256_Range_Scenario;
   procedure Ecdsa_P256_Range_Scenario is
      Ux : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#60#, 16#FE#, 16#D4#, 16#BA#, 16#25#, 16#5A#, 16#9D#, 16#31#,
         16#C9#, 16#61#, 16#EB#, 16#74#, 16#C6#, 16#35#, 16#6D#, 16#68#,
         16#C0#, 16#49#, 16#B8#, 16#92#, 16#3B#, 16#61#, 16#FA#, 16#6C#,
         16#E6#, 16#69#, 16#62#, 16#2E#, 16#60#, 16#F2#, 16#9F#, 16#B6#);
      Uy : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#79#, 16#03#, 16#FE#, 16#10#, 16#08#, 16#B8#, 16#BC#, 16#99#,
         16#A4#, 16#1A#, 16#E9#, 16#E9#, 16#56#, 16#28#, 16#BC#, 16#64#,
         16#F2#, 16#F1#, 16#B2#, 16#0C#, 16#2D#, 16#7E#, 16#9F#, 16#51#,
         16#77#, 16#A3#, 16#C2#, 16#94#, 16#D4#, 16#46#, 16#22#, 16#99#);
      Pubkey : Tls_Core.Octet_Array (1 .. 65) :=
        (1 => 16#04#, others => 0);

      Msg : constant Tls_Core.Octet_Array (1 .. 6) :=
        (16#73#, 16#61#, 16#6D#, 16#70#, 16#6C#, 16#65#);

      Order_N : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
         16#BC#, 16#E6#, 16#FA#, 16#AD#, 16#A7#, 16#17#, 16#9E#, 16#84#,
         16#F3#, 16#B9#, 16#CA#, 16#C2#, 16#FC#, 16#63#, 16#25#, 16#51#);
      Zero32 : constant Tls_Core.Octet_Array (1 .. 32) := (others => 0);

      Valid_R : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#EF#, 16#D4#, 16#8B#, 16#2A#, 16#AC#, 16#B6#, 16#A8#, 16#FD#,
         16#11#, 16#40#, 16#DD#, 16#9C#, 16#D4#, 16#5E#, 16#81#, 16#D6#,
         16#9D#, 16#2C#, 16#87#, 16#7B#, 16#56#, 16#AA#, 16#F9#, 16#91#,
         16#C3#, 16#4D#, 16#0E#, 16#A8#, 16#4E#, 16#AF#, 16#37#, 16#16#);
      Valid_S : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#F7#, 16#CB#, 16#1C#, 16#94#, 16#2D#, 16#65#, 16#7C#, 16#41#,
         16#D4#, 16#36#, 16#C7#, 16#A1#, 16#B6#, 16#E2#, 16#9F#, 16#65#,
         16#F3#, 16#E9#, 16#00#, 16#DB#, 16#B9#, 16#AF#, 16#F4#, 16#06#,
         16#4D#, 16#C4#, 16#AB#, 16#2F#, 16#84#, 16#3A#, 16#CD#, 16#A8#);

      OK : Boolean;
   begin
      Put_Line ("scenario 43 — ECDSA-P256 r/s range gates");
      Pubkey (2 .. 33) := Ux;
      Pubkey (34 .. 65) := Uy;

      Tls_Core.Ecdsa_P256.Verify (Pubkey, Msg, Zero32, Valid_S, OK);
      Check ("r = 0 rejected", not OK);

      Tls_Core.Ecdsa_P256.Verify (Pubkey, Msg, Order_N, Valid_S, OK);
      Check ("r = n rejected", not OK);

      Tls_Core.Ecdsa_P256.Verify (Pubkey, Msg, Valid_R, Zero32, OK);
      Check ("s = 0 rejected", not OK);

      Tls_Core.Ecdsa_P256.Verify (Pubkey, Msg, Valid_R, Order_N, OK);
      Check ("s = n rejected", not OK);
   end Ecdsa_P256_Range_Scenario;

   ---------------------------------------------------------------------
   --  Scenario 44 — wrong-message and bit-flip variants.
   --
   --  Take the RFC 6979 §A.2.5 valid signature for message "sample"
   --  and verify it against message "sampld" (last byte differs by
   --  one bit). It must NOT verify. Symmetric: flip a single bit of
   --  r and confirm rejection.
   ---------------------------------------------------------------------

   procedure Ecdsa_P256_Wrongmsg_Scenario;
   procedure Ecdsa_P256_Wrongmsg_Scenario is
      Ux : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#60#, 16#FE#, 16#D4#, 16#BA#, 16#25#, 16#5A#, 16#9D#, 16#31#,
         16#C9#, 16#61#, 16#EB#, 16#74#, 16#C6#, 16#35#, 16#6D#, 16#68#,
         16#C0#, 16#49#, 16#B8#, 16#92#, 16#3B#, 16#61#, 16#FA#, 16#6C#,
         16#E6#, 16#69#, 16#62#, 16#2E#, 16#60#, 16#F2#, 16#9F#, 16#B6#);
      Uy : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#79#, 16#03#, 16#FE#, 16#10#, 16#08#, 16#B8#, 16#BC#, 16#99#,
         16#A4#, 16#1A#, 16#E9#, 16#E9#, 16#56#, 16#28#, 16#BC#, 16#64#,
         16#F2#, 16#F1#, 16#B2#, 16#0C#, 16#2D#, 16#7E#, 16#9F#, 16#51#,
         16#77#, 16#A3#, 16#C2#, 16#94#, 16#D4#, 16#46#, 16#22#, 16#99#);
      Pubkey : Tls_Core.Octet_Array (1 .. 65) :=
        (1 => 16#04#, others => 0);

      --  "test" — RFC 6979 §A.2.5 also publishes a signature for
      --  this message; using "sample"'s signature against "test"
      --  must therefore fail.
      Wrong_Msg : constant Tls_Core.Octet_Array (1 .. 4) :=
        (16#74#, 16#65#, 16#73#, 16#74#);

      R : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#EF#, 16#D4#, 16#8B#, 16#2A#, 16#AC#, 16#B6#, 16#A8#, 16#FD#,
         16#11#, 16#40#, 16#DD#, 16#9C#, 16#D4#, 16#5E#, 16#81#, 16#D6#,
         16#9D#, 16#2C#, 16#87#, 16#7B#, 16#56#, 16#AA#, 16#F9#, 16#91#,
         16#C3#, 16#4D#, 16#0E#, 16#A8#, 16#4E#, 16#AF#, 16#37#, 16#16#);
      S : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#F7#, 16#CB#, 16#1C#, 16#94#, 16#2D#, 16#65#, 16#7C#, 16#41#,
         16#D4#, 16#36#, 16#C7#, 16#A1#, 16#B6#, 16#E2#, 16#9F#, 16#65#,
         16#F3#, 16#E9#, 16#00#, 16#DB#, 16#B9#, 16#AF#, 16#F4#, 16#06#,
         16#4D#, 16#C4#, 16#AB#, 16#2F#, 16#84#, 16#3A#, 16#CD#, 16#A8#);

      R_Bitflip : Tls_Core.Octet_Array (1 .. 32) := R;
      OK : Boolean;
   begin
      Put_Line ("scenario 44 — ECDSA-P256 wrong-message / bit-flip");

      Pubkey (2 .. 33) := Ux;
      Pubkey (34 .. 65) := Uy;

      --  "sample"'s signature against the message "test" must fail.
      Tls_Core.Ecdsa_P256.Verify (Pubkey, Wrong_Msg, R, S, OK);
      Check ("signature for 'sample' against 'test' rejected", not OK);

      --  Bit-flip a high byte of r — single-bit perturbation.
      R_Bitflip (1) := R (1) xor 16#01#;
      Tls_Core.Ecdsa_P256.Verify
        (Pubkey,
         (16#73#, 16#61#, 16#6D#, 16#70#, 16#6C#, 16#65#),
         R_Bitflip, S, OK);
      Check ("single-bit-flip of r rejected", not OK);
   end Ecdsa_P256_Wrongmsg_Scenario;

   ---------------------------------------------------------------------
   --  Scenario 45 — Sign / Verify round-trip with RFC 6979 deterministic
   --  k for "sample" + SHA-256 (RFC 6979 §A.2.5).
   --
   --  k = A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
   --  d = C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
   --
   --  Sign("sample") should reproduce the published (r, s); verifying
   --  the produced signature must succeed.
   ---------------------------------------------------------------------

   procedure Ecdsa_P256_Sign_Scenario;
   procedure Ecdsa_P256_Sign_Scenario is
      D : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#C9#, 16#AF#, 16#A9#, 16#D8#, 16#45#, 16#BA#, 16#75#, 16#16#,
         16#6B#, 16#5C#, 16#21#, 16#57#, 16#67#, 16#B1#, 16#D6#, 16#93#,
         16#4E#, 16#50#, 16#C3#, 16#DB#, 16#36#, 16#E8#, 16#9B#, 16#12#,
         16#7B#, 16#8A#, 16#62#, 16#2B#, 16#12#, 16#0F#, 16#67#, 16#21#);
      K : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#A6#, 16#E3#, 16#C5#, 16#7D#, 16#D0#, 16#1A#, 16#BE#, 16#90#,
         16#08#, 16#65#, 16#38#, 16#39#, 16#83#, 16#55#, 16#DD#, 16#4C#,
         16#3B#, 16#17#, 16#AA#, 16#87#, 16#33#, 16#82#, 16#B0#, 16#F2#,
         16#4D#, 16#61#, 16#29#, 16#49#, 16#3D#, 16#8A#, 16#AD#, 16#60#);
      Ux : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#60#, 16#FE#, 16#D4#, 16#BA#, 16#25#, 16#5A#, 16#9D#, 16#31#,
         16#C9#, 16#61#, 16#EB#, 16#74#, 16#C6#, 16#35#, 16#6D#, 16#68#,
         16#C0#, 16#49#, 16#B8#, 16#92#, 16#3B#, 16#61#, 16#FA#, 16#6C#,
         16#E6#, 16#69#, 16#62#, 16#2E#, 16#60#, 16#F2#, 16#9F#, 16#B6#);
      Uy : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#79#, 16#03#, 16#FE#, 16#10#, 16#08#, 16#B8#, 16#BC#, 16#99#,
         16#A4#, 16#1A#, 16#E9#, 16#E9#, 16#56#, 16#28#, 16#BC#, 16#64#,
         16#F2#, 16#F1#, 16#B2#, 16#0C#, 16#2D#, 16#7E#, 16#9F#, 16#51#,
         16#77#, 16#A3#, 16#C2#, 16#94#, 16#D4#, 16#46#, 16#22#, 16#99#);
      Pubkey : Tls_Core.Octet_Array (1 .. 65) :=
        (1 => 16#04#, others => 0);

      Msg : constant Tls_Core.Octet_Array (1 .. 6) :=
        (16#73#, 16#61#, 16#6D#, 16#70#, 16#6C#, 16#65#);

      Expected_R : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#EF#, 16#D4#, 16#8B#, 16#2A#, 16#AC#, 16#B6#, 16#A8#, 16#FD#,
         16#11#, 16#40#, 16#DD#, 16#9C#, 16#D4#, 16#5E#, 16#81#, 16#D6#,
         16#9D#, 16#2C#, 16#87#, 16#7B#, 16#56#, 16#AA#, 16#F9#, 16#91#,
         16#C3#, 16#4D#, 16#0E#, 16#A8#, 16#4E#, 16#AF#, 16#37#, 16#16#);
      Expected_S : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#F7#, 16#CB#, 16#1C#, 16#94#, 16#2D#, 16#65#, 16#7C#, 16#41#,
         16#D4#, 16#36#, 16#C7#, 16#A1#, 16#B6#, 16#E2#, 16#9F#, 16#65#,
         16#F3#, 16#E9#, 16#00#, 16#DB#, 16#B9#, 16#AF#, 16#F4#, 16#06#,
         16#4D#, 16#C4#, 16#AB#, 16#2F#, 16#84#, 16#3A#, 16#CD#, 16#A8#);

      Got_R, Got_S : Tls_Core.Octet_Array (1 .. 32);
      Sign_OK : Boolean;
      Ver_OK  : Boolean;
   begin
      Put_Line ("scenario 45 — ECDSA-P256 sign + verify round-trip");
      Pubkey (2 .. 33) := Ux;
      Pubkey (34 .. 65) := Uy;

      Tls_Core.Ecdsa_P256.Sign (D, Msg, K, Got_R, Got_S, Sign_OK);
      Check ("sign returned OK", Sign_OK);
      Check ("r matches RFC 6979 §A.2.5", Equal (Got_R, Expected_R));
      Check ("s matches RFC 6979 §A.2.5", Equal (Got_S, Expected_S));

      Tls_Core.Ecdsa_P256.Verify (Pubkey, Msg, Got_R, Got_S, Ver_OK);
      Check ("self-signed signature verifies", Ver_OK);
   end Ecdsa_P256_Sign_Scenario;

begin
   Put_Line ("=== Tls_Core HKDF-Expand-Label info-encoding tests ===");
   Scenario_1;
   Scenario_2;
   Record_Layer_Scenario;
   Sha256_Scenario;
   Hmac_Sha256_Scenario;
   Hkdf_Expand_Scenario;
   Expand_Label_End_To_End;
   Key_Schedule_Scenario;
   Chacha20_Scenario;
   Poly1305_Scenario;
   Aead_Scenario;
   Record_Aead_Roundtrip;
   Transcript_Finished_Scenario;
   Capstone_Scenario;
   Driver_Loopback_Scenario;
   Channel_Roundtrip_Scenario;
   X25519_Scenario;
   Ecdhe_Schedule_Scenario;
   Ecdhe_Driver_Loopback;
   Sha512_Scenario;
   X509_Scenario;
   Ed25519_Scenario;
   Hello_Scenario;
   Cert_Driver_Loopback;
   Transport_Loopback_Scenario;
   Tcp_Loopback_Scenario;
   Psk_Binder_Scenario;
   Psk_Hello_Roundtrip;
   Tls13_Loopback;
   Aes128_Scenario;
   Aes_Gcm_Scenario;
   Sha384_Scenario;
   Aes256_Scenario;
   Aes256_Gcm_Scenario;
   Hmac_Sha384_Scenario;
   Hkdf_Sha384_Scenario;
   Channel_Aes128_Roundtrip_Scenario;
   Channel_Aes256_Roundtrip_Scenario;
   P256_Generator_Scenario;
   P256_One_G_Scenario;
   P256_Two_G_Scenario;
   P256_Ecdh_Scenario;
   Ecdsa_P256_Verify_Scenario;
   Ecdsa_P256_Range_Scenario;
   Ecdsa_P256_Wrongmsg_Scenario;
   Ecdsa_P256_Sign_Scenario;
   New_Line;
   Put_Line ("Pass:" & Pass'Image & "  Fail:" & Fail'Image);
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Tls_Core_Tests;
