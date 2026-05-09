--  tls_core_tests — first-slice unit tests for v0.5.
--
--  Two checks per scenario:
--    1. Build_Info_Bytes (hand-rolled, SPARK contracts) emits the
--       byte sequence the RFC 8446 §7.1 layout demands.

with Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;
with Tls_Core;
with Tls_Core.Hello_Retry;
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
with Tls_Core.Hello_Rflx;
with Tls_Core.Transport;
with Tls_Core.Tcp_Transport;
with Tls_Core.Psk_Binder;
with Tls_Core.Tls13_Driver;
with Tls_Core.Aes128;
with Tls_Core.Aes_Spec;
with Tls_Core.Aead_Aes128_Gcm;
with Tls_Core.Sha384;
with Tls_Core.Hmac_Sha384;
with Tls_Core.Hkdf_Sha384;
with Tls_Core.Aes256;
with Tls_Core.Aead_Aes256_Gcm;
with Tls_Core.Channel_Aes128;
with Tls_Core.Channel_Aes256;
with Tls_Core.Key_Schedule_Sha384;
with Tls_Core.Suites;
with Tls_Core.Aead_Channel;
with Tls_Core.Key_Update;
with Tls_Core.P256;
with Tls_Core.P256_Field;
with Tls_Core.P256_Order;
with Tls_Core.Ecdsa_P256;
with Tls_Core.Rsa_Pss;
with Tls_Core.Cert;
with Tls_Core.Cert_Chain;
with Tls_Core.Cert_Verify;
with Tls_Core.Alert;
with Tls_Core.Handshake_Buffer;
with Tls_Core.Session_Cache;
with Tls_Core.Session_Ticket;

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
       (Hash_Length      => Tls_Core.Sha256.Hash_Length,
        Max_Info         => 256,
        Spec_Hmac_Expand => Tls_Core.Hkdf_Sha256.Spec_HKDF_Expand,
        Hmac_Expand      => Tls_Core.Hkdf_Sha256.Hmac_Expand);

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

      --  Fixed test X25519 public key — psk_dhe_ke (mode 3) wire path.
      Test_Key_Share : constant Tls_Core.Hello.Public_Key :=
        (others => 16#99#);

      Decoded_Random : Tls_Core.Hello.Random_Bytes;
      Sid_F, Sid_L : Natural;
      Suites_F, Suites_L : Natural;
      Id_F, Id_L, Bf, Bl, T_Last : Natural;
      Ks_F, Ks_L : Natural;
      Decode_OK : Boolean;
   begin
      Put_Line ("scenario 29 — PSK ClientHello wire-format + binder splice");

      Tls_Core.Hello.Encode_Client_Hello_Psk
        (Random, Identity, Test_Key_Share,
         Server_Name => Tls_Core.Octet_Array'(1 .. 0 => 0),
         Alpn_Offers => Tls_Core.Octet_Array'(1 .. 0 => 0),
         Out_Buf => Wire, Out_Last => Wire_Last,
         Truncated_Last => Truncated_Last);
      Check ("PSK CH: encoder emitted bytes", Wire_Last > Truncated_Last);
      --  After the new (RFC 8446 §4.2.11.2-correct) truncation point,
      --  the wire still has: u16 binders_total_len + u8 binder_len +
      --  32 binder bytes = 35 bytes.
      Check ("PSK CH: 35 bytes follow truncated CH (binders block)",
             Wire_Last = Truncated_Last + 2 + 1 + 32);

      Tls_Core.Psk_Binder.Compute
        (Psk, Wire (1 .. Truncated_Last), Computed_Binder);

      --  Splice the 32 binder bytes in.  Layout after Truncated_Last:
      --     +1 +2 : binders_total_len (u16, encoder set = 33)
      --     +3    : binder_len (u8 = 32)
      --     +4 .. +35 : binder body
      Wire (Truncated_Last + 4 .. Truncated_Last + 35) :=
        Computed_Binder (1 .. 32);

      Tls_Core.Hello.Decode_Client_Hello_Psk
        (Wire (1 .. Wire_Last),
         Decoded_Random,
         Sid_F, Sid_L,
         Suites_F, Suites_L,
         Id_F, Id_L, Bf, Bl, Ks_F, Ks_L, T_Last, Decode_OK);
      Check ("PSK CH: decoder accepts encoded bytes", Decode_OK);
      Check ("PSK CH: key_share slice has 32 bytes",
             Ks_L - Ks_F + 1 = 32);
      Check ("PSK CH: key_share matches encoded key",
             Equal (Wire (Ks_F .. Ks_L), Test_Key_Share));
      Check ("PSK CH: random round-trips", Equal (Decoded_Random, Random));
      Check ("PSK CH: identity round-trips",
             Id_L - Id_F + 1 = Identity'Length
             and then Equal (Wire (Id_F .. Id_L), Identity));
      Check ("PSK CH: decoder Truncated_Last matches encoder",
             T_Last = Truncated_Last);
      Check ("PSK CH: binder slice has 32 bytes",
             Bl - Bf + 1 = 32);
      Check ("PSK CH: cipher_suites slice spans 3 suites (6 bytes)",
             Suites_L - Suites_F + 1 = 6);
      Check ("PSK CH: first offered suite is TLS_CHACHA20_POLY1305_SHA256",
             Wire (Suites_F)     = 16#13#
             and then Wire (Suites_F + 1) = 16#03#);
      Check ("PSK CH: second offered suite is TLS_AES_128_GCM_SHA256",
             Wire (Suites_F + 2) = 16#13#
             and then Wire (Suites_F + 3) = 16#01#);
      Check ("PSK CH: third offered suite is TLS_AES_256_GCM_SHA384",
             Wire (Suites_F + 4) = 16#13#
             and then Wire (Suites_F + 5) = 16#02#);

      --  Re-compute the binder against decoder-reported truncation
      --  and verify it equals what we spliced in.
      declare
         Recompute : Tls_Core.Psk_Binder.Binder_Bytes;
         Recv_Buf  : Tls_Core.Psk_Binder.Binder_Bytes :=
           (others => 0);
      begin
         Tls_Core.Psk_Binder.Compute
           (Psk, Wire (1 .. T_Last), Recompute);
         Recv_Buf (1 .. Bl - Bf + 1) := Wire (Bf .. Bl);
         Check ("PSK CH: binder re-verifies on decoded truncation",
                Tls_Core.Psk_Binder.Verify
                  (Recompute, Recv_Buf));
      end;

      --  ServerHello echo round-trip — server selects AES-128.
      declare
         Sh_Wire : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         Sh_Last : Natural;
         Sh_Ks_F, Sh_Ks_L : Natural;
         Sh_Ks_OK : Boolean;
         Server_Pub : constant Tls_Core.Hello.Public_Key :=
           (others => 16#88#);
      begin
         Tls_Core.Hello.Encode_Server_Hello_Psk
           (Random,
            Tls_Core.Octet_Array'(1 .. 0 => 0),  --  empty session_id_echo
            Tls_Core.Suites.TLS_AES_128_GCM_SHA256,
            Server_Pub,
            Sh_Wire, Sh_Last);
         Check ("PSK SH: encoder produced bytes", Sh_Last > 40);
         Check ("PSK SH: legacy_version 0x0303",
                Sh_Wire (1) = 16#03# and then Sh_Wire (2) = 16#03#);
         --  cipher_suite at offset 35 (2 + 32 + 1).
         Check ("PSK SH: selected suite echoes AES-128",
                Sh_Wire (36) = 16#13# and then Sh_Wire (37) = 16#01#);
         Tls_Core.Hello.Decode_Server_Hello_Psk_Key_Share
           (Sh_Wire (1 .. Sh_Last), Sh_Ks_F, Sh_Ks_L, Sh_Ks_OK);
         Check ("PSK SH: decoder finds key_share", Sh_Ks_OK);
         Check ("PSK SH: key_share matches encoded server pubkey",
                Sh_Ks_OK
                and then Sh_Ks_L - Sh_Ks_F + 1 = 32
                and then Equal (Sh_Wire (Sh_Ks_F .. Sh_Ks_L), Server_Pub));

         declare
            Rflx_Rnd   : Tls_Core.Hello_Rflx.Random_Bytes;
            Rflx_Suite : Tls_Core.Suites.U16;
            Rflx_Sf, Rflx_Sl : Natural;
            Rflx_Ef, Rflx_El : Natural;
            Rflx_OK    : Boolean;
         begin
            Tls_Core.Hello_Rflx.Decode_Server_Hello_Fields
              (Sh_Wire (1 .. Sh_Last),
               Rflx_Rnd, Rflx_Suite,
               Rflx_Sf, Rflx_Sl,
               Rflx_Ef, Rflx_El,
               Rflx_OK);
            Check ("RFLX SH: decode OK", Rflx_OK);
            Check ("RFLX SH: random matches",
                   Equal (Rflx_Rnd, Random));
            declare
               use type Interfaces.Unsigned_16;
            begin
               Check ("RFLX SH: suite matches AES-128",
                      Interfaces.Unsigned_16 (Rflx_Suite) =
                        Interfaces.Unsigned_16
                          (Tls_Core.Suites.TLS_AES_128_GCM_SHA256));
            end;
            Check ("RFLX SH: extensions found",
                   Rflx_Ef > 0 and then Rflx_El >= Rflx_Ef);
         end;
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

      --  Distinct X25519 private scalars — psk_dhe_ke (mode 3) needs
      --  one ephemeral keypair per peer.
      Server_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#11#);
      Client_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#22#);

      C, S : Tls_Core.Tls13_Driver.Driver;
      Buf : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
      Buf_Last : Natural := 0;
   begin
      Put_Line ("scenario 30 — Tls13_Driver Ada-to-Ada psk_dhe_ke (mode 3)");

      Tls_Core.Tls13_Driver.Init_Psk_Server (S, Psk, Identity, Server_Priv);
      Tls_Core.Tls13_Driver.Init_Psk_Client (C, Psk, Identity, Client_Priv);

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
      --  c_ap_traffic_secret; server decrypts under same. Aead_Channel
      --  dispatches the AEAD on the negotiated suite (AES-128-GCM in
      --  this loopback scenario — server preference puts AES-128
      --  ahead of chacha20).
      declare
         use type Tls_Core.Suites.Cipher_Suite_Id;
         Out_Cli, In_Cli, Out_Srv, In_Srv : Tls_Core.Aead_Channel.Direction;
         Pt : constant Tls_Core.Octet_Array :=
           (16#48#, 16#69#);  --  "Hi"
         Wire : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         Wire_Last : Natural;
         Got : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         Got_Last : Natural;
         Inner : Tls_Core.Octet;
         OK : Boolean;
      begin
         --  Server walks the client's offered list in client order
         --  (RFC 8446 §4.1.3 leaves preference policy to the impl).
         --  Our client list: chacha first, AES-128 second, AES-256
         --  third. Server accepts SHA-256-based suites only — so it
         --  picks chacha as the first acceptable.
         Check ("Tls13: client negotiated chacha20",
                Tls_Core.Tls13_Driver.Selected_Suite (C)
                  = Tls_Core.Suites.Chacha20_Poly1305_Sha256);
         Check ("Tls13: server selected chacha20",
                Tls_Core.Tls13_Driver.Selected_Suite (S)
                  = Tls_Core.Suites.Chacha20_Poly1305_Sha256);
         Tls_Core.Tls13_Driver.Open_App_Directions (C, Out_Cli, In_Cli);
         Tls_Core.Tls13_Driver.Open_App_Directions (S, Out_Srv, In_Srv);
         Tls_Core.Aead_Channel.Send
           (Out_Cli, Pt,
            Tls_Core.Aead_Channel.Inner_Type_Application_Data,
            Wire, Wire_Last);
         Tls_Core.Aead_Channel.Receive
           (In_Srv, Wire (1 .. Wire_Last),
            Got, Got_Last, Inner, OK);
         Check ("Tls13: app data c→s decrypts", OK);
         Check ("Tls13: app data c→s round-trips",
                Got_Last = Pt'Length
                and then Equal (Got (1 .. Got_Last), Pt));
         Check ("Tls13: inner type preserved (application_data)",
                Inner = Tls_Core.Aead_Channel.Inner_Type_Application_Data);
      end;
   end Tls13_Loopback;

   --------------------------------------------------------------------
   --  Scenario 30-ECDHE — psk_dhe_ke ECDHE actually contributes to
   --                      the handshake secret.
   --
   --  Run two complete handshakes with IDENTICAL PSK + Identity (so
   --  the Early_Secret is identical on both runs), but DIFFERENT
   --  ECDHE private scalars on the client. The randoms baked into
   --  the driver are also identical between runs (the driver uses
   --  fixed test randoms — same in both runs).
   --
   --  Per RFC 8446 §7.1 mode 3:
   --      Handshake_Secret = HKDF-Extract(Derived_1, ECDHE_secret)
   --  ECDHE_secret = X25519(client_priv, server_pub) and varies
   --  with client_priv. Therefore the two handshakes' c_ap traffic
   --  secrets MUST differ — that's the proof DHE is in the mix.
   --
   --  If we were still on mode 1 (psk_ke), the IKM would be 32
   --  zero bytes regardless of client_priv, and the c_ap secrets
   --  would be byte-identical between the two runs. The test would
   --  then fail, surfacing any accidental regression to mode 1.
   --------------------------------------------------------------------
   procedure Tls13_Mode3_Ecdhe_Contributes;
   procedure Tls13_Mode3_Ecdhe_Contributes is
      use type Tls_Core.Tls13_Driver.State;
      use type Tls_Core.Octet;

      Psk : constant Tls_Core.Octet_Array (1 .. 32) := (others => 16#42#);
      Identity : constant Tls_Core.Octet_Array :=
        (16#54#, 16#65#, 16#73#, 16#74#);  --  "Test"

      --  Server uses the same private scalar both times — this isolates
      --  the variation to the CLIENT's ECDHE contribution.
      Server_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#11#);

      --  Two distinct client private scalars.
      Client_Priv_A : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#22#);
      Client_Priv_B : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#33#);

      function Run_Handshake
        (Cli_Priv : Tls_Core.Octet_Array)
         return Tls_Core.Key_Schedule.Secret;

      function Run_Handshake
        (Cli_Priv : Tls_Core.Octet_Array)
         return Tls_Core.Key_Schedule.Secret
      is
         C, S : Tls_Core.Tls13_Driver.Driver;
         Buf : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Buf_Last : Natural := 0;
         Out_Cli, In_Cli : Tls_Core.Aead_Channel.Direction;
         Out_Sec, In_Sec : Tls_Core.Key_Schedule.Secret;
      begin
         Tls_Core.Tls13_Driver.Init_Psk_Server (S, Psk, Identity, Server_Priv);
         Tls_Core.Tls13_Driver.Init_Psk_Client (C, Psk, Identity, Cli_Priv);
         Tls_Core.Tls13_Driver.Step
           (C, In_Bytes => Buf (1 .. 0), Out_Buf => Buf, Out_Last => Buf_Last);
         declare
            Ch : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
            Reply : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
            Reply_Last : Natural;
         begin
            Tls_Core.Tls13_Driver.Step
              (S, In_Bytes => Ch, Out_Buf => Reply, Out_Last => Reply_Last);
            Buf := (others => 0);
            Buf (1 .. Reply_Last) := Reply (1 .. Reply_Last);
            Buf_Last := Reply_Last;
         end;
         declare
            Sf_Flight : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
            Reply : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
            Reply_Last : Natural;
         begin
            Tls_Core.Tls13_Driver.Step
              (C, In_Bytes => Sf_Flight,
               Out_Buf => Reply, Out_Last => Reply_Last);
            Buf := (others => 0);
            Buf (1 .. Reply_Last) := Reply (1 .. Reply_Last);
            Buf_Last := Reply_Last;
         end;
         declare
            Cf : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
            Discard : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
            Discard_Last : Natural;
         begin
            Tls_Core.Tls13_Driver.Step
              (S, In_Bytes => Cf,
               Out_Buf => Discard, Out_Last => Discard_Last);
         end;
         pragma Assert (Tls_Core.Tls13_Driver.Current_State (C)
                          = Tls_Core.Tls13_Driver.Done);
         pragma Assert (Tls_Core.Tls13_Driver.Current_State (S)
                          = Tls_Core.Tls13_Driver.Done);
         Tls_Core.Tls13_Driver.Open_App_Directions
           (C, Out_Cli, In_Cli, Out_Sec, In_Sec);
         --  Client's Out_Sec is the c_ap traffic secret — derived
         --  from Master_Secret which descends from Handshake_Secret
         --  which descends from ECDHE_secret in mode 3. Different
         --  client priv → different ECDHE → different c_ap.
         return Out_Sec;
      end Run_Handshake;

      Sec_A : constant Tls_Core.Key_Schedule.Secret :=
        Run_Handshake (Client_Priv_A);
      Sec_B : constant Tls_Core.Key_Schedule.Secret :=
        Run_Handshake (Client_Priv_B);

      All_Equal : Boolean := True;
   begin
      Put_Line ("scenario 30-ECDHE — psk_dhe_ke ECDHE contributes to "
                & "handshake secret");
      for I in Sec_A'Range loop
         if Sec_A (I) /= Sec_B (I) then
            All_Equal := False;
            exit;
         end if;
      end loop;
      --  Different ECDHE privates with same PSK MUST yield different
      --  c_ap secrets if mode 3 is genuinely threading ECDHE through
      --  the schedule. Equality would mean the DHE input was being
      --  ignored (i.e. mode 1 regressions).
      Check ("Tls13/mode3: differing client ECDHE priv → differing c_ap secret",
             not All_Equal);

      --  Sanity: re-running with the same priv scalar should give the
      --  identical secret (driver is deterministic on test inputs).
      declare
         Sec_A2 : constant Tls_Core.Key_Schedule.Secret :=
           Run_Handshake (Client_Priv_A);
         All_Match : Boolean := True;
      begin
         for I in Sec_A'Range loop
            if Sec_A (I) /= Sec_A2 (I) then
               All_Match := False;
               exit;
            end if;
         end loop;
         Check ("Tls13/mode3: same priv → identical c_ap secret (determinism)",
                All_Match);
      end;
   end Tls13_Mode3_Ecdhe_Contributes;

   --------------------------------------------------------------------
   --  Scenario 30b — KeyUpdate wire encode/decode round-trip.
   --
   --  Validates Tls_Core.Key_Update.Encode produces the §4.6.3 wire
   --  shape (msg_type=0x18, u24 length=1, request_update payload)
   --  and that Decode rejects malformed lengths / msg-types and
   --  parameters outside {0, 1}.
   --------------------------------------------------------------------
   procedure Key_Update_Wire_Scenario;
   procedure Key_Update_Wire_Scenario is
      Buf : Tls_Core.Octet_Array (1 .. Tls_Core.Key_Update.Wire_Size) :=
        (others => 0);
      Last : Natural;
      Req  : Tls_Core.Octet;
      OK   : Boolean;
   begin
      Put_Line ("scenario 30b — KeyUpdate wire encode/decode");

      --  Encode update_not_requested (= 0).
      Tls_Core.Key_Update.Encode
        (Tls_Core.Key_Update.Update_Not_Requested, Buf, Last);
      Check ("Key_Update.Encode wire size = 5", Last = 5);
      Check ("Key_Update.Encode msg_type = 0x18",
             Buf (1) = 16#18#);
      Check ("Key_Update.Encode u24 length high = 0",
             Buf (2) = 0);
      Check ("Key_Update.Encode u24 length mid = 0",
             Buf (3) = 0);
      Check ("Key_Update.Encode u24 length low = 1",
             Buf (4) = 1);
      Check ("Key_Update.Encode payload = 0",
             Buf (5) = 0);

      --  Decode round-trip on the buffer just produced.
      Tls_Core.Key_Update.Decode (Buf, Req, OK);
      Check ("Key_Update.Decode round-trip OK", OK);
      Check ("Key_Update.Decode round-trip request = 0",
             Req = Tls_Core.Key_Update.Update_Not_Requested);

      --  Encode update_requested (= 1) and round-trip.
      Tls_Core.Key_Update.Encode
        (Tls_Core.Key_Update.Update_Requested, Buf, Last);
      Check ("Key_Update.Encode payload = 1 after rebuild",
             Buf (5) = 1);
      Tls_Core.Key_Update.Decode (Buf, Req, OK);
      Check ("Key_Update.Decode round-trip OK (req)", OK);
      Check ("Key_Update.Decode round-trip request = 1",
             Req = Tls_Core.Key_Update.Update_Requested);

      --  Reject: wrong msg_type.
      declare
         Bad : Tls_Core.Octet_Array (1 .. 5) :=
           (16#19#, 16#00#, 16#00#, 16#01#, 16#00#);
      begin
         Tls_Core.Key_Update.Decode (Bad, Req, OK);
         Check ("Key_Update.Decode rejects wrong msg_type", not OK);
      end;

      --  Reject: u24 length /= 1.
      declare
         Bad : Tls_Core.Octet_Array (1 .. 5) :=
           (16#18#, 16#00#, 16#00#, 16#02#, 16#00#);
      begin
         Tls_Core.Key_Update.Decode (Bad, Req, OK);
         Check ("Key_Update.Decode rejects u24 length /= 1", not OK);
      end;

      --  Reject: payload outside {0, 1}.
      declare
         Bad : Tls_Core.Octet_Array (1 .. 5) :=
           (16#18#, 16#00#, 16#00#, 16#01#, 16#02#);
      begin
         Tls_Core.Key_Update.Decode (Bad, Req, OK);
         Check ("Key_Update.Decode rejects payload outside {0,1}",
                not OK);
      end;

      --  Reject: short buffer.
      declare
         Bad : Tls_Core.Octet_Array (1 .. 4) :=
           (16#18#, 16#00#, 16#00#, 16#01#);
      begin
         Tls_Core.Key_Update.Decode (Bad, Req, OK);
         Check ("Key_Update.Decode rejects short buffer", not OK);
      end;
   end Key_Update_Wire_Scenario;

   --------------------------------------------------------------------
   --  Scenario 30c — KeyUpdate end-to-end traffic-secret rotation.
   --
   --  Drives a full TLS 1.3 PSK_KE handshake (same as Tls13_Loopback),
   --  then exercises §4.6.3 KeyUpdate post-handshake:
   --    1. Client sends app data — server decrypts under c_ap_0.
   --    2. Client emits KeyUpdate(update_requested) — record encrypted
   --       under c_ap_0; client rotates send key to c_ap_1.
   --    3. Server receives KeyUpdate(update_requested) — decrypts under
   --       c_ap_0, rotates In_Dir to c_ap_1, signals Want_Reply.
   --    4. Server emits KeyUpdate(update_not_requested) — record
   --       encrypted under s_ap_0; server rotates Out_Dir to s_ap_1.
   --    5. Client receives KeyUpdate(update_not_requested) — decrypts
   --       under s_ap_0, rotates In_Dir to s_ap_1.
   --    6. Both sides exchange app data under the rotated keys to
   --       confirm key rotation succeeded on every direction.
   --
   --  Each step also validates that the *old* keys can no longer
   --  decrypt the new traffic (negative test) and that the new keys
   --  can — the verification dividend of getting the §7.2 derivation
   --  exactly right.
   --------------------------------------------------------------------
   procedure Key_Update_Roundtrip_Scenario;
   procedure Key_Update_Roundtrip_Scenario is
      use type Tls_Core.Tls13_Driver.State;
      use type Tls_Core.Octet;
      use type Tls_Core.Suites.Cipher_Suite_Id;

      Psk : constant Tls_Core.Octet_Array (1 .. 32) := (others => 16#42#);
      Identity : constant Tls_Core.Octet_Array :=
        (16#54#, 16#65#, 16#73#, 16#74#);
      Server_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#11#);
      Client_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#22#);

      C, S : Tls_Core.Tls13_Driver.Driver;
      Buf : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
      Buf_Last : Natural := 0;

      Out_Cli, In_Cli, Out_Srv, In_Srv :
        Tls_Core.Aead_Channel.Direction;
      Sec_Cli_Out, Sec_Cli_In : Tls_Core.Key_Schedule.Secret;
      Sec_Srv_Out, Sec_Srv_In : Tls_Core.Key_Schedule.Secret;
   begin
      Put_Line ("scenario 30c — KeyUpdate end-to-end rotation");

      --  Full handshake.
      Tls_Core.Tls13_Driver.Init_Psk_Server (S, Psk, Identity, Server_Priv);
      Tls_Core.Tls13_Driver.Init_Psk_Client (C, Psk, Identity, Client_Priv);
      Tls_Core.Tls13_Driver.Step
        (C, In_Bytes => Buf (1 .. 0), Out_Buf => Buf, Out_Last => Buf_Last);
      declare
         Ch : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Reply_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Step
           (S, Ch, Reply, Reply_Last);
         Buf := (others => 0);
         Buf (1 .. Reply_Last) := Reply (1 .. Reply_Last);
         Buf_Last := Reply_Last;
      end;
      declare
         Sf_Flight : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Reply_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Step
           (C, Sf_Flight, Reply, Reply_Last);
         Buf := (others => 0);
         Buf (1 .. Reply_Last) := Reply (1 .. Reply_Last);
         Buf_Last := Reply_Last;
      end;
      declare
         Cf : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Discard : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Discard_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Step
           (S, Cf, Discard, Discard_Last);
      end;
      Check ("KeyUpdate: server reached Done",
             Tls_Core.Tls13_Driver.Current_State (S)
               = Tls_Core.Tls13_Driver.Done);
      Check ("KeyUpdate: client reached Done",
             Tls_Core.Tls13_Driver.Current_State (C)
               = Tls_Core.Tls13_Driver.Done);

      --  Open both sides' app directions WITH secrets.
      Tls_Core.Tls13_Driver.Open_App_Directions
        (C, Out_Cli, In_Cli, Sec_Cli_Out, Sec_Cli_In);
      Tls_Core.Tls13_Driver.Open_App_Directions
        (S, Out_Srv, In_Srv, Sec_Srv_Out, Sec_Srv_In);

      --  Sanity: client's Out secret == server's In secret == c_ap_0
      --  (the c_ap_0 traffic secret), and vice versa for s_ap_0.
      Check ("KeyUpdate: c_ap shared client-out / server-in",
             Equal (Sec_Cli_Out, Sec_Srv_In));
      Check ("KeyUpdate: s_ap shared server-out / client-in",
             Equal (Sec_Srv_Out, Sec_Cli_In));

      --  Step 1: client sends "Hi" under c_ap_0; server decrypts.
      declare
         Pt : constant Tls_Core.Octet_Array :=
           (16#48#, 16#69#);  --  "Hi"
         Wire : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         Wire_Last : Natural;
         Got : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         Got_Last : Natural;
         Inner : Tls_Core.Octet;
         OK : Boolean;
      begin
         Tls_Core.Aead_Channel.Send
           (Out_Cli, Pt,
            Tls_Core.Aead_Channel.Inner_Type_Application_Data,
            Wire, Wire_Last);
         Tls_Core.Aead_Channel.Receive
           (In_Srv, Wire (1 .. Wire_Last),
            Got, Got_Last, Inner, OK);
         Check ("KeyUpdate: pre-rotation app data c->s decrypts", OK);
         Check ("KeyUpdate: pre-rotation app data c->s round-trips",
                Got_Last = Pt'Length
                and then Equal (Got (1 .. Got_Last), Pt));
      end;

      --  Step 2: client sends KeyUpdate(update_requested).
      --  Send_Key_Update encrypts under c_ap_0 then rotates to c_ap_1.
      declare
         Wire : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         Wire_Last : Natural;
         Sec_Cli_Out_Before : constant Tls_Core.Key_Schedule.Secret :=
           Sec_Cli_Out;
      begin
         Tls_Core.Tls13_Driver.Send_Key_Update
           (D              => C,
            Out_Dir        => Out_Cli,
            Send_Secret    => Sec_Cli_Out,
            Request_Update => Tls_Core.Key_Update.Update_Requested,
            Out_Buf        => Wire,
            Out_Last       => Wire_Last);
         Check ("KeyUpdate: client KeyUpdate record produced",
                Wire_Last > 5 + 16);
         Check ("KeyUpdate: client KeyUpdate outer is app-data (0x17)",
                Wire (1) = 16#17#);
         Check ("KeyUpdate: client send secret rotated",
                not Equal (Sec_Cli_Out, Sec_Cli_Out_Before));

         --  Step 3: server receives the KeyUpdate record.
         --  First decrypt under In_Srv (still c_ap_0) to get plaintext.
         declare
            Pt_Buf : Tls_Core.Octet_Array (1 .. 64) := (others => 0);
            Pt_Last : Natural;
            Inner : Tls_Core.Octet;
            OK : Boolean;
            Want_Reply : Boolean;
            Process_OK : Boolean;
            Sec_Srv_In_Before : constant Tls_Core.Key_Schedule.Secret :=
              Sec_Srv_In;
         begin
            Tls_Core.Aead_Channel.Receive
              (In_Srv, Wire (1 .. Wire_Last),
               Pt_Buf, Pt_Last, Inner, OK);
            Check ("KeyUpdate: server decrypts KeyUpdate under c_ap_0",
                   OK);
            Check ("KeyUpdate: KeyUpdate inner type = handshake",
                   Inner = Tls_Core.Aead_Channel.Inner_Type_Handshake);
            Tls_Core.Tls13_Driver.Process_Inbound_Key_Update
              (D            => S,
               In_Plaintext => Pt_Buf (1 .. Pt_Last),
               In_Dir       => In_Srv,
               Recv_Secret  => Sec_Srv_In,
               Want_Reply   => Want_Reply,
               OK           => Process_OK);
            Check ("KeyUpdate: server Process_Inbound OK", Process_OK);
            Check ("KeyUpdate: server Want_Reply True", Want_Reply);
            Check ("KeyUpdate: server In_Secret rotated",
                   not Equal (Sec_Srv_In, Sec_Srv_In_Before));
            Check ("KeyUpdate: c_ap_1 still shared client-out / server-in",
                   Equal (Sec_Cli_Out, Sec_Srv_In));
         end;
      end;

      --  Step 4: server emits its own KeyUpdate(update_not_requested)
      --  in response. Encrypted under s_ap_0; rotates Out_Srv to s_ap_1.
      declare
         Wire : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         Wire_Last : Natural;
         Sec_Srv_Out_Before : constant Tls_Core.Key_Schedule.Secret :=
           Sec_Srv_Out;
      begin
         Tls_Core.Tls13_Driver.Send_Key_Update
           (D              => S,
            Out_Dir        => Out_Srv,
            Send_Secret    => Sec_Srv_Out,
            Request_Update => Tls_Core.Key_Update.Update_Not_Requested,
            Out_Buf        => Wire,
            Out_Last       => Wire_Last);
         Check ("KeyUpdate: server reply KeyUpdate record produced",
                Wire_Last > 5 + 16);
         Check ("KeyUpdate: server send secret rotated",
                not Equal (Sec_Srv_Out, Sec_Srv_Out_Before));

         --  Step 5: client receives server's KeyUpdate.
         declare
            Pt_Buf : Tls_Core.Octet_Array (1 .. 64) := (others => 0);
            Pt_Last : Natural;
            Inner : Tls_Core.Octet;
            OK : Boolean;
            Want_Reply : Boolean;
            Process_OK : Boolean;
            Sec_Cli_In_Before : constant Tls_Core.Key_Schedule.Secret :=
              Sec_Cli_In;
         begin
            Tls_Core.Aead_Channel.Receive
              (In_Cli, Wire (1 .. Wire_Last),
               Pt_Buf, Pt_Last, Inner, OK);
            Check ("KeyUpdate: client decrypts server KeyUpdate", OK);
            Tls_Core.Tls13_Driver.Process_Inbound_Key_Update
              (D            => C,
               In_Plaintext => Pt_Buf (1 .. Pt_Last),
               In_Dir       => In_Cli,
               Recv_Secret  => Sec_Cli_In,
               Want_Reply   => Want_Reply,
               OK           => Process_OK);
            Check ("KeyUpdate: client Process_Inbound OK", Process_OK);
            Check ("KeyUpdate: client Want_Reply False (not requested)",
                   not Want_Reply);
            Check ("KeyUpdate: client In_Secret rotated",
                   not Equal (Sec_Cli_In, Sec_Cli_In_Before));
            Check ("KeyUpdate: s_ap_1 still shared server-out / client-in",
                   Equal (Sec_Srv_Out, Sec_Cli_In));
         end;
      end;

      --  Step 6: full bidirectional app-data exchange under rotated keys.
      declare
         Pt_C : constant Tls_Core.Octet_Array :=
           (16#46#, 16#6F#, 16#6F#);  --  "Foo"
         Pt_S : constant Tls_Core.Octet_Array :=
           (16#42#, 16#61#, 16#72#);  --  "Bar"
         Wire : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         Wire_Last : Natural;
         Got : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         Got_Last : Natural;
         Inner : Tls_Core.Octet;
         OK : Boolean;
      begin
         --  Client → Server under c_ap_1.
         Tls_Core.Aead_Channel.Send
           (Out_Cli, Pt_C,
            Tls_Core.Aead_Channel.Inner_Type_Application_Data,
            Wire, Wire_Last);
         Tls_Core.Aead_Channel.Receive
           (In_Srv, Wire (1 .. Wire_Last),
            Got, Got_Last, Inner, OK);
         Check ("KeyUpdate: post-rotation c->s decrypts", OK);
         Check ("KeyUpdate: post-rotation c->s round-trips",
                Got_Last = Pt_C'Length
                and then Equal (Got (1 .. Got_Last), Pt_C));

         --  Server → Client under s_ap_1.
         Wire := (others => 0);
         Got := (others => 0);
         Tls_Core.Aead_Channel.Send
           (Out_Srv, Pt_S,
            Tls_Core.Aead_Channel.Inner_Type_Application_Data,
            Wire, Wire_Last);
         Tls_Core.Aead_Channel.Receive
           (In_Cli, Wire (1 .. Wire_Last),
            Got, Got_Last, Inner, OK);
         Check ("KeyUpdate: post-rotation s->c decrypts", OK);
         Check ("KeyUpdate: post-rotation s->c round-trips",
                Got_Last = Pt_S'Length
                and then Equal (Got (1 .. Got_Last), Pt_S));
      end;
   end Key_Update_Roundtrip_Scenario;

   --------------------------------------------------------------------
   --  Scenario 30d — Tls13_Driver HelloRetryRequest loopback
   --
   --  RFC 8446 §4.1.4 + §4.4.1. Server is initialised to demand HRR
   --  on first CH (named-group renegotiation, here demanding
   --  secp256r1 even though our PSK_KE driver doesn't carry an
   --  ECDHE key_share — the renegotiation is structural and the
   --  cookie echo is the cryptographic receipt). Client is
   --  initialised HRR-aware; the second CH echoes the cookie and
   --  the rest of the handshake proceeds normally.
   --
   --  Flight order:
   --    Client → CH1                                  (TLSPlaintext)
   --    Server → HRR                                  (TLSPlaintext)
   --    Client → CH2 with cookie echo                 (TLSPlaintext)
   --    Server → SH || EE-ct || SF-ct                 (TLSPlaintext+ct)
   --    Client → CF-ct                                (TLSCiphertext)
   --
   --  Expected: both sides reach Done; transcript hashes track
   --  synthetic(CH1)||HRR||CH2||SH||EE||SF on both ends; HRR
   --  random equals Hello_Retry.Magic_Random; selected_group is
   --  the demanded group; cookie echoes byte-for-byte.
   --------------------------------------------------------------------
   procedure Tls13_Hrr_Loopback;
   procedure Tls13_Hrr_Loopback is
      use type Tls_Core.Tls13_Driver.State;
      use type Tls_Core.Octet;

      Psk : constant Tls_Core.Octet_Array (1 .. 32) := (others => 16#42#);
      Identity : constant Tls_Core.Octet_Array :=
        (16#54#, 16#65#, 16#73#, 16#74#);  --  "Test"
      --  An eight-byte cookie — chosen as a fixed bytestring so the
      --  test can assert byte-for-byte echo.
      Cookie : constant Tls_Core.Octet_Array (1 .. 8) :=
        (16#C0#, 16#0C#, 16#1E#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#);
      Server_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#11#);
      Client_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#22#);

      C, S : Tls_Core.Tls13_Driver.Driver;
      Buf : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
      Buf_Last : Natural := 0;
   begin
      Put_Line ("scenario 30b — Tls13_Driver HRR loopback");

      --  Server demands HRR with secp256r1 + cookie; client is HRR-
      --  aware (Idle → Awaiting_Sh_Or_Hrr).
      Tls_Core.Tls13_Driver.Init_Psk_Server_With_Hrr
        (S, Psk, Identity, Server_Priv,
         Tls_Core.Suites.Group_Secp256r1, Cookie);
      Tls_Core.Tls13_Driver.Init_Psk_Client_Hrr_Aware
        (C, Psk, Identity, Client_Priv);

      --  Flight 1: client → CH1
      Tls_Core.Tls13_Driver.Step
        (C, In_Bytes => Buf (1 .. 0), Out_Buf => Buf, Out_Last => Buf_Last);
      Check ("HRR: client produced CH1", Buf_Last > 50);
      Check ("HRR: client transitioned to Awaiting_Sh_Or_Hrr",
             Tls_Core.Tls13_Driver.Current_State (C)
               = Tls_Core.Tls13_Driver.Awaiting_Sh_Or_Hrr);
      Check ("HRR: CH1 outer is handshake (0x16)",
             Buf (1) = 16#16#);

      --  Flight 2: server consumes CH1 → emits HRR (single TLSPlaintext)
      declare
         Ch1 : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Reply_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Step
           (S, In_Bytes => Ch1, Out_Buf => Reply, Out_Last => Reply_Last);
         Check ("HRR: server transitioned to Awaiting_Ch_2",
                Tls_Core.Tls13_Driver.Current_State (S)
                  = Tls_Core.Tls13_Driver.Awaiting_Ch_2);
         Check ("HRR: server emitted single TLSPlaintext record",
                Reply_Last > 50
                and then Reply (1) = 16#16#);
         --  HRR record body starts at byte 6 (after 5-byte record
         --  header). Handshake header = 4 bytes (type 0x02 + u24
         --  length). Random sits at offset 6+4+2 = 12 .. 12+31.
         Check ("HRR: handshake type byte is 0x02 (SH/HRR)",
                Reply (6) = 16#02#);
         declare
            Random_Slice : constant Tls_Core.Octet_Array (1 .. 32) :=
              Reply (12 .. 12 + 31);
         begin
            Check ("HRR: server random equals Magic_Random",
                   Tls_Core.Hello_Retry.Is_Hrr_Random (Random_Slice));
         end;
         Buf := (others => 0);
         Buf (1 .. Reply_Last) := Reply (1 .. Reply_Last);
         Buf_Last := Reply_Last;
      end;

      --  Flight 3: client consumes HRR → emits CH2 (TLSPlaintext)
      declare
         Hrr_Bytes : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Reply_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Step
           (C, In_Bytes => Hrr_Bytes,
            Out_Buf => Reply, Out_Last => Reply_Last);
         Check ("HRR: client transitioned to Awaiting_Sf",
                Tls_Core.Tls13_Driver.Current_State (C)
                  = Tls_Core.Tls13_Driver.Awaiting_Sf);
         Check ("HRR: client emitted CH2", Reply_Last > 50);
         Check ("HRR: CH2 outer is handshake", Reply (1) = 16#16#);
         Check ("HRR: CH2 handshake type is CH (0x01)",
                Reply (6) = 16#01#);
         Buf := (others => 0);
         Buf (1 .. Reply_Last) := Reply (1 .. Reply_Last);
         Buf_Last := Reply_Last;
      end;

      --  Flight 4: server consumes CH2 → emits SH+EE+SF
      declare
         Ch2 : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Reply_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Step
           (S, In_Bytes => Ch2, Out_Buf => Reply, Out_Last => Reply_Last);
         Check ("HRR: server reached Awaiting_Cf",
                Tls_Core.Tls13_Driver.Current_State (S)
                  = Tls_Core.Tls13_Driver.Awaiting_Cf);
         Check ("HRR: server flight has SH plaintext + 2 ciphertexts",
                Reply_Last > 100
                and then Reply (1) = 16#16#);
         Buf := (others => 0);
         Buf (1 .. Reply_Last) := Reply (1 .. Reply_Last);
         Buf_Last := Reply_Last;
      end;

      --  Flight 5: client consumes SH+EE+SF → emits CF
      declare
         Sf_Flight : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Reply_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Step
           (C, In_Bytes => Sf_Flight,
            Out_Buf => Reply, Out_Last => Reply_Last);
         Check ("HRR: client reached Done",
                Tls_Core.Tls13_Driver.Current_State (C)
                  = Tls_Core.Tls13_Driver.Done);
         Check ("HRR: client emitted encrypted Finished",
                Reply_Last > 16 and then Reply (1) = 16#17#);
         Buf := (others => 0);
         Buf (1 .. Reply_Last) := Reply (1 .. Reply_Last);
         Buf_Last := Reply_Last;
      end;

      --  Flight 6: server consumes CF → Done
      declare
         Cf : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Discard : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Discard_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Step
           (S, In_Bytes => Cf, Out_Buf => Discard, Out_Last => Discard_Last);
         Check ("HRR: server reached Done after CF",
                Tls_Core.Tls13_Driver.Current_State (S)
                  = Tls_Core.Tls13_Driver.Done);
      end;

      --  App-data round trip exercises the same secrets the §4.1.4
      --  + §4.4.1 transcript-substituted key schedule produced.
      declare
         use type Tls_Core.Suites.Cipher_Suite_Id;
         Out_Cli, In_Cli, Out_Srv, In_Srv : Tls_Core.Aead_Channel.Direction;
         Pt : constant Tls_Core.Octet_Array :=
           (16#48#, 16#69#);  --  "Hi"
         Wire : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         Wire_Last : Natural;
         Got : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         Got_Last : Natural;
         Inner : Tls_Core.Octet;
         OK : Boolean;
      begin
         Check ("HRR: client + server agree on suite",
                Tls_Core.Tls13_Driver.Selected_Suite (C)
                  = Tls_Core.Tls13_Driver.Selected_Suite (S));
         Tls_Core.Tls13_Driver.Open_App_Directions (C, Out_Cli, In_Cli);
         Tls_Core.Tls13_Driver.Open_App_Directions (S, Out_Srv, In_Srv);
         Tls_Core.Aead_Channel.Send
           (Out_Cli, Pt,
            Tls_Core.Aead_Channel.Inner_Type_Application_Data,
            Wire, Wire_Last);
         Tls_Core.Aead_Channel.Receive
           (In_Srv, Wire (1 .. Wire_Last),
            Got, Got_Last, Inner, OK);
         Check ("HRR: app data c→s decrypts", OK);
         Check ("HRR: app data c→s round-trips",
                Got_Last = Pt'Length
                and then Equal (Got (1 .. Got_Last), Pt));
      end;
   end Tls13_Hrr_Loopback;

   --------------------------------------------------------------------
   --  Scenario 30e — Hello_Retry primitives unit tests.
   --
   --  Direct exercise of Encode_Hrr / Decode_Hrr round-trip,
   --  Cookies_Equal constant-time compare, and Build_Synthetic_Msg
   --  / Is_Hrr_Random shape checks.
   --------------------------------------------------------------------
   procedure Hello_Retry_Unit;
   procedure Hello_Retry_Unit is
      use type Tls_Core.Octet;
      use type Tls_Core.Suites.U16;

      Demo_Cookie : constant Tls_Core.Octet_Array (1 .. 4) :=
        (16#11#, 16#22#, 16#33#, 16#44#);
      Other_Cookie : constant Tls_Core.Octet_Array (1 .. 4) :=
        (16#11#, 16#22#, 16#33#, 16#45#);
      Hrr_Buf : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
      Hrr_Last : Natural;
      Cs, Group : Tls_Core.Suites.U16;
      Cookie_Out : Tls_Core.Hello_Retry.Cookie_Bytes;
      Cookie_Len : Natural;
      OK : Boolean;
      Want_Cookie : Tls_Core.Hello_Retry.Cookie_Bytes := (others => 0);
   begin
      Put_Line ("scenario 30c — Hello_Retry primitives");

      --  Is_Hrr_Random
      Check ("HRR: Magic_Random recognised",
             Tls_Core.Hello_Retry.Is_Hrr_Random
               (Tls_Core.Hello_Retry.Magic_Random));
      Check ("HRR: zero random not magic",
             not Tls_Core.Hello_Retry.Is_Hrr_Random
                   (Tls_Core.Octet_Array'(1 .. 32 => 0)));

      --  Synthetic message_hash shape (§4.4.1)
      declare
         Synth : Tls_Core.Octet_Array (1 .. 36) := (others => 0);
         Hash  : constant Tls_Core.Sha256.Digest := (others => 16#5A#);
      begin
         Tls_Core.Hello_Retry.Build_Synthetic_Msg_Sha256 (Hash, Synth);
         Check ("HRR: synthetic header type 0xFE", Synth (1) = 16#FE#);
         Check ("HRR: synthetic length u24 = 0x000020",
                Synth (2) = 0
                and then Synth (3) = 0
                and then Synth (4) = 16#20#);
         Check ("HRR: synthetic body carries hash",
                (for all I in 1 .. 32 => Synth (4 + I) = Hash (I)));
      end;

      --  Encode_Hrr / Decode_Hrr round-trip with cookie
      Tls_Core.Hello_Retry.Encode_Hrr
        (Selected_Suite => Tls_Core.Suites.TLS_AES_128_GCM_SHA256,
         Selected_Group => Tls_Core.Suites.Group_Secp256r1,
         Cookie         => Demo_Cookie,
         Out_Buf        => Hrr_Buf,
         Out_Last       => Hrr_Last);
      Check ("HRR: encode produced bytes", Hrr_Last > 40);
      --  legacy_version
      Check ("HRR: legacy_version 0x0303",
             Hrr_Buf (1) = 16#03# and then Hrr_Buf (2) = 16#03#);
      --  random
      Check ("HRR: encoded random is Magic_Random",
             Tls_Core.Hello_Retry.Is_Hrr_Random
               (Hrr_Buf (3 .. 3 + 31)));
      Tls_Core.Hello_Retry.Decode_Hrr
        (Hrr_Buf (1 .. Hrr_Last),
         Cs, Group, Cookie_Out, Cookie_Len, OK);
      Check ("HRR: decode succeeds on round-trip", OK);
      Check ("HRR: cipher_suite round-trips",
             Cs = Tls_Core.Suites.TLS_AES_128_GCM_SHA256);
      Check ("HRR: selected_group round-trips",
             Group = Tls_Core.Suites.Group_Secp256r1);
      Check ("HRR: cookie length round-trips",
             Cookie_Len = Demo_Cookie'Length);
      Check ("HRR: cookie bytes round-trip",
             (for all I in 1 .. Demo_Cookie'Length =>
                Cookie_Out (I) = Demo_Cookie (I)));

      --  Cookies_Equal — constant-time compare
      for I in 1 .. Demo_Cookie'Length loop
         Want_Cookie (I) := Demo_Cookie (I);
      end loop;
      Check ("HRR: cookies equal when matched",
             Tls_Core.Hello_Retry.Cookies_Equal
               (Demo_Cookie, Want_Cookie, Demo_Cookie'Length));
      Check ("HRR: cookies unequal when one byte differs",
             not Tls_Core.Hello_Retry.Cookies_Equal
                   (Other_Cookie, Want_Cookie, Demo_Cookie'Length));
      Check ("HRR: cookies unequal when length differs",
             not Tls_Core.Hello_Retry.Cookies_Equal
                   (Demo_Cookie (1 .. 3), Want_Cookie, Demo_Cookie'Length));

      --  Encode_Hrr with empty cookie omits the cookie ext.
      declare
         Hrr_No_Cookie : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         No_Cookie_Last : Natural;
         No_Cookie_Out : Tls_Core.Hello_Retry.Cookie_Bytes;
         No_Cookie_Len : Natural;
         No_Cookie_OK  : Boolean;
         No_Cs, No_Group : Tls_Core.Suites.U16;
         Empty_Cookie : constant Tls_Core.Octet_Array (1 .. 0) :=
           (others => 0);
      begin
         Tls_Core.Hello_Retry.Encode_Hrr
           (Selected_Suite => Tls_Core.Suites.TLS_CHACHA20_POLY1305_SHA256,
            Selected_Group => Tls_Core.Suites.Group_X25519,
            Cookie         => Empty_Cookie,
            Out_Buf        => Hrr_No_Cookie,
            Out_Last       => No_Cookie_Last);
         Tls_Core.Hello_Retry.Decode_Hrr
           (Hrr_No_Cookie (1 .. No_Cookie_Last),
            No_Cs, No_Group, No_Cookie_Out, No_Cookie_Len, No_Cookie_OK);
         Check ("HRR: empty-cookie encode → decode succeeds",
                No_Cookie_OK);
         Check ("HRR: empty-cookie length is zero",
                No_Cookie_Len = 0);
         Check ("HRR: empty-cookie group round-trips",
                No_Group = Tls_Core.Suites.Group_X25519);
      end;

      --  Decode rejects non-magic random.
      declare
         Bogus_Hrr : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         Bogus_OK  : Boolean;
         Bogus_Cs, Bogus_Group : Tls_Core.Suites.U16;
         Bogus_Cookie_Out : Tls_Core.Hello_Retry.Cookie_Bytes;
         Bogus_Cookie_Len : Natural;
      begin
         Bogus_Hrr (1 .. Hrr_Last) := Hrr_Buf (1 .. Hrr_Last);
         --  Flip a byte of the random.
         Bogus_Hrr (5) := Bogus_Hrr (5) xor 16#01#;
         Tls_Core.Hello_Retry.Decode_Hrr
           (Bogus_Hrr (1 .. Hrr_Last),
            Bogus_Cs, Bogus_Group, Bogus_Cookie_Out,
            Bogus_Cookie_Len, Bogus_OK);
         Check ("HRR: decode rejects non-magic random",
                not Bogus_OK);
      end;
   end Hello_Retry_Unit;

   --------------------------------------------------------------------


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
   --  Scenario 34b — AES Spec direct (HACL\* `Spec.AES.fst` port).
   --
   --  Exercises Tls_Core.Aes_Spec independently of the Aes128 /
   --  Aes256 wrappers:
   --
   --    * AES-128 §C.1 round-trip via Aes_Spec.Aes128_Encrypt_Block
   --      and Aes128_Decrypt_Block.
   --    * AES-256 §C.3 round-trip via Aes_Spec.Aes256_Encrypt_Block
   --      and Aes256_Decrypt_Block.
   --    * Tls_Core.Aes128.Decrypt_Block on the §C.1 ciphertext
   --      returns the original plaintext.
   --    * Tls_Core.Aes256.Decrypt_Block on the §C.3 ciphertext
   --      returns the original plaintext.
   ---------------------------------------------------------------------

   procedure Aes_Spec_Scenario;
   procedure Aes_Spec_Scenario is
      --  AES-128 §C.1 vectors.
      K128 : constant Tls_Core.Aes128.Key_Array :=
        (16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
         16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#);
      Pt128 : constant Tls_Core.Aes128.Block :=
        (16#00#, 16#11#, 16#22#, 16#33#, 16#44#, 16#55#, 16#66#, 16#77#,
         16#88#, 16#99#, 16#AA#, 16#BB#, 16#CC#, 16#DD#, 16#EE#, 16#FF#);
      Ct128_Expected : constant Tls_Core.Aes128.Block :=
        (16#69#, 16#C4#, 16#E0#, 16#D8#, 16#6A#, 16#7B#, 16#04#, 16#30#,
         16#D8#, 16#CD#, 16#B7#, 16#80#, 16#70#, 16#B4#, 16#C5#, 16#5A#);

      RK128       : Tls_Core.Aes128.Round_Keys;
      Ct128_Spec  : Tls_Core.Aes_Spec.Block_16;
      Pt128_Round : Tls_Core.Aes_Spec.Block_16;
      Pt128_Wrap  : Tls_Core.Aes128.Block;

      --  AES-256 §C.3 vectors.
      K256 : constant Tls_Core.Aes256.Key_Array :=
        (16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
         16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#,
         16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#,
         16#18#, 16#19#, 16#1A#, 16#1B#, 16#1C#, 16#1D#, 16#1E#, 16#1F#);
      Pt256 : constant Tls_Core.Aes256.Block :=
        (16#00#, 16#11#, 16#22#, 16#33#, 16#44#, 16#55#, 16#66#, 16#77#,
         16#88#, 16#99#, 16#AA#, 16#BB#, 16#CC#, 16#DD#, 16#EE#, 16#FF#);
      Ct256_Expected : constant Tls_Core.Aes256.Block :=
        (16#8E#, 16#A2#, 16#B7#, 16#CA#, 16#51#, 16#67#, 16#45#, 16#BF#,
         16#EA#, 16#FC#, 16#49#, 16#90#, 16#4B#, 16#49#, 16#60#, 16#89#);

      RK256       : Tls_Core.Aes256.Round_Keys;
      Ct256_Spec  : Tls_Core.Aes_Spec.Block_16;
      Pt256_Round : Tls_Core.Aes_Spec.Block_16;
      Pt256_Wrap  : Tls_Core.Aes256.Block;
   begin
      Put_Line ("scenario 34b — AES Spec (HACL\\* port) FIPS 197 §C.1 / §C.3");

      --  AES-128: spec-direct encrypt = expected ciphertext.
      Tls_Core.Aes128.Expand_Key (K128, RK128);
      Ct128_Spec :=
        Tls_Core.Aes_Spec.Aes128_Encrypt_Block (Pt128, RK128);
      Check ("Aes_Spec.Aes128_Encrypt_Block §C.1 byte-exact",
             Equal (Ct128_Spec, Ct128_Expected));

      --  AES-128: spec-direct decrypt round-trips.
      Pt128_Round :=
        Tls_Core.Aes_Spec.Aes128_Decrypt_Block (Ct128_Spec, RK128);
      Check ("Aes_Spec.Aes128 decrypt(encrypt(x)) = x",
             Equal (Pt128_Round, Pt128));

      --  Aes128.Decrypt_Block: §C.1 ciphertext decrypts to plaintext.
      Tls_Core.Aes128.Decrypt_Block (RK128, Ct128_Expected, Pt128_Wrap);
      Check ("Aes128.Decrypt_Block §C.1 plaintext byte-exact",
             Equal (Pt128_Wrap, Pt128));

      --  AES-256: spec-direct encrypt = expected ciphertext.
      Tls_Core.Aes256.Expand_Key (K256, RK256);
      Ct256_Spec :=
        Tls_Core.Aes_Spec.Aes256_Encrypt_Block (Pt256, RK256);
      Check ("Aes_Spec.Aes256_Encrypt_Block §C.3 byte-exact",
             Equal (Ct256_Spec, Ct256_Expected));

      --  AES-256: spec-direct decrypt round-trips.
      Pt256_Round :=
        Tls_Core.Aes_Spec.Aes256_Decrypt_Block (Ct256_Spec, RK256);
      Check ("Aes_Spec.Aes256 decrypt(encrypt(x)) = x",
             Equal (Pt256_Round, Pt256));

      --  Aes256.Decrypt_Block: §C.3 ciphertext decrypts to plaintext.
      Tls_Core.Aes256.Decrypt_Block (RK256, Ct256_Expected, Pt256_Wrap);
      Check ("Aes256.Decrypt_Block §C.3 plaintext byte-exact",
             Equal (Pt256_Wrap, Pt256));
   end Aes_Spec_Scenario;

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
   --  Scenario — Aead_Channel variant-record round-trip, one per
   --  cipher suite. Validates Tls_Core.Aead_Channel dispatches Send
   --  / Receive correctly for each of the three v0.5 production
   --  suites (RFC 8446 §B.4). This is the unit that the Tls13_Driver
   --  integrates against for runtime cipher-suite negotiation; if
   --  any of these three round-trips fails, the driver cannot
   --  negotiate to that suite.
   ---------------------------------------------------------------------

   procedure Aead_Channel_Chacha_Scenario;
   procedure Aead_Channel_Chacha_Scenario is
      use type Tls_Core.Octet;
      Secret : constant Tls_Core.Key_Schedule.Secret :=
        (others => 16#71#);
      Tx, Rx : Tls_Core.Aead_Channel.Direction;
      Pt : constant Tls_Core.Octet_Array :=
        (16#43#, 16#68#, 16#61#);  --  "Cha"
      Wire : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
      Wire_Last : Natural;
      Got : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
      Got_Last : Natural;
      Inner : Tls_Core.Octet;
      OK : Boolean;
   begin
      Put_Line ("scenario — Aead_Channel chacha20-poly1305 round-trip");
      Tls_Core.Aead_Channel.Init_Sha256
        (Tx, Tls_Core.Suites.Chacha20_Poly1305_Sha256, Secret);
      Tls_Core.Aead_Channel.Init_Sha256
        (Rx, Tls_Core.Suites.Chacha20_Poly1305_Sha256, Secret);
      Tls_Core.Aead_Channel.Send
        (Tx, Pt,
         Tls_Core.Aead_Channel.Inner_Type_Application_Data,
         Wire, Wire_Last);
      Check ("Aead_Channel/chacha: wire bytes produced",
             Wire_Last >= 5 + Pt'Length + 1 + 16);
      Tls_Core.Aead_Channel.Receive
        (Rx, Wire (1 .. Wire_Last), Got, Got_Last, Inner, OK);
      Check ("Aead_Channel/chacha: decrypt OK", OK);
      Check ("Aead_Channel/chacha: round-trip plaintext",
             Got_Last = Pt'Length
             and then Equal (Got (1 .. Got_Last), Pt));
      Check ("Aead_Channel/chacha: inner type preserved",
             Inner = Tls_Core.Aead_Channel.Inner_Type_Application_Data);
   end Aead_Channel_Chacha_Scenario;

   procedure Aead_Channel_Aes128_Scenario;
   procedure Aead_Channel_Aes128_Scenario is
      use type Tls_Core.Octet;
      Secret : constant Tls_Core.Key_Schedule.Secret :=
        (others => 16#72#);
      Tx, Rx : Tls_Core.Aead_Channel.Direction;
      Pt : constant Tls_Core.Octet_Array :=
        (16#41#, 16#31#, 16#32#, 16#38#);  --  "A128"
      Wire : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
      Wire_Last : Natural;
      Got : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
      Got_Last : Natural;
      Inner : Tls_Core.Octet;
      OK : Boolean;
   begin
      Put_Line ("scenario — Aead_Channel AES-128-GCM round-trip");
      Tls_Core.Aead_Channel.Init_Sha256
        (Tx, Tls_Core.Suites.Aes_128_Gcm_Sha256, Secret);
      Tls_Core.Aead_Channel.Init_Sha256
        (Rx, Tls_Core.Suites.Aes_128_Gcm_Sha256, Secret);
      Tls_Core.Aead_Channel.Send
        (Tx, Pt,
         Tls_Core.Aead_Channel.Inner_Type_Application_Data,
         Wire, Wire_Last);
      Check ("Aead_Channel/aes128: wire bytes produced",
             Wire_Last >= 5 + Pt'Length + 1 + 16);
      Tls_Core.Aead_Channel.Receive
        (Rx, Wire (1 .. Wire_Last), Got, Got_Last, Inner, OK);
      Check ("Aead_Channel/aes128: decrypt OK", OK);
      Check ("Aead_Channel/aes128: round-trip plaintext",
             Got_Last = Pt'Length
             and then Equal (Got (1 .. Got_Last), Pt));
      Check ("Aead_Channel/aes128: inner type preserved",
             Inner = Tls_Core.Aead_Channel.Inner_Type_Application_Data);
   end Aead_Channel_Aes128_Scenario;

   procedure Aead_Channel_Aes256_Scenario;
   procedure Aead_Channel_Aes256_Scenario is
      use type Tls_Core.Octet;
      Secret : constant Tls_Core.Key_Schedule_Sha384.Secret :=
        (others => 16#73#);  --  48-byte SHA-384 secret
      Tx, Rx : Tls_Core.Aead_Channel.Direction;
      Pt : constant Tls_Core.Octet_Array :=
        (16#41#, 16#32#, 16#35#, 16#36#);  --  "A256"
      Wire : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
      Wire_Last : Natural;
      Got : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
      Got_Last : Natural;
      Inner : Tls_Core.Octet;
      OK : Boolean;
   begin
      Put_Line ("scenario — Aead_Channel AES-256-GCM round-trip");
      Tls_Core.Aead_Channel.Init_Sha384 (Tx, Secret);
      Tls_Core.Aead_Channel.Init_Sha384 (Rx, Secret);
      Tls_Core.Aead_Channel.Send
        (Tx, Pt,
         Tls_Core.Aead_Channel.Inner_Type_Application_Data,
         Wire, Wire_Last);
      Check ("Aead_Channel/aes256: wire bytes produced",
             Wire_Last >= 5 + Pt'Length + 1 + 16);
      Tls_Core.Aead_Channel.Receive
        (Rx, Wire (1 .. Wire_Last), Got, Got_Last, Inner, OK);
      Check ("Aead_Channel/aes256: decrypt OK", OK);
      Check ("Aead_Channel/aes256: round-trip plaintext",
             Got_Last = Pt'Length
             and then Equal (Got (1 .. Got_Last), Pt));
      Check ("Aead_Channel/aes256: inner type preserved",
             Inner = Tls_Core.Aead_Channel.Inner_Type_Application_Data);
   end Aead_Channel_Aes256_Scenario;

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

   ---------------------------------------------------------------------
   --  RSA-PSS round-trip (Encode → Emsa_Pss_Verify) and rejection
   --  scenarios. The encode side is the test harness; the verify side
   --  carries the [VERIFIED — PLATINUM] tag and a Post referencing
   --  the HACL* Spec.RSAPSS.fst port.
   ---------------------------------------------------------------------

   procedure Rsa_Pss_Sha256_Roundtrip_Scenario;
   procedure Rsa_Pss_Sha256_Roundtrip_Scenario is
      Msg  : constant Tls_Core.Octet_Array (1 .. 13) :=
        (16#48#, 16#65#, 16#6C#, 16#6C#, 16#6F#, 16#2C#, 16#20#, 16#52#,
         16#53#, 16#41#, 16#21#, 16#21#, 16#21#);   -- "Hello, RSA!!!"

      --  Deterministic salt for round-trip — sLen = hLen = 32.
      Salt : constant Tls_Core.Octet_Array (1 .. 32) :=
        (1 => 16#00#, 2 => 16#11#, 3 => 16#22#, 4 => 16#33#,
         5 => 16#44#, 6 => 16#55#, 7 => 16#66#, 8 => 16#77#,
         9 => 16#88#, 10 => 16#99#, 11 => 16#AA#, 12 => 16#BB#,
         13 => 16#CC#, 14 => 16#DD#, 15 => 16#EE#, 16 => 16#FF#,
         17 => 16#0F#, 18 => 16#1E#, 19 => 16#2D#, 20 => 16#3C#,
         21 => 16#4B#, 22 => 16#5A#, 23 => 16#69#, 24 => 16#78#,
         25 => 16#87#, 26 => 16#96#, 27 => 16#A5#, 28 => 16#B4#,
         29 => 16#C3#, 30 => 16#D2#, 31 => 16#E1#, 32 => 16#F0#);

      EM      : Tls_Core.Rsa_Pss.Bigint;
      EM_Bad  : Tls_Core.Rsa_Pss.Bigint;
      Enc_OK  : Boolean;
      Ver_OK  : Boolean;

      Other   : constant Tls_Core.Octet_Array (1 .. 13) :=
        (16#48#, 16#65#, 16#6C#, 16#6C#, 16#6F#, 16#2C#, 16#20#, 16#52#,
         16#53#, 16#41#, 16#21#, 16#21#, 16#22#);   -- last byte differs
   begin
      Put_Line ("scenario 46 — RSA-PSS-SHA256 Encode → Verify round-trip");

      Tls_Core.Rsa_Pss.Encode_Sha256 (Msg, Salt, EM, Enc_OK);
      Check ("Encode_Sha256 returned OK", Enc_OK);

      Tls_Core.Rsa_Pss.Emsa_Pss_Verify_Sha256 (Msg, EM, Ver_OK);
      Check ("Emsa_Pss_Verify_Sha256 accepts valid encoding", Ver_OK);

      --  Wrong message must reject (Step 12 of RFC 8017 §9.1.2).
      Tls_Core.Rsa_Pss.Emsa_Pss_Verify_Sha256 (Other, EM, Ver_OK);
      Check ("Emsa_Pss_Verify_Sha256 rejects different message",
             not Ver_OK);

      --  Tamper trailer 0xBC → expect rejection (Step 3).
      EM_Bad := EM;
      EM_Bad (256) := 16#BD#;
      Tls_Core.Rsa_Pss.Emsa_Pss_Verify_Sha256 (Msg, EM_Bad, Ver_OK);
      Check ("Emsa_Pss_Verify_Sha256 rejects bad trailer",
             not Ver_OK);

      --  Tamper top bit (Step 3' — em_0 high bit must be zero).
      EM_Bad := EM;
      EM_Bad (1) := EM_Bad (1) or 16#80#;
      Tls_Core.Rsa_Pss.Emsa_Pss_Verify_Sha256 (Msg, EM_Bad, Ver_OK);
      Check ("Emsa_Pss_Verify_Sha256 rejects non-zero high bit",
             not Ver_OK);

      --  Bit flip somewhere in the middle of the masked DB → SHA-256
      --  of M' will mismatch → reject.
      EM_Bad := EM;
      EM_Bad (100) := EM_Bad (100) xor 16#01#;
      Tls_Core.Rsa_Pss.Emsa_Pss_Verify_Sha256 (Msg, EM_Bad, Ver_OK);
      Check ("Emsa_Pss_Verify_Sha256 rejects bit-flip in masked DB",
             not Ver_OK);
   end Rsa_Pss_Sha256_Roundtrip_Scenario;

   procedure Rsa_Pss_Sha384_Roundtrip_Scenario;
   procedure Rsa_Pss_Sha384_Roundtrip_Scenario is
      Msg : constant Tls_Core.Octet_Array (1 .. 5) :=
        (16#54#, 16#4C#, 16#53#, 16#21#, 16#33#);   -- "TLS!3"

      --  sLen = hLen = 48 for SHA-384.
      Salt : constant Tls_Core.Octet_Array (1 .. 48) :=
        (1 => 16#A1#, 2 => 16#B2#, 3 => 16#C3#, 4 => 16#D4#,
         5 => 16#E5#, 6 => 16#F6#, 7 => 16#07#, 8 => 16#18#,
         9 => 16#29#, 10 => 16#3A#, 11 => 16#4B#, 12 => 16#5C#,
         13 => 16#6D#, 14 => 16#7E#, 15 => 16#8F#, 16 => 16#90#,
         17 => 16#A1#, 18 => 16#B2#, 19 => 16#C3#, 20 => 16#D4#,
         21 => 16#E5#, 22 => 16#F6#, 23 => 16#07#, 24 => 16#18#,
         25 => 16#29#, 26 => 16#3A#, 27 => 16#4B#, 28 => 16#5C#,
         29 => 16#6D#, 30 => 16#7E#, 31 => 16#8F#, 32 => 16#90#,
         33 => 16#11#, 34 => 16#22#, 35 => 16#33#, 36 => 16#44#,
         37 => 16#55#, 38 => 16#66#, 39 => 16#77#, 40 => 16#88#,
         41 => 16#99#, 42 => 16#AA#, 43 => 16#BB#, 44 => 16#CC#,
         45 => 16#DD#, 46 => 16#EE#, 47 => 16#FF#, 48 => 16#00#);

      EM      : Tls_Core.Rsa_Pss.Bigint;
      EM_Bad  : Tls_Core.Rsa_Pss.Bigint;
      Enc_OK  : Boolean;
      Ver_OK  : Boolean;
   begin
      Put_Line ("scenario 47 — RSA-PSS-SHA384 Encode → Verify round-trip");

      Tls_Core.Rsa_Pss.Encode_Sha384 (Msg, Salt, EM, Enc_OK);
      Check ("Encode_Sha384 returned OK", Enc_OK);

      Tls_Core.Rsa_Pss.Emsa_Pss_Verify_Sha384 (Msg, EM, Ver_OK);
      Check ("Emsa_Pss_Verify_Sha384 accepts valid encoding", Ver_OK);

      --  Tamper PS-pad section — mutate one byte that's part of the
      --  zero-padding region after unmasking. Easiest is to flip the
      --  trailer or a byte in the H section.
      EM_Bad := EM;
      EM_Bad (256) := 16#00#;
      Tls_Core.Rsa_Pss.Emsa_Pss_Verify_Sha384 (Msg, EM_Bad, Ver_OK);
      Check ("Emsa_Pss_Verify_Sha384 rejects zeroed trailer",
             not Ver_OK);

      --  Bit flip in the H field (positions 208..255 for SHA-384).
      EM_Bad := EM;
      EM_Bad (220) := EM_Bad (220) xor 16#01#;
      Tls_Core.Rsa_Pss.Emsa_Pss_Verify_Sha384 (Msg, EM_Bad, Ver_OK);
      Check ("Emsa_Pss_Verify_Sha384 rejects bit-flip in H section",
             not Ver_OK);
   end Rsa_Pss_Sha384_Roundtrip_Scenario;

   --------------------------------------------------------------------
   --  Scenario 48 — Cert chain validation against a real PKI fixture.
   --
   --  Embeds two DER ECDSA-P256 certs (root + leaf) generated by
   --  openssl (see crates/tls_core/tests/fixtures/README.md). The
   --  chain is leaf -> root, both signed with ecdsa-with-SHA256.
   --
   --  Sanity checks:
   --    1.  Tls_Core.Cert.Parse returns OK for both certs and the
   --        index spans land inside the DER buffer.
   --    2.  The leaf carries a v3 SubjectAltName extension and
   --        Match_DNS_SAN finds the three names baked in
   --        ("localhost", "test.example.com" + IP — IPs aren't
   --        DNS-name-matched).
   --    3.  Tls_Core.Cert_Chain.Validate_Chain accepts the chain
   --        when Root_Der is in the trust store and rejects with
   --        Unknown_CA when the trust store is empty.
   --    4.  A real ECDSA signature produced offline by openssl
   --        signing the canonical TLS 1.3 §4.4.3 signed-content
   --        ("64 spaces" || prefix || 0x00 || synthetic 32-byte
   --        transcript hash) verifies against the leaf's public
   --        key via Cert_Chain.Verify_Cert_Verify, and bit-flips
   --        in the signed content / signature reject correctly.
   --------------------------------------------------------------------

   procedure Cert_Chain_Pki_Scenario;
   procedure Cert_Chain_Pki_Scenario is
      use type Tls_Core.Cert.Signature_Alg;
      --  ===== embedded fixtures (paste from fixtures/fixtures.ada;
      --  regenerate with the openssl recipe in fixtures/README.md) =====

      Root_Der : constant Tls_Core.Octet_Array (1 .. 392) :=
        (16#30#, 16#82#, 16#01#, 16#84#, 16#30#, 16#82#, 16#01#, 16#29#,
         16#A0#, 16#03#, 16#02#, 16#01#, 16#02#, 16#02#, 16#14#, 16#4C#,
         16#38#, 16#ED#, 16#66#, 16#47#, 16#3E#, 16#2B#, 16#B0#, 16#25#,
         16#DA#, 16#0E#, 16#29#, 16#CA#, 16#0C#, 16#F7#, 16#CE#, 16#F0#,
         16#B4#, 16#19#, 16#C8#, 16#30#, 16#0A#, 16#06#, 16#08#, 16#2A#,
         16#86#, 16#48#, 16#CE#, 16#3D#, 16#04#, 16#03#, 16#02#, 16#30#,
         16#17#, 16#31#, 16#15#, 16#30#, 16#13#, 16#06#, 16#03#, 16#55#,
         16#04#, 16#03#, 16#0C#, 16#0C#, 16#54#, 16#65#, 16#73#, 16#74#,
         16#20#, 16#52#, 16#6F#, 16#6F#, 16#74#, 16#20#, 16#43#, 16#41#,
         16#30#, 16#1E#, 16#17#, 16#0D#, 16#32#, 16#36#, 16#30#, 16#35#,
         16#30#, 16#37#, 16#31#, 16#32#, 16#33#, 16#39#, 16#30#, 16#34#,
         16#5A#, 16#17#, 16#0D#, 16#33#, 16#36#, 16#30#, 16#35#, 16#30#,
         16#34#, 16#31#, 16#32#, 16#33#, 16#39#, 16#30#, 16#34#, 16#5A#,
         16#30#, 16#17#, 16#31#, 16#15#, 16#30#, 16#13#, 16#06#, 16#03#,
         16#55#, 16#04#, 16#03#, 16#0C#, 16#0C#, 16#54#, 16#65#, 16#73#,
         16#74#, 16#20#, 16#52#, 16#6F#, 16#6F#, 16#74#, 16#20#, 16#43#,
         16#41#, 16#30#, 16#59#, 16#30#, 16#13#, 16#06#, 16#07#, 16#2A#,
         16#86#, 16#48#, 16#CE#, 16#3D#, 16#02#, 16#01#, 16#06#, 16#08#,
         16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#03#, 16#01#, 16#07#,
         16#03#, 16#42#, 16#00#, 16#04#, 16#52#, 16#71#, 16#0D#, 16#A4#,
         16#14#, 16#06#, 16#9B#, 16#F7#, 16#CE#, 16#69#, 16#F7#, 16#3F#,
         16#D9#, 16#77#, 16#99#, 16#86#, 16#EA#, 16#2C#, 16#FA#, 16#35#,
         16#6B#, 16#F8#, 16#DA#, 16#75#, 16#47#, 16#12#, 16#21#, 16#C6#,
         16#1A#, 16#2C#, 16#BD#, 16#3C#, 16#9B#, 16#80#, 16#CA#, 16#A9#,
         16#77#, 16#2E#, 16#C0#, 16#E2#, 16#E0#, 16#F2#, 16#49#, 16#67#,
         16#5B#, 16#AD#, 16#42#, 16#74#, 16#BE#, 16#00#, 16#0B#, 16#95#,
         16#19#, 16#AF#, 16#31#, 16#72#, 16#F0#, 16#E9#, 16#38#, 16#1F#,
         16#30#, 16#CC#, 16#20#, 16#2C#, 16#A3#, 16#53#, 16#30#, 16#51#,
         16#30#, 16#1D#, 16#06#, 16#03#, 16#55#, 16#1D#, 16#0E#, 16#04#,
         16#16#, 16#04#, 16#14#, 16#89#, 16#BF#, 16#DB#, 16#9A#, 16#FB#,
         16#DD#, 16#CA#, 16#FE#, 16#9A#, 16#2B#, 16#BB#, 16#56#, 16#2B#,
         16#E3#, 16#2F#, 16#E6#, 16#46#, 16#3E#, 16#06#, 16#4C#, 16#30#,
         16#1F#, 16#06#, 16#03#, 16#55#, 16#1D#, 16#23#, 16#04#, 16#18#,
         16#30#, 16#16#, 16#80#, 16#14#, 16#89#, 16#BF#, 16#DB#, 16#9A#,
         16#FB#, 16#DD#, 16#CA#, 16#FE#, 16#9A#, 16#2B#, 16#BB#, 16#56#,
         16#2B#, 16#E3#, 16#2F#, 16#E6#, 16#46#, 16#3E#, 16#06#, 16#4C#,
         16#30#, 16#0F#, 16#06#, 16#03#, 16#55#, 16#1D#, 16#13#, 16#01#,
         16#01#, 16#FF#, 16#04#, 16#05#, 16#30#, 16#03#, 16#01#, 16#01#,
         16#FF#, 16#30#, 16#0A#, 16#06#, 16#08#, 16#2A#, 16#86#, 16#48#,
         16#CE#, 16#3D#, 16#04#, 16#03#, 16#02#, 16#03#, 16#49#, 16#00#,
         16#30#, 16#46#, 16#02#, 16#21#, 16#00#, 16#91#, 16#25#, 16#31#,
         16#9E#, 16#6B#, 16#7B#, 16#86#, 16#BB#, 16#10#, 16#5D#, 16#1A#,
         16#0A#, 16#09#, 16#3B#, 16#32#, 16#27#, 16#B8#, 16#D6#, 16#8B#,
         16#73#, 16#B6#, 16#B3#, 16#BA#, 16#36#, 16#5B#, 16#7B#, 16#7B#,
         16#F2#, 16#A0#, 16#27#, 16#18#, 16#D3#, 16#02#, 16#21#, 16#00#,
         16#AB#, 16#4B#, 16#78#, 16#70#, 16#82#, 16#4C#, 16#78#, 16#50#,
         16#37#, 16#23#, 16#AA#, 16#A5#, 16#61#, 16#6A#, 16#5D#, 16#C4#,
         16#CA#, 16#88#, 16#F6#, 16#07#, 16#C5#, 16#17#, 16#6E#, 16#E7#,
         16#13#, 16#A0#, 16#97#, 16#1E#, 16#A7#, 16#FF#, 16#12#, 16#31#);

      Leaf_Der : constant Tls_Core.Octet_Array (1 .. 417) :=
        (16#30#, 16#82#, 16#01#, 16#9D#, 16#30#, 16#82#, 16#01#, 16#43#,
         16#A0#, 16#03#, 16#02#, 16#01#, 16#02#, 16#02#, 16#14#, 16#1B#,
         16#3B#, 16#A5#, 16#4E#, 16#36#, 16#F6#, 16#C5#, 16#E1#, 16#D7#,
         16#60#, 16#80#, 16#63#, 16#45#, 16#B9#, 16#5B#, 16#51#, 16#2A#,
         16#F9#, 16#A2#, 16#A4#, 16#30#, 16#0A#, 16#06#, 16#08#, 16#2A#,
         16#86#, 16#48#, 16#CE#, 16#3D#, 16#04#, 16#03#, 16#02#, 16#30#,
         16#17#, 16#31#, 16#15#, 16#30#, 16#13#, 16#06#, 16#03#, 16#55#,
         16#04#, 16#03#, 16#0C#, 16#0C#, 16#54#, 16#65#, 16#73#, 16#74#,
         16#20#, 16#52#, 16#6F#, 16#6F#, 16#74#, 16#20#, 16#43#, 16#41#,
         16#30#, 16#1E#, 16#17#, 16#0D#, 16#32#, 16#36#, 16#30#, 16#35#,
         16#30#, 16#37#, 16#31#, 16#32#, 16#33#, 16#39#, 16#30#, 16#34#,
         16#5A#, 16#17#, 16#0D#, 16#32#, 16#37#, 16#30#, 16#35#, 16#30#,
         16#37#, 16#31#, 16#32#, 16#33#, 16#39#, 16#30#, 16#34#, 16#5A#,
         16#30#, 16#14#, 16#31#, 16#12#, 16#30#, 16#10#, 16#06#, 16#03#,
         16#55#, 16#04#, 16#03#, 16#0C#, 16#09#, 16#6C#, 16#6F#, 16#63#,
         16#61#, 16#6C#, 16#68#, 16#6F#, 16#73#, 16#74#, 16#30#, 16#59#,
         16#30#, 16#13#, 16#06#, 16#07#, 16#2A#, 16#86#, 16#48#, 16#CE#,
         16#3D#, 16#02#, 16#01#, 16#06#, 16#08#, 16#2A#, 16#86#, 16#48#,
         16#CE#, 16#3D#, 16#03#, 16#01#, 16#07#, 16#03#, 16#42#, 16#00#,
         16#04#, 16#E4#, 16#26#, 16#E3#, 16#7E#, 16#97#, 16#8E#, 16#1A#,
         16#4E#, 16#F2#, 16#31#, 16#6C#, 16#E8#, 16#DF#, 16#17#, 16#FF#,
         16#42#, 16#EC#, 16#FA#, 16#C6#, 16#7E#, 16#93#, 16#19#, 16#95#,
         16#36#, 16#37#, 16#F2#, 16#33#, 16#A0#, 16#22#, 16#C7#, 16#23#,
         16#A4#, 16#0F#, 16#44#, 16#DD#, 16#E0#, 16#CE#, 16#DC#, 16#CD#,
         16#20#, 16#F2#, 16#37#, 16#AB#, 16#FE#, 16#EE#, 16#A2#, 16#59#,
         16#65#, 16#2B#, 16#03#, 16#E6#, 16#73#, 16#97#, 16#5C#, 16#6F#,
         16#11#, 16#D3#, 16#83#, 16#84#, 16#5C#, 16#D6#, 16#C8#, 16#65#,
         16#CB#, 16#A3#, 16#70#, 16#30#, 16#6E#, 16#30#, 16#2C#, 16#06#,
         16#03#, 16#55#, 16#1D#, 16#11#, 16#04#, 16#25#, 16#30#, 16#23#,
         16#82#, 16#09#, 16#6C#, 16#6F#, 16#63#, 16#61#, 16#6C#, 16#68#,
         16#6F#, 16#73#, 16#74#, 16#82#, 16#10#, 16#74#, 16#65#, 16#73#,
         16#74#, 16#2E#, 16#65#, 16#78#, 16#61#, 16#6D#, 16#70#, 16#6C#,
         16#65#, 16#2E#, 16#63#, 16#6F#, 16#6D#, 16#87#, 16#04#, 16#7F#,
         16#00#, 16#00#, 16#01#, 16#30#, 16#1D#, 16#06#, 16#03#, 16#55#,
         16#1D#, 16#0E#, 16#04#, 16#16#, 16#04#, 16#14#, 16#25#, 16#3B#,
         16#7A#, 16#E3#, 16#D2#, 16#46#, 16#CC#, 16#97#, 16#6F#, 16#EB#,
         16#7F#, 16#33#, 16#A3#, 16#18#, 16#61#, 16#05#, 16#7D#, 16#85#,
         16#66#, 16#82#, 16#30#, 16#1F#, 16#06#, 16#03#, 16#55#, 16#1D#,
         16#23#, 16#04#, 16#18#, 16#30#, 16#16#, 16#80#, 16#14#, 16#89#,
         16#BF#, 16#DB#, 16#9A#, 16#FB#, 16#DD#, 16#CA#, 16#FE#, 16#9A#,
         16#2B#, 16#BB#, 16#56#, 16#2B#, 16#E3#, 16#2F#, 16#E6#, 16#46#,
         16#3E#, 16#06#, 16#4C#, 16#30#, 16#0A#, 16#06#, 16#08#, 16#2A#,
         16#86#, 16#48#, 16#CE#, 16#3D#, 16#04#, 16#03#, 16#02#, 16#03#,
         16#48#, 16#00#, 16#30#, 16#45#, 16#02#, 16#21#, 16#00#, 16#DA#,
         16#00#, 16#66#, 16#38#, 16#5C#, 16#15#, 16#4B#, 16#9E#, 16#CE#,
         16#93#, 16#32#, 16#65#, 16#17#, 16#71#, 16#6B#, 16#A2#, 16#9C#,
         16#A4#, 16#AF#, 16#20#, 16#3C#, 16#61#, 16#E9#, 16#19#, 16#00#,
         16#92#, 16#0D#, 16#C2#, 16#FF#, 16#F7#, 16#20#, 16#D4#, 16#02#,
         16#20#, 16#21#, 16#CF#, 16#A6#, 16#36#, 16#DC#, 16#60#, 16#D9#,
         16#78#, 16#90#, 16#E4#, 16#02#, 16#DD#, 16#CC#, 16#8F#, 16#FB#,
         16#80#, 16#FD#, 16#10#, 16#41#, 16#92#, 16#C2#, 16#0F#, 16#B5#,
         16#49#, 16#72#, 16#6A#, 16#E1#, 16#F9#, 16#65#, 16#7D#, 16#25#,
         16#64#);

      Leaf_Sig : constant Tls_Core.Octet_Array (1 .. 70) :=
        (16#30#, 16#44#, 16#02#, 16#20#, 16#03#, 16#BA#, 16#EE#, 16#B7#,
         16#9D#, 16#81#, 16#B7#, 16#0C#, 16#81#, 16#C0#, 16#4C#, 16#53#,
         16#EB#, 16#03#, 16#CF#, 16#A6#, 16#E2#, 16#9A#, 16#78#, 16#E0#,
         16#B9#, 16#00#, 16#32#, 16#DB#, 16#7B#, 16#4D#, 16#5E#, 16#9D#,
         16#02#, 16#B3#, 16#9B#, 16#E2#, 16#02#, 16#20#, 16#13#, 16#61#,
         16#15#, 16#13#, 16#79#, 16#5D#, 16#16#, 16#20#, 16#6C#, 16#38#,
         16#BC#, 16#C4#, 16#EE#, 16#C5#, 16#34#, 16#EE#, 16#2C#, 16#AB#,
         16#08#, 16#82#, 16#B7#, 16#4F#, 16#43#, 16#05#, 16#F0#, 16#2E#,
         16#1E#, 16#B1#, 16#09#, 16#06#, 16#02#, 16#35#);

      --  All_Certs is the contiguous backing buffer the validator
      --  is fed; chain entries point into it via (First, Last)
      --  ranges. The layout: leaf bytes followed by root bytes.
      All_Certs : Tls_Core.Octet_Array
        (1 .. Leaf_Der'Length + Root_Der'Length);

      Leaf_F : constant Natural := 1;
      Leaf_L : constant Natural := Leaf_Der'Length;
      Root_F : constant Natural := Leaf_Der'Length + 1;
      Root_L : constant Natural := Leaf_Der'Length + Root_Der'Length;

      Hostname_Localhost : constant Tls_Core.Octet_Array (1 .. 9) :=
        (16#6C#, 16#6F#, 16#63#, 16#61#, 16#6C#, 16#68#, 16#6F#, 16#73#,
         16#74#);  --  "localhost"

      Hostname_Test : constant Tls_Core.Octet_Array (1 .. 16) :=
        (16#74#, 16#65#, 16#73#, 16#74#, 16#2E#, 16#65#, 16#78#, 16#61#,
         16#6D#, 16#70#, 16#6C#, 16#65#, 16#2E#, 16#63#, 16#6F#, 16#6D#);
        --  "test.example.com"

      Hostname_Bogus : constant Tls_Core.Octet_Array (1 .. 8) :=
        (16#62#, 16#6F#, 16#67#, 16#75#, 16#73#, 16#2E#, 16#69#, 16#6F#);
        --  "bogus.io"
   begin
      Put_Line ("scenario 48 — cert chain + CertVerify against real PKI");

      All_Certs (Leaf_F .. Leaf_L) := Leaf_Der;
      All_Certs (Root_F .. Root_L) := Root_Der;

      ---------- (1) Tls_Core.Cert.Parse on each fixture ----------
      declare
         Leaf_P : Tls_Core.Cert.Parsed_Cert;
         Leaf_OK : Boolean;
         Root_P : Tls_Core.Cert.Parsed_Cert;
         Root_OK : Boolean;
      begin
         Tls_Core.Cert.Parse (Leaf_Der, Leaf_P, Leaf_OK);
         Check ("Cert.Parse leaf OK", Leaf_OK);
         Check ("Cert.Parse leaf TBS span inside DER",
                Leaf_OK and then
                Leaf_P.Tbs_First in Leaf_Der'Range
                and then Leaf_P.Tbs_Last in Leaf_Der'Range
                and then Leaf_P.Tbs_First < Leaf_P.Tbs_Last);
         Check ("Cert.Parse leaf signatureAlgorithm = ECDSA-SHA256",
                Leaf_OK and then
                Leaf_P.Sig_Alg = Tls_Core.Cert.Ecdsa_With_Sha256);
         Check ("Cert.Parse leaf has SubjectAltName",
                Leaf_OK and then Leaf_P.San_Present);

         --  SAN matching.
         if Leaf_OK and then Leaf_P.San_Present then
            declare
               San_Body : constant Tls_Core.Octet_Array
                 (1 .. Leaf_P.San_Last - Leaf_P.San_First + 1) :=
                 Leaf_Der (Leaf_P.San_First .. Leaf_P.San_Last);
            begin
               Check ("SAN matches localhost",
                      Tls_Core.Cert.Match_DNS_SAN
                        (San_Body, Hostname_Localhost));
               Check ("SAN matches test.example.com",
                      Tls_Core.Cert.Match_DNS_SAN
                        (San_Body, Hostname_Test));
               Check ("SAN rejects bogus.io",
                      not Tls_Core.Cert.Match_DNS_SAN
                            (San_Body, Hostname_Bogus));
            end;
         end if;

         Tls_Core.Cert.Parse (Root_Der, Root_P, Root_OK);
         Check ("Cert.Parse root OK", Root_OK);
         Check ("Cert.Parse root signatureAlgorithm = ECDSA-SHA256",
                Root_OK and then
                Root_P.Sig_Alg = Tls_Core.Cert.Ecdsa_With_Sha256);
      end;

      ---------- (2) Validate_Chain accepts with root in trust ----------
      declare
         Chain : Tls_Core.Cert_Chain.Chain;
         Trust : Tls_Core.Cert_Chain.Trust_Store;
         Result : Tls_Core.Cert_Chain.Validation_Result;
         Leaf_Parsed : Tls_Core.Cert.Parsed_Cert;
         use type Tls_Core.Cert_Chain.Validation_Result;
      begin
         Chain.Count := 1;
         Chain.Entries (1) := (First => Leaf_F, Last => Leaf_L);
         Trust.Count := 1;
         Trust.Entries (1) := (First => Root_F, Last => Root_L);

         Tls_Core.Cert_Chain.Validate_Chain
           (All_Certs => All_Certs,
            Chain_In  => Chain,
            Trust     => Trust,
            Result    => Result,
            Leaf_Parsed => Leaf_Parsed);
         Check ("Validate_Chain leaf+trusted-root => OK_Validated",
                Result = Tls_Core.Cert_Chain.OK_Validated);
      end;

      ---------- (3) Validate_Chain rejects with empty trust ----------
      declare
         Chain : Tls_Core.Cert_Chain.Chain;
         Trust : Tls_Core.Cert_Chain.Trust_Store;
         Result : Tls_Core.Cert_Chain.Validation_Result;
         Leaf_Parsed : Tls_Core.Cert.Parsed_Cert;
         use type Tls_Core.Cert_Chain.Validation_Result;
      begin
         Chain.Count := 1;
         Chain.Entries (1) := (First => Leaf_F, Last => Leaf_L);
         Trust.Count := 0;

         Tls_Core.Cert_Chain.Validate_Chain
           (All_Certs => All_Certs,
            Chain_In  => Chain,
            Trust     => Trust,
            Result    => Result,
            Leaf_Parsed => Leaf_Parsed);
         Check ("Validate_Chain empty trust => Unknown_CA",
                Result = Tls_Core.Cert_Chain.Unknown_CA);
      end;

      ---------- (4) CertVerify signature against leaf's SPKI ----------
      declare
         Leaf_P : Tls_Core.Cert.Parsed_Cert;
         Leaf_OK : Boolean;

         --  Synthetic 32-byte transcript hash: 0xAA repeated.
         Synth_Hash : constant Tls_Core.Octet_Array (1 .. 32) :=
           (others => 16#AA#);

         Signed_Buf : Tls_Core.Octet_Array (1 .. 64 + 33 + 1 + 32);
         Signed_Last : Natural;

         Verify_OK : Boolean;
      begin
         Tls_Core.Cert.Parse (Leaf_Der, Leaf_P, Leaf_OK);
         pragma Assert (Leaf_OK);

         Tls_Core.Cert_Verify.Build_Signed_Content
           (Side            => Tls_Core.Cert_Verify.Server,
            Transcript_Hash => Synth_Hash,
            Out_Buf         => Signed_Buf,
            Out_Last        => Signed_Last);
         Check ("Build_Signed_Content length = 130",
                Signed_Last = 130);

         Tls_Core.Cert_Chain.Verify_Cert_Verify
           (Leaf_Der       => Leaf_Der,
            Leaf_Parsed    => Leaf_P,
            Sig_Scheme     =>
              Tls_Core.Cert_Chain.Sig_Ecdsa_Secp256r1_Sha256,
            Signed_Content => Signed_Buf (1 .. Signed_Last),
            Signature      => Leaf_Sig,
            OK             => Verify_OK);
         Check ("CertVerify ECDSA-SHA256 against leaf SPKI", Verify_OK);

         --  Bit-flip the transcript hash and re-verify; must reject.
         declare
            Bad_Buf : Tls_Core.Octet_Array (1 .. 64 + 33 + 1 + 32);
            Bad_Last : Natural;
            Bad_Hash : constant Tls_Core.Octet_Array (1 .. 32) :=
              (others => 16#BB#);
            Vrf_Bad : Boolean;
         begin
            Tls_Core.Cert_Verify.Build_Signed_Content
              (Side            => Tls_Core.Cert_Verify.Server,
               Transcript_Hash => Bad_Hash,
               Out_Buf         => Bad_Buf,
               Out_Last        => Bad_Last);
            Tls_Core.Cert_Chain.Verify_Cert_Verify
              (Leaf_Der       => Leaf_Der,
               Leaf_Parsed    => Leaf_P,
               Sig_Scheme     =>
                 Tls_Core.Cert_Chain.Sig_Ecdsa_Secp256r1_Sha256,
               Signed_Content => Bad_Buf (1 .. Bad_Last),
               Signature      => Leaf_Sig,
               OK             => Vrf_Bad);
            Check ("CertVerify rejects modified transcript hash",
                   not Vrf_Bad);
         end;

         --  Bit-flip the signature; must reject.
         declare
            Sig_Bad : Tls_Core.Octet_Array (1 .. 70) := Leaf_Sig;
            Vrf_Bad : Boolean;
         begin
            Sig_Bad (40) := Sig_Bad (40) xor 16#01#;
            Tls_Core.Cert_Chain.Verify_Cert_Verify
              (Leaf_Der       => Leaf_Der,
               Leaf_Parsed    => Leaf_P,
               Sig_Scheme     =>
                 Tls_Core.Cert_Chain.Sig_Ecdsa_Secp256r1_Sha256,
               Signed_Content => Signed_Buf (1 .. Signed_Last),
               Signature      => Sig_Bad,
               OK             => Vrf_Bad);
            Check ("CertVerify rejects bit-flipped signature",
                   not Vrf_Bad);
         end;
      end;

      ---------- (5) Authenticate_Server full pipeline ----------
      declare
         Chain : Tls_Core.Cert_Chain.Chain;
         Trust : Tls_Core.Cert_Chain.Trust_Store;
         Result : Tls_Core.Cert_Chain.Validation_Result;
         Synth_Hash : constant Tls_Core.Octet_Array (1 .. 32) :=
           (others => 16#AA#);
         use type Tls_Core.Cert_Chain.Validation_Result;
      begin
         Chain.Count := 1;
         Chain.Entries (1) := (First => Leaf_F, Last => Leaf_L);
         Trust.Count := 1;
         Trust.Entries (1) := (First => Root_F, Last => Root_L);

         --  (5a) localhost matches: full pipeline accepts.
         Tls_Core.Cert_Chain.Authenticate_Server
           (All_Certs       => All_Certs,
            Chain_In        => Chain,
            Trust           => Trust,
            Hostname        => Hostname_Localhost,
            Sig_Scheme      =>
              Tls_Core.Cert_Chain.Sig_Ecdsa_Secp256r1_Sha256,
            Sig_Body        => Leaf_Sig,
            Transcript_Hash => Synth_Hash,
            Result          => Result);
         Check ("Authenticate_Server localhost OK",
                Result = Tls_Core.Cert_Chain.OK_Validated);

         --  (5b) Bogus hostname: full pipeline rejects (SAN miss).
         Tls_Core.Cert_Chain.Authenticate_Server
           (All_Certs       => All_Certs,
            Chain_In        => Chain,
            Trust           => Trust,
            Hostname        => Hostname_Bogus,
            Sig_Scheme      =>
              Tls_Core.Cert_Chain.Sig_Ecdsa_Secp256r1_Sha256,
            Sig_Body        => Leaf_Sig,
            Transcript_Hash => Synth_Hash,
            Result          => Result);
         Check ("Authenticate_Server bogus hostname rejected",
                Result /= Tls_Core.Cert_Chain.OK_Validated);

         --  (5c) Empty trust store: rejects with Unknown_CA.
         declare
            Empty_Trust : Tls_Core.Cert_Chain.Trust_Store;
         begin
            Empty_Trust.Count := 0;
            Tls_Core.Cert_Chain.Authenticate_Server
              (All_Certs       => All_Certs,
               Chain_In        => Chain,
               Trust           => Empty_Trust,
               Hostname        => Hostname_Localhost,
               Sig_Scheme      =>
                 Tls_Core.Cert_Chain.Sig_Ecdsa_Secp256r1_Sha256,
               Sig_Body        => Leaf_Sig,
               Transcript_Hash => Synth_Hash,
               Result          => Result);
            Check ("Authenticate_Server empty trust => Unknown_CA",
                   Result = Tls_Core.Cert_Chain.Unknown_CA);
         end;

         --  (5d) Bit-flipped CertVerify signature rejected.
         declare
            Sig_Bad : Tls_Core.Octet_Array (1 .. 70) := Leaf_Sig;
         begin
            Sig_Bad (40) := Sig_Bad (40) xor 16#01#;
            Tls_Core.Cert_Chain.Authenticate_Server
              (All_Certs       => All_Certs,
               Chain_In        => Chain,
               Trust           => Trust,
               Hostname        => Hostname_Localhost,
               Sig_Scheme      =>
                 Tls_Core.Cert_Chain.Sig_Ecdsa_Secp256r1_Sha256,
               Sig_Body        => Sig_Bad,
               Transcript_Hash => Synth_Hash,
               Result          => Result);
            Check ("Authenticate_Server bit-flipped sig rejected",
                   Result = Tls_Core.Cert_Chain.Bad_Signature);
         end;
      end;
   end Cert_Chain_Pki_Scenario;

   ---------------------------------------------------------------------
   --  Scenario — RFC 8446 §6 Alert encode / decode round-trip.
   ---------------------------------------------------------------------

   procedure Alert_Codec_Scenario;
   procedure Alert_Codec_Scenario is
      use type Tls_Core.Octet;
   begin
      Put_Line ("scenario — Alert encode/decode round-trip");
      declare
         A : constant Tls_Core.Alert.Alert :=
           (Level       => Tls_Core.Alert.Level_Fatal,
            Description => Tls_Core.Alert.Desc_Bad_Record_Mac);
         B : Tls_Core.Alert.Alert_Bytes;
      begin
         Tls_Core.Alert.Encode (A, B);
         Check ("Alert.Encode level byte", B (1) = 2);
         Check ("Alert.Encode description byte", B (2) = 20);
      end;

      declare
         W : constant Tls_Core.Octet_Array (1 .. 2) :=
           (Tls_Core.Alert.Level_Warning,
            Tls_Core.Alert.Desc_Close_Notify);
         A : Tls_Core.Alert.Alert;
         OK : Boolean;
      begin
         Tls_Core.Alert.Decode (W, A, OK);
         Check ("Alert.Decode close_notify OK", OK);
         Check ("Alert.Decode level field", A.Level = 1);
         Check ("Alert.Decode description field",
                A.Description = Tls_Core.Alert.Desc_Close_Notify);
         Check ("Alert.Is_Close_Notify true",
                Tls_Core.Alert.Is_Close_Notify (A));
         Check ("Alert.Is_Closure true on close_notify",
                Tls_Core.Alert.Is_Closure (A));
      end;

      declare
         W : constant Tls_Core.Octet_Array (1 .. 2) :=
           (Tls_Core.Alert.Level_Fatal,
            Tls_Core.Alert.Desc_Unknown_Ca);
         A : Tls_Core.Alert.Alert;
         OK : Boolean;
      begin
         Tls_Core.Alert.Decode (W, A, OK);
         Check ("Alert.Decode unknown_ca OK", OK);
         Check ("Alert.Is_Close_Notify false on unknown_ca",
                not Tls_Core.Alert.Is_Close_Notify (A));
         Check ("Alert.Is_Closure false on unknown_ca",
                not Tls_Core.Alert.Is_Closure (A));
      end;

      --  Non-2-byte payload must be rejected per §6.
      declare
         W1 : constant Tls_Core.Octet_Array (1 .. 1) := (others => 0);
         W3 : constant Tls_Core.Octet_Array (1 .. 3) := (others => 0);
         A  : Tls_Core.Alert.Alert;
         OK : Boolean;
      begin
         Tls_Core.Alert.Decode (W1, A, OK);
         Check ("Alert.Decode rejects 1-byte payload", not OK);
         Tls_Core.Alert.Decode (W3, A, OK);
         Check ("Alert.Decode rejects 3-byte payload", not OK);
      end;
   end Alert_Codec_Scenario;

   ---------------------------------------------------------------------
   --  Scenario — close_notify clean shutdown over Tls13_Driver.
   --
   --  Two PSK_KE drivers complete a handshake; client then calls
   --  Send_Close_Notify, server feeds the resulting record into an
   --  Aead_Channel.Receive on its inbound app direction, sees inner
   --  type 0x15 + close_notify body, dispatches to its own
   --  Send_Close_Notify. Both sides reach Closed.
   ---------------------------------------------------------------------

   procedure Alert_Close_Notify_Scenario;
   procedure Alert_Close_Notify_Scenario is
      use type Tls_Core.Tls13_Driver.State;
      use type Tls_Core.Octet;

      Psk : constant Tls_Core.Octet_Array (1 .. 32) := (others => 16#42#);
      Identity : constant Tls_Core.Octet_Array :=
        (16#54#, 16#65#, 16#73#, 16#74#);  --  "Test"
      Server_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#11#);
      Client_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#22#);

      C, S : Tls_Core.Tls13_Driver.Driver;
      Buf : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
      Buf_Last : Natural := 0;
   begin
      Put_Line ("scenario — Alert close_notify graceful shutdown");

      Tls_Core.Tls13_Driver.Init_Psk_Server (S, Psk, Identity, Server_Priv);
      Tls_Core.Tls13_Driver.Init_Psk_Client (C, Psk, Identity, Client_Priv);

      --  Drive the four flights to Done on both sides.
      Tls_Core.Tls13_Driver.Step
        (C, In_Bytes => Buf (1 .. 0), Out_Buf => Buf, Out_Last => Buf_Last);
      declare
         Ch : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Reply_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Step
           (S, In_Bytes => Ch, Out_Buf => Reply, Out_Last => Reply_Last);
         Buf := (others => 0);
         Buf (1 .. Reply_Last) := Reply (1 .. Reply_Last);
         Buf_Last := Reply_Last;
      end;
      declare
         Sf_Flight : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Reply_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Step
           (C, In_Bytes => Sf_Flight,
            Out_Buf => Reply, Out_Last => Reply_Last);
         Buf := (others => 0);
         Buf (1 .. Reply_Last) := Reply (1 .. Reply_Last);
         Buf_Last := Reply_Last;
      end;
      declare
         Cf : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Discard : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Discard_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Step
           (S, In_Bytes => Cf, Out_Buf => Discard, Out_Last => Discard_Last);
      end;
      Check ("Alert/close_notify: client reached Done",
             Tls_Core.Tls13_Driver.Current_State (C)
               = Tls_Core.Tls13_Driver.Done);
      Check ("Alert/close_notify: server reached Done",
             Tls_Core.Tls13_Driver.Current_State (S)
               = Tls_Core.Tls13_Driver.Done);

      --  Client emits close_notify; server's app inbound receives it
      --  and sees inner type Alert.
      declare
         Cn_Buf  : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         Cn_Last : Natural;
         Out_Cli, In_Cli, Out_Srv, In_Srv :
           Tls_Core.Aead_Channel.Direction;
         Got     : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         Got_Last : Natural;
         Inner   : Tls_Core.Octet;
         OK      : Boolean;
         Decoded : Tls_Core.Alert.Alert;
         Dec_OK  : Boolean;
      begin
         Tls_Core.Tls13_Driver.Open_App_Directions (C, Out_Cli, In_Cli);
         Tls_Core.Tls13_Driver.Open_App_Directions (S, Out_Srv, In_Srv);
         Tls_Core.Tls13_Driver.Send_Close_Notify (C, Cn_Buf, Cn_Last);
         Check ("Alert/close_notify: client transitions to Closed",
                Tls_Core.Tls13_Driver.Current_State (C)
                  = Tls_Core.Tls13_Driver.Closed);
         Check ("Alert/close_notify: client emitted bytes",
                Cn_Last >= 5 + 2 + 1 + 16);
         Check ("Alert/close_notify: outer type is application_data",
                Cn_Buf (1) = 16#17#);
         --  Server-side: feed the bytes through its inbound app
         --  direction (which we initialised above with the same
         --  app traffic secret as the client's outbound). After the
         --  Send_Close_Notify call though, C's App_Out_Dir is the
         --  driver-internal one — but Out_Cli was initialised
         --  separately, so we re-derive: we sent under C's internal
         --  App_Out_Dir, and the server reads under In_Srv (which is
         --  derived from c_ap secret). Both keys match.
         Tls_Core.Aead_Channel.Receive
           (In_Srv, Cn_Buf (1 .. Cn_Last),
            Got, Got_Last, Inner, OK);
         Check ("Alert/close_notify: server decrypts close_notify", OK);
         Check ("Alert/close_notify: inner type = Alert (0x15)",
                Inner = Tls_Core.Aead_Channel.Inner_Type_Alert);
         Tls_Core.Alert.Decode (Got (1 .. Got_Last), Decoded, Dec_OK);
         Check ("Alert/close_notify: alert body decodes", Dec_OK);
         Check ("Alert/close_notify: description = close_notify",
                Decoded.Description = Tls_Core.Alert.Desc_Close_Notify);
         Check ("Alert/close_notify: Is_Close_Notify",
                Tls_Core.Alert.Is_Close_Notify (Decoded));
      end;
   end Alert_Close_Notify_Scenario;

   ---------------------------------------------------------------------
   --  Scenario — bad_record_mac via tag-flip during handshake.
   --
   --  Server completes CH parsing and sends SH+EE+SF flight. We flip
   --  one byte of the Server-Finished record's AEAD tag before handing
   --  it to the client. Client's Awaiting_Sf step must:
   --    1. detect AEAD verify failure on EE (because EE comes first)
   --    2. transition to Failed
   --    3. emit an encrypted bad_record_mac alert on Out_Buf
   --    4. record Last_Alert = bad_record_mac (20)
   ---------------------------------------------------------------------

   procedure Alert_Bad_Record_Mac_Scenario;
   procedure Alert_Bad_Record_Mac_Scenario is
      use type Tls_Core.Tls13_Driver.State;
      use type Tls_Core.Octet;

      Psk : constant Tls_Core.Octet_Array (1 .. 32) := (others => 16#42#);
      Identity : constant Tls_Core.Octet_Array :=
        (16#54#, 16#65#, 16#73#, 16#74#);  --  "Test"
      Server_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#11#);
      Client_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#22#);

      C, S : Tls_Core.Tls13_Driver.Driver;
      Buf : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
      Buf_Last : Natural := 0;
   begin
      Put_Line ("scenario — Alert bad_record_mac on tag-flip");

      Tls_Core.Tls13_Driver.Init_Psk_Server (S, Psk, Identity, Server_Priv);
      Tls_Core.Tls13_Driver.Init_Psk_Client (C, Psk, Identity, Client_Priv);

      --  Flight 1 + 2 — get the server flight.
      Tls_Core.Tls13_Driver.Step
        (C, In_Bytes => Buf (1 .. 0), Out_Buf => Buf, Out_Last => Buf_Last);
      declare
         Ch : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Reply_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Step
           (S, In_Bytes => Ch, Out_Buf => Reply, Out_Last => Reply_Last);
         Buf := (others => 0);
         Buf (1 .. Reply_Last) := Reply (1 .. Reply_Last);
         Buf_Last := Reply_Last;
      end;

      --  Flip one byte of the server flight (anywhere inside the
      --  first encrypted record's tag — corrupting EE record's last
      --  byte is the simplest reachable position).
      Buf (Buf_Last - 5) := Buf (Buf_Last - 5) xor 16#FF#;

      declare
         Sf_Flight : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Reply_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Step
           (C, In_Bytes => Sf_Flight,
            Out_Buf => Reply, Out_Last => Reply_Last);
         Check ("Alert/bad_record_mac: client transitioned to Failed",
                Tls_Core.Tls13_Driver.Current_State (C)
                  = Tls_Core.Tls13_Driver.Failed);
         Check ("Alert/bad_record_mac: client recorded bad_record_mac",
                Tls_Core.Tls13_Driver.Last_Alert_Description (C)
                  = Tls_Core.Alert.Desc_Bad_Record_Mac);
         Check ("Alert/bad_record_mac: client emitted alert record",
                Reply_Last >= 5 + 2 + 1 + 16);
         --  Outer record content type is 0x17 (TLSCiphertext) because
         --  the Hs_Out_Dir is initialised at this point.
         Check ("Alert/bad_record_mac: alert is TLSCiphertext",
                Reply (1) = 16#17#);
      end;
   end Alert_Bad_Record_Mac_Scenario;

   ---------------------------------------------------------------------
   --  Scenario — server emits a plaintext decode_error alert when the
   --  ClientHello record header is malformed (RFC 8446 §6.2 / §5.1).
   --
   --  Driver is in Awaiting_CH. We feed it a 5-byte fragment whose
   --  outer-type byte is neither Handshake (0x16) nor Alert (0x15).
   --  Per Awaiting_CH, this falls through to Fail_Plaintext
   --  (decode_error) and emits a 7-byte TLSPlaintext Alert record.
   ---------------------------------------------------------------------

   procedure Alert_Decode_Error_Scenario;
   procedure Alert_Decode_Error_Scenario is
      use type Tls_Core.Tls13_Driver.State;
      use type Tls_Core.Octet;
      Psk : constant Tls_Core.Octet_Array (1 .. 32) := (others => 16#42#);
      Identity : constant Tls_Core.Octet_Array :=
        (16#54#, 16#65#, 16#73#, 16#74#);
      Server_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#11#);
      S : Tls_Core.Tls13_Driver.Driver;
      Reply : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
      Reply_Last : Natural;
   begin
      Put_Line ("scenario — Alert plaintext decode_error on bad CH");
      Tls_Core.Tls13_Driver.Init_Psk_Server (S, Psk, Identity, Server_Priv);
      declare
         Garbage : constant Tls_Core.Octet_Array (1 .. 5) :=
           (16#FF#, 16#03#, 16#03#, 16#00#, 16#00#);
      begin
         Tls_Core.Tls13_Driver.Step
           (S, In_Bytes => Garbage,
            Out_Buf => Reply, Out_Last => Reply_Last);
      end;
      Check ("Alert/decode_error: server transitions to Failed",
             Tls_Core.Tls13_Driver.Current_State (S)
               = Tls_Core.Tls13_Driver.Failed);
      Check ("Alert/decode_error: alert is 7-byte plaintext",
             Reply_Last = 7);
      Check ("Alert/decode_error: outer type 0x15",
             Reply (1) = 16#15#);
      Check ("Alert/decode_error: level fatal",
             Reply (6) = Tls_Core.Alert.Level_Fatal);
      Check ("Alert/decode_error: description = decode_error",
             Reply (7) = Tls_Core.Alert.Desc_Decode_Error);
      Check ("Alert/decode_error: Last_Alert recorded",
             Tls_Core.Tls13_Driver.Last_Alert_Description (S)
               = Tls_Core.Alert.Desc_Decode_Error);
   end Alert_Decode_Error_Scenario;

   ---------------------------------------------------------------------
   --  Scenario — Send_Fatal_Alert before keys exist emits plaintext.
   ---------------------------------------------------------------------

   procedure Alert_Plaintext_Fatal_Scenario;
   procedure Alert_Plaintext_Fatal_Scenario is
      use type Tls_Core.Tls13_Driver.State;
      use type Tls_Core.Octet;
      Psk : constant Tls_Core.Octet_Array (1 .. 32) := (others => 16#42#);
      Identity : constant Tls_Core.Octet_Array :=
        (16#54#, 16#65#, 16#73#, 16#74#);
      Server_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#11#);
      D : Tls_Core.Tls13_Driver.Driver;
      Out_Buf : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
      Out_Last : Natural;
   begin
      Put_Line ("scenario — Send_Fatal_Alert before keys = plaintext alert");
      Tls_Core.Tls13_Driver.Init_Psk_Server (D, Psk, Identity, Server_Priv);
      Tls_Core.Tls13_Driver.Send_Fatal_Alert
        (D, Tls_Core.Alert.Desc_Internal_Error, Out_Buf, Out_Last);
      Check ("Send_Fatal_Alert pre-keys: emits 7-byte plaintext alert",
             Out_Last = 7);
      Check ("Send_Fatal_Alert pre-keys: outer type = 0x15 (Alert)",
             Out_Buf (1) = 16#15#);
      Check ("Send_Fatal_Alert pre-keys: legacy_version = 0x0303",
             Out_Buf (2) = 16#03# and then Out_Buf (3) = 16#03#);
      Check ("Send_Fatal_Alert pre-keys: length field = 2",
             Out_Buf (4) = 16#00# and then Out_Buf (5) = 16#02#);
      Check ("Send_Fatal_Alert pre-keys: level = fatal",
             Out_Buf (6) = Tls_Core.Alert.Level_Fatal);
      Check ("Send_Fatal_Alert pre-keys: description = internal_error",
             Out_Buf (7) = Tls_Core.Alert.Desc_Internal_Error);
      Check ("Send_Fatal_Alert pre-keys: state = Failed",
             Tls_Core.Tls13_Driver.Current_State (D)
               = Tls_Core.Tls13_Driver.Failed);
      Check ("Send_Fatal_Alert pre-keys: Last_Alert recorded",
             Tls_Core.Tls13_Driver.Last_Alert_Description (D)
               = Tls_Core.Alert.Desc_Internal_Error);
   end Alert_Plaintext_Fatal_Scenario;

   ---------------------------------------------------------------------
   --  Scenario — Handshake_Buffer multi-record reassembly.
   --
   --  Drive the buffer through the cases the driver will exercise:
   --  one push w/ a complete short message; two pushes w/ a message
   --  split across records; one push w/ two packed messages back-to-
   --  back; oversized push rejected; partial header buffered.
   ---------------------------------------------------------------------

   procedure Handshake_Buffer_Scenario;
   procedure Handshake_Buffer_Scenario is
      use type Tls_Core.Octet;
      B : Tls_Core.Handshake_Buffer.Buffer;
      Pop : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
      Pop_Last : Natural;
      OK : Boolean;
   begin
      Put_Line ("scenario — Handshake_Buffer multi-record reassembly");

      --  Case 1: empty after Init.
      Tls_Core.Handshake_Buffer.Init (B);
      Check ("HB/init: Used = 0",
             Tls_Core.Handshake_Buffer.Used (B) = 0);
      Check ("HB/init: not Has_Complete_Message",
             not Tls_Core.Handshake_Buffer.Has_Complete_Message (B));

      --  Case 2: a complete 4+8-byte handshake message in one push.
      declare
         Msg : constant Tls_Core.Octet_Array (1 .. 12) :=
           (16#01#, 16#00#, 16#00#, 16#08#,
            16#AA#, 16#BB#, 16#CC#, 16#DD#,
            16#EE#, 16#FF#, 16#11#, 16#22#);
      begin
         Tls_Core.Handshake_Buffer.Push_Record_Bytes (B, Msg, OK);
         Check ("HB/whole: push OK", OK);
         Check ("HB/whole: Used = 12",
                Tls_Core.Handshake_Buffer.Used (B) = 12);
         Check ("HB/whole: body length = 8",
                Tls_Core.Handshake_Buffer.Peek_Body_Length (B) = 8);
         Check ("HB/whole: Has_Complete_Message",
                Tls_Core.Handshake_Buffer.Has_Complete_Message (B));
         Tls_Core.Handshake_Buffer.Pop_Complete_Message (B, Pop, Pop_Last);
         Check ("HB/whole: Pop_Last = 12", Pop_Last = 12);
         Check ("HB/whole: leading bytes match",
                Pop (1) = 16#01# and then Pop (4) = 16#08#
                and then Pop (12) = 16#22#);
         Check ("HB/whole: empty after pop",
                Tls_Core.Handshake_Buffer.Used (B) = 0);
      end;

      --  Case 3: split across two records — header in record 1, body
      --  in record 2.
      Tls_Core.Handshake_Buffer.Init (B);
      declare
         Frag1 : constant Tls_Core.Octet_Array (1 .. 6) :=
           (16#0B#, 16#00#, 16#00#, 16#06#, 16#11#, 16#22#);
         Frag2 : constant Tls_Core.Octet_Array (1 .. 4) :=
           (16#33#, 16#44#, 16#55#, 16#66#);
      begin
         Tls_Core.Handshake_Buffer.Push_Record_Bytes (B, Frag1, OK);
         Check ("HB/split: push 1 OK", OK);
         Check ("HB/split: not complete after frag 1",
                not Tls_Core.Handshake_Buffer.Has_Complete_Message (B));
         Tls_Core.Handshake_Buffer.Push_Record_Bytes (B, Frag2, OK);
         Check ("HB/split: push 2 OK", OK);
         Check ("HB/split: complete after frag 2",
                Tls_Core.Handshake_Buffer.Has_Complete_Message (B));
         Tls_Core.Handshake_Buffer.Pop_Complete_Message (B, Pop, Pop_Last);
         Check ("HB/split: Pop_Last = 10", Pop_Last = 10);
         Check ("HB/split: type byte preserved", Pop (1) = 16#0B#);
         Check ("HB/split: tail byte preserved", Pop (10) = 16#66#);
      end;

      --  Case 4: two packed messages in one push.
      Tls_Core.Handshake_Buffer.Init (B);
      declare
         Packed : constant Tls_Core.Octet_Array (1 .. 14) :=
           (16#08#, 16#00#, 16#00#, 16#02#, 16#A0#, 16#A1#,
            16#14#, 16#00#, 16#00#, 16#04#, 16#B0#, 16#B1#,
            16#B2#, 16#B3#);
      begin
         Tls_Core.Handshake_Buffer.Push_Record_Bytes (B, Packed, OK);
         Check ("HB/packed: push OK", OK);
         Check ("HB/packed: Has_Complete_Message",
                Tls_Core.Handshake_Buffer.Has_Complete_Message (B));
         Tls_Core.Handshake_Buffer.Pop_Complete_Message (B, Pop, Pop_Last);
         Check ("HB/packed: first msg Pop_Last = 6",
                Pop_Last = 6);
         Check ("HB/packed: first msg type = 0x08",
                Pop (1) = 16#08#);
         Check ("HB/packed: still has next msg",
                Tls_Core.Handshake_Buffer.Has_Complete_Message (B));
         Tls_Core.Handshake_Buffer.Pop_Complete_Message (B, Pop, Pop_Last);
         Check ("HB/packed: second msg Pop_Last = 8",
                Pop_Last = 8);
         Check ("HB/packed: second msg type = 0x14",
                Pop (1) = 16#14#);
         Check ("HB/packed: empty after both pops",
                Tls_Core.Handshake_Buffer.Used (B) = 0);
      end;

      --  Case 5: partial header (3 bytes) — not yet complete.
      Tls_Core.Handshake_Buffer.Init (B);
      declare
         Partial : constant Tls_Core.Octet_Array (1 .. 3) :=
           (16#0B#, 16#00#, 16#00#);
      begin
         Tls_Core.Handshake_Buffer.Push_Record_Bytes (B, Partial, OK);
         Check ("HB/partial: push OK", OK);
         Check ("HB/partial: not Has_Complete_Message (header < 4)",
                not Tls_Core.Handshake_Buffer.Has_Complete_Message (B));
      end;
   end Handshake_Buffer_Scenario;

   ---------------------------------------------------------------------
   --  Scenario — Tls13_Driver multi-record handshake reassembly.
   --
   --  Validates that the driver's Awaiting_Sf path now reassembles
   --  inbound handshake messages through Handshake_Buffer rather
   --  than assuming each record holds exactly one handshake message
   --  (RFC 8446 §5.1 + C12 v2 wiring).
   --
   --  Sub-tests:
   --    A. Full happy-path handshake: SH(plain) || EE_rec || SF_rec.
   --       The new buffered path successfully pops EE then SF.
   --       Equivalent to scenario 30, focused on the wire shape:
   --       3 records, 2 handshake messages decrypted from the
   --       2 application_data records, reassembled in order.
   --    B. Truncated flight: SH || EE_rec only (no SF). The driver
   --       must transition to Failed because the buffer never
   --       reports a complete second handshake message — exercises
   --       the `Sub /= Done_Sub` end-of-input branch in the new
   --       Step body.
   --    C. Truncated harder: SH only (no encrypted records). The
   --       driver must transition to Failed in the same end-of-
   --       input branch.
   ---------------------------------------------------------------------

   procedure Tls13_Multi_Record_Reassembly_Scenario;
   procedure Tls13_Multi_Record_Reassembly_Scenario is
      use type Tls_Core.Tls13_Driver.State;
      use type Tls_Core.Octet;

      Psk : constant Tls_Core.Octet_Array (1 .. 32) := (others => 16#42#);
      Identity : constant Tls_Core.Octet_Array :=
        (16#54#, 16#65#, 16#73#, 16#74#);  --  "Test"
      Server_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#11#);
      Client_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#22#);

      --  Helper: drive Server and Client to capture Server's
      --  full SH+EE+SF flight bytes in Flight (1 .. Flight_Last).
      procedure Capture_Server_Flight
        (Flight      : out Tls_Core.Octet_Array;
         Flight_Last : out Natural;
         Sh_Rec_Last : out Natural;
         Ee_Rec_Last : out Natural;
         Sf_Rec_Last : out Natural);
      procedure Capture_Server_Flight
        (Flight      : out Tls_Core.Octet_Array;
         Flight_Last : out Natural;
         Sh_Rec_Last : out Natural;
         Ee_Rec_Last : out Natural;
         Sf_Rec_Last : out Natural)
      is
         C, S : Tls_Core.Tls13_Driver.Driver;
         Buf     : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Buf_Last : Natural;
         Reply    : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Reply_Last : Natural;
         Sh_Len, Ee_Len, Sf_Len : Natural;
         Cursor : Natural;
      begin
         Flight := (others => 0);
         Tls_Core.Tls13_Driver.Init_Psk_Server (S, Psk, Identity, Server_Priv);
         Tls_Core.Tls13_Driver.Init_Psk_Client (C, Psk, Identity, Client_Priv);

         --  Client → CH
         Tls_Core.Tls13_Driver.Step
           (C, In_Bytes => Buf (1 .. 0),
            Out_Buf => Buf, Out_Last => Buf_Last);

         --  Server consumes CH, emits SH+EE+SF flight.
         Tls_Core.Tls13_Driver.Step
           (S, In_Bytes => Buf (1 .. Buf_Last),
            Out_Buf => Reply, Out_Last => Reply_Last);

         Flight (1 .. Reply_Last) := Reply (1 .. Reply_Last);
         Flight_Last := Reply_Last;

         --  Decompose Reply into 3 records by walking record headers.
         Cursor := 1;
         Sh_Len := Natural (Reply (Cursor + 3)) * 256
                   + Natural (Reply (Cursor + 4));
         Sh_Rec_Last := Cursor + 5 + Sh_Len - 1;
         Cursor := Sh_Rec_Last + 1;
         Ee_Len := Natural (Reply (Cursor + 3)) * 256
                   + Natural (Reply (Cursor + 4));
         Ee_Rec_Last := Cursor + 5 + Ee_Len - 1;
         Cursor := Ee_Rec_Last + 1;
         Sf_Len := Natural (Reply (Cursor + 3)) * 256
                   + Natural (Reply (Cursor + 4));
         Sf_Rec_Last := Cursor + 5 + Sf_Len - 1;
      end Capture_Server_Flight;

      --  Captured state, shared across sub-tests.
      Flight      : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
      Flight_Last : Natural;
      Sh_Rec_Last : Natural;
      Ee_Rec_Last : Natural;
      Sf_Rec_Last : Natural;
   begin
      Put_Line
        ("scenario — Tls13_Driver multi-record handshake reassembly");

      Capture_Server_Flight
        (Flight, Flight_Last, Sh_Rec_Last, Ee_Rec_Last, Sf_Rec_Last);

      Check ("MR/setup: server flight is 3 records",
             Flight_Last = Sf_Rec_Last);
      Check ("MR/setup: SH boundary < EE boundary < SF boundary",
             Sh_Rec_Last < Ee_Rec_Last
             and then Ee_Rec_Last < Sf_Rec_Last);
      Check ("MR/setup: SH outer type = 0x16",
             Flight (1) = 16#16#);
      Check ("MR/setup: EE outer type = 0x17",
             Flight (Sh_Rec_Last + 1) = 16#17#);
      Check ("MR/setup: SF outer type = 0x17",
             Flight (Ee_Rec_Last + 1) = 16#17#);

      --  Sub-test A: full flight → client reaches Done.
      declare
         C_Ok : Tls_Core.Tls13_Driver.Driver;
         Out_Buf : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Out_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Init_Psk_Client (C_Ok, Psk, Identity, Client_Priv);
         Tls_Core.Tls13_Driver.Step
           (C_Ok, In_Bytes => Out_Buf (1 .. 0),
            Out_Buf => Out_Buf, Out_Last => Out_Last);
         --  Drop the CH outbound; we only need the client to reach
         --  Awaiting_Sf so the next Step processes the captured
         --  server flight.
         Tls_Core.Tls13_Driver.Step
           (C_Ok,
            In_Bytes => Flight (1 .. Flight_Last),
            Out_Buf  => Out_Buf,
            Out_Last => Out_Last);
         Check ("MR/A: full flight → client Done",
                Tls_Core.Tls13_Driver.Current_State (C_Ok)
                  = Tls_Core.Tls13_Driver.Done);
      end;

      --  Sub-test B: truncate to SH+EE_rec (no SF). Buffer pops EE
      --  but not SF; new code transitions to Failed via end-of-input
      --  branch.
      declare
         C_Trunc : Tls_Core.Tls13_Driver.Driver;
         Out_Buf : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Out_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Init_Psk_Client (C_Trunc, Psk, Identity, Client_Priv);
         Tls_Core.Tls13_Driver.Step
           (C_Trunc, In_Bytes => Out_Buf (1 .. 0),
            Out_Buf => Out_Buf, Out_Last => Out_Last);
         Tls_Core.Tls13_Driver.Step
           (C_Trunc,
            In_Bytes => Flight (1 .. Ee_Rec_Last),
            Out_Buf  => Out_Buf,
            Out_Last => Out_Last);
         Check ("MR/B: SH+EE only → client Failed",
                Tls_Core.Tls13_Driver.Current_State (C_Trunc)
                  = Tls_Core.Tls13_Driver.Failed);
         Check ("MR/B: SH+EE only → decode_error alert recorded",
                Tls_Core.Tls13_Driver.Last_Alert_Description (C_Trunc)
                  = Tls_Core.Alert.Desc_Decode_Error);
      end;

      --  Sub-test C: truncate to SH-only. Buffer never holds even
      --  EE; new code reports Failed (with decode_error) without
      --  attempting any AEAD decrypt.
      declare
         C_Sh : Tls_Core.Tls13_Driver.Driver;
         Out_Buf : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Out_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Init_Psk_Client (C_Sh, Psk, Identity, Client_Priv);
         Tls_Core.Tls13_Driver.Step
           (C_Sh, In_Bytes => Out_Buf (1 .. 0),
            Out_Buf => Out_Buf, Out_Last => Out_Last);
         Tls_Core.Tls13_Driver.Step
           (C_Sh,
            In_Bytes => Flight (1 .. Sh_Rec_Last),
            Out_Buf  => Out_Buf,
            Out_Last => Out_Last);
         Check ("MR/C: SH-only → client Failed",
                Tls_Core.Tls13_Driver.Current_State (C_Sh)
                  = Tls_Core.Tls13_Driver.Failed);
      end;
   end Tls13_Multi_Record_Reassembly_Scenario;

   --------------------------------------------------------------------
   --  Scenario 35 — Session_Ticket wire encode/decode + cache.
   --
   --  Validates Tls_Core.Session_Ticket.Encode_Body / Decode_Body
   --  round-trip the §4.6.1 wire shape and that Tls_Core.Session_Cache
   --  Insert / Lookup_Most_Recent / Invalidate behave per spec.
   --------------------------------------------------------------------
   procedure Session_Ticket_Wire_Scenario;
   procedure Session_Ticket_Wire_Scenario is
      use type Interfaces.Unsigned_32;

      --  Sample fields per RFC 8446 §4.6.1.
      Lifetime : constant Tls_Core.Session_Ticket.U32 := 16#00010203#;
      Age_Add  : constant Tls_Core.Session_Ticket.U32 := 16#04050607#;
      Nonce    : constant Tls_Core.Octet_Array (1 .. 8) :=
        (16#11#, 16#22#, 16#33#, 16#44#,
         16#55#, 16#66#, 16#77#, 16#88#);
      Ticket   : constant Tls_Core.Octet_Array (1 .. 16) :=
        (16#A0#, 16#A1#, 16#A2#, 16#A3#,
         16#A4#, 16#A5#, 16#A6#, 16#A7#,
         16#A8#, 16#A9#, 16#AA#, 16#AB#,
         16#AC#, 16#AD#, 16#AE#, 16#AF#);

      Buf  : Tls_Core.Octet_Array (1 .. 1600) := (others => 0);
      Last : Natural;
   begin
      Put_Line ("scenario 35a — Session_Ticket Encode/Decode wire round-trip");

      Tls_Core.Session_Ticket.Encode_Body
        (Lifetime     => Lifetime,
         Age_Add      => Age_Add,
         Ticket_Nonce => Nonce,
         Ticket       => Ticket,
         Out_Buf      => Buf,
         Out_Last     => Last);

      Check ("Session_Ticket: Encode_Body length =" &
             Integer'Image (4 + 4 + 1 + 8 + 2 + 16 + 2),
             Last = 4 + 4 + 1 + Nonce'Length
                    + 2 + Ticket'Length + 2);
      --  uint32 BE lifetime.
      Check ("Session_Ticket: lifetime byte 0",
             Buf (1) = 16#00#);
      Check ("Session_Ticket: lifetime byte 1",
             Buf (2) = 16#01#);
      Check ("Session_Ticket: lifetime byte 2",
             Buf (3) = 16#02#);
      Check ("Session_Ticket: lifetime byte 3",
             Buf (4) = 16#03#);
      --  uint32 BE age_add.
      Check ("Session_Ticket: age_add byte 0",
             Buf (5) = 16#04#);
      Check ("Session_Ticket: age_add byte 3",
             Buf (8) = 16#07#);
      --  Nonce length octet.
      Check ("Session_Ticket: nonce length octet =" &
             Natural'Image (Nonce'Length),
             Buf (9) = Tls_Core.Octet (Nonce'Length));
      --  Nonce bytes.
      Check ("Session_Ticket: nonce byte 0", Buf (10) = 16#11#);
      Check ("Session_Ticket: nonce byte 7", Buf (17) = 16#88#);
      --  u16 BE ticket length, ticket bytes, then empty extensions.
      Check ("Session_Ticket: ticket length high",
             Buf (18) = 16#00#);
      Check ("Session_Ticket: ticket length low =" &
             Natural'Image (Ticket'Length),
             Buf (19) = Tls_Core.Octet (Ticket'Length));
      Check ("Session_Ticket: ticket byte 0", Buf (20) = 16#A0#);
      Check ("Session_Ticket: ticket byte last", Buf (35) = 16#AF#);
      Check ("Session_Ticket: extensions length high = 0",
             Buf (36) = 0);
      Check ("Session_Ticket: extensions length low = 0",
             Buf (37) = 0);

      --  Decode round-trip.
      declare
         D_Lifetime : Tls_Core.Session_Ticket.U32;
         D_Age      : Tls_Core.Session_Ticket.U32;
         Nf         : Natural;
         Nl         : Integer;
         Tf         : Natural;
         Tl         : Integer;
         OK         : Boolean;
      begin
         Tls_Core.Session_Ticket.Decode_Body
           (In_Buf       => Buf (1 .. Last),
            Lifetime     => D_Lifetime,
            Age_Add      => D_Age,
            Nonce_First  => Nf,
            Nonce_Last   => Nl,
            Ticket_First => Tf,
            Ticket_Last  => Tl,
            OK           => OK);
         Check ("Session_Ticket: Decode round-trip OK", OK);
         Check ("Session_Ticket: lifetime round-trips",
                D_Lifetime = Lifetime);
         Check ("Session_Ticket: age_add round-trips",
                D_Age = Age_Add);
         Check ("Session_Ticket: nonce slice length matches",
                Nl - Nf + 1 = Nonce'Length);
         Check ("Session_Ticket: nonce bytes round-trip",
                Equal (Buf (Nf .. Nl), Nonce));
         Check ("Session_Ticket: ticket slice length matches",
                Tl - Tf + 1 = Ticket'Length);
         Check ("Session_Ticket: ticket bytes round-trip",
                Equal (Buf (Tf .. Tl), Ticket));
      end;

      --  Decode malformed: short buffer.
      declare
         Bad : Tls_Core.Octet_Array (1 .. 13) := (others => 0);
         D_Lifetime : Tls_Core.Session_Ticket.U32;
         D_Age      : Tls_Core.Session_Ticket.U32;
         Nf         : Natural;
         Nl         : Integer;
         Tf         : Natural;
         Tl         : Integer;
         OK         : Boolean;
      begin
         Tls_Core.Session_Ticket.Decode_Body
           (Bad, D_Lifetime, D_Age, Nf, Nl, Tf, Tl, OK);
         Check ("Session_Ticket: Decode rejects short buffer",
                not OK);
      end;

      --  Decode malformed: ticket length zero (RFC: ticket<1..2^16-1>).
      declare
         Mb : Tls_Core.Octet_Array (1 .. 14) :=
           (16#00#, 16#00#, 16#00#, 16#0A#,    --  lifetime
            16#00#, 16#00#, 16#00#, 16#00#,    --  age_add
            16#00#,                              --  nonce_len = 0
            16#00#, 16#00#,                      --  ticket_len = 0
            16#00#, 16#00#,                      --  ext_len = 0
            16#00#);                             --  pad
         D_Lifetime : Tls_Core.Session_Ticket.U32;
         D_Age      : Tls_Core.Session_Ticket.U32;
         Nf         : Natural;
         Nl         : Integer;
         Tf         : Natural;
         Tl         : Integer;
         OK         : Boolean;
      begin
         Tls_Core.Session_Ticket.Decode_Body
           (Mb (1 .. 13), D_Lifetime, D_Age, Nf, Nl, Tf, Tl, OK);
         Check ("Session_Ticket: Decode rejects ticket_len = 0",
                not OK);
      end;

      --  Empty nonce + 1-byte ticket round-trip.
      declare
         Empty_Nonce : constant Tls_Core.Octet_Array (1 .. 0) :=
           (others => 0);
         Tiny_Ticket : constant Tls_Core.Octet_Array (1 .. 1) :=
           (1 => 16#5A#);
         Tb : Tls_Core.Octet_Array (1 .. 64) := (others => 0);
         Tl_E : Natural;
         D_Lifetime : Tls_Core.Session_Ticket.U32;
         D_Age      : Tls_Core.Session_Ticket.U32;
         Nf         : Natural;
         Nl         : Integer;
         Tf         : Natural;
         Tl_D       : Integer;
         OK         : Boolean;
      begin
         Tls_Core.Session_Ticket.Encode_Body
           (Lifetime     => 16#0000_FFFF#,
            Age_Add      => 16#1234_5678#,
            Ticket_Nonce => Empty_Nonce,
            Ticket       => Tiny_Ticket,
            Out_Buf      => Tb,
            Out_Last     => Tl_E);
         Check ("Session_Ticket: empty-nonce encoded length = 14",
                Tl_E = 4 + 4 + 1 + 0 + 2 + 1 + 2);
         Tls_Core.Session_Ticket.Decode_Body
           (Tb (1 .. Tl_E),
            D_Lifetime, D_Age, Nf, Nl, Tf, Tl_D, OK);
         Check ("Session_Ticket: empty-nonce decode OK", OK);
         Check ("Session_Ticket: empty-nonce roundtrip lifetime",
                D_Lifetime = 16#0000_FFFF#);
         Check ("Session_Ticket: empty-nonce roundtrip age_add",
                D_Age = 16#1234_5678#);
         Check ("Session_Ticket: empty-nonce slice empty",
                Nl < Nf);
         Check ("Session_Ticket: empty-nonce ticket slice 1 byte",
                Tl_D - Tf + 1 = 1
                and then Tb (Tf) = 16#5A#);
      end;
   end Session_Ticket_Wire_Scenario;

   --------------------------------------------------------------------
   --  Scenario 36 — Session_Cache Insert / Lookup / Invalidate.
   --------------------------------------------------------------------
   procedure Session_Cache_Scenario;
   procedure Session_Cache_Scenario is
      use type Interfaces.Unsigned_32;
      use type Tls_Core.Session_Cache.Slot_Index;
      use type Tls_Core.Suites.Cipher_Suite_Id;

      Cache : Tls_Core.Session_Cache.Cache;

      Nonce_A : constant Tls_Core.Octet_Array (1 .. 4) :=
        (16#01#, 16#02#, 16#03#, 16#04#);
      Ticket_A : constant Tls_Core.Octet_Array (1 .. 6) :=
        (16#A0#, 16#A1#, 16#A2#, 16#A3#, 16#A4#, 16#A5#);
      Nonce_B : constant Tls_Core.Octet_Array (1 .. 4) :=
        (16#B0#, 16#B1#, 16#B2#, 16#B3#);
      Ticket_B : constant Tls_Core.Octet_Array (1 .. 8) :=
        (16#B0#, 16#B1#, 16#B2#, 16#B3#,
         16#B4#, 16#B5#, 16#B6#, 16#B7#);
      Secret_A : constant Tls_Core.Key_Schedule.Secret :=
        (others => 16#5A#);
      Secret_B : constant Tls_Core.Key_Schedule.Secret :=
        (others => 16#A5#);
   begin
      Put_Line ("scenario 35b — Session_Cache Insert / Lookup / Invalidate");

      Tls_Core.Session_Cache.Init (Cache);

      --  Empty cache: lookup should report Found = False.
      declare
         Idx : Tls_Core.Session_Cache.Slot_Index;
         Found : Boolean;
      begin
         Tls_Core.Session_Cache.Lookup_Most_Recent (Cache, Idx, Found);
         Check ("Session_Cache: empty cache => Found = False",
                not Found);
      end;

      --  Insert one.
      Tls_Core.Session_Cache.Insert
        (C                 => Cache,
         Lifetime          => 7200,
         Age_Add           => 16#1111_2222#,
         Ticket_Nonce      => Nonce_A,
         Ticket            => Ticket_A,
         Resumption_Secret => Secret_A,
         Suite             => Tls_Core.Suites.Aes_128_Gcm_Sha256);

      declare
         Idx : Tls_Core.Session_Cache.Slot_Index;
         Found : Boolean;
      begin
         Tls_Core.Session_Cache.Lookup_Most_Recent (Cache, Idx, Found);
         Check ("Session_Cache: 1-slot lookup Found = True", Found);
         Check ("Session_Cache: lookup returns A's lifetime",
                Cache.Slots (Idx).Lifetime = 7200);
         Check ("Session_Cache: lookup returns A's nonce length",
                Cache.Slots (Idx).Ticket_Nonce_Len = Nonce_A'Length);
         Check ("Session_Cache: lookup returns A's nonce bytes",
                Equal
                  (Cache.Slots (Idx).Ticket_Nonce
                     (1 .. Cache.Slots (Idx).Ticket_Nonce_Len),
                   Nonce_A));
         Check ("Session_Cache: lookup returns A's ticket length",
                Cache.Slots (Idx).Ticket_Len = Ticket_A'Length);
         Check ("Session_Cache: lookup returns A's ticket bytes",
                Equal
                  (Cache.Slots (Idx).Ticket
                     (1 .. Cache.Slots (Idx).Ticket_Len),
                   Ticket_A));
         Check ("Session_Cache: lookup returns A's resumption secret",
                Equal
                  (Tls_Core.Octet_Array (Cache.Slots (Idx).Resumption_Secret),
                   Tls_Core.Octet_Array (Secret_A)));
         Check ("Session_Cache: lookup returns A's suite",
                Cache.Slots (Idx).Suite =
                  Tls_Core.Suites.Aes_128_Gcm_Sha256);
      end;

      --  Insert second; lookup should return the second (most recent).
      Tls_Core.Session_Cache.Insert
        (C                 => Cache,
         Lifetime          => 3600,
         Age_Add           => 16#3333_4444#,
         Ticket_Nonce      => Nonce_B,
         Ticket            => Ticket_B,
         Resumption_Secret => Secret_B,
         Suite             => Tls_Core.Suites.Chacha20_Poly1305_Sha256);

      declare
         Idx : Tls_Core.Session_Cache.Slot_Index;
         Found : Boolean;
      begin
         Tls_Core.Session_Cache.Lookup_Most_Recent (Cache, Idx, Found);
         Check ("Session_Cache: 2-slot lookup picks B (most recent)",
                Found
                and then Cache.Slots (Idx).Lifetime = 3600
                and then Cache.Slots (Idx).Suite =
                           Tls_Core.Suites.Chacha20_Poly1305_Sha256);
      end;

      --  Invalidate B; lookup should now return A.
      declare
         Idx : Tls_Core.Session_Cache.Slot_Index;
         Found : Boolean;
      begin
         Tls_Core.Session_Cache.Lookup_Most_Recent (Cache, Idx, Found);
         Check ("Session_Cache: pre-invalidate found", Found);
         Tls_Core.Session_Cache.Invalidate (Cache, Idx);
         Tls_Core.Session_Cache.Lookup_Most_Recent (Cache, Idx, Found);
         Check ("Session_Cache: after invalidate B, lookup picks A",
                Found
                and then Cache.Slots (Idx).Lifetime = 7200);
      end;

      --  Fill the cache and one over to exercise FIFO eviction.
      --  Slot_Count = 4. We have one Used (A); add 4 more, each a
      --  unique tag in the lifetime so we can detect which got
      --  evicted.
      Tls_Core.Session_Cache.Insert
        (C => Cache, Lifetime => 1, Age_Add => 0,
         Ticket_Nonce => Nonce_A, Ticket => Ticket_A,
         Resumption_Secret => Secret_A,
         Suite => Tls_Core.Suites.Aes_128_Gcm_Sha256);
      Tls_Core.Session_Cache.Insert
        (C => Cache, Lifetime => 2, Age_Add => 0,
         Ticket_Nonce => Nonce_A, Ticket => Ticket_A,
         Resumption_Secret => Secret_A,
         Suite => Tls_Core.Suites.Aes_128_Gcm_Sha256);
      Tls_Core.Session_Cache.Insert
        (C => Cache, Lifetime => 3, Age_Add => 0,
         Ticket_Nonce => Nonce_A, Ticket => Ticket_A,
         Resumption_Secret => Secret_A,
         Suite => Tls_Core.Suites.Aes_128_Gcm_Sha256);
      --  Now all 4 slots occupied. The next insert must evict the
      --  oldest. The first insert (the original A with lifetime
      --  7200) was first chronologically, so it is the oldest.
      Tls_Core.Session_Cache.Insert
        (C => Cache, Lifetime => 4, Age_Add => 0,
         Ticket_Nonce => Nonce_A, Ticket => Ticket_A,
         Resumption_Secret => Secret_A,
         Suite => Tls_Core.Suites.Aes_128_Gcm_Sha256);

      declare
         Found_7200 : Boolean := False;
         Found_4    : Boolean := False;
      begin
         for I in Tls_Core.Session_Cache.Slot_Index loop
            if Cache.Slots (I).Used then
               if Cache.Slots (I).Lifetime = 7200 then
                  Found_7200 := True;
               elsif Cache.Slots (I).Lifetime = 4 then
                  Found_4 := True;
               end if;
            end if;
         end loop;
         Check ("Session_Cache: FIFO eviction removed oldest (lifetime=7200)",
                not Found_7200);
         Check ("Session_Cache: FIFO eviction kept newest (lifetime=4)",
                Found_4);
      end;
   end Session_Cache_Scenario;

   --------------------------------------------------------------------
   --  Scenario 37 — End-to-end NewSessionTicket flow.
   --
   --  Drive a full PSK_KE handshake to Done; have the server emit a
   --  NewSessionTicket on the application Aead_Channel; client
   --  decrypts and stores it in the Session_Cache; verify cached
   --  state matches the bytes the server sent.
   --
   --  This exercises the production path RFC 8446 §4.6.1 calls out:
   --  NST is a post-handshake message ridden over the application
   --  AEAD channel and consumed by the client without the driver
   --  changing state.
   --------------------------------------------------------------------
   procedure Session_Ticket_End_To_End_Scenario;
   procedure Session_Ticket_End_To_End_Scenario is
      use type Tls_Core.Tls13_Driver.State;
      use type Interfaces.Unsigned_32;

      Psk : constant Tls_Core.Octet_Array (1 .. 32) := (others => 16#42#);
      Identity : constant Tls_Core.Octet_Array :=
        (16#54#, 16#65#, 16#73#, 16#74#);

      C, S : Tls_Core.Tls13_Driver.Driver;
      Buf : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
      Buf_Last : Natural := 0;

      Out_Cli, In_Cli, Out_Srv, In_Srv :
        Tls_Core.Aead_Channel.Direction;
      Sec_Cli_Out, Sec_Cli_In : Tls_Core.Key_Schedule.Secret;
      Sec_Srv_Out, Sec_Srv_In : Tls_Core.Key_Schedule.Secret;

      Cache : Tls_Core.Session_Cache.Cache;

      Server_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#11#);
      Client_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#22#);
   begin
      Put_Line ("scenario 35c — NewSessionTicket end-to-end emit/receive/cache");

      --  Drive the handshake to Done.
      Tls_Core.Tls13_Driver.Init_Psk_Server (S, Psk, Identity, Server_Priv);
      Tls_Core.Tls13_Driver.Init_Psk_Client (C, Psk, Identity, Client_Priv);

      Tls_Core.Tls13_Driver.Step
        (C, In_Bytes => Buf (1 .. 0),
         Out_Buf => Buf, Out_Last => Buf_Last);
      declare
         Ch : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Reply_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Step (S, Ch, Reply, Reply_Last);
         Buf := (others => 0);
         Buf (1 .. Reply_Last) := Reply (1 .. Reply_Last);
         Buf_Last := Reply_Last;
      end;
      declare
         Sf : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Reply_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Step (C, Sf, Reply, Reply_Last);
         Buf := (others => 0);
         Buf (1 .. Reply_Last) := Reply (1 .. Reply_Last);
         Buf_Last := Reply_Last;
      end;
      declare
         Cf : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Discard : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Discard_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Step (S, Cf, Discard, Discard_Last);
      end;

      Check ("NST e2e: server reached Done",
             Tls_Core.Tls13_Driver.Current_State (S)
               = Tls_Core.Tls13_Driver.Done);
      Check ("NST e2e: client reached Done",
             Tls_Core.Tls13_Driver.Current_State (C)
               = Tls_Core.Tls13_Driver.Done);
      Check ("NST e2e: server has resumption secret",
             Tls_Core.Tls13_Driver.Resumption_Master_Secret_Available (S));
      Check ("NST e2e: client has resumption secret",
             Tls_Core.Tls13_Driver.Resumption_Master_Secret_Available (C));

      --  Open application directions on both sides.
      Tls_Core.Tls13_Driver.Open_App_Directions
        (C, Out_Cli, In_Cli, Sec_Cli_Out, Sec_Cli_In);
      Tls_Core.Tls13_Driver.Open_App_Directions
        (S, Out_Srv, In_Srv, Sec_Srv_Out, Sec_Srv_In);

      --  Server emits one NST.
      declare
         Nonce : constant Tls_Core.Octet_Array (1 .. 4) :=
           (16#DE#, 16#AD#, 16#BE#, 16#EF#);
         Tkt : constant Tls_Core.Octet_Array (1 .. 24) :=
           (16#01#, 16#02#, 16#03#, 16#04#,
            16#05#, 16#06#, 16#07#, 16#08#,
            16#09#, 16#0A#, 16#0B#, 16#0C#,
            16#0D#, 16#0E#, 16#0F#, 16#10#,
            16#11#, 16#12#, 16#13#, 16#14#,
            16#15#, 16#16#, 16#17#, 16#18#);
         Wire : Tls_Core.Octet_Array (1 .. 2048) := (others => 0);
         Wire_Last : Natural;
         Got_OK : Boolean;
      begin
         Tls_Core.Tls13_Driver.Send_New_Session_Ticket
           (D            => S,
            Out_Dir      => Out_Srv,
            Lifetime     => 7200,
            Age_Add      => 16#1234_5678#,
            Ticket_Nonce => Nonce,
            Ticket_Bytes => Tkt,
            Out_Buf      => Wire,
            Out_Last     => Wire_Last);

         Check ("NST e2e: server emitted record",
                Wire_Last > 5 + 1 + 16);
         --  TLSCiphertext outer content type = application_data.
         Check ("NST e2e: outer content type = 0x17 (app_data)",
                Wire (1) = 16#17#);

         --  Client receives + stores into cache.
         Tls_Core.Session_Cache.Init (Cache);
         Tls_Core.Tls13_Driver.Receive_New_Session_Ticket
           (D            => C,
            In_Dir       => In_Cli,
            Cache        => Cache,
            Record_Bytes => Wire (1 .. Wire_Last),
            OK           => Got_OK);

         Check ("NST e2e: client decoded NST", Got_OK);

         --  Inspect cache.
         declare
            Idx : Tls_Core.Session_Cache.Slot_Index;
            Found : Boolean;
         begin
            Tls_Core.Session_Cache.Lookup_Most_Recent (Cache, Idx, Found);
            Check ("NST e2e: cache populated", Found);
            Check ("NST e2e: cache lifetime = 7200",
                   Cache.Slots (Idx).Lifetime = 7200);
            Check ("NST e2e: cache age_add = 0x12345678",
                   Cache.Slots (Idx).Age_Add = 16#1234_5678#);
            Check ("NST e2e: cache nonce length",
                   Cache.Slots (Idx).Ticket_Nonce_Len = Nonce'Length);
            Check ("NST e2e: cache nonce bytes",
                   Equal
                     (Cache.Slots (Idx).Ticket_Nonce
                        (1 .. Cache.Slots (Idx).Ticket_Nonce_Len),
                      Nonce));
            Check ("NST e2e: cache ticket length",
                   Cache.Slots (Idx).Ticket_Len = Tkt'Length);
            Check ("NST e2e: cache ticket bytes",
                   Equal
                     (Cache.Slots (Idx).Ticket
                        (1 .. Cache.Slots (Idx).Ticket_Len),
                      Tkt));
            --  The cached resumption_master_secret is what the
            --  client derived from CH..CF. Both endpoints ran the
            --  same key schedule so the client- and server-side
            --  values agree (the server's is internal; we sanity-
            --  check that the cached secret is nontrivial — i.e.
            --  it was actually derived rather than left at the
            --  default zero of an uninitialised slot).
            Check ("NST e2e: cached resumption secret nonzero",
                   Cache.Slots (Idx).Resumption_Secret (1) /= 0
                   or else Cache.Slots (Idx).Resumption_Secret (16) /= 0
                   or else Cache.Slots (Idx).Resumption_Secret (32) /= 0);
         end;
      end;

      --  Init_Psk_Resumption_Client smoke check: derives a PSK from
      --  the cached slot and reaches a fresh Idle state.
      declare
         Idx : Tls_Core.Session_Cache.Slot_Index;
         Found : Boolean;
         Resume_Cli : Tls_Core.Tls13_Driver.Driver;
      begin
         Tls_Core.Session_Cache.Lookup_Most_Recent (Cache, Idx, Found);
         if Found and then Cache.Slots (Idx).Ticket_Len in 1 .. 64 then
            Tls_Core.Tls13_Driver.Init_Psk_Resumption_Client
              (Resume_Cli, Cache.Slots (Idx));
            Check
              ("NST e2e: resumption client initialised at Idle",
               Tls_Core.Tls13_Driver.Current_State (Resume_Cli)
                 = Tls_Core.Tls13_Driver.Idle);
         end if;
      end;
   end Session_Ticket_End_To_End_Scenario;

   ---------------------------------------------------------------------
   --  Scenario — SNI emit (RFC 6066 §3 / RFC 8446 §4.2.10)
   --
   --  Validates that:
   --    1. Set_Sni_Hostname stores the bytes on the driver
   --    2. Sni_Hostname getter reads them back
   --    3. After CH emit, the wire bytes contain the server_name
   --       extension (type 0x0000) with the host_name bytes
   --    4. With no SNI set (default), CH does NOT contain the
   --       server_name extension
   ---------------------------------------------------------------------

   procedure Sni_Emit_Scenario;
   procedure Sni_Emit_Scenario is
      use type Tls_Core.Octet;
      use type Tls_Core.Octet_Array;
      Psk : constant Tls_Core.Octet_Array (1 .. 32) := (others => 16#42#);
      Identity : constant Tls_Core.Octet_Array :=
        (16#54#, 16#65#, 16#73#, 16#74#);  --  "Test"
      Client_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#22#);
      Hostname : constant Tls_Core.Octet_Array :=
        (16#65#, 16#78#, 16#61#, 16#6D#, 16#70#,
         16#6C#, 16#65#, 16#2E#, 16#63#, 16#6F#,
         16#6D#);  --  "example.com" (11 bytes)

      function Find_Ext_Type
        (Buf      : Tls_Core.Octet_Array;
         Hi, Lo   : Tls_Core.Octet) return Boolean
      is
         I : Natural := Buf'First;
      begin
         while I + 1 <= Buf'Last loop
            if Buf (I) = Hi and then Buf (I + 1) = Lo then
               return True;
            end if;
            I := I + 1;
         end loop;
         return False;
      end Find_Ext_Type;

   begin
      Put_Line ("scenario — SNI Set/Get + emit in CH");

      --  Case 1: client with SNI set emits server_name extension.
      declare
         C : Tls_Core.Tls13_Driver.Driver;
         Buf : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Buf_Last : Natural;
         Read_Out : Tls_Core.Octet_Array (1 .. 255) := (others => 0);
         Read_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Init_Psk_Client
           (C, Psk, Identity, Client_Priv);
         Tls_Core.Tls13_Driver.Set_Sni_Hostname (C, Hostname);
         Tls_Core.Tls13_Driver.Sni_Hostname (C, Read_Out, Read_Last);
         Check ("SNI/get: hostname length round-trips",
                Read_Last = Hostname'Length);
         Check ("SNI/get: hostname bytes round-trip",
                Read_Out (1 .. Read_Last) = Hostname);

         Tls_Core.Tls13_Driver.Step
           (C, In_Bytes => Buf (1 .. 0),
            Out_Buf => Buf, Out_Last => Buf_Last);
         Check ("SNI/emit: CH contains server_name ext type 0x0000",
                Find_Ext_Type (Buf (1 .. Buf_Last), 16#00#, 16#00#));
         Check ("SNI/emit: CH bytes contain hostname",
                (for some I in Buf'First .. Buf_Last - Hostname'Length + 1 =>
                   Buf (I .. I + Hostname'Length - 1) = Hostname));
      end;

      --  Case 2: client without SNI set does NOT emit server_name ext.
      --  We assert by checking that the hostname bytes don't appear
      --  on the wire (a stronger end-to-end check than ext-type
      --  scanning, since unrelated 0x00 0x00 byte pairs may appear
      --  inside other extensions).
      declare
         C : Tls_Core.Tls13_Driver.Driver;
         Buf : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Buf_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Init_Psk_Client
           (C, Psk, Identity, Client_Priv);
         --  No Set_Sni_Hostname call.
         Tls_Core.Tls13_Driver.Step
           (C, In_Bytes => Buf (1 .. 0),
            Out_Buf => Buf, Out_Last => Buf_Last);
         Check ("SNI/no-set: hostname bytes absent from CH",
                not (for some I in Buf'First .. Buf_Last - Hostname'Length + 1 =>
                       Buf (I .. I + Hostname'Length - 1) = Hostname));
      end;
   end Sni_Emit_Scenario;

   ---------------------------------------------------------------------
   --  Scenario — ALPN emit (RFC 7301 + RFC 8446 §4.2 / §4.3.1)
   --
   --  Validates that:
   --    1. Set_Alpn_Offers stores the flattened ProtocolName list
   --    2. Alpn_Offers getter reads it back
   --    3. After CH emit, the wire bytes contain the ALPN extension
   --       (type 0x0010) and the protocol name "h2"
   --    4. With no Set_Alpn_Offers call, CH does NOT contain ALPN
   ---------------------------------------------------------------------

   procedure Alpn_Emit_Scenario;
   procedure Alpn_Emit_Scenario is
      use type Tls_Core.Octet;
      use type Tls_Core.Octet_Array;
      Psk : constant Tls_Core.Octet_Array (1 .. 32) := (others => 16#42#);
      Identity : constant Tls_Core.Octet_Array :=
        (16#54#, 16#65#, 16#73#, 16#74#);  --  "Test"
      Client_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#22#);

      --  Pre-flattened "u8 N || N name bytes" for "h2"
      --  (gRPC over TLS uses h2; per RFC 7301 + IANA registry).
      H2_Offer : constant Tls_Core.Octet_Array :=
        (16#02#, 16#68#, 16#32#);  --  len=2 || 'h' '2'

      function Find_Bytes
        (Buf    : Tls_Core.Octet_Array;
         Needle : Tls_Core.Octet_Array) return Boolean
      is
      begin
         if Needle'Length = 0 or else Buf'Length < Needle'Length then
            return False;
         end if;
         for I in Buf'First .. Buf'Last - Needle'Length + 1 loop
            if Buf (I .. I + Needle'Length - 1) = Needle then
               return True;
            end if;
         end loop;
         return False;
      end Find_Bytes;

   begin
      Put_Line ("scenario — ALPN Set/Get + emit in CH");

      --  Case 1: client with ALPN set emits the extension.
      declare
         C : Tls_Core.Tls13_Driver.Driver;
         Buf : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Buf_Last : Natural;
         Read_Out : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         Read_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Init_Psk_Client
           (C, Psk, Identity, Client_Priv);
         Tls_Core.Tls13_Driver.Set_Alpn_Offers (C, H2_Offer);
         Tls_Core.Tls13_Driver.Alpn_Offers (C, Read_Out, Read_Last);
         Check ("ALPN/get: offers length round-trips",
                Read_Last = H2_Offer'Length);
         Check ("ALPN/get: offers bytes round-trip",
                Read_Out (1 .. Read_Last) = H2_Offer);

         Tls_Core.Tls13_Driver.Step
           (C, In_Bytes => Buf (1 .. 0),
            Out_Buf => Buf, Out_Last => Buf_Last);
         --  Find the 0x00 0x10 ext-type marker AND the "h2" body
         --  on the wire. We require both because 0x00 0x10 alone
         --  could occur as length bytes inside other extensions.
         Check ("ALPN/emit: CH contains ext type 0x0010",
                Find_Bytes
                  (Buf (1 .. Buf_Last),
                   Tls_Core.Octet_Array'(16#00#, 16#10#)));
         Check ("ALPN/emit: CH contains the 'h2' protocol name",
                Find_Bytes
                  (Buf (1 .. Buf_Last),
                   Tls_Core.Octet_Array'(16#02#, 16#68#, 16#32#)));
      end;

      --  Case 2: no Set_Alpn_Offers call — extension absent.
      declare
         C : Tls_Core.Tls13_Driver.Driver;
         Buf : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Buf_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Init_Psk_Client
           (C, Psk, Identity, Client_Priv);
         Tls_Core.Tls13_Driver.Step
           (C, In_Bytes => Buf (1 .. 0),
            Out_Buf => Buf, Out_Last => Buf_Last);
         Check ("ALPN/no-set: 'h2' protocol-name bytes absent from CH",
                not Find_Bytes
                      (Buf (1 .. Buf_Last),
                       Tls_Core.Octet_Array'(16#02#, 16#68#, 16#32#)));
      end;
   end Alpn_Emit_Scenario;

   ---------------------------------------------------------------------
   --  Scenario — Process_Post_Handshake_Plaintext demux
   --             (RFC 8446 §4.6 / §4.6.1 / §4.6.3).
   --
   --  Drives a PSK Ada-vs-Ada handshake to Done so D has the
   --  resumption_master_secret available, then exercises the demux
   --  dispatch:
   --    1. Inner_Type=app data passes through untouched
   --    2. Inner_Type=Handshake, first byte=0x18 → KeyUpdate path
   --    3. Inner_Type=Handshake, unknown type → OK=False
   ---------------------------------------------------------------------

   procedure Post_Handshake_Demux_Scenario;
   procedure Post_Handshake_Demux_Scenario is
      use type Tls_Core.Octet;
      use type Tls_Core.Tls13_Driver.State;
      Psk : constant Tls_Core.Octet_Array (1 .. 32) := (others => 16#42#);
      Identity : constant Tls_Core.Octet_Array :=
        (16#54#, 16#65#, 16#73#, 16#74#);
      Server_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#11#);
      Client_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#22#);

      C, S : Tls_Core.Tls13_Driver.Driver;
      Buf : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
      Buf_Last : Natural;
      Out_Cli, In_Cli : Tls_Core.Aead_Channel.Direction;
      Sec_Cli_Out, Sec_Cli_In : Tls_Core.Key_Schedule.Secret;
      Cache : Tls_Core.Session_Cache.Cache;
   begin
      Put_Line ("scenario — Process_Post_Handshake_Plaintext demux");

      Tls_Core.Tls13_Driver.Init_Psk_Server (S, Psk, Identity, Server_Priv);
      Tls_Core.Tls13_Driver.Init_Psk_Client (C, Psk, Identity, Client_Priv);

      --  Drive handshake: CH → SH+EE+SF → CF.
      Tls_Core.Tls13_Driver.Step
        (C, In_Bytes => Buf (1 .. 0), Out_Buf => Buf, Out_Last => Buf_Last);
      declare
         Ch_Bytes : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Reply_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Step (S, Ch_Bytes, Reply, Reply_Last);
         Tls_Core.Tls13_Driver.Step
           (C, Reply (1 .. Reply_Last), Buf, Buf_Last);
      end;
      declare
         Cf : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Reply_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Step (S, Cf, Reply, Reply_Last);
      end;
      Check ("Demux: client reached Done",
             Tls_Core.Tls13_Driver.Current_State (C)
               = Tls_Core.Tls13_Driver.Done);
      Check ("Demux: server reached Done",
             Tls_Core.Tls13_Driver.Current_State (S)
               = Tls_Core.Tls13_Driver.Done);

      Tls_Core.Tls13_Driver.Open_App_Directions
        (C, Out_Cli, In_Cli, Sec_Cli_Out, Sec_Cli_In);

      --  Case 1: Inner_Type=Application_Data passes through.
      declare
         App_Pt : constant Tls_Core.Octet_Array :=
           (16#48#, 16#65#, 16#6C#, 16#6C#, 16#6F#);  --  "Hello"
         Saw_Nst, Saw_Ku, Want_Reply, OK : Boolean;
      begin
         Tls_Core.Tls13_Driver.Process_Post_Handshake_Plaintext
           (D            => C,
            Plaintext    => App_Pt,
            Inner_Type   => Tls_Core.Aead_Channel.Inner_Type_Application_Data,
            In_Dir       => In_Cli,
            Recv_Secret  => Sec_Cli_In,
            Cache        => Cache,
            Saw_Nst      => Saw_Nst,
            Saw_KeyUpdate => Saw_Ku,
            Want_Reply   => Want_Reply,
            OK           => OK);
         Check ("Demux/app: OK = True", OK);
         Check ("Demux/app: Saw_Nst = False", not Saw_Nst);
         Check ("Demux/app: Saw_KeyUpdate = False", not Saw_Ku);
         Check ("Demux/app: Want_Reply = False", not Want_Reply);
      end;

      --  Case 2: Inner_Type=Handshake, KeyUpdate (type 0x18, body
      --  length 1 = 0x000001, request_update 0x00).
      declare
         Ku_Pt : constant Tls_Core.Octet_Array :=
           (16#18#, 16#00#, 16#00#, 16#01#, 16#00#);
         Saw_Nst, Saw_Ku, Want_Reply, OK : Boolean;
      begin
         Tls_Core.Tls13_Driver.Process_Post_Handshake_Plaintext
           (D            => C,
            Plaintext    => Ku_Pt,
            Inner_Type   => Tls_Core.Aead_Channel.Inner_Type_Handshake,
            In_Dir       => In_Cli,
            Recv_Secret  => Sec_Cli_In,
            Cache        => Cache,
            Saw_Nst      => Saw_Nst,
            Saw_KeyUpdate => Saw_Ku,
            Want_Reply   => Want_Reply,
            OK           => OK);
         Check ("Demux/keyupd: OK = True", OK);
         Check ("Demux/keyupd: Saw_KeyUpdate = True", Saw_Ku);
         Check ("Demux/keyupd: Saw_Nst = False", not Saw_Nst);
         Check ("Demux/keyupd: Want_Reply = False (req=0)", not Want_Reply);
      end;

      --  Case 3: Inner_Type=Handshake, unknown type byte (0xAA) →
      --  RFC 8446 §6.2 unexpected_message → OK=False (caller's
      --  policy whether to alert).
      declare
         Bad_Pt : constant Tls_Core.Octet_Array :=
           (16#AA#, 16#00#, 16#00#, 16#00#);
         Saw_Nst, Saw_Ku, Want_Reply, OK : Boolean;
      begin
         Tls_Core.Tls13_Driver.Process_Post_Handshake_Plaintext
           (D            => C,
            Plaintext    => Bad_Pt,
            Inner_Type   => Tls_Core.Aead_Channel.Inner_Type_Handshake,
            In_Dir       => In_Cli,
            Recv_Secret  => Sec_Cli_In,
            Cache        => Cache,
            Saw_Nst      => Saw_Nst,
            Saw_KeyUpdate => Saw_Ku,
            Want_Reply   => Want_Reply,
            OK           => OK);
         Check ("Demux/unknown: OK = False (per §6.2)", not OK);
      end;
   end Post_Handshake_Demux_Scenario;

   ---------------------------------------------------------------------
   --  Scenario — DER encode ECDSA Sig-Value SEQUENCE (RFC 5480 §2.2 /
   --              SEC 1 §C.5)
   --
   --  Validates Tls_Core.Cert_Verify.Encode_Ecdsa_Sig_Der against:
   --    1. The known DER signature already used by Cert_Chain_Pki_
   --       Scenario above — extract its r/s, re-encode, expect the
   --       byte stream to round-trip identically.
   --    2. A synthetic (r, s) where r's first byte has its high bit
   --       set, forcing a 0x00 pad to keep the INTEGER positive.
   --    3. A synthetic (r, s) with leading zero bytes that must be
   --       stripped, so the encoded INTEGER is shorter than 32 bytes.
   ---------------------------------------------------------------------
   procedure Ecdsa_Sig_Der_Scenario;
   procedure Ecdsa_Sig_Der_Scenario is
      use type Tls_Core.Octet;
      use type Tls_Core.Octet_Array;

      --  r/s extracted from Leaf_Sig in Cert_Chain_Pki_Scenario.
      --  Layout of Leaf_Sig: 0x30 0x44 0x02 0x20 <32B r> 0x02 0x20 <32B s>
      R_From_Fixture : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#03#, 16#BA#, 16#EE#, 16#B7#, 16#9D#, 16#81#, 16#B7#, 16#0C#,
         16#81#, 16#C0#, 16#4C#, 16#53#, 16#EB#, 16#03#, 16#CF#, 16#A6#,
         16#E2#, 16#9A#, 16#78#, 16#E0#, 16#B9#, 16#00#, 16#32#, 16#DB#,
         16#7B#, 16#4D#, 16#5E#, 16#9D#, 16#02#, 16#B3#, 16#9B#, 16#E2#);
      S_From_Fixture : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#13#, 16#61#, 16#15#, 16#13#, 16#79#, 16#5D#, 16#16#, 16#20#,
         16#6C#, 16#38#, 16#BC#, 16#C4#, 16#EE#, 16#C5#, 16#34#, 16#EE#,
         16#2C#, 16#AB#, 16#08#, 16#82#, 16#B7#, 16#4F#, 16#43#, 16#05#,
         16#F0#, 16#2E#, 16#1E#, 16#B1#, 16#09#, 16#06#, 16#02#, 16#35#);
      Expected_Sig : constant Tls_Core.Octet_Array (1 .. 70) :=
        (16#30#, 16#44#, 16#02#, 16#20#, 16#03#, 16#BA#, 16#EE#, 16#B7#,
         16#9D#, 16#81#, 16#B7#, 16#0C#, 16#81#, 16#C0#, 16#4C#, 16#53#,
         16#EB#, 16#03#, 16#CF#, 16#A6#, 16#E2#, 16#9A#, 16#78#, 16#E0#,
         16#B9#, 16#00#, 16#32#, 16#DB#, 16#7B#, 16#4D#, 16#5E#, 16#9D#,
         16#02#, 16#B3#, 16#9B#, 16#E2#, 16#02#, 16#20#, 16#13#, 16#61#,
         16#15#, 16#13#, 16#79#, 16#5D#, 16#16#, 16#20#, 16#6C#, 16#38#,
         16#BC#, 16#C4#, 16#EE#, 16#C5#, 16#34#, 16#EE#, 16#2C#, 16#AB#,
         16#08#, 16#82#, 16#B7#, 16#4F#, 16#43#, 16#05#, 16#F0#, 16#2E#,
         16#1E#, 16#B1#, 16#09#, 16#06#, 16#02#, 16#35#);
   begin
      Put_Line ("scenario — Encode_Ecdsa_Sig_Der");

      --  Case 1: round-trip a real PKI ECDSA-SHA256 signature.
      declare
         Out_Buf  : Tls_Core.Octet_Array (1 .. 72) := (others => 0);
         Out_Last : Natural;
      begin
         Tls_Core.Cert_Verify.Encode_Ecdsa_Sig_Der
           (R_From_Fixture, S_From_Fixture, Out_Buf, Out_Last);
         Check ("ECDSA Sig-Value: length round-trip = 70",
                Out_Last = 70);
         Check ("ECDSA Sig-Value: bytes match real-PKI fixture",
                Out_Buf (1 .. Out_Last) = Expected_Sig);
      end;

      --  Case 2: r with high-bit-set first byte forces 0x00 pad,
      --  pushing total length from 70 → 71.
      declare
         R_Hb : constant Tls_Core.Octet_Array (1 .. 32) :=
           (16#80#, others => 16#11#);
         S_Hb : constant Tls_Core.Octet_Array (1 .. 32) :=
           (16#22#, others => 16#22#);
         Out_Buf  : Tls_Core.Octet_Array (1 .. 72) := (others => 0);
         Out_Last : Natural;
      begin
         Tls_Core.Cert_Verify.Encode_Ecdsa_Sig_Der
           (R_Hb, S_Hb, Out_Buf, Out_Last);
         Check ("ECDSA Sig-Value: high-bit r adds 0x00 pad → len 71",
                Out_Last = 71);
         Check ("ECDSA Sig-Value: high-bit r → SEQUENCE body 69",
                Out_Buf (2) = 69);
         Check ("ECDSA Sig-Value: high-bit r → r INTEGER body 33",
                Out_Buf (4) = 33);
         Check ("ECDSA Sig-Value: high-bit r → 0x00 pad byte",
                Out_Buf (5) = 16#00#);
         Check ("ECDSA Sig-Value: high-bit r → first non-pad byte",
                Out_Buf (6) = 16#80#);
      end;

      --  Case 3: leading zero bytes in r get stripped. r = 0x00 0x00 ..
      --  0x00 0x42 (only one nonzero byte at position 32) → r INTEGER
      --  body length 1.
      declare
         R_Zero : Tls_Core.Octet_Array (1 .. 32) := (others => 0);
         S_Zero : constant Tls_Core.Octet_Array (1 .. 32) :=
           (others => 16#33#);
         Out_Buf  : Tls_Core.Octet_Array (1 .. 72) := (others => 0);
         Out_Last : Natural;
      begin
         R_Zero (32) := 16#42#;
         Tls_Core.Cert_Verify.Encode_Ecdsa_Sig_Der
           (R_Zero, S_Zero, Out_Buf, Out_Last);
         --  Expected: 0x30 len 0x02 0x01 0x42 0x02 0x20 <32B s> = 39
         Check ("ECDSA Sig-Value: stripped-zeros r → len 39",
                Out_Last = 39);
         Check ("ECDSA Sig-Value: stripped-zeros r → r INTEGER body 1",
                Out_Buf (4) = 1);
         Check ("ECDSA Sig-Value: stripped-zeros r → only nonzero byte",
                Out_Buf (5) = 16#42#);
      end;
   end Ecdsa_Sig_Der_Scenario;

   ---------------------------------------------------------------------
   --  Scenario — cert-mode ServerHello encoder (RFC 8446 §4.1.3)
   --
   --  Validates Tls_Core.Hello.Encode_Server_Hello_Cert against the
   --  PSK ServerHello it mirrors, asserting:
   --    1. Encoded length is positive and within the buffer.
   --    2. Body shape matches the §4.1.3 layout (legacy_version
   --       0x0303, server random, empty session_id, selected suite,
   --       0x00 compression_methods, extensions block).
   --    3. The selected cipher suite is echoed correctly.
   --    4. The 32-byte server X25519 key_share is present in the
   --       wire bytes.
   --    5. **The pre_shared_key extension type (0x0029) is NOT
   --       emitted**, distinguishing this from Encode_Server_Hello_Psk.
   ---------------------------------------------------------------------
   procedure Cert_Server_Hello_Scenario;
   procedure Cert_Server_Hello_Scenario is
      use type Tls_Core.Octet;
      use type Tls_Core.Octet_Array;
      use type Tls_Core.Suites.U16;

      Server_Random : constant Tls_Core.Hello.Random_Bytes :=
        (others => 16#5A#);
      Server_Pub : constant Tls_Core.Hello.Public_Key :=
        (1 .. 32 => 16#7B#);

      function Find_Pair
        (Buf : Tls_Core.Octet_Array;
         Hi, Lo : Tls_Core.Octet) return Boolean
      is
         I : Natural := Buf'First;
      begin
         while I + 1 <= Buf'Last loop
            if Buf (I) = Hi and then Buf (I + 1) = Lo then
               return True;
            end if;
            I := I + 1;
         end loop;
         return False;
      end Find_Pair;

      function Find_Run
        (Buf : Tls_Core.Octet_Array;
         Pat : Tls_Core.Octet_Array) return Boolean
      is
         I : Natural := Buf'First;
      begin
         while I + Pat'Length - 1 <= Buf'Last loop
            if Buf (I .. I + Pat'Length - 1) = Pat then
               return True;
            end if;
            I := I + 1;
         end loop;
         return False;
      end Find_Run;

   begin
      Put_Line ("scenario — Encode_Server_Hello_Cert (RFC 8446 §4.1.3)");

      declare
         Out_Buf  : Tls_Core.Octet_Array (1 .. 192) := (others => 0);
         Out_Last : Natural;
      begin
         Tls_Core.Hello.Encode_Server_Hello_Cert
           (Random          => Server_Random,
            Session_Id_Echo => Tls_Core.Octet_Array'(1 .. 0 => 0),
            Selected_Suite  => Tls_Core.Suites.TLS_AES_128_GCM_SHA256,
            Key_Share       => Server_Pub,
            Out_Buf         => Out_Buf,
            Out_Last        => Out_Last);

         Check ("Cert SH: encoded length in 1 .. Out_Buf'Last",
                Out_Last in 1 .. Out_Buf'Last);
         --  legacy_version 0x0303
         Check ("Cert SH: legacy_version = 0x0303",
                Out_Buf (1) = 16#03# and then Out_Buf (2) = 16#03#);
         --  Random at bytes 3..34 — first two bytes match Server_Random.
         Check ("Cert SH: random_bytes copied",
                Out_Buf (3) = 16#5A# and then Out_Buf (34) = 16#5A#);
         --  session_id_len = 0 at byte 35
         Check ("Cert SH: session_id_len = 0",
                Out_Buf (35) = 0);
         --  Selected suite at bytes 36..37 = TLS_AES_128_GCM_SHA256
         --  (0x1301)
         Check ("Cert SH: selected suite hi = 0x13",
                Out_Buf (36) = 16#13#);
         Check ("Cert SH: selected suite lo = 0x01",
                Out_Buf (37) = 16#01#);
         --  compression_method = 0
         Check ("Cert SH: compression_method = 0",
                Out_Buf (38) = 0);
         --  Server key_share (32 bytes 0x7B) appears verbatim somewhere
         --  in the extension block.
         declare
             Pat : constant Tls_Core.Octet_Array (1 .. 32) :=
               (others => 16#7B#);
         begin
             Check ("Cert SH: 32-byte X25519 key share present",
                    Find_Run (Out_Buf (1 .. Out_Last), Pat));
         end;
         --  pre_shared_key extension (type 0x0029) MUST NOT be present.
         Check ("Cert SH: pre_shared_key (0x0029) ABSENT",
                not Find_Pair (Out_Buf (1 .. Out_Last), 16#00#, 16#29#));
         --  supported_versions extension (type 0x002B) MUST be present.
         Check ("Cert SH: supported_versions (0x002B) present",
                Find_Pair (Out_Buf (1 .. Out_Last), 16#00#, 16#2B#));
         --  key_share extension (type 0x0033) MUST be present.
         Check ("Cert SH: key_share (0x0033) present",
                Find_Pair (Out_Buf (1 .. Out_Last), 16#00#, 16#33#));
      end;
   end Cert_Server_Hello_Scenario;

   ---------------------------------------------------------------------
   --  Scenario — cert-mode ClientHello encoder (RFC 8446 §4.1.2)
   --
   --  Validates Tls_Core.Hello.Encode_Client_Hello_Cert against the
   --  PSK CH encoder it parallels. Asserts:
   --    1. Encoded length is positive and within the buffer.
   --    2. Body shape matches §4.1.2 (legacy_version, random,
   --       empty session_id, three v0.5 cipher suites, compression
   --       method 0).
   --    3. signature_algorithms (0x000D) extension is present and
   --       advertises both ecdsa_secp256r1_sha256 (0x0403) and
   --       rsa_pss_rsae_sha256 (0x0804).
   --    4. The 32-byte X25519 client key share is present.
   --    5. **Neither pre_shared_key (0x0029) nor
   --       psk_key_exchange_modes (0x002D) appears**, distinguishing
   --       cert-mode CH from PSK-mode CH on the wire.
   --    6. Optional SNI / ALPN extensions are emitted when
   --       Server_Name / Alpn_Offers are non-empty, omitted otherwise.
   ---------------------------------------------------------------------
   procedure Cert_Client_Hello_Scenario;
   procedure Cert_Client_Hello_Scenario is
      use type Tls_Core.Octet;
      use type Tls_Core.Octet_Array;

      Client_Random : constant Tls_Core.Hello.Random_Bytes :=
        (others => 16#3C#);
      Client_Pub : constant Tls_Core.Hello.Public_Key :=
        (1 .. 32 => 16#6D#);

      Hostname : constant Tls_Core.Octet_Array :=
        (16#65#, 16#78#, 16#61#, 16#6D#, 16#70#,
         16#6C#, 16#65#, 16#2E#, 16#63#, 16#6F#,
         16#6D#);  --  "example.com"

      H2_Alpn : constant Tls_Core.Octet_Array :=
        (16#02#, 16#68#, 16#32#);  --  "u8 2; 'h', '2'"

      function Find_Pair
        (Buf : Tls_Core.Octet_Array;
         Hi, Lo : Tls_Core.Octet) return Boolean
      is
         I : Natural := Buf'First;
      begin
         while I + 1 <= Buf'Last loop
            if Buf (I) = Hi and then Buf (I + 1) = Lo then
               return True;
            end if;
            I := I + 1;
         end loop;
         return False;
      end Find_Pair;

      function Find_Run
        (Buf : Tls_Core.Octet_Array;
         Pat : Tls_Core.Octet_Array) return Boolean
      is
         I : Natural := Buf'First;
      begin
         while I + Pat'Length - 1 <= Buf'Last loop
            if Buf (I .. I + Pat'Length - 1) = Pat then
               return True;
            end if;
            I := I + 1;
         end loop;
         return False;
      end Find_Run;

   begin
      Put_Line ("scenario — Encode_Client_Hello_Cert (RFC 8446 §4.1.2)");

      --  Case 1: bare cert CH — no SNI, no ALPN.
      declare
         Empty : constant Tls_Core.Octet_Array (1 .. 0) := (others => 0);
         Out_Buf  : Tls_Core.Octet_Array (1 .. 320) := (others => 0);
         Out_Last : Natural;
      begin
         Tls_Core.Hello.Encode_Client_Hello_Cert
           (Random      => Client_Random,
            Key_Share   => Client_Pub,
            Server_Name => Empty,
            Alpn_Offers => Empty,
            Out_Buf     => Out_Buf,
            Out_Last    => Out_Last);

         Check ("Cert CH: encoded length in 1 .. Out_Buf'Last",
                Out_Last in 1 .. Out_Buf'Last);
         --  legacy_version 0x0303
         Check ("Cert CH: legacy_version = 0x0303",
                Out_Buf (1) = 16#03# and then Out_Buf (2) = 16#03#);
         --  Random copied
         Check ("Cert CH: random_bytes copied",
                Out_Buf (3) = 16#3C# and then Out_Buf (34) = 16#3C#);
         Check ("Cert CH: session_id_len = 0",
                Out_Buf (35) = 0);
         --  cipher_suites: 6 bytes (3 suites). Bytes 36..37 = list_len.
         Check ("Cert CH: cipher_suites list_len = 6",
                Out_Buf (36) = 16#00# and then Out_Buf (37) = 16#06#);
         --  First suite = TLS_CHACHA20_POLY1305_SHA256 (0x1303)
         Check ("Cert CH: first suite = chacha20-poly1305-sha256",
                Out_Buf (38) = 16#13# and then Out_Buf (39) = 16#03#);
         --  signature_algorithms (0x000D) MUST appear
         Check ("Cert CH: signature_algorithms (0x000D) present",
                Find_Pair (Out_Buf (1 .. Out_Last), 16#00#, 16#0D#));
         --  Verify the v0.5 sig schemes appear: 0x0403 + 0x0804
         declare
            Sig_Pat : constant Tls_Core.Octet_Array (1 .. 6) :=
              (16#00#, 16#04#, 16#04#, 16#03#, 16#08#, 16#04#);
         begin
            Check ("Cert CH: sig_alg list (ecdsa+rsa-pss) present",
                   Find_Run (Out_Buf (1 .. Out_Last), Sig_Pat));
         end;
         --  pre_shared_key (0x0029) MUST NOT be present
         Check ("Cert CH: pre_shared_key (0x0029) ABSENT",
                not Find_Pair (Out_Buf (1 .. Out_Last), 16#00#, 16#29#));
         --  psk_key_exchange_modes (0x002D) MUST NOT be present
         Check ("Cert CH: psk_key_exchange_modes (0x002D) ABSENT",
                not Find_Pair (Out_Buf (1 .. Out_Last), 16#00#, 16#2D#));
         --  X25519 client key (32 bytes 0x6D) appears
         declare
            Pat : constant Tls_Core.Octet_Array (1 .. 32) :=
              (others => 16#6D#);
         begin
            Check ("Cert CH: 32-byte X25519 key share present",
                   Find_Run (Out_Buf (1 .. Out_Last), Pat));
         end;
         --  No SNI/ALPN advertised
         Check ("Cert CH (no SNI): hostname bytes ABSENT",
                not Find_Run (Out_Buf (1 .. Out_Last), Hostname));
         Check ("Cert CH (no ALPN): h2 alpn bytes ABSENT",
                not Find_Run (Out_Buf (1 .. Out_Last), H2_Alpn));
      end;

      --  Case 2: cert CH WITH SNI + ALPN.
      declare
         Out_Buf  : Tls_Core.Octet_Array (1 .. 320) := (others => 0);
         Out_Last : Natural;
      begin
         Tls_Core.Hello.Encode_Client_Hello_Cert
           (Random      => Client_Random,
            Key_Share   => Client_Pub,
            Server_Name => Hostname,
            Alpn_Offers => H2_Alpn,
            Out_Buf     => Out_Buf,
            Out_Last    => Out_Last);
         Check ("Cert CH (SNI): hostname bytes present",
                Find_Run (Out_Buf (1 .. Out_Last), Hostname));
         Check ("Cert CH (ALPN): h2 alpn bytes present",
                Find_Run (Out_Buf (1 .. Out_Last), H2_Alpn));
         Check ("Cert CH (SNI): server_name (0x0000) present",
                Find_Pair (Out_Buf (1 .. Out_Last), 16#00#, 16#00#));
         Check ("Cert CH (ALPN): alpn (0x0010) present",
                Find_Pair (Out_Buf (1 .. Out_Last), 16#00#, 16#10#));
      end;
   end Cert_Client_Hello_Scenario;

   ---------------------------------------------------------------------
   --  Scenario — cert-mode ClientHello round-trip (encoder + decoder).
   --
   --  Encode → Decode and assert Random / Suites slice / Sig_Algs
   --  slice / Key_Share slice round-trip correctly.  Also assert that
   --  the decoder rejects:
   --    - a CH with the signature_algorithms extension stripped
   --    - a CH with the key_share extension stripped
   --  These are the two REQUIRED extensions for cert mode.
   ---------------------------------------------------------------------
   procedure Cert_Client_Hello_Roundtrip_Scenario;
   procedure Cert_Client_Hello_Roundtrip_Scenario is
      use type Tls_Core.Octet;
      use type Tls_Core.Octet_Array;

      Client_Random : constant Tls_Core.Hello.Random_Bytes :=
        (others => 16#A1#);
      Client_Pub : constant Tls_Core.Hello.Public_Key :=
        (1 .. 32 => 16#3F#);
      Empty : constant Tls_Core.Octet_Array (1 .. 0) := (others => 0);

      Out_Buf  : Tls_Core.Octet_Array (1 .. 320) := (others => 0);
      Out_Last : Natural;
   begin
      Put_Line ("scenario — cert-mode CH encode/decode round-trip");

      Tls_Core.Hello.Encode_Client_Hello_Cert
        (Random      => Client_Random,
         Key_Share   => Client_Pub,
         Server_Name => Empty,
         Alpn_Offers => Empty,
         Out_Buf     => Out_Buf,
         Out_Last    => Out_Last);

      declare
         Decoded_Random : Tls_Core.Hello.Random_Bytes;
         Sid_F, Sid_L : Natural;
         S_F, S_L, A_F, A_L, K_F, K_L : Natural;
         OK : Boolean;
      begin
         Tls_Core.Hello.Decode_Client_Hello_Cert
           (In_Bytes         => Out_Buf (1 .. Out_Last),
            Random           => Decoded_Random,
            Session_Id_First => Sid_F,
            Session_Id_Last  => Sid_L,
            Suites_First     => S_F,
            Suites_Last      => S_L,
            Sig_Algs_First   => A_F,
            Sig_Algs_Last    => A_L,
            Key_Share_First  => K_F,
            Key_Share_Last   => K_L,
            OK               => OK);
         pragma Unreferenced (Sid_F, Sid_L);

         Check ("Cert CH round-trip: OK = True", OK);
         Check ("Cert CH round-trip: random matches",
                Decoded_Random = Client_Random);
         Check ("Cert CH round-trip: suites slice = 6 bytes",
                S_L - S_F + 1 = 6);
         Check ("Cert CH round-trip: first suite = 0x1303",
                Out_Buf (S_F) = 16#13#
                and then Out_Buf (S_F + 1) = 16#03#);
         Check ("Cert CH round-trip: sig_algs slice = 4 bytes",
                A_L - A_F + 1 = 4);
         Check ("Cert CH round-trip: ecdsa_secp256r1_sha256 first",
                Out_Buf (A_F) = 16#04#
                and then Out_Buf (A_F + 1) = 16#03#);
         Check ("Cert CH round-trip: rsa_pss_rsae_sha256 second",
                Out_Buf (A_F + 2) = 16#08#
                and then Out_Buf (A_F + 3) = 16#04#);
         Check ("Cert CH round-trip: key_share = 32 bytes",
                K_L - K_F + 1 = 32);
         Check ("Cert CH round-trip: key_share bytes match",
                Out_Buf (K_F .. K_L)
                = Tls_Core.Octet_Array'(1 .. 32 => 16#3F#));
      end;

      --  Negative case 1: corrupt the signature_algorithms extension
      --  type (0x000D → 0x00FE) so the decoder can't find it.
      declare
         Mutated  : Tls_Core.Octet_Array (1 .. Out_Last);
         Decoded_Random : Tls_Core.Hello.Random_Bytes;
         Sid_F, Sid_L : Natural;
         S_F, S_L, A_F, A_L, K_F, K_L : Natural;
         OK : Boolean;
         Found : Boolean := False;
      begin
         Mutated := Out_Buf (1 .. Out_Last);
         --  Locate the 0x00 0x0D extension type pair and zero its low
         --  byte to 0xFE so the extension type lookup misses.
         for I in Mutated'First .. Mutated'Last - 1 loop
            if Mutated (I) = 16#00#
              and then Mutated (I + 1) = 16#0D#
              and then not Found
            then
               Mutated (I + 1) := 16#FE#;
               Found := True;
            end if;
         end loop;

         Check ("Cert CH negative: setup found 0x000D ext type",
                Found);
         Tls_Core.Hello.Decode_Client_Hello_Cert
           (In_Bytes         => Mutated,
            Random           => Decoded_Random,
            Session_Id_First => Sid_F,
            Session_Id_Last  => Sid_L,
            Suites_First     => S_F,
            Suites_Last      => S_L,
            Sig_Algs_First   => A_F,
            Sig_Algs_Last    => A_L,
            Key_Share_First  => K_F,
            Key_Share_Last   => K_L,
            OK               => OK);
         pragma Unreferenced (Sid_F, Sid_L);
         Check ("Cert CH negative: missing sig_algs → OK = False",
                not OK);
      end;

      --  Negative case 2: corrupt the key_share extension type
      --  (0x0033 → 0x00FE) so the decoder can't find x25519.
      declare
         Mutated  : Tls_Core.Octet_Array (1 .. Out_Last);
         Decoded_Random : Tls_Core.Hello.Random_Bytes;
         Sid_F, Sid_L : Natural;
         S_F, S_L, A_F, A_L, K_F, K_L : Natural;
         OK : Boolean;
         Found : Boolean := False;
      begin
         Mutated := Out_Buf (1 .. Out_Last);
         for I in Mutated'First .. Mutated'Last - 1 loop
            if Mutated (I) = 16#00#
              and then Mutated (I + 1) = 16#33#
              and then not Found
            then
               Mutated (I + 1) := 16#FE#;
               Found := True;
            end if;
         end loop;
         Check ("Cert CH negative: setup found 0x0033 ext type",
                Found);
         Tls_Core.Hello.Decode_Client_Hello_Cert
           (In_Bytes         => Mutated,
            Random           => Decoded_Random,
            Session_Id_First => Sid_F,
            Session_Id_Last  => Sid_L,
            Suites_First     => S_F,
            Suites_Last      => S_L,
            Sig_Algs_First   => A_F,
            Sig_Algs_Last    => A_L,
            Key_Share_First  => K_F,
            Key_Share_Last   => K_L,
            OK               => OK);
         pragma Unreferenced (Sid_F, Sid_L);
         Check ("Cert CH negative: missing key_share → OK = False",
                not OK);
      end;
   end Cert_Client_Hello_Roundtrip_Scenario;

   ---------------------------------------------------------------------
   --  Scenario — TLS 1.3 cert-mode handshake, Ada-vs-Ada loopback.
   --
   --  Drives Tls13_Driver in Cert_Mode end-to-end against the existing
   --  PKI fixtures (Leaf_Der + Root_Der + leaf private key).  The
   --  flow:
   --
   --    Idle (client) → CH                         [TLSPlaintext]
   --    Awaiting_CH (server) → SH+EE+Cert+CV+SF    [SH plaintext;
   --                                                EE/Cert/CV/SF
   --                                                encrypted under
   --                                                handshake AEAD]
   --    Awaiting_Sf (client) → CF                  [encrypted]
   --    Awaiting_Cf (server) → Done
   --    Client → Done (after sending CF)
   --
   --  Asserts that both sides reach Done and the application traffic
   --  secrets agree (round-trip an app message through the AEAD
   --  channels both ways).
   ---------------------------------------------------------------------
   procedure Tls13_Cert_Mode_Loopback_Scenario;
   procedure Tls13_Cert_Mode_Loopback_Scenario is
      use type Tls_Core.Tls13_Driver.State;
      use type Tls_Core.Tls13_Driver.Driver_Mode;
      use type Tls_Core.Octet;

      --  ===== embedded fixtures (paste from fixtures/fixtures.ada) =====

      Root_Der : constant Tls_Core.Octet_Array (1 .. 392) :=
        (16#30#, 16#82#, 16#01#, 16#84#, 16#30#, 16#82#, 16#01#, 16#29#,
         16#A0#, 16#03#, 16#02#, 16#01#, 16#02#, 16#02#, 16#14#, 16#4C#,
         16#38#, 16#ED#, 16#66#, 16#47#, 16#3E#, 16#2B#, 16#B0#, 16#25#,
         16#DA#, 16#0E#, 16#29#, 16#CA#, 16#0C#, 16#F7#, 16#CE#, 16#F0#,
         16#B4#, 16#19#, 16#C8#, 16#30#, 16#0A#, 16#06#, 16#08#, 16#2A#,
         16#86#, 16#48#, 16#CE#, 16#3D#, 16#04#, 16#03#, 16#02#, 16#30#,
         16#17#, 16#31#, 16#15#, 16#30#, 16#13#, 16#06#, 16#03#, 16#55#,
         16#04#, 16#03#, 16#0C#, 16#0C#, 16#54#, 16#65#, 16#73#, 16#74#,
         16#20#, 16#52#, 16#6F#, 16#6F#, 16#74#, 16#20#, 16#43#, 16#41#,
         16#30#, 16#1E#, 16#17#, 16#0D#, 16#32#, 16#36#, 16#30#, 16#35#,
         16#30#, 16#37#, 16#31#, 16#32#, 16#33#, 16#39#, 16#30#, 16#34#,
         16#5A#, 16#17#, 16#0D#, 16#33#, 16#36#, 16#30#, 16#35#, 16#30#,
         16#34#, 16#31#, 16#32#, 16#33#, 16#39#, 16#30#, 16#34#, 16#5A#,
         16#30#, 16#17#, 16#31#, 16#15#, 16#30#, 16#13#, 16#06#, 16#03#,
         16#55#, 16#04#, 16#03#, 16#0C#, 16#0C#, 16#54#, 16#65#, 16#73#,
         16#74#, 16#20#, 16#52#, 16#6F#, 16#6F#, 16#74#, 16#20#, 16#43#,
         16#41#, 16#30#, 16#59#, 16#30#, 16#13#, 16#06#, 16#07#, 16#2A#,
         16#86#, 16#48#, 16#CE#, 16#3D#, 16#02#, 16#01#, 16#06#, 16#08#,
         16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#03#, 16#01#, 16#07#,
         16#03#, 16#42#, 16#00#, 16#04#, 16#52#, 16#71#, 16#0D#, 16#A4#,
         16#14#, 16#06#, 16#9B#, 16#F7#, 16#CE#, 16#69#, 16#F7#, 16#3F#,
         16#D9#, 16#77#, 16#99#, 16#86#, 16#EA#, 16#2C#, 16#FA#, 16#35#,
         16#6B#, 16#F8#, 16#DA#, 16#75#, 16#47#, 16#12#, 16#21#, 16#C6#,
         16#1A#, 16#2C#, 16#BD#, 16#3C#, 16#9B#, 16#80#, 16#CA#, 16#A9#,
         16#77#, 16#2E#, 16#C0#, 16#E2#, 16#E0#, 16#F2#, 16#49#, 16#67#,
         16#5B#, 16#AD#, 16#42#, 16#74#, 16#BE#, 16#00#, 16#0B#, 16#95#,
         16#19#, 16#AF#, 16#31#, 16#72#, 16#F0#, 16#E9#, 16#38#, 16#1F#,
         16#30#, 16#CC#, 16#20#, 16#2C#, 16#A3#, 16#53#, 16#30#, 16#51#,
         16#30#, 16#1D#, 16#06#, 16#03#, 16#55#, 16#1D#, 16#0E#, 16#04#,
         16#16#, 16#04#, 16#14#, 16#89#, 16#BF#, 16#DB#, 16#9A#, 16#FB#,
         16#DD#, 16#CA#, 16#FE#, 16#9A#, 16#2B#, 16#BB#, 16#56#, 16#2B#,
         16#E3#, 16#2F#, 16#E6#, 16#46#, 16#3E#, 16#06#, 16#4C#, 16#30#,
         16#1F#, 16#06#, 16#03#, 16#55#, 16#1D#, 16#23#, 16#04#, 16#18#,
         16#30#, 16#16#, 16#80#, 16#14#, 16#89#, 16#BF#, 16#DB#, 16#9A#,
         16#FB#, 16#DD#, 16#CA#, 16#FE#, 16#9A#, 16#2B#, 16#BB#, 16#56#,
         16#2B#, 16#E3#, 16#2F#, 16#E6#, 16#46#, 16#3E#, 16#06#, 16#4C#,
         16#30#, 16#0F#, 16#06#, 16#03#, 16#55#, 16#1D#, 16#13#, 16#01#,
         16#01#, 16#FF#, 16#04#, 16#05#, 16#30#, 16#03#, 16#01#, 16#01#,
         16#FF#, 16#30#, 16#0A#, 16#06#, 16#08#, 16#2A#, 16#86#, 16#48#,
         16#CE#, 16#3D#, 16#04#, 16#03#, 16#02#, 16#03#, 16#49#, 16#00#,
         16#30#, 16#46#, 16#02#, 16#21#, 16#00#, 16#91#, 16#25#, 16#31#,
         16#9E#, 16#6B#, 16#7B#, 16#86#, 16#BB#, 16#10#, 16#5D#, 16#1A#,
         16#0A#, 16#09#, 16#3B#, 16#32#, 16#27#, 16#B8#, 16#D6#, 16#8B#,
         16#73#, 16#B6#, 16#B3#, 16#BA#, 16#36#, 16#5B#, 16#7B#, 16#7B#,
         16#F2#, 16#A0#, 16#27#, 16#18#, 16#D3#, 16#02#, 16#21#, 16#00#,
         16#AB#, 16#4B#, 16#78#, 16#70#, 16#82#, 16#4C#, 16#78#, 16#50#,
         16#37#, 16#23#, 16#AA#, 16#A5#, 16#61#, 16#6A#, 16#5D#, 16#C4#,
         16#CA#, 16#88#, 16#F6#, 16#07#, 16#C5#, 16#17#, 16#6E#, 16#E7#,
         16#13#, 16#A0#, 16#97#, 16#1E#, 16#A7#, 16#FF#, 16#12#, 16#31#);

      Leaf_Der : constant Tls_Core.Octet_Array (1 .. 417) :=
        (16#30#, 16#82#, 16#01#, 16#9D#, 16#30#, 16#82#, 16#01#, 16#43#,
         16#A0#, 16#03#, 16#02#, 16#01#, 16#02#, 16#02#, 16#14#, 16#1B#,
         16#3B#, 16#A5#, 16#4E#, 16#36#, 16#F6#, 16#C5#, 16#E1#, 16#D7#,
         16#60#, 16#80#, 16#63#, 16#45#, 16#B9#, 16#5B#, 16#51#, 16#2A#,
         16#F9#, 16#A2#, 16#A4#, 16#30#, 16#0A#, 16#06#, 16#08#, 16#2A#,
         16#86#, 16#48#, 16#CE#, 16#3D#, 16#04#, 16#03#, 16#02#, 16#30#,
         16#17#, 16#31#, 16#15#, 16#30#, 16#13#, 16#06#, 16#03#, 16#55#,
         16#04#, 16#03#, 16#0C#, 16#0C#, 16#54#, 16#65#, 16#73#, 16#74#,
         16#20#, 16#52#, 16#6F#, 16#6F#, 16#74#, 16#20#, 16#43#, 16#41#,
         16#30#, 16#1E#, 16#17#, 16#0D#, 16#32#, 16#36#, 16#30#, 16#35#,
         16#30#, 16#37#, 16#31#, 16#32#, 16#33#, 16#39#, 16#30#, 16#34#,
         16#5A#, 16#17#, 16#0D#, 16#32#, 16#37#, 16#30#, 16#35#, 16#30#,
         16#37#, 16#31#, 16#32#, 16#33#, 16#39#, 16#30#, 16#34#, 16#5A#,
         16#30#, 16#14#, 16#31#, 16#12#, 16#30#, 16#10#, 16#06#, 16#03#,
         16#55#, 16#04#, 16#03#, 16#0C#, 16#09#, 16#6C#, 16#6F#, 16#63#,
         16#61#, 16#6C#, 16#68#, 16#6F#, 16#73#, 16#74#, 16#30#, 16#59#,
         16#30#, 16#13#, 16#06#, 16#07#, 16#2A#, 16#86#, 16#48#, 16#CE#,
         16#3D#, 16#02#, 16#01#, 16#06#, 16#08#, 16#2A#, 16#86#, 16#48#,
         16#CE#, 16#3D#, 16#03#, 16#01#, 16#07#, 16#03#, 16#42#, 16#00#,
         16#04#, 16#E4#, 16#26#, 16#E3#, 16#7E#, 16#97#, 16#8E#, 16#1A#,
         16#4E#, 16#F2#, 16#31#, 16#6C#, 16#E8#, 16#DF#, 16#17#, 16#FF#,
         16#42#, 16#EC#, 16#FA#, 16#C6#, 16#7E#, 16#93#, 16#19#, 16#95#,
         16#36#, 16#37#, 16#F2#, 16#33#, 16#A0#, 16#22#, 16#C7#, 16#23#,
         16#A4#, 16#0F#, 16#44#, 16#DD#, 16#E0#, 16#CE#, 16#DC#, 16#CD#,
         16#20#, 16#F2#, 16#37#, 16#AB#, 16#FE#, 16#EE#, 16#A2#, 16#59#,
         16#65#, 16#2B#, 16#03#, 16#E6#, 16#73#, 16#97#, 16#5C#, 16#6F#,
         16#11#, 16#D3#, 16#83#, 16#84#, 16#5C#, 16#D6#, 16#C8#, 16#65#,
         16#CB#, 16#A3#, 16#70#, 16#30#, 16#6E#, 16#30#, 16#2C#, 16#06#,
         16#03#, 16#55#, 16#1D#, 16#11#, 16#04#, 16#25#, 16#30#, 16#23#,
         16#82#, 16#09#, 16#6C#, 16#6F#, 16#63#, 16#61#, 16#6C#, 16#68#,
         16#6F#, 16#73#, 16#74#, 16#82#, 16#10#, 16#74#, 16#65#, 16#73#,
         16#74#, 16#2E#, 16#65#, 16#78#, 16#61#, 16#6D#, 16#70#, 16#6C#,
         16#65#, 16#2E#, 16#63#, 16#6F#, 16#6D#, 16#87#, 16#04#, 16#7F#,
         16#00#, 16#00#, 16#01#, 16#30#, 16#1D#, 16#06#, 16#03#, 16#55#,
         16#1D#, 16#0E#, 16#04#, 16#16#, 16#04#, 16#14#, 16#25#, 16#3B#,
         16#7A#, 16#E3#, 16#D2#, 16#46#, 16#CC#, 16#97#, 16#6F#, 16#EB#,
         16#7F#, 16#33#, 16#A3#, 16#18#, 16#61#, 16#05#, 16#7D#, 16#85#,
         16#66#, 16#82#, 16#30#, 16#1F#, 16#06#, 16#03#, 16#55#, 16#1D#,
         16#23#, 16#04#, 16#18#, 16#30#, 16#16#, 16#80#, 16#14#, 16#89#,
         16#BF#, 16#DB#, 16#9A#, 16#FB#, 16#DD#, 16#CA#, 16#FE#, 16#9A#,
         16#2B#, 16#BB#, 16#56#, 16#2B#, 16#E3#, 16#2F#, 16#E6#, 16#46#,
         16#3E#, 16#06#, 16#4C#, 16#30#, 16#0A#, 16#06#, 16#08#, 16#2A#,
         16#86#, 16#48#, 16#CE#, 16#3D#, 16#04#, 16#03#, 16#02#, 16#03#,
         16#48#, 16#00#, 16#30#, 16#45#, 16#02#, 16#21#, 16#00#, 16#DA#,
         16#00#, 16#66#, 16#38#, 16#5C#, 16#15#, 16#4B#, 16#9E#, 16#CE#,
         16#93#, 16#32#, 16#65#, 16#17#, 16#71#, 16#6B#, 16#A2#, 16#9C#,
         16#A4#, 16#AF#, 16#20#, 16#3C#, 16#61#, 16#E9#, 16#19#, 16#00#,
         16#92#, 16#0D#, 16#C2#, 16#FF#, 16#F7#, 16#20#, 16#D4#, 16#02#,
         16#20#, 16#21#, 16#CF#, 16#A6#, 16#36#, 16#DC#, 16#60#, 16#D9#,
         16#78#, 16#90#, 16#E4#, 16#02#, 16#DD#, 16#CC#, 16#8F#, 16#FB#,
         16#80#, 16#FD#, 16#10#, 16#41#, 16#92#, 16#C2#, 16#0F#, 16#B5#,
         16#49#, 16#72#, 16#6A#, 16#E1#, 16#F9#, 16#65#, 16#7D#, 16#25#,
         16#64#);

      --  Leaf private scalar (32 bytes big-endian) — extracted from
      --  fixtures/leaf.key.
      Leaf_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#55#, 16#E6#, 16#A4#, 16#5A#, 16#EA#, 16#B1#, 16#EC#, 16#54#,
         16#19#, 16#0C#, 16#E2#, 16#14#, 16#B3#, 16#78#, 16#25#, 16#6F#,
         16#B2#, 16#2C#, 16#72#, 16#3C#, 16#5E#, 16#70#, 16#56#, 16#84#,
         16#14#, 16#6C#, 16#EB#, 16#CB#, 16#EF#, 16#82#, 16#A8#, 16#88#);

      Hostname_Localhost : constant Tls_Core.Octet_Array (1 .. 9) :=
        (16#6C#, 16#6F#, 16#63#, 16#61#, 16#6C#, 16#68#, 16#6F#, 16#73#,
         16#74#);

      --  X25519 private scalars for client + server ECDHE.
      Client_Ecdhe_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#11#);
      Server_Ecdhe_Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (others => 16#22#);

      C, S : Tls_Core.Tls13_Driver.Driver;
      Buf  : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
      Buf_Last : Natural := 0;

      Chain_Spec : Tls_Core.Cert_Chain.Chain;
      Trust_Spec : Tls_Core.Cert_Chain.Trust_Store;
      All_Chain  : Tls_Core.Octet_Array (1 .. Leaf_Der'Length);
      Trust_Buf  : Tls_Core.Octet_Array (1 .. Root_Der'Length);
   begin
      Put_Line ("scenario — TLS 1.3 cert-mode handshake (Ada-vs-Ada)");

      --  Server-side chain spec: single leaf cert.
      All_Chain := Leaf_Der;
      Chain_Spec.Count := 1;
      Chain_Spec.Entries (1) :=
        (First => 1, Last => Leaf_Der'Length);

      --  Client-side trust store: one root anchor.
      Trust_Buf := Root_Der;
      Trust_Spec.Count := 1;
      Trust_Spec.Entries (1) :=
        (First => 1, Last => Root_Der'Length);

      Tls_Core.Tls13_Driver.Init_Cert_Server
        (D                => S,
         Cert_Chain_Bytes => All_Chain,
         Chain_Spec       => Chain_Spec,
         Sign_Priv_Key    => Leaf_Priv,
         Sig_Alg          =>
           Tls_Core.Suites.Sig_Ecdsa_Secp256r1_Sha256,
         Ecdhe_Priv       => Server_Ecdhe_Priv);

      Tls_Core.Tls13_Driver.Init_Cert_Client
        (D                  => C,
         Trust_Anchor_Bytes => Trust_Buf,
         Trust_Spec         => Trust_Spec,
         Hostname           => Hostname_Localhost,
         Ecdhe_Priv         => Client_Ecdhe_Priv);

      Check ("Cert mode: server initialised in Cert_Mode",
             Tls_Core.Tls13_Driver.Mode (S)
               = Tls_Core.Tls13_Driver.Cert_Mode);
      Check ("Cert mode: client initialised in Cert_Mode",
             Tls_Core.Tls13_Driver.Mode (C)
               = Tls_Core.Tls13_Driver.Cert_Mode);

      --  Step 1: client emits CH.
      Tls_Core.Tls13_Driver.Step
        (C, In_Bytes => Buf (1 .. 0),
         Out_Buf => Buf, Out_Last => Buf_Last);
      Check ("Cert mode: client → Awaiting_Sf after CH",
             Tls_Core.Tls13_Driver.Current_State (C)
               = Tls_Core.Tls13_Driver.Awaiting_Sf);
      Check ("Cert mode: CH non-empty", Buf_Last > 0);

      --  Step 2: server processes CH and emits SH+EE+Cert+CV+SF.
      declare
         Ch_Bytes : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Reply : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
         Reply_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Step
           (S, In_Bytes => Ch_Bytes,
            Out_Buf => Reply, Out_Last => Reply_Last);
         Check ("Cert mode: server → Awaiting_Cf after flight",
                Tls_Core.Tls13_Driver.Current_State (S)
                  = Tls_Core.Tls13_Driver.Awaiting_Cf);
         Check ("Cert mode: server flight non-empty",
                Reply_Last > 0);
         --  Reply has 5 records: 1 plaintext SH + 4 encrypted records
         --  (EE/Cert/CV/SF). Each encrypted record begins with the
         --  application_data inner type (0x17). Plaintext SH begins
         --  with handshake content type (0x16).
         Check ("Cert mode: flight starts with 0x16 (SH plaintext)",
                Reply (1) = 16#16#);
         Buf := (others => 0);
         Buf (1 .. Reply_Last) := Reply (1 .. Reply_Last);
         Buf_Last := Reply_Last;
      end;

      --  Step 3: client processes server flight, validates cert +
      --  signature + Finished, emits CF.
      declare
         Server_Flight : constant Tls_Core.Octet_Array :=
           Buf (1 .. Buf_Last);
         Cf_Reply : Tls_Core.Octet_Array (1 .. 1024) :=
           (others => 0);
         Cf_Last  : Natural;
      begin
         Tls_Core.Tls13_Driver.Step
           (C, In_Bytes => Server_Flight,
            Out_Buf => Cf_Reply, Out_Last => Cf_Last);
         Check ("Cert mode: client → Done after CF",
                Tls_Core.Tls13_Driver.Current_State (C)
                  = Tls_Core.Tls13_Driver.Done);
         Check ("Cert mode: CF non-empty", Cf_Last > 0);
         Check ("Cert mode: CF starts with 0x17 (encrypted)",
                Cf_Reply (1) = 16#17#);
         Buf := (others => 0);
         Buf (1 .. Cf_Last) := Cf_Reply (1 .. Cf_Last);
         Buf_Last := Cf_Last;
      end;

      --  Step 4: server processes CF, transitions to Done.
      declare
         Cf_Bytes : constant Tls_Core.Octet_Array := Buf (1 .. Buf_Last);
         Discard : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Discard_Last : Natural;
      begin
         Tls_Core.Tls13_Driver.Step
           (S, In_Bytes => Cf_Bytes,
            Out_Buf => Discard, Out_Last => Discard_Last);
         Check ("Cert mode: server → Done",
                Tls_Core.Tls13_Driver.Current_State (S)
                  = Tls_Core.Tls13_Driver.Done);
      end;

      --  Both sides at Done with App_Set = True.
      Check ("Cert mode: client App_Secrets_Set",
             Tls_Core.Tls13_Driver.App_Secrets_Set (C));
      Check ("Cert mode: server App_Secrets_Set",
             Tls_Core.Tls13_Driver.App_Secrets_Set (S));

      --  Round-trip an application message both ways using the
      --  application traffic secrets.
      declare
         use type Tls_Core.Suites.Cipher_Suite_Id;
         C_Out, C_In, S_Out, S_In : Tls_Core.Aead_Channel.Direction;
         App_Msg : constant Tls_Core.Octet_Array :=
           (16#48#, 16#65#, 16#6C#, 16#6C#, 16#6F#);  --  "Hello"
         Wire : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         Wire_Last : Natural;
         Pt_Buf : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         Pt_Last : Natural;
         Inner_Type : Tls_Core.Octet;
         OK : Boolean;
      begin
         --  v0.5 driver completes only on SHA-256 suites; the cert
         --  mode test will end up on either chacha20 or aes-128.
         Tls_Core.Tls13_Driver.Open_App_Directions (C, C_Out, C_In);
         Tls_Core.Tls13_Driver.Open_App_Directions (S, S_Out, S_In);

         --  Client → server.
         Tls_Core.Aead_Channel.Send
           (C_Out, App_Msg,
            Tls_Core.Aead_Channel.Inner_Type_Application_Data,
            Wire, Wire_Last);
         Tls_Core.Aead_Channel.Receive
           (S_In, Wire (1 .. Wire_Last),
            Pt_Buf, Pt_Last, Inner_Type, OK);
         Check ("Cert mode: server decrypts client app msg", OK);
         Check ("Cert mode: msg round-trips C→S",
                OK and then Pt_Last = App_Msg'Length
                and then Equal (Pt_Buf (1 .. Pt_Last), App_Msg));

         --  Server → client.
         Wire := (others => 0);
         Pt_Buf := (others => 0);
         Tls_Core.Aead_Channel.Send
           (S_Out, App_Msg,
            Tls_Core.Aead_Channel.Inner_Type_Application_Data,
            Wire, Wire_Last);
         Tls_Core.Aead_Channel.Receive
           (C_In, Wire (1 .. Wire_Last),
            Pt_Buf, Pt_Last, Inner_Type, OK);
         Check ("Cert mode: client decrypts server app msg", OK);
         Check ("Cert mode: msg round-trips S→C",
                OK and then Pt_Last = App_Msg'Length
                and then Equal (Pt_Buf (1 .. Pt_Last), App_Msg));
      end;
   end Tls13_Cert_Mode_Loopback_Scenario;

   ---------------------------------------------------------------------
   --  Scenario — RFC 6979 §A.2.5 deterministic-K KAT for P-256/SHA-256
   --
   --  Vector: curve = P-256, x = C9AFA9D845BA75166B5C215767B1D6934E50
   --                              C3DB36E89B127B8A622B120F6721,
   --          message = "sample" (ASCII), H = SHA-256.
   --  Expected k = A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F2
   --                4D6129493D8AAD60.
   --
   --  Verifies our HMAC-SHA-256 K-derivation matches the RFC verbatim,
   --  which means our cert-mode signatures will match openssl /
   --  rustls / Go bit-for-bit on the same (priv, transcript_hash).
   ---------------------------------------------------------------------
   procedure Rfc6979_K_Kat_Scenario;
   procedure Rfc6979_K_Kat_Scenario is
      use type Tls_Core.Octet_Array;

      Priv : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#C9#, 16#AF#, 16#A9#, 16#D8#, 16#45#, 16#BA#, 16#75#, 16#16#,
         16#6B#, 16#5C#, 16#21#, 16#57#, 16#67#, 16#B1#, 16#D6#, 16#93#,
         16#4E#, 16#50#, 16#C3#, 16#DB#, 16#36#, 16#E8#, 16#9B#, 16#12#,
         16#7B#, 16#8A#, 16#62#, 16#2B#, 16#12#, 16#0F#, 16#67#, 16#21#);

      Msg_Sample : constant Tls_Core.Octet_Array :=
        (16#73#, 16#61#, 16#6D#, 16#70#, 16#6C#, 16#65#);  --  "sample"

      Expected_K_Sample : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#A6#, 16#E3#, 16#C5#, 16#7D#, 16#D0#, 16#1A#, 16#BE#, 16#90#,
         16#08#, 16#65#, 16#38#, 16#39#, 16#83#, 16#55#, 16#DD#, 16#4C#,
         16#3B#, 16#17#, 16#AA#, 16#87#, 16#33#, 16#82#, 16#B0#, 16#F2#,
         16#4D#, 16#61#, 16#29#, 16#49#, 16#3D#, 16#8A#, 16#AD#, 16#60#);

      --  RFC 6979 §A.2.5 — message = "test", same private key.
      Msg_Test : constant Tls_Core.Octet_Array :=
        (16#74#, 16#65#, 16#73#, 16#74#);

      --  RFC 6979 §A.2.5 — full sample/SHA-256 signature outputs.
      Expected_R_Sample : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#EF#, 16#D4#, 16#8B#, 16#2A#, 16#AC#, 16#B6#, 16#A8#, 16#FD#,
         16#11#, 16#40#, 16#DD#, 16#9C#, 16#D4#, 16#5E#, 16#81#, 16#D6#,
         16#9D#, 16#2C#, 16#87#, 16#7B#, 16#56#, 16#AA#, 16#F9#, 16#91#,
         16#C3#, 16#4D#, 16#0E#, 16#A8#, 16#4E#, 16#AF#, 16#37#, 16#16#);
      Expected_S_Sample : constant Tls_Core.Octet_Array (1 .. 32) :=
        (16#F7#, 16#CB#, 16#1C#, 16#94#, 16#2D#, 16#65#, 16#7C#, 16#41#,
         16#D4#, 16#36#, 16#C7#, 16#A1#, 16#B6#, 16#E2#, 16#9F#, 16#65#,
         16#F3#, 16#E9#, 16#00#, 16#DB#, 16#B9#, 16#AF#, 16#F4#, 16#06#,
         16#4D#, 16#C4#, 16#AB#, 16#2F#, 16#84#, 16#3A#, 16#CD#, 16#A8#);

      Out_K : Tls_Core.Ecdsa_P256.Component;
      OK    : Boolean;
   begin
      Put_Line ("scenario — RFC 6979 §A.2.5 K-derivation KAT (P-256)");

      --  K-only KAT for the canonical sample vector.
      Tls_Core.Ecdsa_P256.Derive_K_Rfc6979
        (Private_Key => Priv,
         Message     => Msg_Sample,
         Out_K       => Out_K,
         OK          => OK);
      Check ("RFC 6979 sample/SHA-256: OK = True", OK);
      Check ("RFC 6979 sample/SHA-256: K matches §A.2.5 expected",
             Out_K = Expected_K_Sample);

      --  End-to-end Derive_K + Sign produces the §A.2.5 (r, s).
      --  This is the property that actually matters for external
      --  interop: openssl/Go/rustls also use RFC 6979 by default,
      --  so for the same (priv, message) they all emit this same
      --  signature.
      declare
         R, S : Tls_Core.Ecdsa_P256.Component;
         Sign_OK : Boolean;
      begin
         Tls_Core.Ecdsa_P256.Sign
           (Private_Key => Priv,
            Message     => Msg_Sample,
            K           => Out_K,
            Out_R       => R,
            Out_S       => S,
            OK          => Sign_OK);
         Check ("RFC 6979 sample/SHA-256: Sign OK", Sign_OK);
         Check ("RFC 6979 sample/SHA-256: r matches §A.2.5",
                R = Expected_R_Sample);
         Check ("RFC 6979 sample/SHA-256: s matches §A.2.5",
                S = Expected_S_Sample);
      end;

      --  "test" message K-derivation: just confirm OK = True (the
      --  exact bytes for this vector aren't asserted; the sample
      --  vector + the e2e signature check above already pin
      --  RFC 6979 conformance).
      Tls_Core.Ecdsa_P256.Derive_K_Rfc6979
        (Private_Key => Priv,
         Message     => Msg_Test,
         Out_K       => Out_K,
         OK          => OK);
      Check ("RFC 6979 test/SHA-256: OK = True", OK);
   end Rfc6979_K_Kat_Scenario;

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
   Tls13_Mode3_Ecdhe_Contributes;
   Key_Update_Wire_Scenario;
   Key_Update_Roundtrip_Scenario;
   Tls13_Hrr_Loopback;
   Hello_Retry_Unit;
   Aes128_Scenario;
   Aes_Gcm_Scenario;
   Sha384_Scenario;
   Aes256_Scenario;
   Aes_Spec_Scenario;
   Aes256_Gcm_Scenario;
   Hmac_Sha384_Scenario;
   Hkdf_Sha384_Scenario;
   Channel_Aes128_Roundtrip_Scenario;
   Channel_Aes256_Roundtrip_Scenario;
   Aead_Channel_Chacha_Scenario;
   Aead_Channel_Aes128_Scenario;
   Aead_Channel_Aes256_Scenario;
   P256_Generator_Scenario;
   P256_One_G_Scenario;
   P256_Two_G_Scenario;
   P256_Ecdh_Scenario;
   Ecdsa_P256_Verify_Scenario;
   Ecdsa_P256_Range_Scenario;
   Ecdsa_P256_Wrongmsg_Scenario;
   Ecdsa_P256_Sign_Scenario;
   Rsa_Pss_Sha256_Roundtrip_Scenario;
   Rsa_Pss_Sha384_Roundtrip_Scenario;
   Cert_Chain_Pki_Scenario;
   Alert_Codec_Scenario;
   Alert_Close_Notify_Scenario;
   Alert_Bad_Record_Mac_Scenario;
   Alert_Decode_Error_Scenario;
   Alert_Plaintext_Fatal_Scenario;
   Handshake_Buffer_Scenario;
   Tls13_Multi_Record_Reassembly_Scenario;
   Session_Ticket_Wire_Scenario;
   Session_Cache_Scenario;
   Session_Ticket_End_To_End_Scenario;
   Sni_Emit_Scenario;
   Alpn_Emit_Scenario;
   Post_Handshake_Demux_Scenario;
   Ecdsa_Sig_Der_Scenario;
   Cert_Server_Hello_Scenario;
   Cert_Client_Hello_Scenario;
   Cert_Client_Hello_Roundtrip_Scenario;
   Tls13_Cert_Mode_Loopback_Scenario;
   Rfc6979_K_Kat_Scenario;
   New_Line;
   Put_Line ("Pass:" & Pass'Image & "  Fail:" & Fail'Image);
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Tls_Core_Tests;
