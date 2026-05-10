with Tls_Core.Hkdf;
with Tls_Core.Hkdf_Sha256;
with Tls_Core.Hkdf_Sha384;
with Tls_Core.Hmac_Sha256;
with Tls_Core.Hmac_Sha384;
with Tls_Core.Key_Schedule;
with Tls_Core.Key_Schedule_Sha384;
with Tls_Core.Session_Ticket;
with Tls_Core.Sha256;
with Tls_Core.Sha384;

package body Tls_Core.Key_Sched
with SPARK_Mode
is
   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");
   use type Tls_Core.Suites.Cipher_Suite_Id;

   Derived_Lab : constant Octet_Array (1 .. 7) :=
     (16#64#, 16#65#, 16#72#, 16#69#, 16#76#, 16#65#, 16#64#);
   C_Hs_Lab : constant Octet_Array (1 .. 12) :=
     (16#63#, 16#20#, 16#68#, 16#73#, 16#20#, 16#74#,
      16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
   S_Hs_Lab : constant Octet_Array (1 .. 12) :=
     (16#73#, 16#20#, 16#68#, 16#73#, 16#20#, 16#74#,
      16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
   C_Ap_Lab : constant Octet_Array (1 .. 12) :=
     (16#63#, 16#20#, 16#61#, 16#70#, 16#20#, 16#74#,
      16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
   S_Ap_Lab : constant Octet_Array (1 .. 12) :=
     (16#73#, 16#20#, 16#61#, 16#70#, 16#20#, 16#74#,
      16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
   Finished_Lab : constant Octet_Array (1 .. 8) :=
     (16#66#, 16#69#, 16#6E#, 16#69#, 16#73#, 16#68#, 16#65#, 16#64#);
   Res_Master_Lab : constant Octet_Array (1 .. 10) :=
     (16#72#, 16#65#, 16#73#, 16#20#, 16#6D#,
      16#61#, 16#73#, 16#74#, 16#65#, 16#72#);

   procedure Exp256 is new Tls_Core.Hkdf.Expand_Label
     (Tls_Core.Sha256.Hash_Length, 512,
      Tls_Core.Hkdf_Sha256.Spec_HKDF_Expand, Tls_Core.Hkdf_Sha256.Hmac_Expand);

   procedure Exp384 is new Tls_Core.Hkdf.Expand_Label
     (Tls_Core.Sha384.Hash_Length, 512,
      Tls_Core.Hkdf_Sha384.Spec_HKDF_Expand, Tls_Core.Hkdf_Sha384.Hmac_Expand);

   HL : constant := 32;
   HH : constant := 48;

   procedure Derive_Handshake_Secrets
     (Suite        : Tls_Core.Suites.Cipher_Suite_Id;
      PSK          : Octet_Array;
      Ecdhe_Shared : Octet_Array;
      Th_After_Sh  : Max_Digest;
      C_Hs_Sec    : out Max_Secret;
      S_Hs_Sec    : out Max_Secret;
      Hs_Secret    : out Max_Secret)
   is
      Empty : constant Octet_Array (1 .. 0) := (others => 0);
   begin
      C_Hs_Sec := (others => 0); S_Hs_Sec := (others => 0); Hs_Secret := (others => 0);
      if Suite = Tls_Core.Suites.Aes_256_Gcm_Sha384 then
         declare
            Z48 : constant Octet_Array (1 .. HH) := (others => 0);
            P48 : Tls_Core.Key_Schedule_Sha384.Secret := (others => 0);
            E, D1, H, C, S : Tls_Core.Key_Schedule_Sha384.Secret;
         begin
            P48 (1 .. PSK'Length) := PSK;
            Tls_Core.Key_Schedule_Sha384.Extract (Salt => Z48, IKM => P48, Out_PRK => E);
            Tls_Core.Key_Schedule_Sha384.Derive_Secret (Secret_In => E, Label => Derived_Lab, Messages => Empty, Out_Secret => D1);
            Tls_Core.Key_Schedule_Sha384.Extract (Salt => D1, IKM => Ecdhe_Shared, Out_PRK => H);
            Exp384 (Secret => H, Label => C_Hs_Lab, Context => Th_After_Sh (1 .. HH), Output => C);
            Exp384 (Secret => H, Label => S_Hs_Lab, Context => Th_After_Sh (1 .. HH), Output => S);
            C_Hs_Sec (1 .. HH) := C; S_Hs_Sec (1 .. HH) := S; Hs_Secret (1 .. HH) := H;
         end;
      else
         declare
            Z32 : constant Octet_Array (1 .. HL) := (others => 0);
            E, D1, H, C, S : Tls_Core.Key_Schedule.Secret;
         begin
            Tls_Core.Key_Schedule.Extract (Salt => Z32, IKM => PSK (PSK'First .. PSK'First + 31), Out_PRK => E);
            Tls_Core.Key_Schedule.Derive_Secret (Secret_In => E, Label => Derived_Lab, Messages => Empty, Out_Secret => D1);
            Tls_Core.Key_Schedule.Extract (Salt => D1, IKM => Ecdhe_Shared, Out_PRK => H);
            Exp256 (Secret => H, Label => C_Hs_Lab, Context => Th_After_Sh (1 .. HL), Output => C);
            Exp256 (Secret => H, Label => S_Hs_Lab, Context => Th_After_Sh (1 .. HL), Output => S);
            C_Hs_Sec (1 .. HL) := C; S_Hs_Sec (1 .. HL) := S; Hs_Secret (1 .. HL) := H;
         end;
      end if;
   end Derive_Handshake_Secrets;

   procedure Derive_App_Secrets
     (Suite       : Tls_Core.Suites.Cipher_Suite_Id;
      Hs_Secret   : Max_Secret;
      Th_After_Sf : Max_Digest;
      App_C_Ap   : out Max_Secret;
      App_S_Ap   : out Max_Secret;
      Master_Sec : out Max_Secret)
   is
      Empty : constant Octet_Array (1 .. 0) := (others => 0);
   begin
      App_C_Ap := (others => 0); App_S_Ap := (others => 0); Master_Sec := (others => 0);
      if Suite = Tls_Core.Suites.Aes_256_Gcm_Sha384 then
         declare
            EH : Tls_Core.Sha384.Digest;
            Z48 : constant Tls_Core.Key_Schedule_Sha384.Secret := (others => 0);
            D2, M, C, S : Tls_Core.Key_Schedule_Sha384.Secret;
         begin
            Tls_Core.Sha384.Hash (Empty, EH);
            Exp384 (Secret => Hs_Secret (1 .. HH), Label => Derived_Lab, Context => EH, Output => D2);
            Tls_Core.Key_Schedule_Sha384.Extract (Salt => D2, IKM => Z48, Out_PRK => M);
            Exp384 (Secret => M, Label => C_Ap_Lab, Context => Th_After_Sf (1 .. HH), Output => C);
            Exp384 (Secret => M, Label => S_Ap_Lab, Context => Th_After_Sf (1 .. HH), Output => S);
            App_C_Ap (1 .. HH) := C; App_S_Ap (1 .. HH) := S; Master_Sec (1 .. HH) := M;
         end;
      else
         declare
            EH : Tls_Core.Sha256.Digest;
            Z32 : constant Tls_Core.Key_Schedule.Secret := (others => 0);
            D2, M, C, S : Tls_Core.Key_Schedule.Secret;
         begin
            Tls_Core.Sha256.Hash (Empty, EH);
            Exp256 (Secret => Hs_Secret (1 .. HL), Label => Derived_Lab, Context => EH, Output => D2);
            Tls_Core.Key_Schedule.Extract (Salt => D2, IKM => Z32, Out_PRK => M);
            Exp256 (Secret => M, Label => C_Ap_Lab, Context => Th_After_Sf (1 .. HL), Output => C);
            Exp256 (Secret => M, Label => S_Ap_Lab, Context => Th_After_Sf (1 .. HL), Output => S);
            App_C_Ap (1 .. HL) := C; App_S_Ap (1 .. HL) := S; Master_Sec (1 .. HL) := M;
         end;
      end if;
   end Derive_App_Secrets;

   procedure Build_Finished
     (Suite           : Tls_Core.Suites.Cipher_Suite_Id;
      Base_Key        : Max_Secret;
      Transcript_Hash : Max_Digest;
      Out_Verify      : out Max_Digest)
   is
      Empty : constant Octet_Array (1 .. 0) := (others => 0);
   begin
      Out_Verify := (others => 0);
      if Suite = Tls_Core.Suites.Aes_256_Gcm_Sha384 then
         declare
            FK, R : Tls_Core.Sha384.Digest;
         begin
            Exp384 (Secret => Base_Key (1 .. HH), Label => Finished_Lab, Context => Empty, Output => FK);
            Tls_Core.Hmac_Sha384.Compute (Key => FK, Message => Transcript_Hash (1 .. HH), Out_Tag => R);
            Out_Verify (1 .. HH) := R;
         end;
      else
         declare
            FK, R : Tls_Core.Sha256.Digest;
         begin
            Exp256 (Secret => Base_Key (1 .. HL), Label => Finished_Lab, Context => Empty, Output => FK);
            Tls_Core.Hmac_Sha256.Compute (Key => FK, Message => Transcript_Hash (1 .. HL), Out_Tag => R);
            Out_Verify (1 .. HL) := R;
         end;
      end if;
   end Build_Finished;

   procedure Derive_Resumption_Master_Secret
     (Suite             : Tls_Core.Suites.Cipher_Suite_Id;
      Master_Secret     : Max_Secret;
      Th_After_Cf       : Max_Digest;
      Resumption_Secret : out Max_Secret) is
   begin
      Resumption_Secret := (others => 0);
      if Suite = Tls_Core.Suites.Aes_256_Gcm_Sha384 then
         declare
            R : Tls_Core.Key_Schedule_Sha384.Secret;
         begin
            Exp384 (Secret => Master_Secret (1 .. HH), Label => Res_Master_Lab,
                    Context => Th_After_Cf (1 .. HH), Output => R);
            Resumption_Secret (1 .. HH) := R;
         end;
      else
         declare
            R : Tls_Core.Key_Schedule.Secret;
         begin
            Tls_Core.Session_Ticket.Derive_Resumption_Master_Secret_Sha256
              (Master_Secret (1 .. HL), Th_After_Cf (1 .. HL), R);
            Resumption_Secret (1 .. HL) := R;
         end;
      end if;
   end Derive_Resumption_Master_Secret;

   procedure Transcript_Append
     (Suite   : Tls_Core.Suites.Cipher_Suite_Id;
      Ctx_256 : in out Tls_Core.Transcript.Accumulator;
      Ctx_384 : in out Tls_Core.Transcript_Sha384.Accumulator;
      Message : Octet_Array) is
      pragma Unreferenced (Suite);
   begin
      Tls_Core.Transcript.Append (Ctx_256, Message);
      Tls_Core.Transcript_Sha384.Append (Ctx_384, Message);
   end Transcript_Append;

   procedure Transcript_Snapshot
     (Suite    : Tls_Core.Suites.Cipher_Suite_Id;
      Ctx_256  : Tls_Core.Transcript.Accumulator;
      Ctx_384  : Tls_Core.Transcript_Sha384.Accumulator;
      Out_Hash : out Max_Digest) is
   begin
      Out_Hash := (others => 0);
      if Suite = Tls_Core.Suites.Aes_256_Gcm_Sha384 then
         declare
            H : Tls_Core.Sha384.Digest;
         begin
            Tls_Core.Transcript_Sha384.Snapshot (Ctx_384, H);
            Out_Hash (1 .. HH) := H;
         end;
      else
         declare
            H : Tls_Core.Sha256.Digest;
         begin
            Tls_Core.Transcript.Snapshot (Ctx_256, H);
            Out_Hash (1 .. HL) := H;
         end;
      end if;
   end Transcript_Snapshot;

   procedure Init_Hs_Channel
     (Suite  : Tls_Core.Suites.Cipher_Suite_Id;
      Dir    : out Tls_Core.Aead_Channel.Direction;
      Secret : Max_Secret) is
   begin
      if Suite = Tls_Core.Suites.Aes_256_Gcm_Sha384 then
         Tls_Core.Aead_Channel.Init_Sha384 (Dir, Secret (1 .. HH));
      else
         Tls_Core.Aead_Channel.Init_Sha256 (Dir, Suite, Secret (1 .. HL));
      end if;
   end Init_Hs_Channel;

end Tls_Core.Key_Sched;
