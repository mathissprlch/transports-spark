with Tls_Core.Hkdf;
with Tls_Core.Hkdf_Sha256;
with Tls_Core.Hmac_Sha256;
with Tls_Core.Key_Schedule;
with Tls_Core.Session_Ticket;
with Tls_Core.Sha256;

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

   procedure Expand_256
     is new Tls_Core.Hkdf.Expand_Label
       (Hash_Length      => Tls_Core.Sha256.Hash_Length,
        Max_Info         => 512,
        Spec_Hmac_Expand => Tls_Core.Hkdf_Sha256.Spec_HKDF_Expand,
        Hmac_Expand      => Tls_Core.Hkdf_Sha256.Hmac_Expand);

   procedure Derive_Handshake_Secrets
     (Suite        : Tls_Core.Suites.Cipher_Suite_Id;
      PSK          : Octet_Array;
      Ecdhe_Shared : Octet_Array;
      Th_After_Sh  : Max_Digest;
      C_Hs_Sec    : out Max_Secret;
      S_Hs_Sec    : out Max_Secret;
      Hs_Secret    : out Max_Secret)
   is
      pragma Unreferenced (Suite);
      Empty : constant Octet_Array (1 .. 0) := (others => 0);
      Z32   : constant Octet_Array (1 .. 32) := (others => 0);
      E, D1, H, C, S : Tls_Core.Key_Schedule.Secret;
   begin
      C_Hs_Sec := (others => 0); S_Hs_Sec := (others => 0); Hs_Secret := (others => 0);
      Tls_Core.Key_Schedule.Extract
        (Salt => PSK (PSK'First .. PSK'First + 31), IKM => Z32, Out_PRK => E);
      Tls_Core.Key_Schedule.Derive_Secret
        (Secret_In => E, Label => Derived_Lab, Messages => Empty, Out_Secret => D1);
      Tls_Core.Key_Schedule.Extract (Salt => D1, IKM => Ecdhe_Shared, Out_PRK => H);
      Expand_256 (Secret => H, Label => C_Hs_Lab, Context => Th_After_Sh (1 .. 32), Output => C);
      Expand_256 (Secret => H, Label => S_Hs_Lab, Context => Th_After_Sh (1 .. 32), Output => S);
      C_Hs_Sec (1 .. 32) := C; S_Hs_Sec (1 .. 32) := S; Hs_Secret (1 .. 32) := H;
   end Derive_Handshake_Secrets;

   procedure Derive_App_Secrets
     (Suite       : Tls_Core.Suites.Cipher_Suite_Id;
      Hs_Secret   : Max_Secret;
      Th_After_Sf : Max_Digest;
      App_C_Ap   : out Max_Secret;
      App_S_Ap   : out Max_Secret;
      Master_Sec : out Max_Secret)
   is
      pragma Unreferenced (Suite);
      Empty : constant Octet_Array (1 .. 0) := (others => 0);
      EH    : Tls_Core.Sha256.Digest;
      D2, M, C, S : Tls_Core.Key_Schedule.Secret;
      Z32   : constant Tls_Core.Key_Schedule.Secret := (others => 0);
   begin
      App_C_Ap := (others => 0); App_S_Ap := (others => 0); Master_Sec := (others => 0);
      Tls_Core.Sha256.Hash (Empty, EH);
      Expand_256 (Secret => Hs_Secret (1 .. 32), Label => Derived_Lab, Context => EH, Output => D2);
      Tls_Core.Key_Schedule.Extract (Salt => D2, IKM => Z32, Out_PRK => M);
      Expand_256 (Secret => M, Label => C_Ap_Lab, Context => Th_After_Sf (1 .. 32), Output => C);
      Expand_256 (Secret => M, Label => S_Ap_Lab, Context => Th_After_Sf (1 .. 32), Output => S);
      App_C_Ap (1 .. 32) := C; App_S_Ap (1 .. 32) := S; Master_Sec (1 .. 32) := M;
   end Derive_App_Secrets;

   procedure Build_Finished
     (Suite           : Tls_Core.Suites.Cipher_Suite_Id;
      Base_Key        : Max_Secret;
      Transcript_Hash : Max_Digest;
      Out_Verify      : out Max_Digest)
   is
      pragma Unreferenced (Suite);
      Empty : constant Octet_Array (1 .. 0) := (others => 0);
      FK, R : Tls_Core.Sha256.Digest;
   begin
      Out_Verify := (others => 0);
      Expand_256 (Secret => Base_Key (1 .. 32), Label => Finished_Lab, Context => Empty, Output => FK);
      Tls_Core.Hmac_Sha256.Compute (Key => FK, Message => Transcript_Hash (1 .. 32), Out_Tag => R);
      Out_Verify (1 .. 32) := R;
   end Build_Finished;

   procedure Derive_Resumption_Master_Secret
     (Suite             : Tls_Core.Suites.Cipher_Suite_Id;
      Master_Secret     : Max_Secret;
      Th_After_Cf       : Max_Digest;
      Resumption_Secret : out Max_Secret)
   is
      pragma Unreferenced (Suite);
      R : Tls_Core.Key_Schedule.Secret;
   begin
      Resumption_Secret := (others => 0);
      Tls_Core.Session_Ticket.Derive_Resumption_Master_Secret_Sha256
        (Master_Secret (1 .. 32), Th_After_Cf (1 .. 32), R);
      Resumption_Secret (1 .. 32) := R;
   end Derive_Resumption_Master_Secret;

   procedure Transcript_Append
     (Suite   : Tls_Core.Suites.Cipher_Suite_Id;
      Ctx_256 : in out Tls_Core.Transcript.Accumulator;
      Ctx_384 : in out Tls_Core.Transcript_Sha384.Accumulator;
      Message : Octet_Array) is
   begin
      if Suite = Tls_Core.Suites.Aes_256_Gcm_Sha384 then
         Tls_Core.Transcript_Sha384.Append (Ctx_384, Message);
      else
         Tls_Core.Transcript.Append (Ctx_256, Message);
      end if;
   end Transcript_Append;

   procedure Transcript_Snapshot
     (Suite    : Tls_Core.Suites.Cipher_Suite_Id;
      Ctx_256  : Tls_Core.Transcript.Accumulator;
      Ctx_384  : Tls_Core.Transcript_Sha384.Accumulator;
      Out_Hash : out Max_Digest) is
      H : Tls_Core.Sha256.Digest;
   begin
      Out_Hash := (others => 0);
      if Suite = Tls_Core.Suites.Aes_256_Gcm_Sha384 then
         null;
      else
         Tls_Core.Transcript.Snapshot (Ctx_256, H);
         Out_Hash (1 .. 32) := H;
      end if;
   end Transcript_Snapshot;

   procedure Init_Hs_Channel
     (Suite  : Tls_Core.Suites.Cipher_Suite_Id;
      Dir    : out Tls_Core.Aead_Channel.Direction;
      Secret : Max_Secret) is
   begin
      if Suite = Tls_Core.Suites.Aes_256_Gcm_Sha384 then
         Tls_Core.Aead_Channel.Init_Sha384 (Dir, Secret (1 .. 48));
      else
         Tls_Core.Aead_Channel.Init_Sha256 (Dir, Suite, Secret (1 .. 32));
      end if;
   end Init_Hs_Channel;

end Tls_Core.Key_Sched;
