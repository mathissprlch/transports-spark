with Tls_Core.Hkdf;
with Tls_Core.Hkdf_Sha256;
with Tls_Core.Hmac_Sha256;
with Tls_Core.Session_Ticket;

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

   procedure Expand_Label_256
     is new Tls_Core.Hkdf.Expand_Label
       (Hash_Length      => Tls_Core.Sha256.Hash_Length,
        Max_Info         => 512,
        Spec_Hmac_Expand => Tls_Core.Hkdf_Sha256.Spec_HKDF_Expand,
        Hmac_Expand      => Tls_Core.Hkdf_Sha256.Hmac_Expand);

   procedure Derive_Handshake_Secrets
     (Suite        : Tls_Core.Suites.Cipher_Suite_Id;
      PSK          : Octet_Array;
      Ecdhe_Shared : Octet_Array;
      Th_After_Sh  : Tls_Core.Sha256.Digest;
      C_Hs_Sec    : out Tls_Core.Key_Schedule.Secret;
      S_Hs_Sec    : out Tls_Core.Key_Schedule.Secret;
      Hs_Secret    : out Tls_Core.Key_Schedule.Secret)
   is
      pragma Unreferenced (Suite);
      Empty_In : constant Octet_Array (1 .. 0) := (others => 0);
      Zero_32  : constant Octet_Array (1 .. 32) := (others => 0);
      Early    : Tls_Core.Key_Schedule.Secret;
      Der_1    : Tls_Core.Key_Schedule.Secret;
   begin
      Tls_Core.Key_Schedule.Extract
        (Salt => PSK, IKM => Zero_32, Out_PRK => Early);
      Tls_Core.Key_Schedule.Derive_Secret
        (Secret_In => Early, Label => Derived_Lab,
         Messages  => Empty_In, Out_Secret => Der_1);
      Tls_Core.Key_Schedule.Extract
        (Salt => Der_1, IKM => Ecdhe_Shared, Out_PRK => Hs_Secret);
      Expand_Label_256
        (Secret => Hs_Secret, Label => C_Hs_Lab,
         Context => Th_After_Sh, Output => C_Hs_Sec);
      Expand_Label_256
        (Secret => Hs_Secret, Label => S_Hs_Lab,
         Context => Th_After_Sh, Output => S_Hs_Sec);
   end Derive_Handshake_Secrets;

   procedure Derive_App_Secrets
     (Suite      : Tls_Core.Suites.Cipher_Suite_Id;
      Hs_Secret  : Tls_Core.Key_Schedule.Secret;
      Th_After_Sf : Tls_Core.Sha256.Digest;
      App_C_Ap   : out Tls_Core.Key_Schedule.Secret;
      App_S_Ap   : out Tls_Core.Key_Schedule.Secret;
      Master_Sec : out Tls_Core.Key_Schedule.Secret)
   is
      pragma Unreferenced (Suite);
      Empty_In : constant Octet_Array (1 .. 0) := (others => 0);
      Empty_H  : Tls_Core.Sha256.Digest;
      Der_2    : Tls_Core.Key_Schedule.Secret;
      Zero_32  : constant Tls_Core.Key_Schedule.Secret := (others => 0);
   begin
      Tls_Core.Sha256.Hash (Empty_In, Empty_H);
      Expand_Label_256
        (Secret => Hs_Secret, Label => Derived_Lab,
         Context => Empty_H, Output => Der_2);
      Tls_Core.Key_Schedule.Extract
        (Salt => Der_2, IKM => Zero_32, Out_PRK => Master_Sec);
      Expand_Label_256
        (Secret => Master_Sec, Label => C_Ap_Lab,
         Context => Th_After_Sf, Output => App_C_Ap);
      Expand_Label_256
        (Secret => Master_Sec, Label => S_Ap_Lab,
         Context => Th_After_Sf, Output => App_S_Ap);
   end Derive_App_Secrets;

   procedure Build_Finished
     (Suite           : Tls_Core.Suites.Cipher_Suite_Id;
      Base_Key        : Tls_Core.Key_Schedule.Secret;
      Transcript_Hash : Tls_Core.Sha256.Digest;
      Out_Verify      : out Tls_Core.Sha256.Digest)
   is
      pragma Unreferenced (Suite);
      Empty_Ctx : constant Octet_Array (1 .. 0) := (others => 0);
      Fin_Key   : Tls_Core.Sha256.Digest;
   begin
      Expand_Label_256
        (Secret => Base_Key, Label => Finished_Lab,
         Context => Empty_Ctx, Output => Fin_Key);
      Tls_Core.Hmac_Sha256.Compute
        (Key => Fin_Key, Message => Transcript_Hash, Out_Tag => Out_Verify);
   end Build_Finished;

   procedure Derive_Resumption_Master_Secret
     (Suite             : Tls_Core.Suites.Cipher_Suite_Id;
      Master_Secret     : Tls_Core.Key_Schedule.Secret;
      Th_After_Cf       : Tls_Core.Sha256.Digest;
      Resumption_Secret : out Tls_Core.Key_Schedule.Secret)
   is
      pragma Unreferenced (Suite);
   begin
      Tls_Core.Session_Ticket.Derive_Resumption_Master_Secret_Sha256
        (Master_Secret     => Master_Secret,
         Transcript_Hash   => Th_After_Cf,
         Resumption_Secret => Resumption_Secret);
   end Derive_Resumption_Master_Secret;

   procedure Transcript_Append
     (Suite   : Tls_Core.Suites.Cipher_Suite_Id;
      Ctx_256 : in out Tls_Core.Transcript.Accumulator;
      Ctx_384 : in out Tls_Core.Transcript_Sha384.Accumulator;
      Message : Octet_Array)
   is
      pragma Unreferenced (Ctx_384);
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
      Out_Hash : out Tls_Core.Sha256.Digest)
   is
      pragma Unreferenced (Ctx_384);
   begin
      if Suite = Tls_Core.Suites.Aes_256_Gcm_Sha384 then
         Out_Hash := (others => 0);
      else
         Tls_Core.Transcript.Snapshot (Ctx_256, Out_Hash);
      end if;
   end Transcript_Snapshot;

   procedure Init_Hs_Channel
     (Suite  : Tls_Core.Suites.Cipher_Suite_Id;
      Dir    : out Tls_Core.Aead_Channel.Direction;
      Secret : Tls_Core.Key_Schedule.Secret)
   is
   begin
      Tls_Core.Aead_Channel.Init_Sha256 (Dir, Suite, Secret);
   end Init_Hs_Channel;

end Tls_Core.Key_Sched;
