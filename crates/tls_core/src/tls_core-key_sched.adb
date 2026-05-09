with Tls_Core.Hkdf;
with Tls_Core.Hkdf_Sha256;
with Tls_Core.Hkdf_Sha384;
with Tls_Core.Hmac_Sha256;
with Tls_Core.Hmac_Sha384;
with Tls_Core.Key_Schedule;
with Tls_Core.Key_Schedule_Sha384;
with Tls_Core.Sha256;
with Tls_Core.Sha384;
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

   procedure Hkdf_Expand_Label_256
     is new Tls_Core.Hkdf.Expand_Label
       (Hash_Length      => Tls_Core.Sha256.Hash_Length,
        Max_Info         => 512,
        Spec_Hmac_Expand => Tls_Core.Hkdf_Sha256.Spec_HKDF_Expand,
        Hmac_Expand      => Tls_Core.Hkdf_Sha256.Hmac_Expand);

   procedure Hkdf_Expand_Label_384
     is new Tls_Core.Hkdf.Expand_Label
       (Hash_Length      => Tls_Core.Sha384.Hash_Length,
        Max_Info         => 512,
        Spec_Hmac_Expand => Tls_Core.Hkdf_Sha384.Spec_HKDF_Expand,
        Hmac_Expand      => Tls_Core.Hkdf_Sha384.Hmac_Expand);

   procedure Derive_Handshake_Secrets
     (Suite          : Tls_Core.Suites.Cipher_Suite_Id;
      PSK            : Octet_Array;
      Ecdhe_Shared   : Octet_Array;
      Th_After_Sh    : Max_Digest;
      C_Hs_Sec      : out Max_Secret;
      S_Hs_Sec      : out Max_Secret;
      Hs_Secret      : out Max_Secret)
   is
      Empty_In : constant Octet_Array (1 .. 0) := (others => 0);
   begin
      C_Hs_Sec := (others => 0);
      S_Hs_Sec := (others => 0);
      Hs_Secret := (others => 0);

      if Suite = Tls_Core.Suites.Aes_256_Gcm_Sha384 then
         declare
            Early   : Tls_Core.Key_Schedule_Sha384.Secret;
            Der_1   : Tls_Core.Key_Schedule_Sha384.Secret;
            Hs_Tmp  : Tls_Core.Key_Schedule_Sha384.Secret;
            C_Tmp   : Tls_Core.Key_Schedule_Sha384.Secret;
            S_Tmp   : Tls_Core.Key_Schedule_Sha384.Secret;
            Psk_48  : Tls_Core.Key_Schedule_Sha384.Secret := (others => 0);
            Zero_48 : constant Octet_Array (1 .. 48) := (others => 0);
         begin
            Psk_48 (1 .. PSK'Length) := PSK;
            Tls_Core.Key_Schedule_Sha384.Extract
              (Salt => Psk_48, IKM => Zero_48, Out_PRK => Early);
            Tls_Core.Key_Schedule_Sha384.Derive_Secret
              (Secret_In => Early, Label => Derived_Lab,
               Messages  => Empty_In, Out_Secret => Der_1);
            Tls_Core.Key_Schedule_Sha384.Extract
              (Salt => Der_1, IKM => Ecdhe_Shared, Out_PRK => Hs_Tmp);
            Hkdf_Expand_Label_384
              (Secret => Hs_Tmp, Label => C_Hs_Lab,
               Context => Th_After_Sh (1 .. 48), Output => C_Tmp);
            Hkdf_Expand_Label_384
              (Secret => Hs_Tmp, Label => S_Hs_Lab,
               Context => Th_After_Sh (1 .. 48), Output => S_Tmp);
            C_Hs_Sec (1 .. 48) := C_Tmp;
            S_Hs_Sec (1 .. 48) := S_Tmp;
            Hs_Secret (1 .. 48) := Hs_Tmp;
         end;
      else
         declare
            Early   : Tls_Core.Key_Schedule.Secret;
            Der_1   : Tls_Core.Key_Schedule.Secret;
            Hs_Tmp  : Tls_Core.Key_Schedule.Secret;
            C_Tmp   : Tls_Core.Key_Schedule.Secret;
            S_Tmp   : Tls_Core.Key_Schedule.Secret;
            Zero_32 : constant Octet_Array (1 .. 32) := (others => 0);
            Psk_32  : Tls_Core.Key_Schedule.Secret := (others => 0);
         begin
            Psk_32 (1 .. PSK'Length) := PSK;
            Tls_Core.Key_Schedule.Extract
              (Salt => Psk_32, IKM => Zero_32, Out_PRK => Early);
            Tls_Core.Key_Schedule.Derive_Secret
              (Secret_In => Early, Label => Derived_Lab,
               Messages  => Empty_In, Out_Secret => Der_1);
            Tls_Core.Key_Schedule.Extract
              (Salt => Der_1, IKM => Ecdhe_Shared, Out_PRK => Hs_Tmp);
            Hkdf_Expand_Label_256
              (Secret => Hs_Tmp, Label => C_Hs_Lab,
               Context => Th_After_Sh (1 .. 32), Output => C_Tmp);
            Hkdf_Expand_Label_256
              (Secret => Hs_Tmp, Label => S_Hs_Lab,
               Context => Th_After_Sh (1 .. 32), Output => S_Tmp);
            C_Hs_Sec (1 .. 32) := C_Tmp;
            S_Hs_Sec (1 .. 32) := S_Tmp;
            Hs_Secret (1 .. 32) := Hs_Tmp;
         end;
      end if;
   end Derive_Handshake_Secrets;

   procedure Derive_App_Secrets
     (Suite          : Tls_Core.Suites.Cipher_Suite_Id;
      Hs_Secret      : Max_Secret;
      Th_After_Sf    : Max_Digest;
      App_C_Ap       : out Max_Secret;
      App_S_Ap       : out Max_Secret;
      Master_Sec     : out Max_Secret)
   is
   begin
      App_C_Ap := (others => 0);
      App_S_Ap := (others => 0);
      Master_Sec := (others => 0);

      if Suite = Tls_Core.Suites.Aes_256_Gcm_Sha384 then
         declare
            Hs_48     : constant Tls_Core.Key_Schedule_Sha384.Secret :=
              Hs_Secret (1 .. 48);
            Empty_H   : Tls_Core.Sha384.Digest;
            Der_2     : Tls_Core.Key_Schedule_Sha384.Secret;
            Master    : Tls_Core.Key_Schedule_Sha384.Secret;
            C_Tmp     : Tls_Core.Key_Schedule_Sha384.Secret;
            S_Tmp     : Tls_Core.Key_Schedule_Sha384.Secret;
            Zero_48   : constant Tls_Core.Key_Schedule_Sha384.Secret :=
              (others => 0);
            Empty_In  : constant Octet_Array (1 .. 0) := (others => 0);
         begin
            Tls_Core.Sha384.Hash (Empty_In, Empty_H);
            Hkdf_Expand_Label_384
              (Secret => Hs_48, Label => Derived_Lab,
               Context => Empty_H, Output => Der_2);
            Tls_Core.Key_Schedule_Sha384.Extract
              (Salt => Der_2, IKM => Zero_48, Out_PRK => Master);
            Hkdf_Expand_Label_384
              (Secret => Master, Label => C_Ap_Lab,
               Context => Th_After_Sf (1 .. 48), Output => C_Tmp);
            Hkdf_Expand_Label_384
              (Secret => Master, Label => S_Ap_Lab,
               Context => Th_After_Sf (1 .. 48), Output => S_Tmp);
            App_C_Ap (1 .. 48) := C_Tmp;
            App_S_Ap (1 .. 48) := S_Tmp;
            Master_Sec (1 .. 48) := Master;
         end;
      else
         declare
            Hs_32     : constant Tls_Core.Key_Schedule.Secret :=
              Hs_Secret (1 .. 32);
            Empty_H   : Tls_Core.Sha256.Digest;
            Der_2     : Tls_Core.Key_Schedule.Secret;
            Master    : Tls_Core.Key_Schedule.Secret;
            C_Tmp     : Tls_Core.Key_Schedule.Secret;
            S_Tmp     : Tls_Core.Key_Schedule.Secret;
            Zero_32   : constant Tls_Core.Key_Schedule.Secret := (others => 0);
            Empty_In  : constant Octet_Array (1 .. 0) := (others => 0);
         begin
            Tls_Core.Sha256.Hash (Empty_In, Empty_H);
            Hkdf_Expand_Label_256
              (Secret => Hs_32, Label => Derived_Lab,
               Context => Empty_H, Output => Der_2);
            Tls_Core.Key_Schedule.Extract
              (Salt => Der_2, IKM => Zero_32, Out_PRK => Master);
            Hkdf_Expand_Label_256
              (Secret => Master, Label => C_Ap_Lab,
               Context => Th_After_Sf (1 .. 32), Output => C_Tmp);
            Hkdf_Expand_Label_256
              (Secret => Master, Label => S_Ap_Lab,
               Context => Th_After_Sf (1 .. 32), Output => S_Tmp);
            App_C_Ap (1 .. 32) := C_Tmp;
            App_S_Ap (1 .. 32) := S_Tmp;
            Master_Sec (1 .. 32) := Master;
         end;
      end if;
   end Derive_App_Secrets;

   procedure Build_Finished
     (Suite           : Tls_Core.Suites.Cipher_Suite_Id;
      Base_Key        : Max_Secret;
      Transcript_Hash : Max_Digest;
      Out_Verify      : out Max_Digest)
   is
      Empty_Ctx : constant Octet_Array (1 .. 0) := (others => 0);
   begin
      Out_Verify := (others => 0);

      if Suite = Tls_Core.Suites.Aes_256_Gcm_Sha384 then
         declare
            Fin_Key : Tls_Core.Sha384.Digest;
            Result  : Tls_Core.Sha384.Digest;
         begin
            Hkdf_Expand_Label_384
              (Secret => Base_Key (1 .. 48), Label => Finished_Lab,
               Context => Empty_Ctx, Output => Fin_Key);
            Tls_Core.Hmac_Sha384.Compute
              (Key     => Fin_Key,
               Message => Transcript_Hash (1 .. 48),
               Out_Tag => Result);
            Out_Verify (1 .. 48) := Result;
         end;
      else
         declare
            Fin_Key : Tls_Core.Sha256.Digest;
            Result  : Tls_Core.Sha256.Digest;
         begin
            Hkdf_Expand_Label_256
              (Secret => Base_Key (1 .. 32), Label => Finished_Lab,
               Context => Empty_Ctx, Output => Fin_Key);
            Tls_Core.Hmac_Sha256.Compute
              (Key     => Fin_Key,
               Message => Transcript_Hash (1 .. 32),
               Out_Tag => Result);
            Out_Verify (1 .. 32) := Result;
         end;
      end if;
   end Build_Finished;

   procedure Derive_Resumption_Master_Secret
     (Suite             : Tls_Core.Suites.Cipher_Suite_Id;
      Master_Secret     : Max_Secret;
      Th_After_Cf       : Max_Digest;
      Resumption_Secret : out Max_Secret)
   is
   begin
      Resumption_Secret := (others => 0);

      if Suite = Tls_Core.Suites.Aes_256_Gcm_Sha384 then
         declare
            Res_Lab : constant Octet_Array (1 .. 10) :=
              (16#72#, 16#65#, 16#73#, 16#20#, 16#6D#,
               16#61#, 16#73#, 16#74#, 16#65#, 16#72#);
         begin
            Hkdf_Expand_Label_384
              (Secret  => Master_Secret (1 .. 48),
               Label   => Res_Lab,
               Context => Th_After_Cf (1 .. 48),
               Output  => Resumption_Secret (1 .. 48));
         end;
      else
         declare
            Result : Tls_Core.Key_Schedule.Secret;
         begin
            Tls_Core.Session_Ticket.Derive_Resumption_Master_Secret_Sha256
              (Master_Secret     => Master_Secret (1 .. 32),
               Transcript_Hash   => Th_After_Cf (1 .. 32),
               Resumption_Secret => Result);
            Resumption_Secret (1 .. 32) := Result;
         end;
      end if;
   end Derive_Resumption_Master_Secret;

end Tls_Core.Key_Sched;
