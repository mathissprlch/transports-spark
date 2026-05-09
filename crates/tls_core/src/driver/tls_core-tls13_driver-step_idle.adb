with Tls_Core.Hello;
with Tls_Core.Psk_Binder;
with Tls_Core.Key_Sched;
with Tls_Core.Tls13_Driver.Helpers; use Tls_Core.Tls13_Driver.Helpers;

package body Tls_Core.Tls13_Driver.Step_Idle
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   procedure Handle
     (D        : in out Driver;
      In_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   is
      pragma Unreferenced (In_Bytes);
   begin
      Out_Buf := (others => 0);
      Out_Last := 0;

      if D.My_Role /= Client then
         D.Cur_State := Failed;
         return;
      end if;

      if D.Mode = Cert_Mode then
         declare
            Client_Random : constant Tls_Core.Hello.Random_Bytes :=
              (others => 16#A1#);
            Ch_Body : Octet_Array (1 .. 512) := (others => 0);
            Ch_Body_Last : Natural;
            Ch_Hs   : Octet_Array (1 .. 1024) := (others => 0);
            Ch_Hs_Last : Natural;
            Ch_Rec  : Octet_Array (1 .. 1024) := (others => 0);
            Ch_Rec_Last : Natural;
         begin
            Tls_Core.Hello.Encode_Client_Hello_Cert
              (Random      => Client_Random,
               Key_Share   => D.My_Ecdhe_Pub,
               Server_Name => D.Sni_Hostname (1 .. D.Sni_Len),
               Alpn_Offers => D.Alpn_Offers (1 .. D.Alpn_Offers_Len),
               Out_Buf     => Ch_Body,
               Out_Last    => Ch_Body_Last);
            Encode_Hs_Message
              (Hs_Type_CH, Ch_Body (1 .. Ch_Body_Last),
               Ch_Hs, Ch_Hs_Last);
            Tls_Core.Key_Sched.Transcript_Append (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Ch_Hs (1 .. Ch_Hs_Last));
            Wrap_Tls_Plaintext
              (Ch_Hs (1 .. Ch_Hs_Last), Ch_Rec, Ch_Rec_Last);
            Out_Buf (1 .. Ch_Rec_Last) := Ch_Rec (1 .. Ch_Rec_Last);
            Out_Last := Ch_Rec_Last;
            D.Cur_State := Awaiting_Sf;
         end;
         return;
      end if;

      declare
         Client_Random : constant Tls_Core.Hello.Random_Bytes :=
           (others => 16#A1#);
         Ch_Body : Octet_Array (1 .. 512) := (others => 0);
         Ch_Body_Last : Natural;
         T_Last  : Natural;
         Binder  : Tls_Core.Psk_Binder.Binder_Bytes;
         Ch_Hs   : Octet_Array (1 .. 1024) := (others => 0);
         Ch_Hs_Last : Natural;
         Ch_Rec  : Octet_Array (1 .. 1024) := (others => 0);
         Ch_Rec_Last : Natural;
      begin
         Tls_Core.Hello.Encode_Client_Hello_Psk
           (Client_Random,
            D.Identity (1 .. D.Identity_Len),
            D.My_Ecdhe_Pub,
            D.Sni_Hostname (1 .. D.Sni_Len),
            D.Alpn_Offers (1 .. D.Alpn_Offers_Len),
            Ch_Body, Ch_Body_Last, T_Last);
         Ch_Hs := (others => 0);
         Ch_Hs (1) := Hs_Type_CH;
         Ch_Hs (2) := Octet ((Ch_Body_Last / 65536) mod 256);
         Ch_Hs (3) := Octet ((Ch_Body_Last / 256) mod 256);
         Ch_Hs (4) := Octet (Ch_Body_Last mod 256);
         Ch_Hs (5 .. 4 + T_Last) := Ch_Body (1 .. T_Last);
         Tls_Core.Psk_Binder.Compute
           (PSK                    => D.PSK,
            Truncated_Client_Hello => Ch_Hs (1 .. 4 + T_Last),
            Out_Binder             => Binder,
            Is_Resumption          => D.Is_Resumption);
         Ch_Body (T_Last + 4 .. T_Last + 35) := Binder (1 .. 32);
         Encode_Hs_Message
           (Hs_Type_CH, Ch_Body (1 .. Ch_Body_Last),
            Ch_Hs, Ch_Hs_Last);
         Tls_Core.Key_Sched.Transcript_Append (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Ch_Hs (1 .. Ch_Hs_Last));
         Wrap_Tls_Plaintext
           (Ch_Hs (1 .. Ch_Hs_Last), Ch_Rec, Ch_Rec_Last);
         Out_Buf (1 .. Ch_Rec_Last) := Ch_Rec (1 .. Ch_Rec_Last);
         Out_Last := Ch_Rec_Last;
         if D.Hrr_Aware then
            D.Cur_State := Awaiting_Sh_Or_Hrr;
         else
            D.Cur_State := Awaiting_Sf;
         end if;
      end;
   end Handle;

end Tls_Core.Tls13_Driver.Step_Idle;
