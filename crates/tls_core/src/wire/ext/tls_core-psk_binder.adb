with Tls_Core.Hkdf;
with Tls_Core.Hkdf_Sha256;
with Tls_Core.Hkdf_Sha384;
with Tls_Core.Hmac_Sha256;
with Tls_Core.Hmac_Sha384;
with Tls_Core.Key_Schedule;
with Tls_Core.Key_Schedule_Sha384;
with Tls_Core.Sha384;

package body Tls_Core.Psk_Binder
  with SPARK_Mode
is


   use type Tls_Core.Octet;
   use type Tls_Core.Suites.Cipher_Suite_Id;

   procedure Exp256 is new
     Tls_Core.Hkdf.Expand_Label
       (Tls_Core.Sha256.Hash_Length,
        512,
        Tls_Core.Hkdf_Sha256.Spec_HKDF_Expand,
        Tls_Core.Hkdf_Sha256.Hmac_Expand);

   procedure Exp384 is new
     Tls_Core.Hkdf.Expand_Label
       (Tls_Core.Sha384.Hash_Length,
        512,
        Tls_Core.Hkdf_Sha384.Spec_HKDF_Expand,
        Tls_Core.Hkdf_Sha384.Hmac_Expand);

   Ext_Binder_Label : constant Octet_Array (1 .. 10) :=
     [16#65#,
      16#78#,
      16#74#,
      16#20#,
      16#62#,
      16#69#,
      16#6E#,
      16#64#,
      16#65#,
      16#72#];
   Res_Binder_Label : constant Octet_Array (1 .. 10) :=
     [16#72#,
      16#65#,
      16#73#,
      16#20#,
      16#62#,
      16#69#,
      16#6E#,
      16#64#,
      16#65#,
      16#72#];
   Finished_Label   : constant Octet_Array (1 .. 8) :=
     [16#66#, 16#69#, 16#6E#, 16#69#, 16#73#, 16#68#, 16#65#, 16#64#];

   procedure Compute
     (PSK                    : Octet_Array;
      Truncated_Client_Hello : Octet_Array;
      Out_Binder             : out Binder_Bytes;
      Is_Resumption          : Boolean := False;
      Suite                  : Tls_Core.Suites.Cipher_Suite_Id :=
        Tls_Core.Suites.Chacha20_Poly1305_Sha256)
   is
      Empty : constant Octet_Array (1 .. 0) := [others => 0];
      Label : constant Octet_Array (1 .. 10) :=
        (if Is_Resumption then Res_Binder_Label else Ext_Binder_Label);
   begin
      Out_Binder := [others => 0];
      if Suite = Tls_Core.Suites.Aes_256_Gcm_Sha384 then
         declare
            Z48        : constant Octet_Array (1 .. 48) := [others => 0];
            P48        : Tls_Core.Key_Schedule_Sha384.Secret := [others => 0];
            ES, BK, FK : Tls_Core.Key_Schedule_Sha384.Secret;
            PH         : Tls_Core.Sha384.Digest;
            R          : Tls_Core.Sha384.Digest;
         begin
            P48 (1 .. PSK'Length) := PSK;
            Tls_Core.Key_Schedule_Sha384.Extract
              (Salt => Z48, IKM => P48, Out_PRK => ES);
            Tls_Core.Key_Schedule_Sha384.Derive_Secret
              (Secret_In  => ES,
               Label      => Label,
               Messages   => Empty,
               Out_Secret => BK);
            Exp384
              (Secret  => BK,
               Label   => Finished_Label,
               Context => Empty,
               Output  => FK);
            Tls_Core.Sha384.Hash (Truncated_Client_Hello, PH);
            Tls_Core.Hmac_Sha384.Compute
              (Key => FK, Message => PH, Out_Tag => R);
            Out_Binder (1 .. 48) := R;
         end;
      else
         declare
            Z32        : constant Octet_Array (1 .. 32) := [others => 0];
            ES, BK, FK : Tls_Core.Key_Schedule.Secret;
            PH         : Tls_Core.Sha256.Digest;
         begin
            Tls_Core.Key_Schedule.Extract
              (Salt => Z32, IKM => PSK, Out_PRK => ES);
            Tls_Core.Key_Schedule.Derive_Secret
              (Secret_In  => ES,
               Label      => Label,
               Messages   => Empty,
               Out_Secret => BK);
            Exp256
              (Secret  => BK,
               Label   => Finished_Label,
               Context => Empty,
               Output  => FK);
            Tls_Core.Sha256.Hash (Truncated_Client_Hello, PH);
            Tls_Core.Hmac_Sha256.Compute
              (Key => FK, Message => PH, Out_Tag => Out_Binder (1 .. 32));
         end;
      end if;
   end Compute;

   function Verify
     (Computed : Binder_Bytes; Received : Binder_Bytes) return Boolean
   is
      Diff : Octet := 0;
   begin
      for I in Computed'Range loop
         Diff := Diff or (Computed (I) xor Received (I));
      end loop;
      return Diff = 0;
   end Verify;

end Tls_Core.Psk_Binder;
