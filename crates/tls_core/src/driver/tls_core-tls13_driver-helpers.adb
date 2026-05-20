with Tls_Core.Hmac_Sha256;
with Tls_Core.Key_Sched;

package body Tls_Core.Tls13_Driver.Helpers
  with SPARK_Mode
is

   procedure Prime_Driver_Defaults (D : in out Driver) is
      Zero_Secret : constant Tls_Core.Key_Sched.Max_Secret := [others => 0];
      Zero_Digest : constant Tls_Core.Key_Sched.Max_Digest := [others => 0];
   begin
      D.Suite := Tls_Core.Suites.Chacha20_Poly1305_Sha256;
      D.C_Hs_Sec := Zero_Secret;
      D.S_Hs_Sec := Zero_Secret;
      D.Hs_Secret := Zero_Secret;
      D.Expected_Cf := Zero_Digest;
      D.App_C_Ap := Zero_Secret;
      D.App_S_Ap := Zero_Secret;
      D.Master_Sec := Zero_Secret;
      D.Master_Set := False;
      D.Res_Master_Sec := Zero_Secret;
      D.Res_Master_Set := False;
      Tls_Core.Key_Sched.Init_Hs_Channel
        (Tls_Core.Suites.Chacha20_Poly1305_Sha256, D.Hs_Out_Dir, Zero_Secret);
      Tls_Core.Key_Sched.Init_Hs_Channel
        (Tls_Core.Suites.Chacha20_Poly1305_Sha256, D.Hs_In_Dir, Zero_Secret);
   end Prime_Driver_Defaults;

   procedure Build_Plaintext_Alert
     (Level       : Octet;
      Description : Octet;
      Out_Buf     : out Octet_Array;
      Out_Last    : out Natural) is
   begin
      Out_Buf := [others => 0];
      Out_Buf (1) := Rec_Type_Alert;
      Out_Buf (2) := 16#03#;
      Out_Buf (3) := 16#03#;
      Out_Buf (4) := 16#00#;
      Out_Buf (5) := 16#02#;
      Out_Buf (6) := Level;
      Out_Buf (7) := Description;
      Out_Last := 7;
   end Build_Plaintext_Alert;

   procedure Build_Encrypted_Alert
     (Dir         : in out Tls_Core.Aead_Channel.Direction;
      Level       : Octet;
      Description : Octet;
      Out_Buf     : out Octet_Array;
      Out_Last    : out Natural)
   is
      Body_Bytes : Tls_Core.Alert.Alert_Bytes;
   begin
      Tls_Core.Alert.Encode
        (Tls_Core.Alert.Alert'(Level => Level, Description => Description),
         Body_Bytes);
      Tls_Core.Aead_Channel.Send
        (Dir,
         Body_Bytes,
         Tls_Core.Aead_Channel.Inner_Type_Alert,
         Out_Buf,
         Out_Last);
   end Build_Encrypted_Alert;

   procedure Fail_Plaintext
     (D           : in out Driver;
      Description : Octet;
      Out_Buf     : out Octet_Array;
      Out_Last    : out Natural) is
   begin
      Build_Plaintext_Alert
        (Tls_Core.Alert.Level_Fatal, Description, Out_Buf, Out_Last);
      D.Last_Alert := Description;
      D.Cur_State := Failed;
   end Fail_Plaintext;

   procedure Fail_Encrypted
     (D           : in out Driver;
      Description : Octet;
      Out_Buf     : out Octet_Array;
      Out_Last    : out Natural) is
   begin
      Build_Encrypted_Alert
        (D.Hs_Out_Dir,
         Tls_Core.Alert.Level_Fatal,
         Description,
         Out_Buf,
         Out_Last);
      D.Last_Alert := Description;
      D.Cur_State := Failed;
   end Fail_Encrypted;

   procedure Encode_Hs_Message
     (Msg_Type   : Octet;
      Body_Bytes : Octet_Array;
      Out_Buf    : out Octet_Array;
      Out_Last   : out Natural)
   is
      Len : constant Natural := Body_Bytes'Length;
   begin
      Out_Buf := [others => 0];
      Out_Buf (1) := Msg_Type;
      Out_Buf (2) := Octet ((Len / 65536) mod 256);
      Out_Buf (3) := Octet ((Len / 256) mod 256);
      Out_Buf (4) := Octet (Len mod 256);
      if Len > 0 then
         Out_Buf (5 .. 4 + Len) := Body_Bytes;
      end if;
      Out_Last := 4 + Len;
   end Encode_Hs_Message;

   procedure Wrap_Tls_Plaintext
     (Hs_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   is
      Len : constant Natural := Hs_Bytes'Length;
   begin
      Out_Buf := [others => 0];
      Out_Buf (1) := Rec_Type_Handshake;
      Out_Buf (2) := 16#03#;
      Out_Buf (3) := 16#03#;
      Out_Buf (4) := Octet ((Len / 256) mod 256);
      Out_Buf (5) := Octet (Len mod 256);
      Out_Buf (6 .. 5 + Len) := Hs_Bytes;
      Out_Last := 5 + Len;
   end Wrap_Tls_Plaintext;

   procedure Ensure_App_Out_Dir (D : in out Driver) is
   begin
      case D.My_Role is
         when Server =>
            Tls_Core.Key_Sched.Init_Hs_Channel
              (D.Suite, D.App_Out_Dir, D.App_S_Ap);

         when Client =>
            Tls_Core.Key_Sched.Init_Hs_Channel
              (D.Suite, D.App_Out_Dir, D.App_C_Ap);
      end case;
      D.App_Out_Set := True;
   end Ensure_App_Out_Dir;

end Tls_Core.Tls13_Driver.Helpers;
