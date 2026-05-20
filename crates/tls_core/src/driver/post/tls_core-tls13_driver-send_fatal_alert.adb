separate (Tls_Core.Tls13_Driver)
procedure Send_Fatal_Alert
  (D           : in out Driver;
   Description : Octet;
   Out_Buf     : out Octet_Array;
   Out_Last    : out Natural) is
begin
   case D.Cur_State is
      when Done               =>
         Ensure_App_Out_Dir (D);
         Build_Encrypted_Alert
           (D.App_Out_Dir,
            Tls_Core.Alert.Level_Fatal,
            Description,
            Out_Buf,
            Out_Last);

      when Idle | Awaiting_CH =>
         Build_Plaintext_Alert
           (Tls_Core.Alert.Level_Fatal, Description, Out_Buf, Out_Last);

      when others             =>
         --  Excluded by Pre.
         Out_Buf := (others => 0);
         Out_Last := 0;
   end case;
   D.Last_Alert := Description;
   D.Cur_State := Failed;
end Send_Fatal_Alert;
