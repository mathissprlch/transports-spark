package body GRPC.Channel is

   procedure Initialize
     (C      : in out Instance;
      Host   : String;
      Port   : Positive;
      Scheme : Scheme_Type := HTTP)
   is
      Port_Img : constant String := Port'Image;
      Port_Str : constant String :=
        (if Port_Img (Port_Img'First) = ' '
         then Port_Img (Port_Img'First + 1 .. Port_Img'Last)
         else Port_Img);
   begin
      C.Host      := To_Unbounded_String (Host);
      C.Port      := Port;
      C.Scheme    := Scheme;
      C.Authority := To_Unbounded_String (Host & ":" & Port_Str);
   end Initialize;

end GRPC.Channel;
