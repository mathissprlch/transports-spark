package body Http1_Core.Server is

   use type Wire.Octet_Offset;
   use type Wire.Octet;

   Inbound_Capacity  : constant := 16384;
   Outbound_Capacity : constant := 65536;
   Body_Capacity     : constant := 16384;

   procedure Listen
     (L    : in out Listener;
      Host : String;
      Port : Natural)
   is
   begin
      Transport.Listen (L.Trans, Host, Port);
   end Listen;

   procedure Stop (L : in out Listener) is
   begin
      if Transport.Is_Listening (L.Trans) then
         Transport.Stop (L.Trans);
      end if;
   end Stop;

   ---------------------------------------------------------------------
   --  Read until the request head (\r\n\r\n) is complete OR the
   --  buffer fills up. Returns the position of the first body byte
   --  in `Last_Recv` if the head was found.
   ---------------------------------------------------------------------

   procedure Read_Until_Head
     (Chan       : Transport.Channel;
      Buf        : in out Wire.Octet_Array;
      Last_Recv  : out Wire.Octet_Offset;
      OK         : out Boolean);

   procedure Read_Until_Head
     (Chan       : Transport.Channel;
      Buf        : in out Wire.Octet_Array;
      Last_Recv  : out Wire.Octet_Offset;
      OK         : out Boolean)
   is
      Cursor : Wire.Octet_Offset := Buf'First - 1;
   begin
      OK := False;
      Last_Recv := Buf'First - 1;
      loop
         if Cursor >= Buf'Last then return; end if;
         declare
            Slice : Wire.Octet_Array (Cursor + 1 .. Buf'Last);
            Got_Last : Wire.Octet_Offset;
            Got_OK   : Boolean;
         begin
            Transport.Receive (Chan, Slice, Got_Last, Got_OK);
            if not Got_OK then return; end if;
            Buf (Slice'First .. Got_Last) := Slice (Slice'First .. Got_Last);
            Cursor := Got_Last;
         end;
         --  Look for CRLF CRLF.
         for I in Buf'First .. Cursor - 3 loop
            if Buf (I) = 13 and Buf (I + 1) = 10
              and Buf (I + 2) = 13 and Buf (I + 3) = 10
            then
               Last_Recv := Cursor;
               OK := True;
               return;
            end if;
         end loop;
      end loop;
   end Read_Until_Head;

   ---------------------------------------------------------------------
   --  Read N more body bytes after the head.
   ---------------------------------------------------------------------

   procedure Read_Exactly
     (Chan : Transport.Channel;
      Buf  : in out Wire.Octet_Array;
      First, Last : Wire.Octet_Offset;
      OK   : out Boolean);

   procedure Read_Exactly
     (Chan : Transport.Channel;
      Buf  : in out Wire.Octet_Array;
      First, Last : Wire.Octet_Offset;
      OK   : out Boolean)
   is
      Cursor : Wire.Octet_Offset := First - 1;
   begin
      OK := False;
      while Cursor < Last loop
         declare
            Slice : Wire.Octet_Array (Cursor + 1 .. Last);
            Got_Last : Wire.Octet_Offset;
            Got_OK   : Boolean;
         begin
            Transport.Receive (Chan, Slice, Got_Last, Got_OK);
            if not Got_OK then return; end if;
            Buf (Slice'First .. Got_Last) := Slice (Slice'First .. Got_Last);
            Cursor := Got_Last;
         end;
      end loop;
      OK := True;
   end Read_Exactly;

   ---------------------------------------------------------------------
   --  Accept_And_Serve.
   ---------------------------------------------------------------------

   procedure Accept_And_Serve (L : in out Listener) is
      Chan : Transport.Channel;

      Inbound : Wire.Octet_Array (1 .. Inbound_Capacity) :=
        (others => 0);
      Inbound_Last : Wire.Octet_Offset;
      Head_OK : Boolean;

      Req : Wire.Request;
      Req_Valid : Boolean;
   begin
      Transport.Accept_One (L.Trans, Chan);

      Read_Until_Head (Chan, Inbound, Inbound_Last, Head_OK);
      if not Head_OK then
         Transport.Close (Chan);
         return;
      end if;

      Wire.Parse_Request_Head
        (Inbound (Inbound'First .. Inbound_Last), Req, Req_Valid);
      if not Req_Valid then
         declare
            Out_Buf  : Wire.Octet_Array (1 .. 256);
            Out_Last : Wire.Octet_Offset;
            Empty_Headers : Wire.Header_Block;
            Empty_Body : constant Wire.Octet_Array (1 .. 0) :=
              (others => 0);
         begin
            Wire.Encode_Response
              (Out_Buf      => Out_Buf,
               Out_Last     => Out_Last,
               Status       => 400,
               Reason       => "Bad Request",
               Headers      => Empty_Headers,
               Headers_Last => 0,
               Body_Bytes   => Empty_Body);
            Transport.Send (Chan, Out_Buf (Out_Buf'First .. Out_Last));
         end;
         Transport.Close (Chan);
         return;
      end if;

      --  Drain Content-Length body bytes if not yet fully buffered.
      declare
         Body_Start : constant Wire.Octet_Offset :=
           Req.Header_Section_Last;
         Body_End   : constant Wire.Octet_Offset :=
           Body_Start + Wire.Octet_Offset (Req.Content_Length) - 1;
         Body_OK    : Boolean := True;
      begin
         if Req.Has_Content_Length and then Req.Content_Length > 0 then
            if Body_End > Wire.Octet_Offset (Inbound'Last) then
               Body_OK := False;
            elsif Body_End > Inbound_Last then
               Read_Exactly
                 (Chan, Inbound, Inbound_Last + 1, Body_End, Body_OK);
            end if;
         end if;

         if not Body_OK then
            Transport.Close (Chan);
            return;
         end if;

         declare
            Body_Slice : Wire.Octet_Array
              (1 .. (if Req.Has_Content_Length
                     then Wire.Octet_Offset (Req.Content_Length)
                     else 0)) := (others => 0);
            Resp_Status : Natural := 200;
            Resp_Reason : String (1 .. 64) := (others => ' ');
            Reason_Last : Natural := 0;
            Resp_Headers : Wire.Header_Block;
            Resp_Headers_Last : Natural := 0;
            Resp_Body : Wire.Octet_Array (1 .. Body_Capacity) :=
              (others => 0);
            Resp_Body_Last : Wire.Octet_Offset := 0;
            Out_Buf  : Wire.Octet_Array (1 .. Outbound_Capacity) :=
              (others => 0);
            Out_Last : Wire.Octet_Offset;
         begin
            if Body_Slice'Length > 0 then
               Body_Slice :=
                 Inbound (Body_Start ..
                            Body_Start + Body_Slice'Length - 1);
            end if;
            Resp_Reason (1 .. 2) := "OK"; Reason_Last := 2;
            Handle_Request
              (Request               => Req,
               Request_Body          => Body_Slice,
               Response_Status       => Resp_Status,
               Response_Reason       => Resp_Reason,
               Reason_Last           => Reason_Last,
               Response_Headers      => Resp_Headers,
               Response_Headers_Last => Resp_Headers_Last,
               Response_Body         => Resp_Body,
               Response_Body_Last    => Resp_Body_Last);

            Wire.Encode_Response
              (Out_Buf      => Out_Buf,
               Out_Last     => Out_Last,
               Status       => Resp_Status,
               Reason       => Resp_Reason (1 .. Reason_Last),
               Headers      => Resp_Headers,
               Headers_Last => Resp_Headers_Last,
               Body_Bytes   =>
                 Resp_Body
                   (Resp_Body'First ..
                      (if Resp_Body_Last >= Resp_Body'First
                       then Resp_Body_Last
                       else Resp_Body'First - 1)));
            Transport.Send (Chan, Out_Buf (Out_Buf'First .. Out_Last));
         end;
      end;

      Transport.Close (Chan);
   end Accept_And_Serve;

end Http1_Core.Server;
