with Ada.Characters.Handling;

package body Http1_Core.Wire is

   use type Octet_Offset;
   use type Octet;

   CR : constant Octet := 13;
   LF : constant Octet := 10;
   SP : constant Octet := 32;
   HT : constant Octet := 9;

   function To_Char (B : Octet) return Character is
     (Character'Val (Natural (B)));

   --  Locate index of first CRLF starting at From (inclusive).
   --  Returns 0 if not found within Input. The returned index points
   --  at the CR byte; LF is at Result + 1.
   function Find_CRLF
     (Input : Octet_Array; From : Octet_Offset) return Octet_Offset;

   function Find_CRLF
     (Input : Octet_Array; From : Octet_Offset) return Octet_Offset
   is
      I : Octet_Offset := From;
   begin
      while I < Input'Last loop
         if Input (I) = CR and Input (I + 1) = LF then
            return I;
         end if;
         I := I + 1;
      end loop;
      return 0;
   end Find_CRLF;

   --  Parse one header line "Name: Value\r\n" between [From, CRLF_At-1].
   procedure Parse_Header_Line
     (Input    : Octet_Array;
      From     : Octet_Offset;
      CRLF_At  : Octet_Offset;
      H        : out Header;
      OK       : out Boolean);

   procedure Parse_Header_Line
     (Input    : Octet_Array;
      From     : Octet_Offset;
      CRLF_At  : Octet_Offset;
      H        : out Header;
      OK       : out Boolean)
   is
      Colon : Octet_Offset := 0;
      Val_Start, Val_End : Octet_Offset;
   begin
      H := (others => <>);
      OK := False;

      --  RFC 9112 §5.2 / §5.5 — reject obs-fold (line starting with SP/HT).
      if From > Input'Last then return; end if;
      if Input (From) = SP or Input (From) = HT then return; end if;

      for I in From .. CRLF_At - 1 loop
         if Input (I) = Octet (Character'Pos (':')) then
            Colon := I;
            exit;
         end if;
      end loop;
      if Colon = 0 or Colon = From then return; end if;

      declare
         Name_Len : constant Natural := Natural (Colon - From);
      begin
         if Name_Len > Max_Header_Name_Len then return; end if;
         for I in 1 .. Name_Len loop
            H.Name (I) := To_Char (Input (From + Octet_Offset (I) - 1));
         end loop;
         H.Name_Last := Name_Len;
      end;

      --  Strip leading OWS after colon.
      Val_Start := Colon + 1;
      while Val_Start < CRLF_At
        and then (Input (Val_Start) = SP or Input (Val_Start) = HT)
      loop
         Val_Start := Val_Start + 1;
      end loop;

      --  Strip trailing OWS before CRLF.
      Val_End := CRLF_At - 1;
      while Val_End >= Val_Start
        and then (Input (Val_End) = SP or Input (Val_End) = HT)
      loop
         Val_End := Val_End - 1;
      end loop;

      declare
         Val_Len : constant Integer := Integer (Val_End - Val_Start) + 1;
      begin
         if Val_Len < 0 or else Val_Len > Max_Header_Value_Len then
            return;
         end if;
         for I in 1 .. Val_Len loop
            H.Value (I) := To_Char (Input (Val_Start + Octet_Offset (I) - 1));
         end loop;
         H.Value_Last := Val_Len;
      end;

      OK := True;
   end Parse_Header_Line;

   procedure Parse_Request_Head
     (Input : Octet_Array;
      Req   : out Request;
      Valid : out Boolean)
   is
      use Ada.Characters.Handling;
      Cursor : Octet_Offset;
      Line_End : Octet_Offset;
   begin
      Req := (others => <>);
      Valid := False;

      if Input'Length < 16 then return; end if;  --  too short for any request

      --  Request line: "METHOD SP URI SP HTTP/1.1 CRLF"
      Line_End := Find_CRLF (Input, Input'First);
      if Line_End = 0 then return; end if;

      declare
         Sp1, Sp2 : Octet_Offset := 0;
      begin
         for I in Input'First .. Line_End - 1 loop
            if Input (I) = SP then
               if Sp1 = 0 then
                  Sp1 := I;
               elsif Sp2 = 0 then
                  Sp2 := I;
                  exit;
               end if;
            end if;
         end loop;
         if Sp1 = 0 or Sp2 = 0 then return; end if;

         declare
            Mlen : constant Natural := Natural (Sp1 - Input'First);
            Ulen : constant Natural := Natural (Sp2 - Sp1) - 1;
         begin
            if Mlen > Max_Method_Len or Ulen > Max_Uri_Len
              or Mlen = 0 or Ulen = 0
            then return; end if;
            for I in 1 .. Mlen loop
               Req.Method (I) :=
                 To_Char (Input (Input'First + Octet_Offset (I) - 1));
            end loop;
            Req.Method_Last := Mlen;
            for I in 1 .. Ulen loop
               Req.Uri (I) :=
                 To_Char (Input (Sp1 + Octet_Offset (I)));
            end loop;
            Req.Uri_Last := Ulen;
         end;

         --  Verify HTTP/1.1 (we don't accept HTTP/1.0 in v0.3).
         if Line_End - Sp2 < 9 then return; end if;
         declare
            Ver : String (1 .. 8);
         begin
            for I in 1 .. 8 loop
               Ver (I) := To_Char (Input (Sp2 + Octet_Offset (I)));
            end loop;
            if Ver /= "HTTP/1.1" then return; end if;
         end;
      end;

      Cursor := Line_End + 2;  --  skip CRLF

      --  Header section.
      Headers_Loop :
      loop
         if Cursor + 1 > Input'Last then return; end if;
         --  Empty line CRLF terminates headers.
         if Input (Cursor) = CR and Input (Cursor + 1) = LF then
            Cursor := Cursor + 2;
            exit Headers_Loop;
         end if;

         Line_End := Find_CRLF (Input, Cursor);
         if Line_End = 0 then return; end if;

         declare
            H  : Header;
            OK : Boolean;
         begin
            Parse_Header_Line (Input, Cursor, Line_End, H, OK);
            if not OK then return; end if;
            if Req.Headers_Last = Max_Headers then return; end if;
            Req.Headers_Last := Req.Headers_Last + 1;
            Req.Headers (Req.Headers_Last) := H;

            --  Eager interpretation of Content-Length / Connection.
            declare
               Lower_Name : String (1 .. H.Name_Last);
            begin
               for I in 1 .. H.Name_Last loop
                  Lower_Name (I) := To_Lower (H.Name (I));
               end loop;
               if Lower_Name = "content-length" then
                  declare
                     Vstr : constant String :=
                       H.Value (1 .. H.Value_Last);
                  begin
                     Req.Content_Length := Natural'Value (Vstr);
                     Req.Has_Content_Length := True;
                  exception
                     when others => return;  --  malformed
                  end;
               elsif Lower_Name = "connection" then
                  declare
                     Vlower : String (1 .. H.Value_Last);
                  begin
                     for I in 1 .. H.Value_Last loop
                        Vlower (I) := To_Lower (H.Value (I));
                     end loop;
                     if Vlower = "close" then
                        Req.Connection_Close := True;
                     end if;
                  end;
               end if;
            end;
         end;

         Cursor := Line_End + 2;
      end loop Headers_Loop;

      Req.Header_Section_Last := Cursor;
      Valid := True;
   end Parse_Request_Head;

   function Find_Header
     (Headers      : Header_Block;
      Headers_Last : Natural;
      Name         : String) return Natural
   is
      use Ada.Characters.Handling;
      Want : String (1 .. Name'Length);
   begin
      for I in 1 .. Name'Length loop
         Want (I) := To_Lower (Name (Name'First + I - 1));
      end loop;
      for I in 1 .. Headers_Last loop
         if Headers (I).Name_Last = Name'Length then
            declare
               Have : String (1 .. Name'Length);
            begin
               for J in 1 .. Name'Length loop
                  Have (J) := To_Lower (Headers (I).Name (J));
               end loop;
               if Have = Want then return I; end if;
            end;
         end if;
      end loop;
      return 0;
   end Find_Header;

   procedure Append_String
     (Buf  : in out Octet_Array;
      Cur  : in out Octet_Offset;
      Text : String);
   procedure Append_String
     (Buf  : in out Octet_Array;
      Cur  : in out Octet_Offset;
      Text : String) is
   begin
      for I in Text'Range loop
         Cur := Cur + 1;
         Buf (Cur) := Octet (Character'Pos (Text (I)));
      end loop;
   end Append_String;

   procedure Encode_Response
     (Out_Buf      : in out Octet_Array;
      Out_Last     : out Octet_Offset;
      Status       : Natural;
      Reason       : String;
      Headers      : Header_Block;
      Headers_Last : Natural;
      Body_Bytes   : Octet_Array)
   is
      Cur : Octet_Offset := Out_Buf'First - 1;
      Status_Img : constant String := Natural'Image (Status);
      --  Strip leading space from 'Image
      Status_Str : constant String :=
        Status_Img (Status_Img'First + 1 .. Status_Img'Last);
      Body_Len_Img : constant String :=
        Natural'Image (Body_Bytes'Length);
      Body_Len_Str : constant String :=
        Body_Len_Img (Body_Len_Img'First + 1 .. Body_Len_Img'Last);
   begin
      Append_String (Out_Buf, Cur, "HTTP/1.1 ");
      Append_String (Out_Buf, Cur, Status_Str);
      Append_String (Out_Buf, Cur, " ");
      Append_String (Out_Buf, Cur, Reason);
      Append_String (Out_Buf, Cur, String'(Character'Val (13) &
                                            Character'Val (10)));

      for I in 1 .. Headers_Last loop
         Append_String (Out_Buf, Cur,
                        Headers (I).Name (1 .. Headers (I).Name_Last));
         Append_String (Out_Buf, Cur, ": ");
         Append_String (Out_Buf, Cur,
                        Headers (I).Value (1 .. Headers (I).Value_Last));
         Append_String (Out_Buf, Cur, String'(Character'Val (13) &
                                               Character'Val (10)));
      end loop;

      --  Implicit Content-Length + Connection: close (the v0.3
      --  server always closes after one response).
      Append_String (Out_Buf, Cur, "Content-Length: ");
      Append_String (Out_Buf, Cur, Body_Len_Str);
      Append_String (Out_Buf, Cur, String'(Character'Val (13) &
                                            Character'Val (10)));
      Append_String (Out_Buf, Cur, "Connection: close");
      Append_String (Out_Buf, Cur, String'(Character'Val (13) &
                                            Character'Val (10)));
      Append_String (Out_Buf, Cur, String'(Character'Val (13) &
                                            Character'Val (10)));

      for I in Body_Bytes'Range loop
         Cur := Cur + 1;
         Out_Buf (Cur) := Body_Bytes (I);
      end loop;

      Out_Last := Cur;
   end Encode_Response;

   function Make_Header (Name : String; Value : String) return Header is
      H : Header;
   begin
      if Name'Length > Max_Header_Name_Len
        or Value'Length > Max_Header_Value_Len
      then
         raise Constraint_Error with "header too long";
      end if;
      for I in 1 .. Name'Length loop
         H.Name (I) := Name (Name'First + I - 1);
      end loop;
      H.Name_Last := Name'Length;
      for I in 1 .. Value'Length loop
         H.Value (I) := Value (Value'First + I - 1);
      end loop;
      H.Value_Last := Value'Length;
      return H;
   end Make_Header;

end Http1_Core.Wire;
