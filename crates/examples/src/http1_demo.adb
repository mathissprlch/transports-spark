--  http1_demo — minimal HTTP/1.1 server.
--  Routes:
--    GET /        → "Hello from Ada HTTP/1.1!"
--    GET /echo    → echoes query string after "?"
--    POST /upper  → uppercases the request body
--  All other paths → 404.
--  One request per connection (Connection: close), v0.3 scope.
--
--  Run:  ./bin/http1_demo [port]   (default 8080)
--  Test: curl -sv http://localhost:8080/
--        curl -sv http://localhost:8080/echo?hello%20world
--        curl -sv -X POST -d 'mixed Case' http://localhost:8080/upper

with Ada.Text_IO;
with Ada.Command_Line;
with Ada.Characters.Handling;

with Http1_Core.Server;
with Http1_Core.Wire;

procedure Http1_Demo is
   use Ada.Text_IO;
   use type Http1_Core.Wire.Octet_Offset;

   procedure Handle_Request
     (Request               : Http1_Core.Wire.Request;
      Request_Body          : Http1_Core.Wire.Octet_Array;
      Response_Status       : out Natural;
      Response_Reason       : in out String;
      Reason_Last           : out Natural;
      Response_Headers      : in out Http1_Core.Wire.Header_Block;
      Response_Headers_Last : out Natural;
      Response_Body         : in out Http1_Core.Wire.Octet_Array;
      Response_Body_Last    : out Http1_Core.Wire.Octet_Offset);

   procedure Handle_Request
     (Request               : Http1_Core.Wire.Request;
      Request_Body          : Http1_Core.Wire.Octet_Array;
      Response_Status       : out Natural;
      Response_Reason       : in out String;
      Reason_Last           : out Natural;
      Response_Headers      : in out Http1_Core.Wire.Header_Block;
      Response_Headers_Last : out Natural;
      Response_Body         : in out Http1_Core.Wire.Octet_Array;
      Response_Body_Last    : out Http1_Core.Wire.Octet_Offset)
   is
      Method : constant String :=
        Request.Method (1 .. Request.Method_Last);
      Uri    : constant String :=
        Request.Uri (1 .. Request.Uri_Last);

      procedure Set_Body (Text : String);
      procedure Set_Body (Text : String) is
      begin
         for I in Text'Range loop
            Response_Body
              (Response_Body'First + Http1_Core.Wire.Octet_Offset
                 (I - Text'First)) :=
              Http1_Core.Wire.Octet (Character'Pos (Text (I)));
         end loop;
         Response_Body_Last :=
           Response_Body'First + Http1_Core.Wire.Octet_Offset
             (Text'Length) - 1;
      end Set_Body;

      Q_Pos : Natural := 0;
   begin
      Response_Status := 200;
      Response_Reason := (others => ' ');
      Response_Reason (1 .. 2) := "OK"; Reason_Last := 2;
      Response_Headers (Response_Headers'First) :=
        Http1_Core.Wire.Make_Header ("Content-Type", "text/plain");
      Response_Headers_Last := Response_Headers'First;
      Response_Body_Last := Response_Body'First - 1;

      Put_Line ("  ← " & Method & " " & Uri);

      if Method = "GET" and then Uri = "/" then
         Set_Body ("Hello from Ada HTTP/1.1!" & ASCII.LF);

      elsif Method = "GET"
        and then Request.Uri_Last >= 5
        and then Uri (Uri'First .. Uri'First + 4) = "/echo"
      then
         for I in Uri'Range loop
            if Uri (I) = '?' then Q_Pos := I; exit; end if;
         end loop;
         if Q_Pos = 0 or Q_Pos = Uri'Last then
            Set_Body ("(no query)" & ASCII.LF);
         else
            Set_Body
              ("echo: " & Uri (Q_Pos + 1 .. Uri'Last) & ASCII.LF);
         end if;

      elsif Method = "POST" and then Uri = "/upper" then
         declare
            use Ada.Characters.Handling;
            Out_Pos : Http1_Core.Wire.Octet_Offset := Response_Body'First - 1;
         begin
            for I in Request_Body'Range loop
               Out_Pos := Out_Pos + 1;
               Response_Body (Out_Pos) :=
                 Http1_Core.Wire.Octet
                   (Character'Pos
                      (To_Upper
                         (Character'Val
                            (Natural (Request_Body (I))))));
            end loop;
            Response_Body_Last := Out_Pos;
         end;

      else
         Response_Status := 404;
         Response_Reason (1 .. 9) := "Not Found";
         Reason_Last := 9;
         Set_Body ("not found: " & Method & " " & Uri & ASCII.LF);
      end if;
   end Handle_Request;

   procedure Run is new Http1_Core.Server.Accept_And_Serve
     (Handle_Request => Handle_Request);

   L : Http1_Core.Server.Listener;
   Port : Natural := 8080;
begin
   if Ada.Command_Line.Argument_Count >= 1 then
      Port := Natural'Value (Ada.Command_Line.Argument (1));
   end if;
   Http1_Core.Server.Listen (L, "0.0.0.0", Port);
   Put_Line ("http1_demo: listening on 0.0.0.0:" & Port'Image);
   loop
      begin
         Run (L);
      exception
         when others =>
            Put_Line ("http1_demo: connection error, retrying");
      end;
   end loop;
end Http1_Demo;
