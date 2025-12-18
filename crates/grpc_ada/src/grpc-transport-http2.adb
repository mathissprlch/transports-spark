--  GRPC.Transport.HTTP2 body — AWS bridge for unary RPCs.
--
--  v0.1 wires the patched AWS HTTP/2 server to GRPC.Server's dispatcher.
--  Each AWS request runs through Service_Cb: we materialize a
--  Server_Stream over the request body, look up the registered handler
--  by :path, and let the handler write its response into the stream's
--  buffers via the GRPC.Transport.Stream interface. After the handler
--  returns we pack the buffers into an AWS.Response.Data and attach
--  the gRPC trailers using the Add_Trailer API from patch 1.

with Ada.Characters.Handling;
with Ada.Streams; use Ada.Streams;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Unchecked_Deallocation;

with AWS.Config;
with AWS.Config.Set;
with AWS.Default;
with AWS.Headers;
with AWS.Messages;
with AWS.Response;
with AWS.Response.Set;
with AWS.Server;
with AWS.Status;

with GRPC.Call;
with GRPC.Framing;
with GRPC.Server;
with GRPC.Status;
with Interfaces;
use type GRPC.Server.Method_Handler;

package body GRPC.Transport.HTTP2 is

   procedure Free is new Ada.Unchecked_Deallocation
     (Object => Stream_Element_Array, Name => Octet_Array_Access);

   --  Single-server-per-process state. The AWS callback is a plain
   --  function pointer with no closure, so the dispatcher target is
   --  stashed here. Re-entering Run while a server is active is a
   --  programmer error — guarded by the Active check.
   Active     : access GRPC.Server.Instance := null;
   Web_Server : AWS.Server.HTTP;

   --  AWS callback. Translates one HTTP/2 request into one gRPC
   --  unary round-trip.
   function Service_Cb (Request : AWS.Status.Data) return AWS.Response.Data;

   --  Build a trailers-only error response: 200 OK, empty body, with
   --  grpc-status / grpc-message in the trailing HEADERS frame. Used
   --  when no handler is registered for :path or when the handler
   --  fails to write a response.
   function Trailers_Only
     (Code    : GRPC.Status.Code;
      Message : String) return AWS.Response.Data;

   --  Compose the gRPC trailers for a Response_Trailers map plus the
   --  final status, then attach them via the patched API. The handler
   --  may have already pushed grpc-status into Trailers; if not, we
   --  add OK by default.
   procedure Attach_Trailers
     (R : in out AWS.Response.Data;
      H : GRPC.Metadata.Headers);

   ---------
   -- Run --
   ---------

   procedure Run (S : in out GRPC.Server.Instance) is
      Cfg : AWS.Config.Object := AWS.Config.Default_Config;
   begin
      if Active /= null then
         raise Program_Error
           with "GRPC.Transport.HTTP2.Run: another server is already active";
      end if;

      AWS.Config.Set.Server_Name (Cfg, "grpc_ada");
      AWS.Config.Set.Server_Host (Cfg, To_String (S.Address));
      AWS.Config.Set.Server_Port (Cfg, S.Port);
      AWS.Config.Set.HTTP2_Activated (Cfg, True);
      AWS.Config.Set.Max_Connection (Cfg, AWS.Default.Max_Connection);

      Active := S'Unrestricted_Access;
      S.Listening := True;

      AWS.Server.Start
        (Web_Server => Web_Server,
         Callback   => Service_Cb'Access,
         Config     => Cfg);

      AWS.Server.Wait (AWS.Server.Forever);
   end Run;

   ----------
   -- Stop --
   ----------

   procedure Stop (S : in out GRPC.Server.Instance) is
   begin
      if Active = null then
         return;
      end if;
      AWS.Server.Shutdown (Web_Server);
      S.Listening := False;
      Active      := null;
   end Stop;

   --------------------
   -- Trailers_Only --
   --------------------

   function Trailers_Only
     (Code    : GRPC.Status.Code;
      Message : String) return AWS.Response.Data
   is
      Empty : constant Stream_Element_Array (1 .. 0) := (others => 0);
      R     : AWS.Response.Data :=
                AWS.Response.Build
                  (Content_Type => "application/grpc+proto",
                   Message_Body => Empty,
                   Status_Code  => AWS.Messages.S200);
   begin
      AWS.Response.Set.Add_Trailer
        (R, "grpc-status", GRPC.Status.To_String (Code));
      if Message'Length > 0 then
         AWS.Response.Set.Add_Trailer (R, "grpc-message", Message);
      end if;
      return R;
   end Trailers_Only;

   ----------------------
   -- Attach_Trailers --
   ----------------------

   procedure Attach_Trailers
     (R : in out AWS.Response.Data;
      H : GRPC.Metadata.Headers)
   is
      Have_Status : Boolean := False;
   begin
      for E of H loop
         declare
            Key : constant String := To_String (E.Key);
         begin
            AWS.Response.Set.Add_Trailer (R, Key, To_String (E.Value));
            if Ada.Characters.Handling.To_Lower (Key) = "grpc-status" then
               Have_Status := True;
            end if;
         end;
      end loop;

      if not Have_Status then
         AWS.Response.Set.Add_Trailer
           (R, "grpc-status", GRPC.Status.To_String (GRPC.Status.OK));
      end if;
   end Attach_Trailers;

   ----------------
   -- Service_Cb --
   ----------------

   function Service_Cb (Request : AWS.Status.Data) return AWS.Response.Data is
      Path    : constant String := AWS.Status.URI (Request);
      Body_In : constant Stream_Element_Array := AWS.Status.Binary_Data (Request);
      Handler : GRPC.Server.Method_Handler;
      Stream  : aliased Server_Stream;
      Call_Ctx : GRPC.Call.Instance;
   begin
      if Active = null then
         return Trailers_Only
           (GRPC.Status.Unavailable, "server not running");
      end if;

      Handler := GRPC.Server.Lookup (Active.all, Path);
      if Handler = null then
         return Trailers_Only
           (GRPC.Status.Unimplemented, "method not found: " & Path);
      end if;

      --  Wire request side of the stream.
      Stream.Path         := To_Unbounded_String (Path);
      Stream.Request_Body := new Stream_Element_Array'(Body_In);

      --  Carry inbound HTTP/2 headers into Request_Headers. AWS exposes
      --  these via Headers.List; we pass them through unchanged so the
      --  handler can read grpc-timeout, custom metadata, etc.
      declare
         List : constant AWS.Headers.List := AWS.Status.Header (Request);
      begin
         for I in 1 .. AWS.Headers.Count (List) loop
            declare
               El : constant AWS.Headers.Element := AWS.Headers.Get (List, I);
            begin
               GRPC.Metadata.Add_ASCII
                 (Stream.Request_Headers,
                  To_String (El.Name), To_String (El.Value));
            end;
         end loop;
      end;

      Call_Ctx.Side        := GRPC.Call.Server_Side;
      Call_Ctx.Method_Path := To_Unbounded_String (Path);
      Call_Ctx.Phase       := GRPC.Call.Active;

      --  Dispatch. Handler reads the request via Receive_Message and
      --  writes the response via Send_*; exceptions become INTERNAL.
      begin
         Handler (Stream'Access, Call_Ctx);
      exception
         when others =>
            Free (Stream.Request_Body);
            Free (Stream.Response_Body);
            return Trailers_Only
              (GRPC.Status.Internal, "handler raised");
      end;

      --  Pack outbound buffers into an AWS response. Slice down to the
      --  bytes the handler actually wrote — Response_Body is grown in
      --  doubling-mode, so its physical length may exceed Length.
      declare
         Body_Slice : constant Stream_Element_Array :=
           (if Stream.Response_Body = null
            then Stream_Element_Array'(1 .. 0 => 0)
            else Stream.Response_Body
                   (Stream.Response_Body'First
                    .. Stream.Response_Body'First + Stream.Response_Length - 1));
         R : AWS.Response.Data :=
               AWS.Response.Build
                 (Content_Type => "application/grpc+proto",
                  Message_Body => Body_Slice,
                  Status_Code  => AWS.Messages.S200);
      begin
         Attach_Trailers (R, Stream.Response_Trailers);
         Free (Stream.Request_Body);
         Free (Stream.Response_Body);
         return R;
      end;
   end Service_Cb;

   --------------------------
   -- Send_Initial_Headers --
   --------------------------

   overriding procedure Send_Initial_Headers
     (S          : in out Server_Stream;
      Headers    : GRPC.Metadata.Headers;
      End_Stream : Boolean)
   is
      pragma Unreferenced (End_Stream);
   begin
      S.Response_Headers := Headers;
      S.Headers_Sent     := True;
   end Send_Initial_Headers;

   ------------------
   -- Send_Message --
   ------------------

   overriding procedure Send_Message
     (S          : in out Server_Stream;
      Payload    : Protobuf.IO.Octet_Array;
      End_Stream : Boolean)
   is
      pragma Unreferenced (End_Stream);
      Required : constant Stream_Element_Count :=
        S.Response_Length
          + Stream_Element_Count (GRPC.Framing.Header_Size)
          + Payload'Length;
      Capacity : constant Stream_Element_Count :=
        (if S.Response_Body = null
         then 0
         else S.Response_Body'Length);
   begin
      --  Grow the buffer in doubling mode. Streaming RPCs will call
      --  Send_Message many times; unary calls it exactly once.
      if Required > Capacity then
         declare
            New_Cap : Stream_Element_Count := Stream_Element_Count'Max (Capacity * 2, 1024);
            Old     : Octet_Array_Access  := S.Response_Body;
         begin
            while New_Cap < Required loop
               New_Cap := New_Cap * 2;
            end loop;
            S.Response_Body := new Stream_Element_Array (1 .. New_Cap);
            if Old /= null then
               S.Response_Body (1 .. S.Response_Length) := Old (1 .. S.Response_Length);
               Free (Old);
            end if;
         end;
      end if;

      --  Write the 5-byte gRPC length prefix in place.
      declare
         Cursor : Protobuf.IO.Write_Cursor :=
           (Position => S.Response_Length);
      begin
         GRPC.Framing.Encode_Header
           (Buffer => S.Response_Body.all,
            Cursor => Cursor,
            Length => Interfaces.Unsigned_32 (Payload'Length),
            Flag   => 0);
         --  Append the payload bytes after the prefix.
         S.Response_Body
           (Cursor.Position + 1 .. Cursor.Position + Payload'Length) := Payload;
         S.Response_Length := Cursor.Position + Payload'Length;
      end;
   end Send_Message;

   --------------------
   -- Send_Trailers --
   --------------------

   overriding procedure Send_Trailers
     (S        : in out Server_Stream;
      Trailers : GRPC.Metadata.Headers)
   is
   begin
      S.Response_Trailers := Trailers;
      S.Trailers_Sent     := True;
   end Send_Trailers;

   -----------------------------
   -- Receive_Initial_Headers --
   -----------------------------

   overriding procedure Receive_Initial_Headers
     (S       : in out Server_Stream;
      Headers : out GRPC.Metadata.Headers;
      Got     : out Boolean)
   is
   begin
      Headers := S.Request_Headers;
      Got     := True;
   end Receive_Initial_Headers;

   ---------------------
   -- Receive_Message --
   ---------------------

   overriding procedure Receive_Message
     (S       : in out Server_Stream;
      Payload : out Protobuf.IO.Octet_Array;
      Last    : out Protobuf.IO.Octet_Count;
      Got     : out Boolean)
   is
   begin
      if S.Request_Consumed
        or else S.Request_Body = null
        or else S.Request_Body'Length < GRPC.Framing.Header_Size
      then
         Last := 0;
         Got  := False;
         return;
      end if;

      declare
         Cursor : Protobuf.IO.Read_Cursor;
         Length : Interfaces.Unsigned_32;
         Flag   : GRPC.Framing.Compression_Flag;
      begin
         GRPC.Framing.Decode_Header
           (Buffer => S.Request_Body.all,
            Cursor => Cursor,
            Length => Length,
            Flag   => Flag);

         if Stream_Element_Count (Length) > Payload'Length then
            --  Caller's buffer is too small; signal end-of-stream so the
            --  handler can react. Real fix is dynamic sizing — left as a
            --  bare-metal port point.
            Last := 0;
            Got  := False;
            return;
         end if;

         Payload (Payload'First .. Payload'First + Stream_Element_Offset (Length) - 1) :=
           S.Request_Body
             (S.Request_Body'First + Cursor.Position
              .. S.Request_Body'First + Cursor.Position
                 + Stream_Element_Offset (Length) - 1);
         Last := Stream_Element_Count (Length);
         Got  := True;
         S.Request_Consumed := True;
      end;
   end Receive_Message;

   ----------------------
   -- Receive_Trailers --
   ----------------------

   overriding procedure Receive_Trailers
     (S        : in out Server_Stream;
      Trailers : out GRPC.Metadata.Headers;
      Got      : out Boolean)
   is
      pragma Unreferenced (S);
   begin
      Trailers := GRPC.Metadata.Entry_Vectors.Empty_Vector;
      Got      := False;
   end Receive_Trailers;

end GRPC.Transport.HTTP2;
