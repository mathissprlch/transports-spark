--  GRPC.Transport.HTTP2 body — stubs.
--
--  Each operation raises Program_Error pending the AWS link. The shape
--  is set so dropping in real bodies is a self-contained change: this
--  file only references AWS, the rest of the runtime never has to.

package body GRPC.Transport.HTTP2 is

   Pending : constant String := "GRPC.Transport.HTTP2: pending AWS integration";

   ---------
   -- Run --

   procedure Run (S : in out GRPC.Server.Instance) is
      pragma Unreferenced (S);
   begin
      raise Program_Error with Pending;
   end Run;

   ----------
   -- Stop --

   procedure Stop (S : in out GRPC.Server.Instance) is
      pragma Unreferenced (S);
   begin
      raise Program_Error with Pending;
   end Stop;

   --------------------------
   -- Send_Initial_Headers --

   overriding procedure Send_Initial_Headers
     (S          : in out Server_Stream;
      Headers    : GRPC.Metadata.Headers;
      End_Stream : Boolean)
   is
      pragma Unreferenced (S, Headers, End_Stream);
   begin
      raise Program_Error with Pending;
   end Send_Initial_Headers;

   ------------------
   -- Send_Message --

   overriding procedure Send_Message
     (S          : in out Server_Stream;
      Payload    : Protobuf.IO.Octet_Array;
      End_Stream : Boolean)
   is
      pragma Unreferenced (S, Payload, End_Stream);
   begin
      raise Program_Error with Pending;
   end Send_Message;

   --------------------
   -- Send_Trailers --

   overriding procedure Send_Trailers
     (S        : in out Server_Stream;
      Trailers : GRPC.Metadata.Headers)
   is
      pragma Unreferenced (S, Trailers);
   begin
      raise Program_Error with Pending;
   end Send_Trailers;

   -----------------------------
   -- Receive_Initial_Headers --

   overriding procedure Receive_Initial_Headers
     (S       : in out Server_Stream;
      Headers : out GRPC.Metadata.Headers;
      Got     : out Boolean)
   is
      pragma Unreferenced (S, Headers, Got);
   begin
      raise Program_Error with Pending;
   end Receive_Initial_Headers;

   ---------------------
   -- Receive_Message --

   overriding procedure Receive_Message
     (S       : in out Server_Stream;
      Payload : out Protobuf.IO.Octet_Array;
      Last    : out Protobuf.IO.Octet_Count;
      Got     : out Boolean)
   is
      pragma Unreferenced (S, Payload, Last, Got);
   begin
      raise Program_Error with Pending;
   end Receive_Message;

   ----------------------
   -- Receive_Trailers --

   overriding procedure Receive_Trailers
     (S        : in out Server_Stream;
      Trailers : out GRPC.Metadata.Headers;
      Got      : out Boolean)
   is
      pragma Unreferenced (S, Trailers, Got);
   begin
      raise Program_Error with Pending;
   end Receive_Trailers;

end GRPC.Transport.HTTP2;
