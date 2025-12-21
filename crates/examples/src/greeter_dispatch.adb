with Greeter_Impl;
with Helloworld.Greeter;
with Helloworld.Hello_Reply;
with Helloworld.Hello_Request;
with Protobuf.IO;

package body Greeter_Dispatch is

   Max_Message : constant := 64 * 1024;

   --  Library-level service singleton — Method_Handler'Access requires
   --  the handler subprogram to live here too.
   Service : aliased Greeter_Impl.Service;

   ----------------------
   -- Say_Hello_Handler --
   ----------------------

   procedure Say_Hello_Handler
     (Stream : not null access GRPC.Transport.Stream'Class;
      Call   : in out GRPC.Call.Instance)
   is
      pragma Unreferenced (Call);
      Inbound  : Protobuf.IO.Octet_Array (1 .. Max_Message);
      Last     : Protobuf.IO.Octet_Count;
      Got      : Boolean;
      Request  : Helloworld.Hello_Request.T;
      Response : Helloworld.Hello_Reply.T;
      Outbound : Protobuf.IO.Octet_Array (1 .. Max_Message);
      Cursor   : Protobuf.IO.Write_Cursor;
   begin
      Stream.Receive_Message (Inbound, Last, Got);
      if not Got then
         return;
      end if;

      Helloworld.Hello_Request.Decode (Inbound (1 .. Last), Request);
      Service.Say_Hello (Request, Response);
      Helloworld.Hello_Reply.Encode (Response, Outbound, Cursor);
      Stream.Send_Message
        (Outbound (1 .. Cursor.Position), End_Stream => True);
   end Say_Hello_Handler;

   --------------
   -- Register --
   --------------

   procedure Register (Server : in out GRPC.Server.Instance) is
   begin
      GRPC.Server.Register_Method
        (Server,
         Helloworld.Greeter.Path_Say_Hello,
         Say_Hello_Handler'Access);
   end Register;

end Greeter_Dispatch;
