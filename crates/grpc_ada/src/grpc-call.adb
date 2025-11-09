with GRPC.Deadline;

package body GRPC.Call is

   procedure Initialize_Client_Request
     (C         : in out Instance;
      Path      : String;
      Authority : String;
      Scheme    : String := "http";
      Deadline  : Duration := 0.0)
   is
   begin
      C.Side := Client_Side;
      C.Method_Path := To_Unbounded_String (Path);
      C.Deadline_Seconds := Deadline;
      GRPC.Metadata.Add_ASCII (C.Request_Metadata, ":method", "POST");
      GRPC.Metadata.Add_ASCII (C.Request_Metadata, ":scheme", Scheme);
      GRPC.Metadata.Add_ASCII (C.Request_Metadata, ":path",   Path);
      GRPC.Metadata.Add_ASCII (C.Request_Metadata, ":authority", Authority);
      GRPC.Metadata.Add_ASCII (C.Request_Metadata, "te", "trailers");
      GRPC.Metadata.Add_ASCII (C.Request_Metadata,
                               "content-type", "application/grpc+proto");
      if Deadline > 0.0 then
         GRPC.Metadata.Add_ASCII
           (C.Request_Metadata, "grpc-timeout",
            GRPC.Deadline.Format_Timeout (Deadline));
      end if;
      C.Phase := Initial;
   end Initialize_Client_Request;

end GRPC.Call;
