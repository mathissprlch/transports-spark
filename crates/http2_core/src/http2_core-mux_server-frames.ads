--  Http2_Core.Mux_Server.Frames — frame-emission helpers.
--
--  Private child of Http2_Core.Mux_Server. All variants of the
--  mux server use these to produce HEADERS / DATA / SETTINGS /
--  PING / GOAWAY / RST_STREAM frames into the connection-scope
--  buffer and write them on the channel. Centralizing here means
--  the per-variant bodies don't repeat HPACK-encode + frame-wrap
--  + Transport.Send.

with Http2_Core.Hpack;
with Http2_Core.Transport;

private package Http2_Core.Mux_Server.Frames is

   procedure Send_Settings_Initial
     (L    : in out Listener;
      Chan : Transport.Channel);

   procedure Send_Settings_Ack
     (L    : in out Listener;
      Chan : Transport.Channel);

   procedure Send_Ping_Ack
     (L    : in out Listener;
      Chan : Transport.Channel;
      Echo : RFLX.RFLX_Types.Bytes);

   procedure Send_Goaway
     (L              : in out Listener;
      Chan           : Transport.Channel;
      Last_Stream_Id : Bit_Len);

   procedure Send_Rst_Stream
     (L          : in out Listener;
      Chan       : Transport.Channel;
      Stream_Id  : Bit_Len;
      Error_Code : Bit_Len);

   --  RFC 9113 §6.9 — open the connection-level (Stream_Id=0) or
   --  per-stream flow-control window by `Increment` bytes. Without
   --  these, the peer stops sending after the default 65 535-byte
   --  window is exhausted (~64 KB of inbound data).
   procedure Send_Window_Update
     (L         : in out Listener;
      Chan      : Transport.Channel;
      Stream_Id : Bit_Len;
      Increment : Bit_Len);

   procedure Send_Headers_Frame
     (L          : in out Listener;
      Chan       : Transport.Channel;
      Stream_Id  : Bit_Len;
      Headers_In : Hpack.Header_Block;
      End_Stream : Boolean);

   procedure Send_Data_Frame
     (L          : in out Listener;
      Chan       : Transport.Channel;
      Stream_Id  : Bit_Len;
      Payload    : RFLX.RFLX_Types.Bytes;
      End_Stream : Boolean);

   --  Strip the 5-byte gRPC length prefix from a DATA payload.
   --  Returns an empty slice if the input is too short or the
   --  declared length doesn't fit.
   function Strip_Grpc_Frame
     (View : RFLX.RFLX_Types.Bytes) return RFLX.RFLX_Types.Bytes;

end Http2_Core.Mux_Server.Frames;
