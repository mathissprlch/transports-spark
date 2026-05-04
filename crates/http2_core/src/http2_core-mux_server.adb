--  Body shell for Http2_Core.Mux_Server.
--
--  Lifecycle plumbing only. Each Accept_And_Serve_Multi_* variant
--  lives in its own subunit:
--
--    http2_core-mux_server-accept_and_serve_multi.adb
--    http2_core-mux_server-accept_and_serve_multi_server_stream.adb
--    http2_core-mux_server-accept_and_serve_multi_client_stream.adb
--    http2_core-mux_server-accept_and_serve_multi_bidi_stream.adb
--
--  All four instantiate Http2_Core.Mux_Server.Driver with their
--  variant-specific hooks.

with Http2_Core.Mux_Server.Slots;

package body Http2_Core.Mux_Server is

   procedure Listen
     (L    : in out Listener;
      Host : String;
      Port : Natural)
   is
   begin
      Transport.Listen (L.Trans, Host, Port);
      Slots.Allocate_FSM_Buffers (L);
   end Listen;

   procedure Attach_Buffer
     (L   : in out Listener;
      Buf : in out RFLX.RFLX_Types.Bytes_Ptr)
   is
   begin
      L.Buf := Buf;
      Buf := null;
   end Attach_Buffer;

   procedure Detach_Buffer
     (L   : in out Listener;
      Buf : out RFLX.RFLX_Types.Bytes_Ptr)
   is
   begin
      Buf := L.Buf;
      L.Buf := null;
   end Detach_Buffer;

   procedure Stop (L : in out Listener) is
   begin
      if Transport.Is_Listening (L.Trans) then
         Transport.Stop (L.Trans);
      end if;
      Slots.Release_FSM_Buffers (L);
   end Stop;

   procedure Accept_And_Serve_Multi (L : in out Listener) is separate;

   procedure Accept_And_Serve_Multi_Server_Stream
     (L : in out Listener) is separate;

   procedure Accept_And_Serve_Multi_Client_Stream
     (L : in out Listener) is separate;

   procedure Accept_And_Serve_Multi_Bidi_Stream
     (L : in out Listener) is separate;

end Http2_Core.Mux_Server;
