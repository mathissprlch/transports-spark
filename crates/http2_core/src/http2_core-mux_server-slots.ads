--  Http2_Core.Mux_Server.Slots — slot-pool and connection-prologue
--  helpers. Private child of Http2_Core.Mux_Server.

with Http2_Core.Transport;
with Http2_Core.Wire;

private package Http2_Core.Mux_Server.Slots is

   --  §3.4: read 24 byte preface from client, validate.
   procedure Receive_Preface (Chan : Transport.Channel);

   --  Read one HTTP/2 frame from the channel into L.Buf. On
   --  Success, Header is the decoded frame header and Last is the
   --  index of the last payload byte in L.Buf.
   procedure Read_Frame
     (L       : in out Listener;
      Chan    : Transport.Channel;
      Header  : out Wire.Frame_Header;
      Last    : out RFLX.RFLX_Types.Index;
      Success : out Boolean);

   --  Find an in-use slot whose Stream_Id matches. 0 = not found.
   function Find_Slot
     (L         : Listener;
      Stream_Id : Bit_Len) return Natural;

   --  Reserve a free slot for a new stream. Initializes the
   --  per-slot FSM. 0 = pool exhausted.
   function Allocate_Slot
     (L         : in out Listener;
      Stream_Id : Bit_Len) return Natural;

   --  Finalize the FSM and return the slot to Free.
   procedure Release_Slot
     (L : in out Listener;
      I : Positive);

   procedure Allocate_FSM_Buffers (L : in out Listener);
   procedure Release_FSM_Buffers (L : in out Listener);

end Http2_Core.Mux_Server.Slots;
