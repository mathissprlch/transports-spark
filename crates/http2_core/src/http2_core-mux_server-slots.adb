with Ada.Unchecked_Deallocation;

with RFLX.RFLX_Builtin_Types;
with RFLX.Stream.Open.FSM;

package body Http2_Core.Mux_Server.Slots is

   use type RFLX.RFLX_Types.Index;
   use type RFLX.RFLX_Types.Byte;
   use type RFLX.RFLX_Types.Bytes_Ptr;
   use type RFLX.RFLX_Builtin_Types.Bit_Length;

   subtype U8 is RFLX.RFLX_Types.Byte;

   FSM_Buffer_Size : constant := 16384;

   procedure Free is new Ada.Unchecked_Deallocation
     (RFLX.RFLX_Types.Bytes, RFLX.RFLX_Types.Bytes_Ptr);

   procedure Receive_Preface (Chan : Transport.Channel) is
      Pref_Bytes : RFLX.RFLX_Types.Bytes
        (RFLX.RFLX_Types.Index'First ..
           RFLX.RFLX_Types.Index'First +
           RFLX.RFLX_Types.Index (Wire.Preface'Length) - 1);
      Pref_OK : Boolean;
   begin
      Transport.Receive_Full (Chan, Pref_Bytes, Pref_OK);
      if not Pref_OK then
         raise Mux_Server_Error with "EOF before preface";
      end if;
      for I in Pref_Bytes'Range loop
         if Pref_Bytes (I) /=
           U8 (Character'Pos
                 (Wire.Preface
                    (Wire.Preface'First +
                       Integer (I - Pref_Bytes'First))))
         then
            raise Mux_Server_Error with "bad preface";
         end if;
      end loop;
   end Receive_Preface;

   procedure Read_Frame
     (L       : in out Listener;
      Chan    : Transport.Channel;
      Header  : out Wire.Frame_Header;
      Last    : out RFLX.RFLX_Types.Index;
      Success : out Boolean)
   is
      Hdr_Bytes : RFLX.RFLX_Types.Bytes
        (L.Buf'First .. L.Buf'First + 8);
      Hdr_OK : Boolean;
   begin
      Header  := (others => <>);
      Last    := L.Buf'First;
      Success := False;

      Transport.Receive_Full (Chan, Hdr_Bytes, Hdr_OK);
      if not Hdr_OK then
         return;
      end if;
      L.Buf.all (Hdr_Bytes'Range) := Hdr_Bytes;

      declare
         Hdr_Valid : Boolean;
      begin
         Wire.Decode_Frame_Header
           (Buffer => Hdr_Bytes, Header => Header, Valid => Hdr_Valid);
         if not Hdr_Valid then
            return;
         end if;
      end;

      if Header.Length = 0 then
         Last    := Hdr_Bytes'Last;
         Success := True;
         return;
      end if;

      declare
         Body_First : constant RFLX.RFLX_Types.Index :=
           Hdr_Bytes'Last + 1;
         Body_Last  : constant RFLX.RFLX_Types.Index :=
           Body_First + RFLX.RFLX_Types.Index (Header.Length) - 1;
         Body_Slice : RFLX.RFLX_Types.Bytes (Body_First .. Body_Last);
         Body_OK    : Boolean;
      begin
         Transport.Receive_Full (Chan, Body_Slice, Body_OK);
         if not Body_OK then
            return;
         end if;
         L.Buf.all (Body_Slice'Range) := Body_Slice;
         Last    := Body_Slice'Last;
         Success := True;
      end;
   end Read_Frame;

   function Find_Slot
     (L         : Listener;
      Stream_Id : Bit_Len) return Natural
   is
   begin
      for I in L.Slots'Range loop
         if L.Slots (I).Phase /= Free
           and then L.Slots (I).Stream_Id = Stream_Id
         then
            return I;
         end if;
      end loop;
      return 0;
   end Find_Slot;

   function Allocate_Slot
     (L         : in out Listener;
      Stream_Id : Bit_Len) return Natural
   is
   begin
      for I in L.Slots'Range loop
         if L.Slots (I).Phase = Free then
            L.Slots (I).Phase := Awaiting_Body;
            L.Slots (I).Stream_Id := Stream_Id;
            L.Slots (I).Headers_Last :=
              L.Headers (I)'First - 1;
            L.Slots (I).Body_Cursor :=
              Integer (L.Bodies (I)'First) - 1;
            L.Slots (I).Slot_Trailers_Last :=
              L.Slot_Trailers (I)'First - 1;
            L.Slots (I).End_Of_Request := False;
            --  Inherit the peer's most recent
            --  SETTINGS_INITIAL_WINDOW_SIZE as our send-side
            --  per-stream initial window.
            L.Slots (I).Stream_Send_Window :=
              L.Initial_Stream_Window;
            L.Slots (I).In_Continuation := False;
            L.Slots (I).Cont_End_Stream := False;
            L.Slots (I).Cont_Last := 0;
            RFLX.Stream.Open.FSM.Initialize
              (L.Ctxs (I),
               L.Slots (I).Inbound_Buf,
               L.Slots (I).Outgoing_Buf);
            return I;
         end if;
      end loop;
      return 0;
   end Allocate_Slot;

   procedure Release_Slot
     (L : in out Listener;
      I : Positive)
   is
   begin
      if RFLX.Stream.Open.FSM.Initialized (L.Ctxs (I)) then
         RFLX.Stream.Open.FSM.Finalize
           (L.Ctxs (I),
            L.Slots (I).Inbound_Buf,
            L.Slots (I).Outgoing_Buf);
      end if;
      L.Slots (I).Phase := Free;
      L.Slots (I).Stream_Id := 0;
   end Release_Slot;

   procedure Allocate_FSM_Buffers (L : in out Listener) is
   begin
      for I in L.Slots'Range loop
         L.Slots (I).Inbound_Buf :=
           new RFLX.RFLX_Types.Bytes'(1 .. FSM_Buffer_Size => 0);
         L.Slots (I).Outgoing_Buf :=
           new RFLX.RFLX_Types.Bytes'(1 .. FSM_Buffer_Size => 0);
         L.Slots (I).Cont_Buf :=
           new RFLX.RFLX_Types.Bytes'(1 .. FSM_Buffer_Size => 0);
      end loop;
   end Allocate_FSM_Buffers;

   procedure Release_FSM_Buffers (L : in out Listener) is
   begin
      for I in L.Slots'Range loop
         if L.Slots (I).Inbound_Buf /= null then
            Free (L.Slots (I).Inbound_Buf);
         end if;
         if L.Slots (I).Outgoing_Buf /= null then
            Free (L.Slots (I).Outgoing_Buf);
         end if;
         if L.Slots (I).Cont_Buf /= null then
            Free (L.Slots (I).Cont_Buf);
         end if;
      end loop;
   end Release_FSM_Buffers;

end Http2_Core.Mux_Server.Slots;
