--  Http1_Core.Transport — TCP socket adapter, byte-oriented.
--  Same shape as Http2_Core.Transport but uses Ada.Streams.Stream_Element
--  directly (no RFLX dependency in http1_core).

with Ada.Streams;
private with GNAT.Sockets;

package Http1_Core.Transport is

   subtype Octet is Ada.Streams.Stream_Element;
   subtype Octet_Array is Ada.Streams.Stream_Element_Array;
   subtype Octet_Offset is Ada.Streams.Stream_Element_Offset;

   type Channel is limited private;

   function Is_Open (Chan : Channel) return Boolean;

   procedure Send
     (Chan : Channel;
      Data : Octet_Array)
   with Pre => Is_Open (Chan);

   --  Read up to Buffer'Length bytes; Last is the index of the last
   --  byte filled (Buffer'First - 1 if zero). Sets Success := False on
   --  EOF or socket error.
   procedure Receive
     (Chan    : Channel;
      Buffer  : out Octet_Array;
      Last    : out Octet_Offset;
      Success : out Boolean)
   with Pre => Is_Open (Chan);

   procedure Close (Chan : in out Channel)
   with
     Pre  => Is_Open (Chan),
     Post => not Is_Open (Chan);

   type Listener is limited private;

   procedure Listen
     (L    : in out Listener;
      Host : String;
      Port : Natural);

   function Is_Listening (L : Listener) return Boolean;

   procedure Accept_One
     (L    : in out Listener;
      Chan : in out Channel)
   with
     Pre  => Is_Listening (L),
     Post => Is_Open (Chan);

   procedure Stop (L : in out Listener)
   with
     Pre  => Is_Listening (L),
     Post => not Is_Listening (L);

   Connect_Error : exception;

private

   type Channel is limited record
      Socket : GNAT.Sockets.Socket_Type;
      Open   : Boolean := False;
   end record;

   type Listener is limited record
      Socket    : GNAT.Sockets.Socket_Type;
      Listening : Boolean := False;
   end record;

end Http1_Core.Transport;
