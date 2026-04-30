--  Mqtt_Core.Transport — bare-metal stub.
--
--  Same API surface as the TCP variant in `../transport_tcp/`,
--  but with no GNAT.Sockets dependency so the entire mqtt_core
--  graph can build for a Cortex-M / Cortex-R target without
--  pulling in hosted-OS networking.
--
--  Every operation currently raises `Connect_Error` so a caller
--  trying to actually communicate over this Transport gets a
--  clear runtime failure rather than silent corruption. Real
--  bare-metal Transport implementations (UART loopback for
--  smoke tests, LWIP for IP-over-Ethernet on Zynq, MQTT-SN over
--  serial for Cortex-M IoT, etc.) replace this body without
--  touching the spec or any client code.
--
--  Build selection: `mqtt_core.gpr` has a scenario variable
--  TRANSPORT={tcp|bare} that picks which subdirectory of
--  `src/` is compiled. Default is `tcp`; bare-metal builds set
--  TRANSPORT=bare.
--
--  This stub exists to PROVE the API surface is implementation-
--  agnostic. Once it builds and links cleanly without any
--  hosted-OS dependency, the next-layer crates (mqtt_core proper,
--  examples, http2_core, grpc_core) are unblocked for bare-metal
--  cross-compilation.

with RFLX.RFLX_Types;

package Mqtt_Core.Transport is

   type Channel is limited private;

   procedure Connect
     (Chan : in out Channel;
      Host : String;
      Port : Natural);

   function Is_Open (Chan : Channel) return Boolean;

   procedure Send
     (Chan : Channel;
      Data : RFLX.RFLX_Types.Bytes)
   with Pre => Is_Open (Chan);

   procedure Receive
     (Chan    : Channel;
      Buffer  : out RFLX.RFLX_Types.Bytes;
      Last    : out RFLX.RFLX_Types.Index;
      Success : out Boolean)
   with Pre => Is_Open (Chan);

   procedure Receive_Full
     (Chan    : Channel;
      Buffer  : out RFLX.RFLX_Types.Bytes;
      Success : out Boolean)
   with Pre => Is_Open (Chan);

   procedure Close (Chan : in out Channel)
   with
     Pre  => Is_Open (Chan),
     Post => not Is_Open (Chan);

   Connect_Error : exception;
   Send_Error    : exception;

private

   --  Placeholder fields — the real bare-metal Transport
   --  implementations will replace this body and may need
   --  different storage. Keeping the spec minimal so a UART
   --  driver, LWIP socket, or memory-loopback can substitute.
   type Channel is limited record
      Open : Boolean := False;
   end record;

end Mqtt_Core.Transport;
