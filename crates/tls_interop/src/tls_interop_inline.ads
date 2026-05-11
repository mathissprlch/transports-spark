with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with GNAT.OS_Lib;
with Tls_Core.Tcp_Transport;
with Tls_Interop_Peers;     use Tls_Interop_Peers;

package Tls_Interop_Inline is

   type Inline_Result is (Pass, Fail);

   procedure Run_Handshake_C2S
     (Peer    : Peer_Kind;
      Mode    : Mode_Kind;
      Cipher  : Cipher_Kind;
      Port    : Natural;
      Result  : out Inline_Result;
      Elapsed : out Duration;
      Note    : out Unbounded_String);

   --  Opens a TCP listener on 127.0.0.1:Port for the s2c handshake.
   --  Callers MUST invoke this BEFORE spawning the peer client; if
   --  the listener isn't up by the time the peer's connect() runs,
   --  the peer exits with ECONNREFUSED and Run_Handshake_S2C blocks
   --  forever on Accept_One.
   procedure Open_S2C_Listener
     (Port : Natural;
      L    : out Tls_Core.Tcp_Transport.Listener;
      OK   : out Boolean);

   procedure Run_Handshake_S2C
     (L       : in out Tls_Core.Tcp_Transport.Listener;
      Peer    : Peer_Kind;
      Mode    : Mode_Kind;
      Cipher  : Cipher_Kind;
      Result  : out Inline_Result;
      Elapsed : out Duration;
      Note    : out Unbounded_String);

   procedure Run_Throughput_C2S
     (Peer    : Peer_Kind;
      Mode    : Mode_Kind;
      Cipher  : Cipher_Kind;
      Port    : Natural;
      Bytes   : Natural;
      Result  : out Inline_Result;
      Elapsed : out Duration;
      Note    : out Unbounded_String);

   procedure Run_Peer_Vs_Peer
     (Server_Bin  : String;
      Server_Args : GNAT.OS_Lib.Argument_List;
      Client_Bin  : String;
      Client_Args : GNAT.OS_Lib.Argument_List;
      Result      : out Inline_Result;
      Elapsed     : out Duration;
      Note        : out Unbounded_String);

end Tls_Interop_Inline;
