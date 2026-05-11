with Tls_Interop_Peers; use Tls_Interop_Peers;

package Tls_Interop_Bench is

   type Peer_Array is array (Positive range <>) of Peer_Kind;
   type Feature_Array is array (Positive range <>) of Feature_Kind;

   procedure Run_Handshake_Bench
     (Peers       : Peer_Array;
      Features    : Feature_Array;
      Runs        : Positive;
      Log_Dir     : String;
      EC_Dir      : String;
      Psk_Hex     : String;
      Psk_Id      : String);

   procedure Run_Peer_Vs_Peer_Bench
     (Peers   : Peer_Array;
      Runs    : Positive;
      EC_Dir  : String);

   procedure Run_Throughput_Bench
     (Peers       : Peer_Array;
      Features    : Feature_Array;
      Runs        : Positive;
      Bytes       : Natural;
      Log_Dir     : String;
      EC_Dir      : String;
      Psk_Hex     : String;
      Psk_Id      : String);

end Tls_Interop_Bench;
