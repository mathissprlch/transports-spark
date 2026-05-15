with GNATCOLL.JSON;
with Tls_Interop_Peers; use Tls_Interop_Peers;

package Tls_Interop_Bench is

   type Peer_Array is array (Positive range <>) of Peer_Kind;
   type Feature_Array is array (Positive range <>) of Feature_Kind;

   --  All bench procedures append per-row JSON objects to Json_Out
   --  and emit one terse progress line per row to stdout.  The full
   --  numeric table is the JSON artifact, not the terminal.  Caller
   --  writes the assembled array to a file (see docs/conventions.md §15).

   procedure Run_Handshake_Bench
     (Peers       : Peer_Array;
      Features    : Feature_Array;
      Runs        : Positive;
      Log_Dir     : String;
      EC_Dir      : String;
      Psk_Hex     : String;
      Psk_Id      : String;
      Json_Out    : in out GNATCOLL.JSON.JSON_Array);

   procedure Run_Peer_Vs_Peer_Bench
     (Peers    : Peer_Array;
      Runs     : Positive;
      EC_Dir   : String;
      Json_Out : in out GNATCOLL.JSON.JSON_Array);

   procedure Run_Throughput_Bench
     (Peers       : Peer_Array;
      Features    : Feature_Array;
      Runs        : Positive;
      Bytes       : Natural;
      Log_Dir     : String;
      EC_Dir      : String;
      Psk_Hex     : String;
      Psk_Id      : String;
      Json_Out    : in out GNATCOLL.JSON.JSON_Array);

end Tls_Interop_Bench;
