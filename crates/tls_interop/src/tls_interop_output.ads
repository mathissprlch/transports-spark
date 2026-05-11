with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with GNATCOLL.JSON;
with Tls_Interop_Peers;     use Tls_Interop_Peers;

package Tls_Interop_Output is

   function Image_Time (D : Duration) return String;

   procedure Md_Peer_Header (Peer : Peer_Kind);

   procedure Md_Feature_Row
     (Feature_Lbl : String;
      C2S_Result, S2C_Result : Cell_Result;
      C2S_Time,   S2C_Time   : Duration;
      Note : String);

   Json_Rows : GNATCOLL.JSON.JSON_Array := GNATCOLL.JSON.Empty_Array;

   procedure Json_Peer_Feature
     (Peer : Peer_Kind;
      Feat : Feature_Kind;
      C2S_Result, S2C_Result : Cell_Result;
      C2S_Time,   S2C_Time   : Duration;
      Note : String);

end Tls_Interop_Output;
