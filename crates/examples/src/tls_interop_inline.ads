with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
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

end Tls_Interop_Inline;
