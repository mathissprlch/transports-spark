--  Tls_Core.Handshake_Driver — wire-level PSK_KE state machine.
--
--  Drives the four-message PSK_KE handshake (RFC 8446 §2.2 +
--  appendix on PSK-only mode) symbolically: each side starts
--  Idle, transitions through {Sent_CH, Recv_SH, Sent_Finished,
--  Recv_Finished, Done} as inbound Handshake records arrive
--  and outbound ones are produced. Once Done, traffic-secret
--  fields hold the four secrets from §7.1.
--
--  This is the orchestration layer over the v0.5 primitives:
--
--    Tls_Core.Records          -- parse/encode TLSPlaintext frames
--    Tls_Core.Transcript       -- running SHA-256 over Handshake bytes
--    Tls_Core.Handshake        -- PSK_KE key-schedule tree
--    Tls_Core.Finished         -- RFC §4.4.4 verify_data
--
--  No I/O. The driver works in terms of Octet_Array buffers; the
--  caller plugs in whatever transport ferries bytes across.
--
--  miTLS reference: src/tls/MiTLS.Handshake.fst transition log;
--  the F* `step` ghost there has the same call/return shape.

with Tls_Core.Handshake;
with Tls_Core.Transcript;

package Tls_Core.Handshake_Driver
with SPARK_Mode => Off
is

   type Role is (Client, Server);

   type State is
     (Idle,                 --  Nothing sent or received yet.
      Awaiting_Server_Hello,  --  Client sent CH, waiting for SH.
      Awaiting_Client_Hello,  --  Server is waiting for CH.
      Awaiting_Finished,    --  Hellos exchanged, awaiting peer Finished.
      Done,                 --  All four messages processed.
      Failed);              --  Verify failed or unexpected message.

   --  Driver context. Internally holds the role, current state,
   --  the transcript-hash accumulator, the PSK, and on success
   --  the four traffic secrets from RFC 8446 §7.1.
   type Driver is private;

   --  Initialize for a given role with a 32-byte PSK. The PSK is
   --  copied; caller can free its buffer.
   procedure Init
     (D    : out Driver;
      For_Role : Role;
      PSK  : Octet_Array)
   with Pre => PSK'Length = 32 and then PSK'Last < Integer'Last - 1024;

   --  Accept an inbound Handshake message body (no record-layer
   --  envelope; just the type+u24-length+body bytes). Advances
   --  state, optionally producing an outbound Handshake message
   --  body in Out_Buf. Sets Out_Last = 0 if no reply this step.
   --
   --  When state hits Done, traffic secrets are populated and
   --  Get_Secrets can be called.
   procedure Step
     (D         : in out Driver;
      In_Bytes  : Octet_Array;
      Out_Buf   : out Octet_Array;
      Out_Last  : out Natural)
   with Pre =>
       In_Bytes'Length in 0 .. 1024
       and then In_Bytes'Last < Integer'Last - 1024
       and then Out_Buf'Length >= 256
       and then Out_Buf'First = 1;

   --  Query state.
   function Current_State (D : Driver) return State;

   --  After Done: copy out the four traffic secrets.
   procedure Get_Secrets
     (D       : Driver;
      Out_Sec : out Tls_Core.Handshake.Traffic_Secrets)
   with Pre => Current_State (D) = Done;

private

   subtype PSK_Bytes is Octet_Array (1 .. 32);
   subtype Hello_Bytes is Octet_Array (1 .. 1024);

   type Driver is record
      My_Role          : Role := Client;
      Cur_State        : State := Idle;
      Hash_Ctx         : Tls_Core.Transcript.Accumulator;
      PSK              : PSK_Bytes := (others => 0);

      --  We retain the recorded ClientHello and ServerHello bytes
      --  (and the peer Finished bytes) so the §7.1 schedule can
      --  re-key using the exact transcripts the peers exchanged.
      CH_Buf           : Hello_Bytes := (others => 0);
      CH_Len           : Natural := 0;
      SH_Buf           : Hello_Bytes := (others => 0);
      SH_Len           : Natural := 0;
      SF_Buf           : Hello_Bytes := (others => 0);
      SF_Len           : Natural := 0;

      --  Filled when state becomes Done.
      Secrets_Set      : Boolean := False;
      Secrets          : Tls_Core.Handshake.Traffic_Secrets;
   end record;

   function Current_State (D : Driver) return State is (D.Cur_State);

end Tls_Core.Handshake_Driver;
