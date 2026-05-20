--  Tls_Core.Transport — in-process two-direction TLS 1.3 pipe.
--
--  Wraps a pair of Tls_Core.Channel.Direction's (one for the local
--  peer's outbound traffic, one for its inbound) into a single
--  endpoint object. Two peers each hold a Pipe initialised with
--  the same Traffic_Secrets but mirrored Roles, then exchange
--  plaintext via Send / Drain (encrypt + emit wire bytes) and
--  Inject / Receive (consume wire bytes + decrypt).
--
--  No I/O. The Pipe owns two Octet_Array byte buffers:
--    * outbound — bytes produced by Send, awaiting Drain.
--    * inbound  — bytes produced by Inject, awaiting Receive.
--
--  The orchestration models the network without touching it:
--  bytes a peer Drain's are exactly the bytes its counterpart
--  must Inject. Sequence-numbered, AEAD-protected per RFC 8446
--  §5.2 (the Channel layer does the framing + AEAD).
--
--  miTLS reference: src/tls/MiTLS.Connection.fst — same shape,
--  send-buffer / recv-buffer slot pair on top of the StAE layer.
--
--  This is the v0.5-final glue layer. A real-network adapter
--  (TCP, UDP-DTLS, in-memory tee) plugs straight in by carrying
--  bytes between Drain and Inject.

with Tls_Core.Channel;
with Tls_Core.Handshake;

package Tls_Core.Transport
  with SPARK_Mode => Off
is

   --  An in-process two-direction TLS pipe. Client and server each
   --  hold one of these and use Send/Receive to talk to each other
   --  through it. Sequence-numbered, AEAD-protected per RFC 8446 §5.2.
   type Pipe is limited private;

   --  Set up a Pipe from a fully-derived set of traffic secrets.
   --  Client encrypts outbound with Secrets.Client_App; decrypts
   --  inbound with Secrets.Server_App. Server is the mirror.
   type Role is (Client, Server);

   procedure Init
     (P       : out Pipe;
      Role_Of : Role;
      Secrets : Tls_Core.Handshake.Traffic_Secrets);

   --  Send: encrypt one record and append wire bytes to the pipe's
   --  outbound buffer. Receive (on the peer's Pipe instance) parses
   --  the next record from its inbound buffer and decrypts.
   procedure Send (P : in out Pipe; Plaintext : Octet_Array)
   with Pre => Plaintext'Length in 1 .. 16384;

   --  Hand the bytes that another peer's Send produced back into
   --  this peer for Receive to consume. (Models the network: the
   --  other side sent these bytes, this side now has them.)
   procedure Inject (P : in out Pipe; Bytes : Octet_Array);

   --  Take the next outbound wire bytes since the last Drain. Caller
   --  is responsible for delivering them to the peer (e.g. via the
   --  peer's Inject).
   procedure Drain
     (P : in out Pipe; Out_Buf : out Octet_Array; Out_Last : out Natural);

   --  Pop one decrypted record from the inbound buffer. Sets OK = False
   --  if no full record is available or the AEAD verify fails.
   procedure Receive
     (P        : in out Pipe;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural;
      OK       : out Boolean);

private

   --  Wire-buffer capacity. One TLS 1.3 record on the wire is at
   --  most 5 (header) + 16384 (plaintext) + 16 (tag) = 16405 bytes;
   --  give ourselves room for several queued records per direction.
   Buffer_Capacity : constant := 65536;

   subtype Wire_Buffer is Octet_Array (1 .. Buffer_Capacity);

   type Pipe is limited record
      My_Role : Role := Client;

      --  Send_Dir encrypts outbound plaintext (Client uses
      --  Client_App secret, Server uses Server_App).
      Send_Dir : Tls_Core.Channel.Direction;

      --  Recv_Dir decrypts inbound ciphertext (Client uses
      --  Server_App secret, Server uses Client_App).
      Recv_Dir : Tls_Core.Channel.Direction;

      --  Bytes Send'd but not yet Drain'd.
      Outbound      : Wire_Buffer := [others => 0];
      Outbound_Last : Natural := 0;

      --  Bytes Inject'd but not yet Receive'd.
      Inbound      : Wire_Buffer := [others => 0];
      Inbound_Last : Natural := 0;
   end record;

end Tls_Core.Transport;
