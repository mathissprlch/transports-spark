separate (Tls_Core.Tls13_Driver)
procedure Send_New_Session_Ticket
  (D            : Driver;
   Out_Dir      : in out Tls_Core.Aead_Channel.Direction;
   Lifetime     : Tls_Core.Session_Ticket.U32;
   Age_Add      : Tls_Core.Session_Ticket.U32;
   Ticket_Nonce : Octet_Array;
   Ticket_Bytes : Octet_Array;
   Out_Buf      : out Octet_Array;
   Out_Last     : out Natural)
is
   pragma Unreferenced (D);

   Hs_Type_New_Session_Ticket : constant Octet := 16#04#;

   --  Worst-case body length per Session_Ticket spec.
   Body_Buf  :
     Octet_Array (1 .. Tls_Core.Session_Ticket.Max_Nst_Body_Length) :=
       (others => 0);
   Body_Last : Natural;

   --  Handshake-message wrapper (4-byte header + body).
   Hs_Buf  :
     Octet_Array (1 .. 4 + Tls_Core.Session_Ticket.Max_Nst_Body_Length) :=
       (others => 0);
   Hs_Last : Natural;
begin
   Out_Buf := (others => 0);
   Out_Last := 0;

   --  1. Build NST body.
   Tls_Core.Session_Ticket.Encode_Body
     (Lifetime     => Lifetime,
      Age_Add      => Age_Add,
      Ticket_Nonce => Ticket_Nonce,
      Ticket       => Ticket_Bytes,
      Out_Buf      => Body_Buf,
      Out_Last     => Body_Last);

   --  2. Wrap as Handshake message (type 4 + u24 length + body).
   Encode_Hs_Message
     (Hs_Type_New_Session_Ticket, Body_Buf (1 .. Body_Last), Hs_Buf, Hs_Last);

   --  3. Encrypt the whole Handshake message as one application
   --     traffic record. Inner type is Handshake per §5.4.
   Tls_Core.Aead_Channel.Send
     (Out_Dir,
      Hs_Buf (1 .. Hs_Last),
      Tls_Core.Aead_Channel.Inner_Type_Handshake,
      Out_Buf,
      Out_Last);
end Send_New_Session_Ticket;
