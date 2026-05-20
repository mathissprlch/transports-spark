separate (Tls_Core.Tls13_Driver)
procedure Receive_New_Session_Ticket
  (D            : Driver;
   In_Dir       : in out Tls_Core.Aead_Channel.Direction;
   Cache        : in out Tls_Core.Session_Cache.Cache;
   Record_Bytes : Octet_Array;
   OK           : out Boolean)
is
   Hs_Type_New_Session_Ticket : constant Octet := 16#04#;

   Pt_Buf     :
     Octet_Array (1 .. 4 + Tls_Core.Session_Ticket.Max_Nst_Body_Length) :=
       [others => 0];
   Pt_Last    : Natural;
   Inner_Type : Octet;
   Decrypt_OK : Boolean;
begin
   OK := False;

   Tls_Core.Aead_Channel.Receive
     (In_Dir, Record_Bytes, Pt_Buf, Pt_Last, Inner_Type, Decrypt_OK);
   if not Decrypt_OK
     or else Inner_Type /= Tls_Core.Aead_Channel.Inner_Type_Handshake
     or else Pt_Last < 4
     or else Pt_Buf (1) /= Hs_Type_New_Session_Ticket
   then
      return;
   end if;

   --  Validate the u24 length matches the rest of the buffer.
   declare
      L : constant Natural :=
        Natural (Pt_Buf (2))
        * 65536
        + Natural (Pt_Buf (3)) * 256
        + Natural (Pt_Buf (4));
   begin
      if 4 + L /= Pt_Last then
         return;
      end if;
      if L < 14 or else L > Tls_Core.Session_Ticket.Max_Nst_Body_Length then
         return;
      end if;

      --  Decode body. Body_Slice has 'First = 1 by construction.
      declare
         Body_Slice : constant Octet_Array (1 .. L) := Pt_Buf (5 .. 4 + L);
         Lt         : Tls_Core.Session_Ticket.U32;
         Ag         : Tls_Core.Session_Ticket.U32;
         Nf         : Natural;
         Tf         : Natural;
         Nl         : Integer;
         Tl         : Integer;
         Decode_OK  : Boolean;
      begin
         Tls_Core.Session_Ticket.Decode_Body
           (In_Buf       => Body_Slice,
            Lifetime     => Lt,
            Age_Add      => Ag,
            Nonce_First  => Nf,
            Nonce_Last   => Nl,
            Ticket_First => Tf,
            Ticket_Last  => Tl,
            OK           => Decode_OK);
         if not Decode_OK then
            return;
         end if;

         --  Insert into cache. The Decode_Body Post guarantees
         --  the index ranges are valid sub-slices of Body_Slice,
         --  so the slice expressions below are safe.
         if Nl >= Nf then
            Tls_Core.Session_Cache.Insert
              (C                 => Cache,
               Lifetime          => Lt,
               Age_Add           => Ag,
               Ticket_Nonce      => Body_Slice (Nf .. Nl),
               Ticket            => Body_Slice (Tf .. Tl),
               Resumption_Secret => D.Res_Master_Sec (1 .. 32),
               Suite             => D.Suite);
         else
            declare
               Empty_Nonce : constant Octet_Array (1 .. 0) := [others => 0];
            begin
               Tls_Core.Session_Cache.Insert
                 (C                 => Cache,
                  Lifetime          => Lt,
                  Age_Add           => Ag,
                  Ticket_Nonce      => Empty_Nonce,
                  Ticket            => Body_Slice (Tf .. Tl),
                  Resumption_Secret => D.Res_Master_Sec (1 .. 32),
                  Suite             => D.Suite);
            end;
         end if;
         OK := True;
      end;
   end;
end Receive_New_Session_Ticket;
