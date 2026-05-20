separate (Tls_Core.Tls13_Driver)
procedure Step
  (D        : in out Driver;
   In_Bytes : Octet_Array;
   Out_Buf  : out Octet_Array;
   Out_Last : out Natural) is
begin
   Out_Buf := [others => 0];
   Out_Last := 0;

   --  RFC 8446 §4.4.2 + §4.4.3 — cert-mode dispatch.  Mode is set
   --  by Init_Cert_Server / Init_Cert_Client; for all other Init_*
   --  routines it remains Psk_Mode and the PSK handlers run as
   --  before.  Awaiting_Sh_Or_Hrr / Awaiting_Ch_2 (HRR path) are
   --  not yet cert-aware; they stay PSK-only and a cert-mode
   --  driver that triggers HRR will fail Step (caller-visible
   --  via Failed state) — to be lifted in a follow-up when HRR
   --  cert flows are needed.
   --
   --  Spec mirror: miTLS src/tls/MiTLS.Handshake.Server.fst :
   --               serverHandshakeStep — dispatches by (state,
   --               handshake_mode) tuple; we mirror the same
   --               two-axis structure.
   case D.Cur_State is
      when Idle               =>
         --  Step_Idle already branches on D.Mode internally
         --  (cert-mode emits Encode_Client_Hello_Cert; PSK-mode
         --  emits Encode_Client_Hello_Psk).
         Step_Idle.Handle (D, In_Bytes, Out_Buf, Out_Last);

      when Awaiting_Sf        =>
         --  Client awaiting server flight.  PSK-mode = SH+EE+SF;
         --  cert-mode = SH+EE+Cert+CertVerify+SF.
         if D.Mode = Cert_Mode then
            Step_Awaiting_Sf_Cert.Handle (D, In_Bytes, Out_Buf, Out_Last);
         else
            Step_Awaiting_Sf.Handle (D, In_Bytes, Out_Buf, Out_Last);
         end if;

      when Awaiting_CH        =>
         --  Server awaiting client hello.  Cert-mode emits the
         --  §4.4.2 + §4.4.3 server flight; PSK-mode emits SH+EE+SF.
         if D.Mode = Cert_Mode then
            Step_Awaiting_Ch_Cert.Handle (D, In_Bytes, Out_Buf, Out_Last);
         else
            Step_Awaiting_Ch.Handle (D, In_Bytes, Out_Buf, Out_Last);
         end if;

      when Awaiting_Cf        =>
         --  Server awaiting client Finished — same shape for PSK
         --  and cert; the cert path arrives here once the client
         --  has verified the chain + CertVerify.
         Step_Awaiting_Cf.Handle (D, In_Bytes, Out_Buf, Out_Last);

      when Awaiting_Sh_Or_Hrr =>
         Step_Hrr.Handle_Sh_Or_Hrr (D, In_Bytes, Out_Buf, Out_Last);

      when Awaiting_Ch_2      =>
         Step_Hrr.Handle_Ch_2 (D, In_Bytes, Out_Buf, Out_Last);

      when others             =>
         null;
   end case;
end Step;
