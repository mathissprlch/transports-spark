--  Tls_Core.Session_Ticket — RFC 8446 §4.6.1 NewSessionTicket
--  encode/decode + RFC 8446 §4.6.1 / §7.1 resumption-secret derivation.
--
--  Source: RFC 8446 §4.6.1 (NewSessionTicket post-handshake message),
--          §7.1 (resumption_master_secret), §4.2.11 (pre_shared_key
--          extension — produced by ClientHello / ServerHello layers,
--          not this module).
--
--  Wire shape (NewSessionTicket, RFC 8446 §4.6.1):
--
--      struct {
--          uint32 ticket_lifetime;
--          uint32 ticket_age_add;
--          opaque ticket_nonce<0..255>;
--          opaque ticket<1..2^16-1>;
--          Extension extensions<0..2^16-2>;
--      } NewSessionTicket;
--
--  v0.5 simplification: the extensions list we EMIT is empty (the
--  only extension RFC 8446 defines for NST is early_data, which is
--  out of scope per CLAUDE.md §0a). Decode tolerates and skips any
--  extensions block that fits in the bounded body buffer.
--
--  Resumption-PSK derivation (RFC 8446 §4.6.1):
--
--      PSK = HKDF-Expand-Label
--              (resumption_master_secret, "resumption",
--               ticket_nonce, Hash.length)
--
--  with `resumption_master_secret` itself derived per §7.1:
--
--      resumption_master_secret =
--          Derive-Secret (Master_Secret, "res master",
--                         ClientHello ... client Finished)
--
--  v0.5 scope (per CLAUDE.md §0a — ship only paths in production
--  use): the SHA-256-based suite path is implemented end-to-end
--  here. The SHA-384 resumption path is left for the same wave that
--  ports the SHA-384 internal key schedule into Tls13_Driver (see
--  the wall-hit note in tls_core-tls13_driver.ads).
--
--  Spec mirror (CLAUDE.md §0c): miTLS
--    src/tls/MiTLS.HandshakeMessages.fst : newSessionTicket type
--    src/tls/MiTLS.KS.fst                : resume_psk_secret
--
--  Tag policy (CLAUDE.md §4): all entry points carry a [VERIFIED —
--  AoRTE] tag — the wire encode / decode and the HKDF-Expand-Label
--  composition do not have a portable computational spec to mirror
--  from HACL\* the way the primitive does (HKDF-Expand-Label is
--  already pinned to its spec one layer down — see Tls_Core.Hkdf).

with Tls_Core.Key_Schedule;
with Tls_Core.Sha256;

package Tls_Core.Session_Ticket
with SPARK_Mode
is

   use type Interfaces.Unsigned_32;

   --  RFC 8446 §4.6.1 wire bounds.
   subtype U32 is Interfaces.Unsigned_32;

   --  Ticket nonce: 0..255 bytes per §4.6.1.
   Max_Ticket_Nonce_Length : constant := 255;
   subtype Ticket_Nonce_Length is Natural range 0 .. Max_Ticket_Nonce_Length;

   --  Ticket: 1..2^16-1 bytes per §4.6.1. v0.5 caps at 1024 because
   --  our cache slot size has to be fixed (see tls_core-session_cache).
   --  Real-world tickets from production servers are typically 32–512
   --  bytes (the opaque ticket is server-state ciphertext); 1024
   --  comfortably covers OpenSSL / rustls / Go default ticket sizes.
   Max_Ticket_Length : constant := 1024;
   subtype Ticket_Length is Positive range 1 .. Max_Ticket_Length;

   --  Extensions block we tolerate on decode: 0..256 bytes (early_data
   --  is the only registered extension and is 4 bytes when present;
   --  256 leaves headroom for unrecognised extensions a forward-
   --  compatible peer may emit).
   Max_Nst_Extensions_Length : constant := 256;

   --  Buffer holding a concatenated NewSessionTicket body (excluding
   --  the 4-byte handshake-message header).
   --
   --  Computed worst-case: 4 (lifetime) + 4 (age_add) + 1 + 255
   --  (nonce) + 2 + 1024 (ticket) + 2 + 256 (extensions) = 1548.
   Max_Nst_Body_Length : constant := 1548;
   subtype Nst_Body_Length is Natural range 0 .. Max_Nst_Body_Length;

   --  Resumption-master-secret derivation label, RFC 8446 §7.1.
   --  ASCII "res master" (10 bytes).
   Res_Master_Label : constant Octet_Array (1 .. 10) :=
     (Character'Pos ('r'), Character'Pos ('e'), Character'Pos ('s'),
      Character'Pos (' '),
      Character'Pos ('m'), Character'Pos ('a'), Character'Pos ('s'),
      Character'Pos ('t'), Character'Pos ('e'), Character'Pos ('r'));

   --  PSK-from-ticket label, RFC 8446 §4.6.1.
   --  ASCII "resumption" (10 bytes).
   Resumption_Label : constant Octet_Array (1 .. 10) :=
     (Character'Pos ('r'), Character'Pos ('e'), Character'Pos ('s'),
      Character'Pos ('u'), Character'Pos ('m'), Character'Pos ('p'),
      Character'Pos ('t'), Character'Pos ('i'), Character'Pos ('o'),
      Character'Pos ('n'));

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Encode the NewSessionTicket body (no
   --                      4-byte handshake header).
   --
   --  Standard:    RFC 8446 §4.6.1 (struct NewSessionTicket)
   --  Spec mirror: miTLS src/parsers/MiTLS.Parsers.NewSessionTicket13.rfc
   --
   --  Functional:  Out_Buf (1 .. Out_Last) is the §4.6.1 wire body
   --               with the supplied lifetime / age_add / nonce / ticket
   --               and an empty extensions list. The decode side
   --               (Decode_Body) is the inverse on this output.
   --  Proven at:   gnatprove --level=2 (audit-clean)
   --------------------------------------------------------------------
   procedure Encode_Body
     (Lifetime     : U32;
      Age_Add      : U32;
      Ticket_Nonce : Octet_Array;
      Ticket       : Octet_Array;
      Out_Buf      : out Octet_Array;
      Out_Last     : out Natural)
   with
     Pre =>
       Out_Buf'First = 1
       and then Ticket_Nonce'Length in 0 .. Max_Ticket_Nonce_Length
       and then Ticket'Length in 1 .. Max_Ticket_Length
       and then Out_Buf'Length >=
         4 + 4 + 1 + Ticket_Nonce'Length
         + 2 + Ticket'Length + 2,
     Post =>
       Out_Last in 0 .. Out_Buf'Last
       and then Out_Last =
         4 + 4 + 1 + Ticket_Nonce'Length
         + 2 + Ticket'Length + 2;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Decode the NewSessionTicket body.
   --
   --  In_Buf is the body (no 4-byte handshake header).
   --  Returns ranges into In_Buf for the ticket_nonce and ticket
   --  fields; OK = False on malformed input.
   --
   --  Standard:    RFC 8446 §4.6.1 (struct NewSessionTicket)
   --  Spec mirror: miTLS src/parsers/MiTLS.Parsers.NewSessionTicket13.rfc
   --
   --  Functional:  When OK = True, the index ranges describe valid
   --               sub-slices of In_Buf and the lifetime/age_add are
   --               the field-aligned u32 BE values.
   --  Proven at:   gnatprove --level=2 (audit-clean)
   --------------------------------------------------------------------
   procedure Decode_Body
     (In_Buf       : Octet_Array;
      Lifetime     : out U32;
      Age_Add      : out U32;
      Nonce_First  : out Natural;
      Nonce_Last   : out Integer;
      Ticket_First : out Natural;
      Ticket_Last  : out Integer;
      OK           : out Boolean)
   with
     Pre  =>
       In_Buf'First = 1
       and then In_Buf'Length <= Max_Nst_Body_Length,
     Post =>
       (if OK then
          Nonce_First in In_Buf'First .. In_Buf'Last + 1
          and then Nonce_Last in In_Buf'First - 1 .. In_Buf'Last
          and then Nonce_Last >= Nonce_First - 1
          and then Nonce_Last - Nonce_First + 1 <= Max_Ticket_Nonce_Length
          and then Ticket_First in In_Buf'First .. In_Buf'Last
          and then Ticket_Last in In_Buf'First .. In_Buf'Last
          and then Ticket_First <= Ticket_Last
          and then Ticket_Last - Ticket_First + 1 <= Max_Ticket_Length);

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Derive the resumption_master_secret
   --                      (SHA-256 cipher suites).
   --
   --  Standard:    RFC 8446 §7.1 (resumption_master_secret =
   --               Derive-Secret(Master_Secret, "res master",
   --                             ClientHello..client Finished))
   --  Spec mirror: miTLS src/tls/MiTLS.KS.fst : ks_server_13_postch
   --
   --  Functional:  Resumption_Secret = HKDF-Expand-Label
   --                 (Master_Secret, "res master",
   --                  Transcript_Hash, Hash.length).
   --               (Caller hashes the CH..CF transcript and passes the
   --               digest as Transcript_Hash; this matches §7.1's
   --               Derive-Secret expansion.)
   --  Proven at:   gnatprove --level=2 (audit-clean)
   --------------------------------------------------------------------
   procedure Derive_Resumption_Master_Secret_Sha256
     (Master_Secret     : Tls_Core.Key_Schedule.Secret;
      Transcript_Hash   : Tls_Core.Sha256.Digest;
      Resumption_Secret : out Tls_Core.Key_Schedule.Secret);

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Derive the resumption-PSK from a stored
   --                      resumption_master_secret + ticket_nonce.
   --
   --  Standard:    RFC 8446 §4.6.1 (PSK = HKDF-Expand-Label
   --               (resumption_master_secret, "resumption",
   --                ticket_nonce, Hash.length))
   --  Spec mirror: miTLS src/tls/MiTLS.KS.fst : resume_psk_secret
   --
   --  Functional:  Psk = HKDF-Expand-Label
   --                 (Resumption_Secret, "resumption",
   --                  Ticket_Nonce, Hash.length).
   --  Proven at:   gnatprove --level=2 (audit-clean)
   --------------------------------------------------------------------
   procedure Derive_Psk_From_Ticket_Sha256
     (Resumption_Secret : Tls_Core.Key_Schedule.Secret;
      Ticket_Nonce      : Octet_Array;
      Psk               : out Tls_Core.Key_Schedule.Secret)
   with
     Pre =>
       Ticket_Nonce'Length in 0 .. Max_Ticket_Nonce_Length
       and then Ticket_Nonce'Last < Integer'Last - 256;

end Tls_Core.Session_Ticket;
