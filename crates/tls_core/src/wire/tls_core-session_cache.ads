--  Tls_Core.Session_Cache — bounded, heap-free TLS 1.3 session
--  cache for resumption tickets (RFC 8446 §4.6.1, §2.2).
--
--  Source: RFC 8446 §4.6.1 (NewSessionTicket), §2.2 (resumption flow).
--
--  Design constraints (docs/conventions.md "no per-op heap" pattern, carried
--  over from the MQTT track):
--
--    1. Fixed-size cache: 4 slots. No `new`. Suitable for bare-metal.
--    2. FIFO eviction when full: oldest slot is overwritten.
--    3. Each slot holds the resumption_master_secret + ticket
--       (opaque server bytes) + ticket_nonce + ticket_age_add +
--       ticket_lifetime + the cipher suite the original handshake
--       negotiated. The PSK itself is NOT stored — it is derived on
--       resumption from (resumption_master_secret, ticket_nonce) via
--       Tls_Core.Session_Ticket.Derive_Psk_From_Ticket_Sha256.
--
--    4. Server-identity keying: the cache is a single opaque blob
--       per Tls_Core handle (a TLS 1.3 client typically opens one
--       cache per (host, port) pair; layering above tls_core does
--       that demux). This module just holds the slots.
--
--  v0.5 scope: SHA-256-based suites only (per the same wall-hit as
--  Tls13_Driver). The slot stores a SHA-256 resumption secret.
--
--  Spec mirror: miTLS src/tls/MiTLS.Ticket.fst : ticket_cache.

with Tls_Core.Key_Schedule;
with Tls_Core.Session_Ticket;
with Tls_Core.Suites;

package Tls_Core.Session_Cache
with SPARK_Mode
is

   use type Interfaces.Unsigned_32;

   --  Cache capacity. Picked small because the bare-metal targets
   --  (light-lm3s Cortex-M3) have ~64 KiB SRAM total. Each slot is
   --  ~1.4 KiB (one 1024-byte ticket + the bookkeeping fields), so
   --  4 slots = ~5.6 KiB. Hosted clients can wrap multiple Cache
   --  instances if they need a larger pool.
   Slot_Count : constant := 4;
   subtype Slot_Index is Positive range 1 .. Slot_Count;

   --  Per-slot bookkeeping. The Used flag distinguishes empty from
   --  occupied slots; Insertion_Seq orders slots so FIFO eviction
   --  picks the lowest sequence number.
   --
   --  All fields are stack-allocated; no 'access types, no `new`.
   type Slot is record
      Used              : Boolean := False;
      Insertion_Seq     : Interfaces.Unsigned_32 := 0;

      --  RFC 8446 §4.6.1 fields.
      Lifetime          : Tls_Core.Session_Ticket.U32 := 0;
      Age_Add           : Tls_Core.Session_Ticket.U32 := 0;

      Ticket_Nonce_Len  : Tls_Core.Session_Ticket.Ticket_Nonce_Length := 0;
      Ticket_Nonce      : Octet_Array
        (1 .. Tls_Core.Session_Ticket.Max_Ticket_Nonce_Length) :=
          (others => 0);

      Ticket_Len        : Natural := 0;
      Ticket            : Octet_Array
        (1 .. Tls_Core.Session_Ticket.Max_Ticket_Length) :=
          (others => 0);

      --  Derived secret used to recompute the resumption-PSK on
      --  the next handshake (RFC 8446 §4.6.1 binding).
      Resumption_Secret : Tls_Core.Key_Schedule.Secret := (others => 0);

      --  The cipher suite the original handshake negotiated. The
      --  resumption ClientHello SHOULD offer the same suite first
      --  (RFC 8446 §4.2.11).
      Suite             : Tls_Core.Suites.Cipher_Suite_Id :=
        Tls_Core.Suites.Aes_128_Gcm_Sha256;
   end record;

   type Slot_Array is array (Slot_Index) of Slot;

   type Cache is record
      Slots         : Slot_Array;
      Next_Seq      : Interfaces.Unsigned_32 := 1;
   end record;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Initialise the cache to empty.
   --
   --  Standard:    n/a (housekeeping)
   --  Spec mirror: miTLS src/tls/MiTLS.Ticket.fst : empty_cache
   --
   --  Functional:  All slots have Used = False after Init; Next_Seq
   --               starts at 1 so the first inserted slot has a
   --               nonzero Insertion_Seq.
   --  Proven at:   gnatprove --level=2 (audit-clean)
   --------------------------------------------------------------------
   procedure Init (C : out Cache)
   with
     Post =>
       (for all I in Slot_Index => not C.Slots (I).Used)
       and then C.Next_Seq = 1;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Store a (ticket, resumption_secret) pair.
   --
   --  Standard:    RFC 8446 §4.6.1 (storage side of NST).
   --  Spec mirror: miTLS src/tls/MiTLS.Ticket.fst : insert
   --
   --  Functional:  After Insert, at least one slot has Used = True
   --               and stores (Lifetime, Age_Add, copies of
   --               Ticket_Nonce / Ticket, Resumption_Secret, Suite).
   --               If the cache was full, the slot with the lowest
   --               Insertion_Seq is the one that got overwritten
   --               (FIFO eviction).
   --  Proven at:   gnatprove --level=2 (audit-clean)
   --------------------------------------------------------------------
   procedure Insert
     (C                 : in out Cache;
      Lifetime          : Tls_Core.Session_Ticket.U32;
      Age_Add           : Tls_Core.Session_Ticket.U32;
      Ticket_Nonce      : Octet_Array;
      Ticket            : Octet_Array;
      Resumption_Secret : Tls_Core.Key_Schedule.Secret;
      Suite             : Tls_Core.Suites.Cipher_Suite_Id)
   with
     Pre =>
       Ticket_Nonce'Length in
         0 .. Tls_Core.Session_Ticket.Max_Ticket_Nonce_Length
       and then Ticket'Length in
         1 .. Tls_Core.Session_Ticket.Max_Ticket_Length,
     Post =>
       (for some I in Slot_Index => C.Slots (I).Used);

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Look up the most-recently-inserted slot
   --                      that is still Used.
   --
   --  Returns Found = True when at least one slot is occupied; the
   --  returned Index points to the slot with the highest Insertion_Seq
   --  (i.e. most recent). Found = False on an empty cache.
   --
   --  v0.5 simplification: real implementations index by server
   --  identity. Layering above tls_core supplies one cache per
   --  (host, port); this lookup picks freshest within the cache.
   --
   --  Standard:    RFC 8446 §4.6.1 (storage / lookup side of resumption).
   --  Spec mirror: miTLS src/tls/MiTLS.Ticket.fst : lookup
   --  Proven at:   gnatprove --level=2 (audit-clean)
   --------------------------------------------------------------------
   procedure Lookup_Most_Recent
     (C     : Cache;
      Index : out Slot_Index;
      Found : out Boolean)
   with Post =>
     (if Found then C.Slots (Index).Used);

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Mark a slot empty. Called after using a
   --                      one-shot ticket so it isn't presented twice
   --                      (RFC 8446 §4.2.11 forbids ticket reuse).
   --
   --  Standard:    RFC 8446 §4.2.11.
   --  Proven at:   gnatprove --level=2 (audit-clean)
   --------------------------------------------------------------------
   procedure Invalidate (C : in out Cache; Index : Slot_Index)
   with
     Post => not C.Slots (Index).Used
             and then (for all I in Slot_Index =>
                         (if I /= Index then
                            C.Slots (I).Used = C'Old.Slots (I).Used));

end Tls_Core.Session_Cache;
