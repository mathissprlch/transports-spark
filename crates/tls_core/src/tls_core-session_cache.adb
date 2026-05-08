package body Tls_Core.Session_Cache
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   ---------------------------------------------------------------------
   --  Init — empty all slots.
   ---------------------------------------------------------------------

   procedure Init (C : out Cache) is
   begin
      for I in Slot_Index loop
         C.Slots (I) :=
           (Used              => False,
            Insertion_Seq     => 0,
            Lifetime          => 0,
            Age_Add           => 0,
            Ticket_Nonce_Len  => 0,
            Ticket_Nonce      => (others => 0),
            Ticket_Len        => 0,
            Ticket            => (others => 0),
            Resumption_Secret => (others => 0),
            Suite             => Tls_Core.Suites.Aes_128_Gcm_Sha256);
         pragma Loop_Invariant
           (for all J in Slot_Index'First .. I =>
              not C.Slots (J).Used);
      end loop;
      C.Next_Seq := 1;
   end Init;

   ---------------------------------------------------------------------
   --  Insert — pick a target slot then overwrite it.
   --
   --  Selection policy:
   --    1. First Used = False slot wins (cache not yet full).
   --    2. Otherwise, slot with the lowest Insertion_Seq (oldest)
   --       wins (FIFO eviction).
   --
   --  Insertion_Seq saturates at U32'Last; with 4 slots and a 32-bit
   --  counter the wraparound is irrelevant in practice (would need
   --  >4 billion handshakes on the same Cache instance).
   ---------------------------------------------------------------------

   procedure Insert
     (C                 : in out Cache;
      Lifetime          : Tls_Core.Session_Ticket.U32;
      Age_Add           : Tls_Core.Session_Ticket.U32;
      Ticket_Nonce      : Octet_Array;
      Ticket            : Octet_Array;
      Resumption_Secret : Tls_Core.Key_Schedule.Secret;
      Suite             : Tls_Core.Suites.Cipher_Suite_Id)
   is
      Target      : Slot_Index := Slot_Index'First;
      Found_Empty : Boolean := False;
      Oldest_Seq  : Interfaces.Unsigned_32 :=
        Interfaces.Unsigned_32'Last;
   begin
      --  Phase 1: prefer an empty slot.
      for I in Slot_Index loop
         if not C.Slots (I).Used then
            Target := I;
            Found_Empty := True;
            exit;
         end if;
         pragma Loop_Invariant (not Found_Empty);
      end loop;

      --  Phase 2: if no empty slot, evict the FIFO oldest.
      if not Found_Empty then
         for I in Slot_Index loop
            if C.Slots (I).Insertion_Seq <= Oldest_Seq then
               Oldest_Seq := C.Slots (I).Insertion_Seq;
               Target := I;
            end if;
            pragma Loop_Invariant (Target in Slot_Index);
         end loop;
      end if;

      --  Write the chosen slot.
      C.Slots (Target).Used := True;
      C.Slots (Target).Insertion_Seq := C.Next_Seq;
      C.Slots (Target).Lifetime := Lifetime;
      C.Slots (Target).Age_Add := Age_Add;

      C.Slots (Target).Ticket_Nonce_Len := Ticket_Nonce'Length;
      C.Slots (Target).Ticket_Nonce := (others => 0);
      if Ticket_Nonce'Length > 0 then
         C.Slots (Target).Ticket_Nonce (1 .. Ticket_Nonce'Length) :=
           Ticket_Nonce;
      end if;

      C.Slots (Target).Ticket_Len := Ticket'Length;
      C.Slots (Target).Ticket := (others => 0);
      C.Slots (Target).Ticket (1 .. Ticket'Length) := Ticket;

      C.Slots (Target).Resumption_Secret := Resumption_Secret;
      C.Slots (Target).Suite := Suite;

      --  Bump sequence counter (saturating).
      if C.Next_Seq < Interfaces.Unsigned_32'Last then
         C.Next_Seq := C.Next_Seq + 1;
      end if;
   end Insert;

   ---------------------------------------------------------------------
   --  Lookup_Most_Recent — pick the highest Insertion_Seq among
   --                       Used slots.
   ---------------------------------------------------------------------

   procedure Lookup_Most_Recent
     (C     : Cache;
      Index : out Slot_Index;
      Found : out Boolean)
   is
      Best_Seq : Interfaces.Unsigned_32 := 0;
   begin
      Index := Slot_Index'First;
      Found := False;

      for I in Slot_Index loop
         if C.Slots (I).Used
           and then (not Found
                     or else C.Slots (I).Insertion_Seq >= Best_Seq)
         then
            Index := I;
            Best_Seq := C.Slots (I).Insertion_Seq;
            Found := True;
         end if;
         pragma Loop_Invariant
           (if Found then C.Slots (Index).Used);
      end loop;
   end Lookup_Most_Recent;

   ---------------------------------------------------------------------
   --  Invalidate — flip Used = False on a single slot.
   ---------------------------------------------------------------------

   procedure Invalidate (C : in out Cache; Index : Slot_Index) is
   begin
      C.Slots (Index).Used := False;
      C.Slots (Index).Insertion_Seq := 0;
   end Invalidate;

end Tls_Core.Session_Cache;
