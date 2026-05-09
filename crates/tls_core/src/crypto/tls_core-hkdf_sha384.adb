with Tls_Core.Hmac_Sha384;

package body Tls_Core.Hkdf_Sha384
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   function Spec_HKDF_Expand_Block
     (PRK         : Octet_Array;
      Info        : Octet_Array;
      T_Prev      : Tls_Core.Sha384.Digest;
      Counter     : Octet;
      First_Block : Boolean) return Tls_Core.Sha384.Digest
   is
      Buf_Len : constant Natural :=
        (if First_Block then Info'Length + 1
         else Hash_Length + Info'Length + 1);
      Buf     : Octet_Array (1 .. Buf_Len) := (others => 0);
      Off     : Natural := 0;
      Result  : Tls_Core.Sha384.Digest;
   begin
      if not First_Block then
         Buf (1 .. Hash_Length) := T_Prev;
         Off := Hash_Length;
      end if;
      for K in 1 .. Info'Length loop
         Buf (Off + K) := Info (Info'First + K - 1);
         pragma Loop_Invariant
           (for all J in 1 .. K =>
              Buf (Off + J) = Info (Info'First + J - 1));
      end loop;
      Buf (Buf_Len) := Counter;
      Tls_Core.Hmac_Sha384.Compute
        (Key     => PRK,
         Message => Buf,
         Out_Tag => Result);
      return Result;
   end Spec_HKDF_Expand_Block;

   function Spec_HKDF_Expand
     (PRK  : Octet_Array;
      Info : Octet_Array;
      L    : Positive) return Octet_Array
   is
      OKM    : Octet_Array (1 .. L) := (others => 0);
      T_Prev : Tls_Core.Sha384.Digest := (others => 0);
      T_Curr : Tls_Core.Sha384.Digest;
      Cursor : Natural := 0;
      Idx    : Natural := 0;
      First  : Boolean := True;
   begin
      while Cursor < L loop
         pragma Loop_Variant (Decreases => L - Cursor);
         pragma Loop_Invariant (Cursor < L);
         pragma Loop_Invariant (Idx * Hash_Length <= Cursor);
         pragma Loop_Invariant (Idx in 0 .. 254);
         Idx := Idx + 1;

         T_Curr := Spec_HKDF_Expand_Block
           (PRK         => PRK,
            Info        => Info,
            T_Prev      => T_Prev,
            Counter     => Octet (Idx),
            First_Block => First);

         declare
            Take : constant Natural := Natural'Min (Hash_Length, L - Cursor);
         begin
            for K in 1 .. Take loop
               OKM (Cursor + K) := T_Curr (K);
               pragma Loop_Invariant
                 (for all J in 1 .. K =>
                    OKM (Cursor + J) = T_Curr (J));
            end loop;
            Cursor := Cursor + Take;
         end;

         T_Prev := T_Curr;
         First  := False;
      end loop;
      return OKM;
   end Spec_HKDF_Expand;

   procedure Expand
     (PRK  : Octet_Array;
      Info : Octet_Array;
      OKM  : out Octet_Array)
   is
      Spec_Result : constant Octet_Array :=
        Spec_HKDF_Expand (PRK, Info, OKM'Length);
   begin
      OKM := (others => 0);
      for I in 1 .. OKM'Length loop
         OKM (OKM'First + I - 1) := Spec_Result (I);
         pragma Loop_Invariant
           (for all J in 1 .. I =>
              OKM (OKM'First + J - 1) = Spec_Result (J));
      end loop;
   end Expand;

   procedure Hmac_Expand
     (Prk    : Octet_Array;
      Info   : Octet_Array;
      Output : out Octet_Array)
   is
   begin
      Expand (PRK => Prk, Info => Info, OKM => Output);
   end Hmac_Expand;

end Tls_Core.Hkdf_Sha384;
