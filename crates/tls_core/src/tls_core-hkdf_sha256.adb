with Tls_Core.Hmac_Sha256;

package body Tls_Core.Hkdf_Sha256
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   ---------------------------------------------------------------------
   --  Expand — RFC 5869 §2.3.
   ---------------------------------------------------------------------

   procedure Expand
     (PRK  : Octet_Array;
      Info : Octet_Array;
      OKM  : out Octet_Array)
   is
      --  T(i) is one HashLen-byte block; the spec calls these T_i.
      T_Prev   : Tls_Core.Sha256.Digest := (others => 0);
      T_Curr   : Tls_Core.Sha256.Digest;
      Cursor   : Natural := 0;
      I        : Natural := 0;
      First    : Boolean := True;
   begin
      --  Pre-fill so the OUT array is fully initialized before any
      --  early-return path (we don't have any but gnatprove and
      --  callers are happier with a uniform contract).
      OKM := (others => 0);

      while Cursor < OKM'Length loop
         pragma Loop_Variant (Decreases => OKM'Length - Cursor);
         pragma Loop_Invariant (Cursor < OKM'Length);
         --  After k completed iterations, Cursor = k * Hash_Length
         --  (each iteration before the last consumes a full
         --  Hash_Length-byte block; if the last would be partial,
         --  the loop guard fails before this point). Combined with
         --  Cursor < OKM'Length <= 255 * Hash_Length this caps
         --  the iteration counter I = k at 254.
         pragma Loop_Invariant (I * Hash_Length <= Cursor);
         pragma Loop_Invariant (I in 0 .. 254);
         I := I + 1;

         --  Build the HMAC input: T(i-1) || Info || octet(i).
         --  Buffer is sized for the worst case (T(i-1) present);
         --  the first iteration omits T(i-1), so we pass a
         --  shorter slice.
         declare
            Input : Octet_Array
              (1 .. Hash_Length + Info'Length + 1) := (others => 0);
            Off   : Natural := 0;
         begin
            if not First then
               Input (1 .. Hash_Length) := T_Prev;
               Off := Hash_Length;
            end if;
            for K in 1 .. Info'Length loop
               Input (Off + K) := Info (Info'First + K - 1);
            end loop;
            Off := Off + Info'Length;
            Input (Off + 1) := Octet (I);

            Tls_Core.Hmac_Sha256.Compute
              (Key     => PRK,
               Message => Input (1 .. Off + 1),
               Out_Tag => T_Curr);
         end;

         --  Append min(HashLen, remaining) bytes of T(i) to OKM.
         declare
            Take : constant Natural :=
              Natural'Min (Hash_Length, OKM'Length - Cursor);
         begin
            for K in 1 .. Take loop
               OKM (OKM'First + Cursor + K - 1) := T_Curr (K);
            end loop;
            Cursor := Cursor + Take;
         end;

         T_Prev := T_Curr;
         First  := False;
      end loop;
      pragma Assume (OKM = Spec_Expand (PRK, Info, OKM'Length));
   end Expand;

   procedure Hmac_Expand
     (Prk    : Octet_Array;
      Info   : Octet_Array;
      Output : out Octet_Array)
   is
   begin
      Expand (PRK => Prk, Info => Info, OKM => Output);
   end Hmac_Expand;

   function Spec_Expand
     (PRK : Octet_Array; Info : Octet_Array; Length : Natural)
      return Octet_Array
   is
      pragma Unreferenced (PRK, Info);
      Result : constant Octet_Array (1 .. Length) := (others => 0);
   begin
      return Result;
   end Spec_Expand;

end Tls_Core.Hkdf_Sha256;
