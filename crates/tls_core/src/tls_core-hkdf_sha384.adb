with Tls_Core.Hmac_Sha384;

package body Tls_Core.Hkdf_Sha384
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   procedure Expand
     (PRK  : Octet_Array;
      Info : Octet_Array;
      OKM  : out Octet_Array)
   is
      T_Prev   : Tls_Core.Sha384.Digest := (others => 0);
      T_Curr   : Tls_Core.Sha384.Digest;
      Cursor   : Natural := 0;
      I        : Natural := 0;
      First    : Boolean := True;
   begin
      OKM := (others => 0);

      while Cursor < OKM'Length loop
         pragma Loop_Variant (Decreases => OKM'Length - Cursor);
         pragma Loop_Invariant (Cursor < OKM'Length);
         pragma Loop_Invariant (I * Hash_Length <= Cursor);
         pragma Loop_Invariant (I in 0 .. 254);
         I := I + 1;

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

            Tls_Core.Hmac_Sha384.Compute
              (Key     => PRK,
               Message => Input (1 .. Off + 1),
               Out_Tag => T_Curr);
         end;

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
