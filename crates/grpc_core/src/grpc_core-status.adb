package body Grpc_Core.Status
with SPARK_Mode
is

   procedure From_String
     (S     : String;
      C     : out Code;
      Valid : out Boolean)
   is
      N : Natural := 0;
   begin
      C     := OK;
      Valid := False;
      if S'Length not in 1 .. 2 then
         return;
      end if;
      --  Indexed form so the prover can correlate iteration count
      --  with N's possible values: after K iterations N < 10**K.
      --  S'Length is bounded to 2 above, so the loop runs at most
      --  twice, hence N stays ≤ 99.
      for K in 1 .. S'Length loop
         pragma Loop_Invariant (K in 1 .. S'Length);
         pragma Loop_Invariant
           (if K = 1 then N = 0 else N in 0 .. 9);
         declare
            Ch : constant Character :=
              S (S'First + K - 1);
         begin
            if Ch not in '0' .. '9' then
               return;
            end if;
            N := N * 10 + Character'Pos (Ch) - Character'Pos ('0');
         end;
      end loop;
      if N > 16 then
         return;
      end if;
      C     := Code'Val (N);
      Valid := True;
   end From_String;

   procedure To_String
     (C    : Code;
      Buf  : out String;
      Last : out Natural)
   is
      N : constant Natural := Code'Pos (C);
   begin
      Buf := [others => ' '];
      if N >= 10 then
         Buf (Buf'First) :=
           Character'Val (Character'Pos ('0') + N / 10);
         Buf (Buf'First + 1) :=
           Character'Val (Character'Pos ('0') + N mod 10);
         Last := Buf'First + 1;
      else
         Buf (Buf'First) :=
           Character'Val (Character'Pos ('0') + N);
         Last := Buf'First;
      end if;
   end To_String;

end Grpc_Core.Status;
