separate (Tls_Core.X509_Spki)
   procedure Read_TLV_Header
     (Buf          : Octet_Array;
      Cur          : Natural;
      Expected_Tag : Octet;
      Body_First   : out Natural;
      Body_Last    : out Natural;
      After        : out Natural;
      OK           : out Boolean)
   is
      Tag_Cur : Natural;
      Tag_OK  : Boolean;
      Len     : Natural;
      Used    : Natural;
      Len_OK  : Boolean;
   begin
      Body_First := Cur;
      Body_Last  := Cur;
      After      := Cur;
      OK         := False;

      Read_Tag (Buf, Cur, Expected_Tag, Tag_Cur, Tag_OK);
      if not Tag_OK then
         return;
      end if;
      --  Tag_Cur = Cur + 1, in Buf'First+1 .. Buf'Last+1
      if Tag_Cur > Buf'Last then
         return;
      end if;
      --  Tag_Cur in 1 .. Buf'Last
      Read_Length (Buf, Tag_Cur, Len, Used, Len_OK);
      if not Len_OK then
         return;
      end if;
      --  Read_Length post: Used in 1..5, Tag_Cur+Used <= Buf'Last+1,
      --  Len <= Buf'Length.
      pragma Assert (Tag_Cur + Used <= Buf'Last + 1);
      pragma Assert (Len <= Buf'Length);

      declare
         BF : constant Natural := Tag_Cur + Used;
         --  BF in Tag_Cur+1 .. Buf'Last+1
         --     = Cur+2     .. Buf'Last+1
      begin
         pragma Assert (BF in Cur + 2 .. Buf'Last + 1);
         --  Need: BF + Len - 1 <= Buf'Last and BF + Len <= Buf'Last+1
         --  We have BF <= Buf'Last+1 and Len <= Buf'Length =
         --  Buf'Last - Buf'First + 1 = Buf'Last (since Buf'First=1).
         --  But that's not enough — need BF + Len - 1 <= Buf'Last.
         --  Read_Length only constrains Len <= Buf'Length, not the
         --  cumulative position.  So we have to range-check here.
         if Len > Buf'Last - BF + 1 then
            --  Body would run past end of buffer.
            return;
         end if;
         --  Now BF + Len <= Buf'Last + 1, all positions safe.
         pragma Assert (BF + Len <= Buf'Last + 1);
         Body_First := BF;
         if Len = 0 then
            Body_Last := BF - 1;  --  empty body convention
            After     := BF;
         else
            Body_Last := BF + Len - 1;
            After     := BF + Len;
         end if;
         OK := True;
      end;
   end Read_TLV_Header;
