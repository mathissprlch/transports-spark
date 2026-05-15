with Http2_Core.Hpack.Static_Table;
with Http2_Core.Hpack.Int_Codec;
with Http2_Core.Hpack.String_Literal;

package body Http2_Core.Hpack
with SPARK_Mode
is

   use type Interfaces.Unsigned_8;

   subtype U8 is Interfaces.Unsigned_8;

   function Make_Header
     (Name  : String;
      Value : String)
      return Header_Field
   is
      Result : Header_Field;
   begin
      Result.Name (1 .. Name'Length) := Name;
      Result.Name_Last               := Name'Length;
      if Value'Length > 0 then
         Result.Value (1 .. Value'Length) := Value;
      end if;
      Result.Value_Last := Value'Length;
      return Result;
   end Make_Header;

   --  Conversions between this package's Octet_Array and the
   --  identically-shaped types in the codec sibling packages. Same
   --  trade-off as in String_Literal — nominal-typing tax.

   function To_Int (A : Octet_Array) return Int_Codec.Octet_Array;
   function To_Int (A : Octet_Array) return Int_Codec.Octet_Array is
      R : Int_Codec.Octet_Array (A'Range);
   begin
      for I in A'Range loop
         R (I) := Int_Codec.Octet (A (I));
      end loop;
      return R;
   end To_Int;

   function To_Str (A : Octet_Array) return String_Literal.Octet_Array;
   function To_Str (A : Octet_Array) return String_Literal.Octet_Array is
      R : String_Literal.Octet_Array (A'Range);
   begin
      for I in A'Range loop
         R (I) := String_Literal.Octet (A (I));
      end loop;
      return R;
   end To_Str;

   ---------------------------------------------------------------------
   --  Encode
   ---------------------------------------------------------------------

   procedure Encode
     (Headers     : Header_Block;
      Output      : in out Octet_Array;
      Output_Last : out Natural;
      Output_OK   : out Boolean)
   is
      Out_Idx : Integer := Output'First - 1;

      --  Helpers writing into Output starting at Out_Idx + 1; on
      --  failure they set Output_OK=False and we abort.

      --  Inline integer encode at Out_Idx + 1 using a small scratch
      --  the size of the worst-case prefix + continuation bytes
      --  (4 bytes covers our 2**21 cap with N=4..7).
      procedure Emit_Integer
        (Discriminator : U8;
         N             : Int_Codec.Prefix_Bits;
         Value         : Natural)
      with Pre => Out_Idx + 1 <= Output'Last;

      procedure Emit_Integer
        (Discriminator : U8;
         N             : Int_Codec.Prefix_Bits;
         Value         : Natural)
      is
         Scratch : Int_Codec.Octet_Array (1 .. 4) := (others => 0);
         IC_Last : Natural;
         IC_OK   : Boolean;
      begin
         Scratch (1) := Int_Codec.Octet (Discriminator);
         Int_Codec.Encode
           (Value       => Value,
            N           => N,
            Output      => Scratch,
            Output_Last => IC_Last,
            Output_OK   => IC_OK);
         if not IC_OK then
            Output_OK := False;
            return;
         end if;
         if Out_Idx + IC_Last > Output'Last then
            Output_OK := False;
            return;
         end if;
         for I in 1 .. IC_Last loop
            Out_Idx := Out_Idx + 1;
            Output (Out_Idx) := U8 (Scratch (I));
         end loop;
      end Emit_Integer;

      procedure Emit_String_Raw (S : String);
      procedure Emit_String_Raw (S : String) is
         Scratch : String_Literal.Octet_Array (1 .. 1 + 4 + S'Length + 1) :=
           (others => 0);
         Input   : String_Literal.Octet_Array (1 .. S'Length);
         SL_Last : Natural;
         SL_OK   : Boolean;
      begin
         for I in 1 .. S'Length loop
            Input (I) :=
              String_Literal.Octet (Character'Pos (S (S'First + I - 1)));
         end loop;
         String_Literal.Encode_Raw
           (Input       => Input,
            Output      => Scratch,
            Output_Last => SL_Last,
            Output_OK   => SL_OK);
         if not SL_OK then
            Output_OK := False;
            return;
         end if;
         if Out_Idx + SL_Last > Output'Last then
            Output_OK := False;
            return;
         end if;
         for I in 1 .. SL_Last loop
            Out_Idx := Out_Idx + 1;
            Output (Out_Idx) := U8 (Scratch (I));
         end loop;
      end Emit_String_Raw;

   begin
      Output_OK := True;

      for H of Headers loop
         declare
            Found_Index : Natural;
            Exact_Match : Boolean;
         begin
            Static_Table.Find
              (Name        => H.Name (1 .. H.Name_Last),
               Value       => H.Value (1 .. H.Value_Last),
               Found_Index => Found_Index,
               Exact_Match => Exact_Match);

            if Exact_Match then
               --  §6.1 Indexed Header Field. Discriminator: 1xxxxxxx.
               Emit_Integer
                 (Discriminator => 16#80#,
                  N             => 7,
                  Value         => Found_Index);

            elsif Found_Index > 0 then
               --  §6.2.2 Literal Without Indexing, name from index.
               --  Discriminator: 0000xxxx (high nibble = 0x00). v0.2
               --  used Never-Indexed (0x10) here, but Python grpcio
               --  RST_STREAMs on receiving 0x10 for response headers
               --  even though it's spec-legal. Switching to Without-
               --  Indexing (0x00) is interoperable with both grpcurl
               --  and grpcio and matches what they emit themselves.
               Emit_Integer
                 (Discriminator => 16#00#,
                  N             => 4,
                  Value         => Found_Index);
               Emit_String_Raw
                 (H.Value (1 .. H.Value_Last));

            else
               --  §6.2.2 Literal Without Indexing, literal name.
               if Out_Idx >= Output'Last then
                  Output_OK := False;
                  exit;
               end if;
               Out_Idx := Out_Idx + 1;
               Output (Out_Idx) := 16#00#;
               Emit_String_Raw
                 (H.Name (1 .. H.Name_Last));
               Emit_String_Raw
                 (H.Value (1 .. H.Value_Last));
            end if;

            exit when not Output_OK;
         end;
      end loop;

      if Output_OK then
         Output_Last := Out_Idx;
      else
         Output_Last := Output'First - 1;
      end if;
   end Encode;

   procedure Encode_With_Table
     (Headers       : Header_Block;
      Encoder_Table : in out Dynamic_Table.Table;
      Output        : in out Octet_Array;
      Output_Last   : out Natural;
      Output_OK     : out Boolean)
   is
      Out_Idx : Integer := Output'First - 1;

      procedure Emit_Integer
        (Discriminator : U8; N : Int_Codec.Prefix_Bits; Value : Natural)
      with Pre => Out_Idx + 1 <= Output'Last;
      procedure Emit_Integer
        (Discriminator : U8; N : Int_Codec.Prefix_Bits; Value : Natural)
      is
         Scratch : Int_Codec.Octet_Array (1 .. 4) := (others => 0);
         IC_Last : Natural;
         IC_OK   : Boolean;
      begin
         Scratch (1) := Int_Codec.Octet (Discriminator);
         Int_Codec.Encode (Value, N, Scratch, IC_Last, IC_OK);
         if not IC_OK or else Out_Idx + IC_Last > Output'Last then
            Output_OK := False; return;
         end if;
         for I in 1 .. IC_Last loop
            Out_Idx := Out_Idx + 1;
            Output (Out_Idx) := U8 (Scratch (I));
         end loop;
      end Emit_Integer;

      procedure Emit_String_Raw (S : String);
      procedure Emit_String_Raw (S : String) is
         Scratch : String_Literal.Octet_Array
           (1 .. 1 + 4 + S'Length + 1) := (others => 0);
         Input   : String_Literal.Octet_Array (1 .. S'Length);
         SL_Last : Natural;
         SL_OK   : Boolean;
      begin
         for I in 1 .. S'Length loop
            Input (I) := String_Literal.Octet
              (Character'Pos (S (S'First + I - 1)));
         end loop;
         String_Literal.Encode_Raw (Input, Scratch, SL_Last, SL_OK);
         if not SL_OK or else Out_Idx + SL_Last > Output'Last then
            Output_OK := False; return;
         end if;
         for I in 1 .. SL_Last loop
            Out_Idx := Out_Idx + 1;
            Output (Out_Idx) := U8 (Scratch (I));
         end loop;
      end Emit_String_Raw;

   begin
      Output_OK := True;
      for H of Headers loop
         declare
            Name  : String renames H.Name (1 .. H.Name_Last);
            Value : String renames H.Value (1 .. H.Value_Last);
            S_Idx   : Natural;
            S_Exact : Boolean;
            D_Idx   : Natural;
            D_Exact : Boolean;
         begin
            Static_Table.Find (Name, Value, S_Idx, S_Exact);

            if S_Exact then
               Emit_Integer (16#80#, 7, S_Idx);
            else
               Dynamic_Table.Find
                 (Encoder_Table, Name, Value, D_Idx, D_Exact);

               if D_Exact then
                  Emit_Integer (16#80#, 7, D_Idx + 61);
               elsif D_Idx > 0 then
                  Emit_Integer (16#40#, 6, D_Idx + 61);
                  Emit_String_Raw (Value);
                  Dynamic_Table.Add (Encoder_Table, Name, Value);
               elsif S_Idx > 0 then
                  Emit_Integer (16#40#, 6, S_Idx);
                  Emit_String_Raw (Value);
                  Dynamic_Table.Add (Encoder_Table, Name, Value);
               else
                  if Out_Idx >= Output'Last then
                     Output_OK := False; exit;
                  end if;
                  Out_Idx := Out_Idx + 1;
                  Output (Out_Idx) := 16#40#;
                  Emit_String_Raw (Name);
                  Emit_String_Raw (Value);
                  Dynamic_Table.Add (Encoder_Table, Name, Value);
               end if;
            end if;
            exit when not Output_OK;
         end;
      end loop;
      Output_Last := (if Output_OK then Out_Idx else Output'First - 1);
   end Encode_With_Table;

   ---------------------------------------------------------------------
   --  Decode
   ---------------------------------------------------------------------

   procedure Decode
     (Input         : Octet_Array;
      Headers       : in out Header_Block;
      Headers_Last  : out Natural;
      Output_OK     : out Boolean;
      Decoder_State : in out Dynamic_Table.Table)
   is
      Idx        : Integer := Input'First;
      Hdr_Idx    : Integer := Headers'First - 1;
      Ic_Input   : constant Int_Codec.Octet_Array := To_Int (Input);
      Sl_Input   : constant String_Literal.Octet_Array := To_Str (Input);
   begin
      Output_OK    := True;
      Headers_Last := Headers'First - 1;

      while Idx <= Input'Last loop
         declare
            B : constant U8 := Input (Idx);
            Index_Value : Natural;
            IC_Last     : Natural;
            IC_OK       : Boolean;
         begin
            if (B and 16#80#) /= 0 then
               --  §6.1 Indexed Header Field: 1xxxxxxx, 7-prefix.
               Int_Codec.Decode
                 (Input     => Ic_Input,
                  First     => Idx,
                  N         => 7,
                  Value     => Index_Value,
                  Last      => IC_Last,
                  Output_OK => IC_OK);
               if not IC_OK or else Index_Value = 0 then
                  Output_OK := False;
                  return;
               end if;
               if Hdr_Idx >= Headers'Last then
                  Output_OK := False;
                  return;
               end if;
               Hdr_Idx := Hdr_Idx + 1;
               if Index_Value <= 61 then
                  declare
                     N_Buf  : String (1 .. Max_Header_Length);
                     N_Last : Natural;
                     V_Buf  : String (1 .. Max_Header_Length);
                     V_Last : Natural;
                  begin
                     Static_Table.Get_Name
                       (Index_Value, N_Buf, N_Last);
                     Static_Table.Get_Value
                       (Index_Value, V_Buf, V_Last);
                     Headers (Hdr_Idx).Name (1 .. N_Last) :=
                       N_Buf (1 .. N_Last);
                     Headers (Hdr_Idx).Name_Last := N_Last;
                     if V_Last > 0 then
                        Headers (Hdr_Idx).Value (1 .. V_Last) :=
                          V_Buf (1 .. V_Last);
                     end if;
                     Headers (Hdr_Idx).Value_Last := V_Last;
                  end;
               else
                  --  Dynamic table — entry index is (Index_Value - 61).
                  declare
                     N_Buf  : String (1 .. Max_Header_Length);
                     N_Last : Natural;
                     V_Buf  : String (1 .. Max_Header_Length);
                     V_Last : Natural;
                     DT_OK  : Boolean;
                  begin
                     Dynamic_Table.Lookup
                       (Decoder_State,
                        Index      => Index_Value - 61,
                        Name       => N_Buf,
                        Name_Last  => N_Last,
                        Value      => V_Buf,
                        Value_Last => V_Last,
                        OK         => DT_OK);
                     if not DT_OK then
                        Output_OK := False;
                        return;
                     end if;
                     Headers (Hdr_Idx).Name (1 .. N_Last) :=
                       N_Buf (1 .. N_Last);
                     Headers (Hdr_Idx).Name_Last := N_Last;
                     if V_Last > 0 then
                        Headers (Hdr_Idx).Value (1 .. V_Last) :=
                          V_Buf (1 .. V_Last);
                     end if;
                     Headers (Hdr_Idx).Value_Last := V_Last;
                  end;
               end if;
               Idx := IC_Last + 1;

            elsif (B and 16#E0#) = 16#20# then
               --  §6.3 Dynamic Table Size Update: 001xxxxx, 5-prefix.
               --  Apply directly; the SETTINGS_HEADER_TABLE_SIZE
               --  upper bound check is the caller's responsibility.
               Int_Codec.Decode
                 (Input     => Ic_Input,
                  First     => Idx,
                  N         => 5,
                  Value     => Index_Value,
                  Last      => IC_Last,
                  Output_OK => IC_OK);
               if not IC_OK then
                  Output_OK := False;
                  return;
               end if;
               Dynamic_Table.Set_Max_Size
                 (Decoder_State, Index_Value);
               Idx := IC_Last + 1;

            else
               --  §6.2.* literal: 01xxxxxx (incremental indexing,
               --  6-prefix), 0001xxxx (never indexed, 4-prefix),
               --  or 0000xxxx (without indexing, 4-prefix). Only
               --  the 0x40 (incremental) form is added to our
               --  decoder dynamic table.
               declare
                  Pfx_N      : Int_Codec.Prefix_Bits;
                  Name_Idx   : Natural;
                  Has_Name   : Boolean;
                  Add_Entry  : constant Boolean :=
                    (B and 16#40#) /= 0;
               begin
                  if Add_Entry then
                     Pfx_N := 6;
                  else
                     Pfx_N := 4;
                  end if;
                  Int_Codec.Decode
                    (Input     => Ic_Input,
                     First     => Idx,
                     N         => Pfx_N,
                     Value     => Name_Idx,
                     Last      => IC_Last,
                     Output_OK => IC_OK);
                  if not IC_OK then
                     Output_OK := False;
                     return;
                  end if;
                  Has_Name := Name_Idx > 0;

                  if Hdr_Idx >= Headers'Last then
                     Output_OK := False;
                     return;
                  end if;
                  Hdr_Idx := Hdr_Idx + 1;

                  if Has_Name then
                     if Name_Idx <= 61 then
                        declare
                           N_Buf  : String (1 .. Max_Header_Length);
                           N_Last : Natural;
                        begin
                           Static_Table.Get_Name
                             (Name_Idx, N_Buf, N_Last);
                           Headers (Hdr_Idx).Name (1 .. N_Last) :=
                             N_Buf (1 .. N_Last);
                           Headers (Hdr_Idx).Name_Last := N_Last;
                        end;
                     else
                        declare
                           N_Buf  : String (1 .. Max_Header_Length);
                           N_Last : Natural;
                           V_Buf  : String (1 .. Max_Header_Length);
                           V_Last : Natural;
                           DT_OK  : Boolean;
                        begin
                           Dynamic_Table.Lookup
                             (Decoder_State,
                              Index      => Name_Idx - 61,
                              Name       => N_Buf,
                              Name_Last  => N_Last,
                              Value      => V_Buf,
                              Value_Last => V_Last,
                              OK         => DT_OK);
                           if not DT_OK then
                              Output_OK := False;
                              return;
                           end if;
                           Headers (Hdr_Idx).Name (1 .. N_Last) :=
                             N_Buf (1 .. N_Last);
                           Headers (Hdr_Idx).Name_Last := N_Last;
                        end;
                     end if;
                     Idx := IC_Last + 1;
                  else
                     if IC_Last + 1 > Input'Last then
                        Output_OK := False;
                        return;
                     end if;
                     declare
                        Name_Buf  : String_Literal.Octet_Array
                          (Headers (Hdr_Idx + 0).Name'Range);
                        SL_Out    : Natural;
                        SL_Cons   : Natural;
                        SL_OK     : Boolean;
                     begin
                        String_Literal.Decode
                          (Input       => Sl_Input,
                           First       => IC_Last + 1,
                           Output      => Name_Buf,
                           Last        => SL_Cons,
                           Output_Last => SL_Out,
                           Output_OK   => SL_OK);
                        if not SL_OK then
                           Output_OK := False;
                           return;
                        end if;
                        for I in 1 .. SL_Out loop
                           Headers (Hdr_Idx).Name (I) :=
                             Character'Val (Natural (Name_Buf (I)));
                        end loop;
                        Headers (Hdr_Idx).Name_Last := SL_Out;
                        Idx := SL_Cons + 1;
                     end;
                  end if;

                  if Idx > Input'Last then
                     Output_OK := False;
                     return;
                  end if;
                  declare
                     Val_Buf  : String_Literal.Octet_Array
                       (Headers (Hdr_Idx).Value'Range);
                     SL_Out    : Natural;
                     SL_Cons   : Natural;
                     SL_OK     : Boolean;
                  begin
                     String_Literal.Decode
                       (Input       => Sl_Input,
                        First       => Idx,
                        Output      => Val_Buf,
                        Last        => SL_Cons,
                        Output_Last => SL_Out,
                        Output_OK   => SL_OK);
                     if not SL_OK then
                        Output_OK := False;
                        return;
                     end if;
                     for I in 1 .. SL_Out loop
                        Headers (Hdr_Idx).Value (I) :=
                          Character'Val (Natural (Val_Buf (I)));
                     end loop;
                     Headers (Hdr_Idx).Value_Last := SL_Out;
                     Idx := SL_Cons + 1;
                  end;

                  --  §6.2.1 incremental indexing — add the just-
                  --  decoded (name, value) to the dynamic table so
                  --  later indices can refer back to it.
                  if Add_Entry then
                     Dynamic_Table.Add
                       (Decoder_State,
                        Headers (Hdr_Idx).Name
                          (1 .. Headers (Hdr_Idx).Name_Last),
                        Headers (Hdr_Idx).Value
                          (1 .. Headers (Hdr_Idx).Value_Last));
                  end if;
               end;
            end if;
         end;
      end loop;

      Headers_Last := Hdr_Idx;
   end Decode;

end Http2_Core.Hpack;
