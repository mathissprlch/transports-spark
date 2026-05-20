separate (Tls_Core.Cert_Chain)
procedure Parse_Ecdsa_Sig_Der
  (Sig : Octet_Array;
   R   : out Tls_Core.Ecdsa_P256.Component;
   S   : out Tls_Core.Ecdsa_P256.Component;
   OK  : out Boolean)
is
   --  Inline a tiny DER walker — same shape as Tls_Core.Cert.Read_Tlv
   --  but bounded to <= 80 bytes so we don't need a long-form length
   --  parser path.
   procedure Read_Tlv_Small
     (Buf : Octet_Array;
      Pos : Natural;
      Tag : out Octet;
      VP  : out Natural;
      VL  : out Natural;
      Nx  : out Natural;
      Ok  : out Boolean)
   with
     Pre  => Buf'First = 1 and then Buf'Last < Integer'Last - 16,
     Post =>
       (if Ok
        then
          VP in Buf'First .. Buf'Last + 1
          and then VL <= Buf'Length
          and then (if VL > 0
                    then VP in Buf'Range and then VP + VL - 1 in Buf'Range)
          and then Nx = VP + VL);

   procedure Read_Tlv_Small
     (Buf : Octet_Array;
      Pos : Natural;
      Tag : out Octet;
      VP  : out Natural;
      VL  : out Natural;
      Nx  : out Natural;
      Ok  : out Boolean)
   is
      L0       : Octet;
      Hdr_End  : Natural;
      Len      : Natural := 0;
      N_Octets : Natural;
   begin
      Tag := 0;
      VP := Buf'First;
      VL := 0;
      Nx := Buf'First;
      Ok := False;
      if Pos < Buf'First or else Pos >= Buf'Last then
         return;
      end if;
      Tag := Buf (Pos);
      L0 := Buf (Pos + 1);
      if L0 < 16#80# then
         Len := Natural (L0);
         Hdr_End := Pos + 1;
      elsif L0 = 16#80# then
         return;
      else
         N_Octets := Natural (L0 and 16#7F#);
         if N_Octets = 0 or else N_Octets > 2 then
            return;
         end if;
         if Pos + 1 + N_Octets > Buf'Last then
            return;
         end if;
         Len := 0;
         for I in 1 .. N_Octets loop
            --  Before iter I, Len < 256**(I-1). Each step at most
            --  multiplies by 256 and adds < 256, so Len stays
            --  < 256**I. With N_Octets <= 2, Len < 65536 at exit.
            pragma Loop_Invariant (I in 1 .. 2);
            pragma Loop_Invariant (if I = 1 then Len = 0 else Len < 256);
            Len := Len * 256 + Natural (Buf (Pos + 1 + I));
         end loop;
         Hdr_End := Pos + 1 + N_Octets;
      end if;
      if Len > Buf'Last - Hdr_End then
         return;
      end if;
      VP := Hdr_End + 1;
      VL := Len;
      Nx := Hdr_End + 1 + Len;
      Ok := True;
   end Read_Tlv_Small;

   Outer_Tag                    : Octet;
   Outer_VP, Outer_VL, Outer_Nx : Natural;
   Outer_OK                     : Boolean;
   R_Tag                        : Octet;
   R_VP, R_VL, R_Nx             : Natural;
   R_OK                         : Boolean;
   S_Tag                        : Octet;
   S_VP, S_VL, S_Nx             : Natural;
   S_OK                         : Boolean;
begin
   R := [others => 0];
   S := [others => 0];
   OK := False;

   Read_Tlv_Small
     (Sig, Sig'First, Outer_Tag, Outer_VP, Outer_VL, Outer_Nx, Outer_OK);
   if not Outer_OK or else Outer_Tag /= 16#30# then
      return;
   end if;
   if Outer_Nx /= Sig'Last + 1 then
      return;
   end if;

   Read_Tlv_Small (Sig, Outer_VP, R_Tag, R_VP, R_VL, R_Nx, R_OK);
   if not R_OK or else R_Tag /= 16#02# then
      return;
   end if;
   if R_Nx > Outer_VP + Outer_VL then
      return;
   end if;

   Read_Tlv_Small (Sig, R_Nx, S_Tag, S_VP, S_VL, S_Nx, S_OK);
   if not S_OK or else S_Tag /= 16#02# then
      return;
   end if;
   if S_Nx /= Outer_VP + Outer_VL then
      return;
   end if;

   --  Strip a leading 0x00 sign byte if present, then left-pad to 32 BE.
   declare
      RL : Natural := R_VL;
      RP : Natural := R_VP;
      SL : Natural := S_VL;
      SP : Natural := S_VP;
   begin
      if RL > 0
        and then RP <= Sig'Last
        and then Sig (RP) = 16#00#
        and then RL > 1
      then
         RP := RP + 1;
         RL := RL - 1;
      end if;
      if SL > 0
        and then SP <= Sig'Last
        and then Sig (SP) = 16#00#
        and then SL > 1
      then
         SP := SP + 1;
         SL := SL - 1;
      end if;
      if RL > 32 or else SL > 32 or else RL = 0 or else SL = 0 then
         return;
      end if;
      --  Right-aligned (BE) into 32-byte component.
      if RP + RL - 1 > Sig'Last or else SP + SL - 1 > Sig'Last then
         return;
      end if;
      for I in 0 .. RL - 1 loop
         R (32 - RL + 1 + I) := Sig (RP + I);
      end loop;
      for I in 0 .. SL - 1 loop
         S (32 - SL + 1 + I) := Sig (SP + I);
      end loop;
      OK := True;
   end;
end Parse_Ecdsa_Sig_Der;
