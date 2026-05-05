--  Http2_Core.Hpack.Huffman — RFC 7541 §5.2 + Appendix B.
--
--  Source: RFC 7541 — HPACK: Header Compression for HTTP/2,
--  IETF Standard, May 2015. Appendix B (page 28+) gives the
--  Huffman code table for HTTP/2 header literals.
--
--  Each row pairs a symbol (0..255 = byte value, 256 = EOS) with
--  a left-aligned 32-bit code and the actual code-length in bits.
--  Codes were transcribed from nghttp2's public reference table
--  (`lib/nghttp2_hd_huffman_data.c`, `huff_sym_table`) on
--  2026-04-12 — bit-equivalent to RFC 7541 §Appendix B.
--
--  v0.2 scope per ../specs/SCOPE.md: encoder emits H=0 (raw)
--  by default; the table here is required for DECODING incoming
--  H=1 strings, which standards-compliant peers may emit at any
--  time. Encode_To_Huffman is provided too for completeness; the
--  high-level encoder in the parent Hpack package selects raw or
--  Huffman per outgoing string.

with Interfaces;

package Http2_Core.Hpack.Huffman
with SPARK_Mode
is

   --  256 bytes plus the End-of-String pseudo-symbol (RFC 7541 §5.2,
   --  used only as terminator/padding by the encoder).
   subtype Symbol is Natural range 0 .. 256;

   type Code_Bits is range 1 .. 30;

   type Huffman_Code is record
      Bits : Code_Bits;
      Code : Interfaces.Unsigned_32;
   end record;

   type Code_Table_T is array (Symbol) of Huffman_Code;

   --  Codes are LEFT-aligned to 32 bits; the actual code is the high
   --  `Bits` bits. EOS (symbol 256) is 30 bits all 1s — the longest
   --  code, used by the encoder to pad incomplete final bytes.
   Code_Table : constant Code_Table_T :=
     (

        0 => (Bits => 13, Code => 16#FFC00000#),  --    0 (.)
        1 => (Bits => 23, Code => 16#FFFFB000#),  --    1 (.)
        2 => (Bits => 28, Code => 16#FFFFFE20#),  --    2 (.)
        3 => (Bits => 28, Code => 16#FFFFFE30#),  --    3 (.)
        4 => (Bits => 28, Code => 16#FFFFFE40#),  --    4 (.)
        5 => (Bits => 28, Code => 16#FFFFFE50#),  --    5 (.)
        6 => (Bits => 28, Code => 16#FFFFFE60#),  --    6 (.)
        7 => (Bits => 28, Code => 16#FFFFFE70#),  --    7 (.)
        8 => (Bits => 28, Code => 16#FFFFFE80#),  --    8 (.)
        9 => (Bits => 24, Code => 16#FFFFEA00#),  --    9 (.)
       10 => (Bits => 30, Code => 16#FFFFFFF0#),  --   10 (.)
       11 => (Bits => 28, Code => 16#FFFFFE90#),  --   11 (.)
       12 => (Bits => 28, Code => 16#FFFFFEA0#),  --   12 (.)
       13 => (Bits => 30, Code => 16#FFFFFFF4#),  --   13 (.)
       14 => (Bits => 28, Code => 16#FFFFFEB0#),  --   14 (.)
       15 => (Bits => 28, Code => 16#FFFFFEC0#),  --   15 (.)
       16 => (Bits => 28, Code => 16#FFFFFED0#),  --   16 (.)
       17 => (Bits => 28, Code => 16#FFFFFEE0#),  --   17 (.)
       18 => (Bits => 28, Code => 16#FFFFFEF0#),  --   18 (.)
       19 => (Bits => 28, Code => 16#FFFFFF00#),  --   19 (.)
       20 => (Bits => 28, Code => 16#FFFFFF10#),  --   20 (.)
       21 => (Bits => 28, Code => 16#FFFFFF20#),  --   21 (.)
       22 => (Bits => 30, Code => 16#FFFFFFF8#),  --   22 (.)
       23 => (Bits => 28, Code => 16#FFFFFF30#),  --   23 (.)
       24 => (Bits => 28, Code => 16#FFFFFF40#),  --   24 (.)
       25 => (Bits => 28, Code => 16#FFFFFF50#),  --   25 (.)
       26 => (Bits => 28, Code => 16#FFFFFF60#),  --   26 (.)
       27 => (Bits => 28, Code => 16#FFFFFF70#),  --   27 (.)
       28 => (Bits => 28, Code => 16#FFFFFF80#),  --   28 (.)
       29 => (Bits => 28, Code => 16#FFFFFF90#),  --   29 (.)
       30 => (Bits => 28, Code => 16#FFFFFFA0#),  --   30 (.)
       31 => (Bits => 28, Code => 16#FFFFFFB0#),  --   31 (.)
       32 => (Bits =>  6, Code => 16#50000000#),  --   32 ( )
       33 => (Bits => 10, Code => 16#FE000000#),  --   33 (!)
       34 => (Bits => 10, Code => 16#FE400000#),  --   34 (")
       35 => (Bits => 12, Code => 16#FFA00000#),  --   35 (#)
       36 => (Bits => 13, Code => 16#FFC80000#),  --   36 ($)
       37 => (Bits =>  6, Code => 16#54000000#),  --   37 (%)
       38 => (Bits =>  8, Code => 16#F8000000#),  --   38 (&)
       39 => (Bits => 11, Code => 16#FF400000#),  --   39 (')
       40 => (Bits => 10, Code => 16#FE800000#),  --   40 (()
       41 => (Bits => 10, Code => 16#FEC00000#),  --   41 ())
       42 => (Bits =>  8, Code => 16#F9000000#),  --   42 (*)
       43 => (Bits => 11, Code => 16#FF600000#),  --   43 (+)
       44 => (Bits =>  8, Code => 16#FA000000#),  --   44 (,)
       45 => (Bits =>  6, Code => 16#58000000#),  --   45 (-)
       46 => (Bits =>  6, Code => 16#5C000000#),  --   46 (.)
       47 => (Bits =>  6, Code => 16#60000000#),  --   47 (/)
       48 => (Bits =>  5, Code => 16#00000000#),  --   48 (0)
       49 => (Bits =>  5, Code => 16#08000000#),  --   49 (1)
       50 => (Bits =>  5, Code => 16#10000000#),  --   50 (2)
       51 => (Bits =>  6, Code => 16#64000000#),  --   51 (3)
       52 => (Bits =>  6, Code => 16#68000000#),  --   52 (4)
       53 => (Bits =>  6, Code => 16#6C000000#),  --   53 (5)
       54 => (Bits =>  6, Code => 16#70000000#),  --   54 (6)
       55 => (Bits =>  6, Code => 16#74000000#),  --   55 (7)
       56 => (Bits =>  6, Code => 16#78000000#),  --   56 (8)
       57 => (Bits =>  6, Code => 16#7C000000#),  --   57 (9)
       58 => (Bits =>  7, Code => 16#B8000000#),  --   58 (:)
       59 => (Bits =>  8, Code => 16#FB000000#),  --   59 (;)
       60 => (Bits => 15, Code => 16#FFF80000#),  --   60 (<)
       61 => (Bits =>  6, Code => 16#80000000#),  --   61 (=)
       62 => (Bits => 12, Code => 16#FFB00000#),  --   62 (>)
       63 => (Bits => 10, Code => 16#FF000000#),  --   63 (?)
       64 => (Bits => 13, Code => 16#FFD00000#),  --   64 (@)
       65 => (Bits =>  6, Code => 16#84000000#),  --   65 (A)
       66 => (Bits =>  7, Code => 16#BA000000#),  --   66 (B)
       67 => (Bits =>  7, Code => 16#BC000000#),  --   67 (C)
       68 => (Bits =>  7, Code => 16#BE000000#),  --   68 (D)
       69 => (Bits =>  7, Code => 16#C0000000#),  --   69 (E)
       70 => (Bits =>  7, Code => 16#C2000000#),  --   70 (F)
       71 => (Bits =>  7, Code => 16#C4000000#),  --   71 (G)
       72 => (Bits =>  7, Code => 16#C6000000#),  --   72 (H)
       73 => (Bits =>  7, Code => 16#C8000000#),  --   73 (I)
       74 => (Bits =>  7, Code => 16#CA000000#),  --   74 (J)
       75 => (Bits =>  7, Code => 16#CC000000#),  --   75 (K)
       76 => (Bits =>  7, Code => 16#CE000000#),  --   76 (L)
       77 => (Bits =>  7, Code => 16#D0000000#),  --   77 (M)
       78 => (Bits =>  7, Code => 16#D2000000#),  --   78 (N)
       79 => (Bits =>  7, Code => 16#D4000000#),  --   79 (O)
       80 => (Bits =>  7, Code => 16#D6000000#),  --   80 (P)
       81 => (Bits =>  7, Code => 16#D8000000#),  --   81 (Q)
       82 => (Bits =>  7, Code => 16#DA000000#),  --   82 (R)
       83 => (Bits =>  7, Code => 16#DC000000#),  --   83 (S)
       84 => (Bits =>  7, Code => 16#DE000000#),  --   84 (T)
       85 => (Bits =>  7, Code => 16#E0000000#),  --   85 (U)
       86 => (Bits =>  7, Code => 16#E2000000#),  --   86 (V)
       87 => (Bits =>  7, Code => 16#E4000000#),  --   87 (W)
       88 => (Bits =>  8, Code => 16#FC000000#),  --   88 (X)
       89 => (Bits =>  7, Code => 16#E6000000#),  --   89 (Y)
       90 => (Bits =>  8, Code => 16#FD000000#),  --   90 (Z)
       91 => (Bits => 13, Code => 16#FFD80000#),  --   91 ([)
       92 => (Bits => 19, Code => 16#FFFE0000#),  --   92 (\)
       93 => (Bits => 13, Code => 16#FFE00000#),  --   93 (])
       94 => (Bits => 14, Code => 16#FFF00000#),  --   94 (^)
       95 => (Bits =>  6, Code => 16#88000000#),  --   95 (_)
       96 => (Bits => 15, Code => 16#FFFA0000#),  --   96 (`)
       97 => (Bits =>  5, Code => 16#18000000#),  --   97 (a)
       98 => (Bits =>  6, Code => 16#8C000000#),  --   98 (b)
       99 => (Bits =>  5, Code => 16#20000000#),  --   99 (c)
      100 => (Bits =>  6, Code => 16#90000000#),  --  100 (d)
      101 => (Bits =>  5, Code => 16#28000000#),  --  101 (e)
      102 => (Bits =>  6, Code => 16#94000000#),  --  102 (f)
      103 => (Bits =>  6, Code => 16#98000000#),  --  103 (g)
      104 => (Bits =>  6, Code => 16#9C000000#),  --  104 (h)
      105 => (Bits =>  5, Code => 16#30000000#),  --  105 (i)
      106 => (Bits =>  7, Code => 16#E8000000#),  --  106 (j)
      107 => (Bits =>  7, Code => 16#EA000000#),  --  107 (k)
      108 => (Bits =>  6, Code => 16#A0000000#),  --  108 (l)
      109 => (Bits =>  6, Code => 16#A4000000#),  --  109 (m)
      110 => (Bits =>  6, Code => 16#A8000000#),  --  110 (n)
      111 => (Bits =>  5, Code => 16#38000000#),  --  111 (o)
      112 => (Bits =>  6, Code => 16#AC000000#),  --  112 (p)
      113 => (Bits =>  7, Code => 16#EC000000#),  --  113 (q)
      114 => (Bits =>  6, Code => 16#B0000000#),  --  114 (r)
      115 => (Bits =>  5, Code => 16#40000000#),  --  115 (s)
      116 => (Bits =>  5, Code => 16#48000000#),  --  116 (t)
      117 => (Bits =>  6, Code => 16#B4000000#),  --  117 (u)
      118 => (Bits =>  7, Code => 16#EE000000#),  --  118 (v)
      119 => (Bits =>  7, Code => 16#F0000000#),  --  119 (w)
      120 => (Bits =>  7, Code => 16#F2000000#),  --  120 (x)
      121 => (Bits =>  7, Code => 16#F4000000#),  --  121 (y)
      122 => (Bits =>  7, Code => 16#F6000000#),  --  122 (z)
      123 => (Bits => 15, Code => 16#FFFC0000#),  --  123 ({)
      124 => (Bits => 11, Code => 16#FF800000#),  --  124 (|)
      125 => (Bits => 14, Code => 16#FFF40000#),  --  125 (})
      126 => (Bits => 13, Code => 16#FFE80000#),  --  126 (~)
      127 => (Bits => 28, Code => 16#FFFFFFC0#),  --  127 (.)
      128 => (Bits => 20, Code => 16#FFFE6000#),  --  128 (.)
      129 => (Bits => 22, Code => 16#FFFF4800#),  --  129 (.)
      130 => (Bits => 20, Code => 16#FFFE7000#),  --  130 (.)
      131 => (Bits => 20, Code => 16#FFFE8000#),  --  131 (.)
      132 => (Bits => 22, Code => 16#FFFF4C00#),  --  132 (.)
      133 => (Bits => 22, Code => 16#FFFF5000#),  --  133 (.)
      134 => (Bits => 22, Code => 16#FFFF5400#),  --  134 (.)
      135 => (Bits => 23, Code => 16#FFFFB200#),  --  135 (.)
      136 => (Bits => 22, Code => 16#FFFF5800#),  --  136 (.)
      137 => (Bits => 23, Code => 16#FFFFB400#),  --  137 (.)
      138 => (Bits => 23, Code => 16#FFFFB600#),  --  138 (.)
      139 => (Bits => 23, Code => 16#FFFFB800#),  --  139 (.)
      140 => (Bits => 23, Code => 16#FFFFBA00#),  --  140 (.)
      141 => (Bits => 23, Code => 16#FFFFBC00#),  --  141 (.)
      142 => (Bits => 24, Code => 16#FFFFEB00#),  --  142 (.)
      143 => (Bits => 23, Code => 16#FFFFBE00#),  --  143 (.)
      144 => (Bits => 24, Code => 16#FFFFEC00#),  --  144 (.)
      145 => (Bits => 24, Code => 16#FFFFED00#),  --  145 (.)
      146 => (Bits => 22, Code => 16#FFFF5C00#),  --  146 (.)
      147 => (Bits => 23, Code => 16#FFFFC000#),  --  147 (.)
      148 => (Bits => 24, Code => 16#FFFFEE00#),  --  148 (.)
      149 => (Bits => 23, Code => 16#FFFFC200#),  --  149 (.)
      150 => (Bits => 23, Code => 16#FFFFC400#),  --  150 (.)
      151 => (Bits => 23, Code => 16#FFFFC600#),  --  151 (.)
      152 => (Bits => 23, Code => 16#FFFFC800#),  --  152 (.)
      153 => (Bits => 21, Code => 16#FFFEE000#),  --  153 (.)
      154 => (Bits => 22, Code => 16#FFFF6000#),  --  154 (.)
      155 => (Bits => 23, Code => 16#FFFFCA00#),  --  155 (.)
      156 => (Bits => 22, Code => 16#FFFF6400#),  --  156 (.)
      157 => (Bits => 23, Code => 16#FFFFCC00#),  --  157 (.)
      158 => (Bits => 23, Code => 16#FFFFCE00#),  --  158 (.)
      159 => (Bits => 24, Code => 16#FFFFEF00#),  --  159 (.)
      160 => (Bits => 22, Code => 16#FFFF6800#),  --  160 (.)
      161 => (Bits => 21, Code => 16#FFFEE800#),  --  161 (.)
      162 => (Bits => 20, Code => 16#FFFE9000#),  --  162 (.)
      163 => (Bits => 22, Code => 16#FFFF6C00#),  --  163 (.)
      164 => (Bits => 22, Code => 16#FFFF7000#),  --  164 (.)
      165 => (Bits => 23, Code => 16#FFFFD000#),  --  165 (.)
      166 => (Bits => 23, Code => 16#FFFFD200#),  --  166 (.)
      167 => (Bits => 21, Code => 16#FFFEF000#),  --  167 (.)
      168 => (Bits => 23, Code => 16#FFFFD400#),  --  168 (.)
      169 => (Bits => 22, Code => 16#FFFF7400#),  --  169 (.)
      170 => (Bits => 22, Code => 16#FFFF7800#),  --  170 (.)
      171 => (Bits => 24, Code => 16#FFFFF000#),  --  171 (.)
      172 => (Bits => 21, Code => 16#FFFEF800#),  --  172 (.)
      173 => (Bits => 22, Code => 16#FFFF7C00#),  --  173 (.)
      174 => (Bits => 23, Code => 16#FFFFD600#),  --  174 (.)
      175 => (Bits => 23, Code => 16#FFFFD800#),  --  175 (.)
      176 => (Bits => 21, Code => 16#FFFF0000#),  --  176 (.)
      177 => (Bits => 21, Code => 16#FFFF0800#),  --  177 (.)
      178 => (Bits => 22, Code => 16#FFFF8000#),  --  178 (.)
      179 => (Bits => 21, Code => 16#FFFF1000#),  --  179 (.)
      180 => (Bits => 23, Code => 16#FFFFDA00#),  --  180 (.)
      181 => (Bits => 22, Code => 16#FFFF8400#),  --  181 (.)
      182 => (Bits => 23, Code => 16#FFFFDC00#),  --  182 (.)
      183 => (Bits => 23, Code => 16#FFFFDE00#),  --  183 (.)
      184 => (Bits => 20, Code => 16#FFFEA000#),  --  184 (.)
      185 => (Bits => 22, Code => 16#FFFF8800#),  --  185 (.)
      186 => (Bits => 22, Code => 16#FFFF8C00#),  --  186 (.)
      187 => (Bits => 22, Code => 16#FFFF9000#),  --  187 (.)
      188 => (Bits => 23, Code => 16#FFFFE000#),  --  188 (.)
      189 => (Bits => 22, Code => 16#FFFF9400#),  --  189 (.)
      190 => (Bits => 22, Code => 16#FFFF9800#),  --  190 (.)
      191 => (Bits => 23, Code => 16#FFFFE200#),  --  191 (.)
      192 => (Bits => 26, Code => 16#FFFFF800#),  --  192 (.)
      193 => (Bits => 26, Code => 16#FFFFF840#),  --  193 (.)
      194 => (Bits => 20, Code => 16#FFFEB000#),  --  194 (.)
      195 => (Bits => 19, Code => 16#FFFE2000#),  --  195 (.)
      196 => (Bits => 22, Code => 16#FFFF9C00#),  --  196 (.)
      197 => (Bits => 23, Code => 16#FFFFE400#),  --  197 (.)
      198 => (Bits => 22, Code => 16#FFFFA000#),  --  198 (.)
      199 => (Bits => 25, Code => 16#FFFFF600#),  --  199 (.)
      200 => (Bits => 26, Code => 16#FFFFF880#),  --  200 (.)
      201 => (Bits => 26, Code => 16#FFFFF8C0#),  --  201 (.)
      202 => (Bits => 26, Code => 16#FFFFF900#),  --  202 (.)
      203 => (Bits => 27, Code => 16#FFFFFBC0#),  --  203 (.)
      204 => (Bits => 27, Code => 16#FFFFFBE0#),  --  204 (.)
      205 => (Bits => 26, Code => 16#FFFFF940#),  --  205 (.)
      206 => (Bits => 24, Code => 16#FFFFF100#),  --  206 (.)
      207 => (Bits => 25, Code => 16#FFFFF680#),  --  207 (.)
      208 => (Bits => 19, Code => 16#FFFE4000#),  --  208 (.)
      209 => (Bits => 21, Code => 16#FFFF1800#),  --  209 (.)
      210 => (Bits => 26, Code => 16#FFFFF980#),  --  210 (.)
      211 => (Bits => 27, Code => 16#FFFFFC00#),  --  211 (.)
      212 => (Bits => 27, Code => 16#FFFFFC20#),  --  212 (.)
      213 => (Bits => 26, Code => 16#FFFFF9C0#),  --  213 (.)
      214 => (Bits => 27, Code => 16#FFFFFC40#),  --  214 (.)
      215 => (Bits => 24, Code => 16#FFFFF200#),  --  215 (.)
      216 => (Bits => 21, Code => 16#FFFF2000#),  --  216 (.)
      217 => (Bits => 21, Code => 16#FFFF2800#),  --  217 (.)
      218 => (Bits => 26, Code => 16#FFFFFA00#),  --  218 (.)
      219 => (Bits => 26, Code => 16#FFFFFA40#),  --  219 (.)
      220 => (Bits => 28, Code => 16#FFFFFFD0#),  --  220 (.)
      221 => (Bits => 27, Code => 16#FFFFFC60#),  --  221 (.)
      222 => (Bits => 27, Code => 16#FFFFFC80#),  --  222 (.)
      223 => (Bits => 27, Code => 16#FFFFFCA0#),  --  223 (.)
      224 => (Bits => 20, Code => 16#FFFEC000#),  --  224 (.)
      225 => (Bits => 24, Code => 16#FFFFF300#),  --  225 (.)
      226 => (Bits => 20, Code => 16#FFFED000#),  --  226 (.)
      227 => (Bits => 21, Code => 16#FFFF3000#),  --  227 (.)
      228 => (Bits => 22, Code => 16#FFFFA400#),  --  228 (.)
      229 => (Bits => 21, Code => 16#FFFF3800#),  --  229 (.)
      230 => (Bits => 21, Code => 16#FFFF4000#),  --  230 (.)
      231 => (Bits => 23, Code => 16#FFFFE600#),  --  231 (.)
      232 => (Bits => 22, Code => 16#FFFFA800#),  --  232 (.)
      233 => (Bits => 22, Code => 16#FFFFAC00#),  --  233 (.)
      234 => (Bits => 25, Code => 16#FFFFF700#),  --  234 (.)
      235 => (Bits => 25, Code => 16#FFFFF780#),  --  235 (.)
      236 => (Bits => 24, Code => 16#FFFFF400#),  --  236 (.)
      237 => (Bits => 24, Code => 16#FFFFF500#),  --  237 (.)
      238 => (Bits => 26, Code => 16#FFFFFA80#),  --  238 (.)
      239 => (Bits => 23, Code => 16#FFFFE800#),  --  239 (.)
      240 => (Bits => 26, Code => 16#FFFFFAC0#),  --  240 (.)
      241 => (Bits => 27, Code => 16#FFFFFCC0#),  --  241 (.)
      242 => (Bits => 26, Code => 16#FFFFFB00#),  --  242 (.)
      243 => (Bits => 26, Code => 16#FFFFFB40#),  --  243 (.)
      244 => (Bits => 27, Code => 16#FFFFFCE0#),  --  244 (.)
      245 => (Bits => 27, Code => 16#FFFFFD00#),  --  245 (.)
      246 => (Bits => 27, Code => 16#FFFFFD20#),  --  246 (.)
      247 => (Bits => 27, Code => 16#FFFFFD40#),  --  247 (.)
      248 => (Bits => 27, Code => 16#FFFFFD60#),  --  248 (.)
      249 => (Bits => 28, Code => 16#FFFFFFE0#),  --  249 (.)
      250 => (Bits => 27, Code => 16#FFFFFD80#),  --  250 (.)
      251 => (Bits => 27, Code => 16#FFFFFDA0#),  --  251 (.)
      252 => (Bits => 27, Code => 16#FFFFFDC0#),  --  252 (.)
      253 => (Bits => 27, Code => 16#FFFFFDE0#),  --  253 (.)
      254 => (Bits => 27, Code => 16#FFFFFE00#),  --  254 (.)
      255 => (Bits => 26, Code => 16#FFFFFB80#),  --  255 (.)
      256 => (Bits => 30, Code => 16#FFFFFFFC#)   --  EOS
     );

   --  Byte sequence type used by the encoder and decoder. Local to
   --  Http2_Core.Hpack to avoid coupling to RFLX runtime types
   --  (HPACK is hand-written; the higher Frame layer bridges to
   --  RFLX.RFLX_Types.Bytes when the encoded HPACK fragment is
   --  written into a HEADERS frame's Payload).
   subtype Octet is Interfaces.Unsigned_8;
   type Octet_Array is array (Positive range <>) of Octet;

   --  Encode `Input` (raw header-string bytes) as a Huffman bit
   --  stream per §5.2. Final byte is padded with the high bits of
   --  the EOS code per §5.2.4. Sets Output_Last to the last
   --  written index; Output_OK = False indicates the caller's
   --  buffer was too small.
   procedure Encode
     (Input       : Octet_Array;
      Output      : in out Octet_Array;
      Output_Last : out Natural;
      Output_OK   : out Boolean)
   with Pre => Output'Length >= 1
               and then Output'Last < Natural'Last
               and then Input'Last < Natural'Last;

   --  Worst-case Huffman expansion: 30 bits per input symbol. Useful
   --  for sizing Output before calling Encode. Caller must bound
   --  Input_Length so the multiplication stays in Natural range —
   --  any realistic header is well under this.
   function Max_Encoded_Length (Input_Length : Natural) return Natural
   is ((Input_Length * 30 + 7) / 8 + 1)
   with Pre => Input_Length <= (Natural'Last - 7) / 30;

   --  Decode a Huffman bit stream `Input` into raw bytes `Output`.
   --  Walks the canonical code table for each emitted symbol; O(257
   --  * 30) bit comparisons per symbol — naive but correct and fine
   --  for v0.2 header-sized inputs (rarely > 256 bytes).
   --  §5.2.3 padding rule: any incomplete final byte MUST be the
   --  most significant bits of the EOS code (i.e. all 1s).
   --  Decoder enforces this; non-1 padding sets Output_OK=False.
   procedure Decode
     (Input       : Octet_Array;
      Output      : in out Octet_Array;
      Output_Last : out Natural;
      Output_OK   : out Boolean)
   with Pre => Output'Length >= 1
               and then Output'Last < Natural'Last
               and then Input'Last < Natural'Last
               and then Input'Length <= Natural'Last / 8;

end Http2_Core.Hpack.Huffman;
