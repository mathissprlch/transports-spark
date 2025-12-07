------------------------------------------------------------------------------
--                              Ada Web Server                              --
--                                                                          --
--                     Copyright (C) 2012-2025, AdaCore                     --
--                                                                          --
--  This library is free software;  you can redistribute it and/or modify   --
--  it under terms of the  GNU General Public License  as published by the  --
--  Free Software  Foundation;  either version 3,  or (at your  option) any --
--  later version. This library is distributed in the hope that it will be  --
--  useful, but WITHOUT ANY WARRANTY;  without even the implied warranty of --
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                    --
--                                                                          --
--  As a special exception under Section 7 of GPL version 3, you are        --
--  granted additional permissions described in the GCC Runtime Library     --
--  Exception, version 3.1, as published by the Free Software Foundation.   --
--                                                                          --
--  You should have received a copy of the GNU General Public License and   --
--  a copy of the GCC Runtime Library Exception along with this program;    --
--  see the files COPYING3 and COPYING.RUNTIME respectively.  If not, see   --
--  <http://www.gnu.org/licenses/>.                                         --
--                                                                          --
--  As a special exception, if other files instantiate generics from this   --
--  unit, or you link this unit with other files to produce an executable,  --
--  this  unit  does not  by itself cause  the resulting executable to be   --
--  covered by the GNU General Public License. This exception does not      --
--  however invalidate any other reasons why the executable file  might be  --
--  covered by the  GNU Public License.                                     --
------------------------------------------------------------------------------

pragma Ada_2022;

pragma Style_Checks ("M32766");
--  Allow long lines

--  This package provides target dependent definitions of constant/types for
--  use by the AWS library. This package should not be directly with'd
--  by an application program.

--  This file is generated automatically, do not modify it by hand! Instead,
--  make changes to aws-os_lib-tmplt.c and rebuild the AWS library.
--  This is the version for darwin-arm64

with Interfaces.C.Strings;
with System;
with GNAT.OS_Lib;

package OS_Lib is

   use Interfaces;

   ---------------------------------
   -- General platform parameters --
   ---------------------------------

   type OS_Type is (Windows, VMS, Other_OS);
   Target_OS                   : constant OS_Type := Other_OS;
   pragma Warnings (Off, Target_OS);
   --  Suppress warnings on Target_OS since it is in general tested for
   --  equality with a constant value to implement conditional compilation,
   --  which normally generates a constant condition warning.

   Target_Name                 : constant String  := "darwin-arm64";

   Executable_Extension : constant String    := "";
   Directory_Separator  : constant Character := '/';
   Path_Separator       : constant Character := ':';

   --  Sizes of various data types

   SIZEOF_unsigned_int         : constant := 4;           --  Size of unsigned int
   SIZEOF_fd_set               : constant := 128;         --  fd_set
   FD_SETSIZE                  : constant := 1024;        --  Max fd value
   SIZEOF_sin_family           : constant := 8;           --  Size of sa.sin_family
   SIN_FAMILY_OFFSET           : constant := 1;           --  sin_family offset in record

   --  Sizes (in bytes) of the components of struct timeval

   --  Poll values


   -----------------
   -- Fcntl flags --
   -----------------


   ----------------------
   -- Ioctl operations --
   ----------------------


   ---------------------------------------
   -- getaddrinfo getnameinfo constants --
   ---------------------------------------


   ------------------
   -- Errno values --
   ------------------

   --  The following constants are defined from <errno.h>


   --------------
   -- Families --
   --------------


   ------------------
   -- Socket modes --
   ------------------


   -----------------
   -- Host errors --
   -----------------


   --------------------
   -- Shutdown modes --
   --------------------


   ---------------------
   -- Protocol levels --
   ---------------------


   -------------------
   -- Request flags --
   -------------------

   --  Flags set on all send(2) calls

   --------------------
   -- Socket options --
   --------------------


   --  Some types

   type nfds_t is mod 2 ** SIZEOF_nfds_t;
   for nfds_t'Size use SIZEOF_nfds_t;

   type FD_Type
     is range -(2 ** (SIZEOF_fd_type - 1)) .. 2 ** (SIZEOF_fd_type - 1) - 1;
   for FD_Type'Size use SIZEOF_fd_type;

   type Events_Type is mod 2 ** SIZEOF_pollfd_events;
   for Events_Type'Size use SIZEOF_pollfd_events;

   type socklen_t is mod 2 ** SIZEOF_socklen_t;
   for socklen_t'Size use SIZEOF_socklen_t;

   type timeval_tv_sec_t
     is range -(2 ** (SIZEOF_tv_sec - 1)) .. 2 ** (SIZEOF_tv_sec - 1) - 1;
   for timeval_tv_sec_t'Size use SIZEOF_tv_sec;

   type timeval_tv_usec_t
     is range -(2 ** (SIZEOF_tv_usec - 1)) .. 2 ** (SIZEOF_tv_usec - 1) - 1;
   for timeval_tv_usec_t'Size use SIZEOF_tv_usec;

   type Timeval is record
      tv_sec  : timeval_tv_sec_t;  -- Seconds
      tv_usec : timeval_tv_usec_t; -- Microseconds
   end record;
   pragma Convention (C, Timeval);

   type sa_family_t is mod 2 ** SIZEOF_sin_family;
   for sa_family_t'Size use SIZEOF_sin_family;

   type In6_Addr is array (1 .. 8) of Interfaces.Unsigned_16;
   pragma Convention (C, In6_Addr);

   type Sockaddr_In6 is record
      Length   : Interfaces.Unsigned_8 := 0;
      Family   : sa_family_t := 0;
      Port     : Interfaces.C.unsigned_short := 0;
      FlowInfo : Interfaces.Unsigned_32 := 0;
      Addr     : In6_Addr := [others => 0];
      Scope_Id : Interfaces.Unsigned_32 := 0;
   end record;
   pragma Convention (C, Sockaddr_In6);

   type Addr_Info;
   type Addr_Info_Access is access all Addr_Info;

   type Addr_Info is record
      ai_flags     : C.int;
      ai_family    : C.int;
      ai_socktype  : C.int;
      ai_protocol  : C.int;
      ai_addrlen   : socklen_t;
      ai_canonname : C.Strings.chars_ptr;
      ai_addr      : System.Address;
      ai_next      : Addr_Info_Access;
   end record;
   pragma Convention (C, Addr_Info);

   --  Some routines

   function GetAddrInfo
     (node    : C.Strings.chars_ptr;
      service : C.Strings.chars_ptr;
      hints   : Addr_Info;
      res     : not null access Addr_Info_Access) return C.int;

   procedure FreeAddrInfo (res : Addr_Info_Access);

   function GAI_StrError (ecode : C.int) return C.Strings.chars_ptr;

   function Socket_StrError (ecode : Integer) return C.Strings.chars_ptr;

   function Set_Sock_Opt
     (S       : C.int;
      Level   : C.int;
      OptName : C.int;
      OptVal  : System.Address;
      OptLen  : C.int) return C.int;

   function C_Ioctl (S : C.int; Req : C.int; Arg : access C.int) return C.int;

   function C_Close (Fd : C.int) return C.int;
   procedure WSA_Startup (Version : C.int; Data : System.Address) is null;
   function Socket_Errno return Integer renames GNAT.OS_Lib.Errno;

   ---------------------------
   -- Secure Socket options --
   ---------------------------


private

   pragma Import (C, GetAddrInfo, "getaddrinfo");
   pragma Import (C, FreeAddrInfo, "freeaddrinfo");
   pragma Import (C, Set_Sock_Opt, "setsockopt");
   pragma Import (C, GAI_StrError, "gai_strerror");
   pragma Import (C, Socket_StrError, "strerror");
   pragma Import (C, C_Ioctl, "ioctl");
   pragma Import (C, C_Close, "close");

end OS_Lib;
