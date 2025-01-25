/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#ifndef __APPLE_GNU_DEFS__
#define __APPLE_GNU_DEFS__

#include <stdint.h>

// MacOSX SDK 10.4u
// \usr\include\mach-o\stab.h
enum STAB_TYPE : uint8_t
{
    /* Global variable.  Only the name is significant.
    To find the address, look in the corresponding external symbol.  */
    N_GSYM = 0x20u,

    /* Function name or text-segment variable for C. Value is its address.
    // Desc is supposedly starting line number, but GCC doesn't set it
    // and DBX seems not to miss it. */
    N_FUN = 0x24u,

    /* Data-segment variable with internal linkage.  Value is its address.
           "Static Sym".  */
    N_STSYM = 0x26u,

    /* BSS-segment variable with internal linkage.  Value is its address.  */
    N_LCSYM = 0x28u,

    // Indicates that this file was compiled by GCC.
    // Name is always "gcc2_compiled."
    N_OPT = 0x3cu,

    // Name/directory of main source file.
    // Value is start/end text address of the compilation.
    N_SO = 0x64u,

    // Object file name
    // Value is object modtime epoch
    N_OSO = 0x66u,

    /* Name of sub-source file (#include file).
       Value is starting text address of the compilation.  */
    N_SOL = 0x84u,
};

// MacOSX SDK 10.4u
// \usr\include\mach-o\reloc.h
struct relocation_info
{
    int32_t r_address; /* offset in the section to */
    /* what is being relocated */
    uint32_t r_symbolnum : 24, /* symbol index if r_extern == 1 or
                               /* section ordinal if r_extern == 0 */
        r_pcrel : 1, /* was relocated pc relative already */
        r_length : 2, /* 0=byte, 1=word, 2=long, 3=quad */
        r_extern : 1, /* does not include value of sym referenced */
        r_type : 4; /* if not 0, machine specific relocation type */
};

// MacOSX SDK 10.4u
// \usr\include\c++\4.0.0\cxxabi.h
class _type_info
{
public:
    uint32_t __vfptr; // void *vfptr;
    uint32_t type_name; // const char * __type_name
};

class class_type_info : public _type_info
{
};

class si_class_type_info : public class_type_info
{
public:
    uint32_t base_type; // const __class_type_info * base_type
};

class base_class_type_info
{
public:
    uint32_t base_type; // const __class_type_info * __base_type
    uint32_t offset_flags; // long __offset_flags
};

class vmi_class_type_info : public class_type_info
{
public:
    uint32_t flags;
    uint32_t base_count;
    base_class_type_info base_info[1];
};

// Apple gdb-437
// \src\bfd\mach-o.h
enum BFD_MACH_O : uint8_t
{
    BFD_MACH_O_N_STAB = 0xe0, /* If any of these bits set, a symbolic debugging entry.  */
    BFD_MACH_O_N_PEXT = 0x10, /* Private external symbol bit.  */
    BFD_MACH_O_N_TYPE = 0x0e, /* Mask for the type bits.  */
    BFD_MACH_O_N_EXT = 0x01, /* External symbol bit, set for external symbols.  */
    BFD_MACH_O_N_UNDF = 0x00, /* Undefined, n_sect == NO_SECT.  */
    BFD_MACH_O_N_ABS = 0x02, /* Absolute, n_sect == NO_SECT.  */
    BFD_MACH_O_N_SECT = 0x0e, /* Defined in section number n_sect.  */
    BFD_MACH_O_N_PBUD = 0x0c, /* Prebound undefined (defined in a dylib).  */
    BFD_MACH_O_N_INDR = 0x0a /* Indirect.  */
};

#endif // __APPLE_GNU_DEFS__