#pragma once

#include <cstdint>

// Arbitrary values.
enum class RelocatedSymbol : uint32_t
{
    enum_type_info = 0x3fff0000,
    class_type_info = 0x3fff0001,
    si_class_type_info = 0x3fff0002,
    vmi_class_type_info = 0x3fff0003,
    cxa_pure_virtual = 0x3fff0004,
};

// MacOSX SDK 10.4u
// \usr\include\c++\4.0.0\cxxabi.h
struct __type_info
{
    uint32_t __vfptr; // void *vfptr;
    uint32_t type_name; // const char * __type_name
};

struct __class_type_info : public __type_info
{
};

struct __si_class_type_info : public __class_type_info
{
    uint32_t base_type; // const __class_type_info * base_type
};

struct __base_class_type_info
{
    uint32_t base_type; // const __class_type_info * __base_type
    uint32_t offset_flags; // long __offset_flags

    enum __offset_flags_masks
    {
        __virtual_mask = 0x1,
        __public_mask = 0x2, // base is public
        __offset_shift = 8
    };
};

struct __vmi_class_type_info : public __class_type_info
{
    uint32_t flags;
    uint32_t base_count;
    __base_class_type_info base_info[1];

    enum __flags_masks
    {
        __non_diamond_repeat_mask = 0x1, // has two or more distinct base class objects of the same type
        __diamond_shaped_mask = 0x2 // has base class object with two or more derived objects
    };
};

struct __vtable_info
{
    int32_t offset_to_this; // offset for casting to this
    uint32_t type_info; // const __class_type_info *
    uint32_t function_address[1];
};
