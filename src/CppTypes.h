#pragma once

#include <cstdint>
#include <set>
#include <string>
#include <tcb/span.hpp>
#include <unordered_map>
#include <vector>

using index_t = uint32_t;
constexpr index_t InvalidIndex = index_t(~0);

struct Namespace;
struct Function;
struct Enum;
struct Variable;
struct BaseClass;
struct VTableEntry;
struct VTable;
struct Class;
struct NonVirtualThunk;
struct FunctionInstruction;
struct FunctionVariant;
struct Function;
struct HeaderFile;
struct SourceFile;

struct Namespace
{
    std::string m_name;
    std::string m_namespaceName; // a::b::c becomes c.
    index_t m_parentNamespaceIndex = InvalidIndex; // Namespace is contained in another namespace.
    std::vector<index_t> m_childNamespaceIndices; // Namespace in this namespace.
    std::vector<index_t> m_classIndices; // Direct classes in this namespace (not contained in other classes).
    std::vector<index_t> m_functionIndices; // Direct functions in this namespace (not contained in classes).
    std::vector<index_t> m_variableIndices; // Direct variables in this namespace (not contained in classes).
    std::vector<index_t> m_enumIndices; // Direct enums in this namespace (not contained in classes).
};

struct Enum
{
    std::string m_name;
    index_t m_parentNamespaceIndex = InvalidIndex; // Enum is contained in namespace.
    index_t m_parentClassIndex = InvalidIndex; // Enum is contained in class.
    index_t m_parentFunctionIndex = InvalidIndex; // Enum is contained in function.

    // TODO: Add properties: type, values(?)...
};

struct Variable // Static or global data variable.
{
    enum class Type : uint8_t
    {
        Global, // N_GSYM
        Static, // N_STSYM
        Local, // N_LCSYM
    };

    std::string m_name;
    uint64_t m_address = 0;
    uint16_t m_description = 0; // ???
    uint8_t m_section = 0 /*NO_SECT*/; // TODO: fix this.
    Type m_type = Type::Global;

    index_t m_parentNamespaceIndex = InvalidIndex; // Variable is contained in namespace.
    index_t m_parentClassIndex = InvalidIndex; // Variable is contained in class.
    index_t m_parentFunctionIndex = InvalidIndex; // Variable is contained in function.

    // TODO: Add properties: extern, const, initializer value...
};

enum class BaseClassVisibility : uint8_t
{
    Unknown, // Single base class will provide no information about visibility.
    Private_Or_Protected, // Private or protected.
    Public, // Public.
};

struct VTableEntry
{
    bool IsFirstDeclaration() const { return !m_isOverride && !m_isImplicit; }

    std::string m_name;
    index_t m_functionIndex = InvalidIndex;
    index_t m_thunkIndex = InvalidIndex;

    // The most bottom base class that this virtual function overrides.
    // Index refers to Class::m_allBaseClasses.
    index_t m_allBaseClassIndex = InvalidIndex;

    bool m_isDtor = false; // Virtual function is destructor.
    bool m_isPureVirtual = false; // Virtual function is pure (= 0).
    bool m_isOverride = false; // Virtual function overrides a virtual function of a base class.
    bool m_isImplicit = false; // Virtual function implicitly inherits a virtual function of a base class.
};

struct VTable
{
    uint16_t Size() const;

    std::vector<VTableEntry> m_entries;
    uint16_t m_offset = 0; // Offset in bytes, corresponding to BaseClass::baseOffset.
};

struct BaseClass
{
    index_t m_classIndex = InvalidIndex;
    uint16_t m_baseOffset = 0; // Base offset in bytes.
    BaseClassVisibility m_visibility = BaseClassVisibility::Unknown;
    bool m_isVirtual = false; // Virtual inheritance.
};

struct Class // Alias Struct
{
    const BaseClass *GetBaseClass(uint16_t baseOffset) const;

    std::string m_name;
    std::string m_className; // a::b::c becomes c.
    uint16_t m_size = 0; // Size of this class.
    std::vector<VTable> m_vtables; // Primary vtable at 0, secondary vtables with thunks to base classes with offsets at >=1.
    index_t m_parentNamespaceIndex = InvalidIndex; // Class is contained in namespace.
    index_t m_parentClassIndex = InvalidIndex; // Class is contained in another class.
    std::vector<BaseClass> m_directBaseClasses; // Direct base classes. First to last.
    // All base classes in hierarchy, ordered from leaves to roots, with adjusted offsets.
    std::vector<BaseClass> m_allBaseClasses;
    std::vector<index_t> m_childClassIndices; // Classes inside this class.
    std::vector<index_t> m_functionIndices; // Functions inside this class.
    std::vector<index_t> m_variableIndices; // Variables inside this class (statics).
    std::vector<index_t> m_enumIndices; // Enums inside this class.
};

struct NonVirtualThunk
{
    std::string m_name;
    uint64_t m_address = 0;
    bool m_isDtor = false;
};

struct FunctionInstruction
{
    uint64_t m_address = 0;
    index_t headerFileIndex = InvalidIndex;
    index_t sourceFileIndex = InvalidIndex;
};

struct FunctionVariant
{
    std::string m_mangledName;
    uint64_t m_address = 0;
    uint32_t m_size = 0;
    uint16_t m_sourceLine = 0;
    uint8_t m_section = 0 /*NO_SECT*/; // TODO: fix this.
    std::vector<FunctionInstruction> m_instructions;
};

struct Function
{
    const std::string &GetMangledName(size_t variantIndex) const;
    uint64_t GetVirtualAddressBegin(size_t variantIndex) const;
    uint64_t GetVirtualAddressEnd(size_t variantIndex) const;
    uint16_t GetSourceLine(size_t variantIndex) const;
    bool IsClassMemberFunction() const;

    static std::vector<std::string> GetParameterTypes(const std::string &functionParameters);

    std::string m_name;

    std::string m_functionBaseName; // The base name. Does not include trailing template arguments.
    std::string m_functionDeclContextName; // The context name. For "a::b::c", this becomes "a::b".
    std::string m_functionName; // The entire name.
    std::string m_functionParameters;
    std::string m_functionReturnType;
    std::vector<std::string> m_functionParameterTypes;

    bool m_isCtorOrDtor = false;
    bool m_isLocalFunction = false; // :f  Local non-global function, lives in cpp, static
    bool m_isConst = false;

    index_t m_headerFileIndex = InvalidIndex;
    index_t m_sourceFileIndex = InvalidIndex;
    index_t m_parentNamespaceIndex = InvalidIndex; // Function is contained in namespace.
    index_t m_parentClassIndex = InvalidIndex; // Function is contained in class.

    std::vector<index_t> m_classIndices; // Classes inside this function. Most likely empty.
    std::vector<index_t> m_variableIndices; // Variables inside this function.
    std::vector<index_t> m_enumIndices; // Enums inside this function. Most likely empty.

    std::vector<FunctionVariant> m_variants;
};

struct HeaderFile // .h
{
    std::string m_name;
    // std::vector<index_t> m_functionIndices;
    // std::vector<index_t> m_variableIndices;
    // std::vector<index_t> m_enumIndices;
};

struct SourceFile // .cpp
{
    std::string m_name;
    uint64_t m_addressBegin = 0; // Begin address.
    uint64_t m_addressEnd = 0; // End address.
    std::vector<index_t> m_headerFileIndices;
    std::vector<index_t> m_functionIndices;
    std::vector<index_t> m_variableIndices;
    std::vector<index_t> m_enumIndices;
};

using Namespaces = std::vector<Namespace>;
using Enums = std::vector<Enum>;
using Variables = std::vector<Variable>;
using Classes = std::vector<Class>;
using NonVirtualThunks = std::vector<NonVirtualThunk>;
using Functions = std::vector<Function>;
using HeaderFiles = std::vector<HeaderFile>;
using SourceFiles = std::vector<SourceFile>;

using StringToIndexMap = std::unordered_map<std::string, index_t>;
using AddressToIndexMap = std::unordered_map<uint64_t, index_t>;
using StringToIndexMultiMap = std::unordered_multimap<std::string, index_t>;

std::set<std::string> CreateHeaderFileSet(const HeaderFiles &headerFiles, const Function &function);
