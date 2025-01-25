#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

using index_t = uint32_t;
constexpr index_t InvalidIndex = index_t(~0);

struct Namespace
{
    std::string m_name;
    index_t m_parentNamespaceIndex = InvalidIndex; // Namespace is contained in another namespace.
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
    std::string m_name;
    index_t m_parentNamespaceIndex = InvalidIndex; // Variable is contained in namespace.
    index_t m_parentClassIndex = InvalidIndex; // Variable is contained in class.
    index_t m_parentFunctionIndex = InvalidIndex; // Variable is contained in function.

    // TODO: Add properties: extern, const, initializer value...
};

struct BaseClass
{
    index_t m_classIndex = InvalidIndex;

    // TODO: Add properties: virtual, public, protected, private...
};

struct Class // Alias Struct
{
    std::string m_name;
    index_t m_parentNamespaceIndex = InvalidIndex; // Class is contained in namespace.
    index_t m_parentClassIndex = InvalidIndex; // Class is contained in another class.
    std::vector<BaseClass> m_baseClasses; // Class inheritance.
    std::vector<index_t> m_childClassIndices; // Classes inside this class.
    std::vector<index_t> m_functionIndices; // Functions inside this class.
    std::vector<index_t> m_variableIndices; // Variables inside this class (statics).
    std::vector<index_t> m_enumIndices; // Enums inside this class.
};

struct Function
{
    std::string m_name;
    std::string m_mangled; // Mangled name as seen in symbol table.
    index_t m_parentNamespaceIndex = InvalidIndex; // Function is contained in namespace.
    index_t m_parentClassIndex = InvalidIndex; // Function is contained in class.
    bool definedInHeader = false; // Is defined in header.
    std::vector<index_t> m_classIndices; // Classes inside this function. Most likely empty.
    std::vector<index_t> m_variableIndices; // Variables inside this function.
    std::vector<index_t> m_enumIndices; // Enums inside this function. Most likely empty.

    // TODO: Add properties: virtual, pure virtual, override, const, constructor, destructor...
};

struct HeaderFile // .h
{
    std::string m_name;
    std::vector<index_t> m_functionIndices;
    std::vector<index_t> m_variableIndices;
    std::vector<index_t> m_enumIndices;
};

struct SourceFile // .cpp
{
    std::string m_name;
    std::vector<index_t> m_headerFileIndices;
    std::vector<index_t> m_functionIndices;
    std::vector<index_t> m_variableIndices;
    std::vector<index_t> m_enumIndices;
};

using Namespaces = std::vector<Namespace>;
using Enums = std::vector<Enum>;
using Variables = std::vector<Variable>;
using Classes = std::vector<Class>;
using Functions = std::vector<Function>;
using HeaderFiles = std::vector<HeaderFile>;
using SourceFiles = std::vector<SourceFile>;

using StringToIndexMap = std::unordered_map<std::string, index_t>;

int main(int argc, char **argv)
{
    return 0;
}
