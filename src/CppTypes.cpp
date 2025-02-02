#include "CppTypes.h"

#include "utility.h"

#include <LIEF/MachO/Symbol.hpp>

#include <cassert>

std::string_view Function::GetMangledName(size_t symbolIndex) const
{
    assert(symbolIndex < m_symbols.size());
    const LIEF::MachO::Symbol *symbol = m_symbols[symbolIndex];
    return {symbol->name().data(), symbol->name().size() - 2};
}

uint32_t Function::GetVirtualAddress(size_t symbolIndex) const
{
    assert(symbolIndex < m_symbols.size());
    return m_symbols[symbolIndex]->value();
}

uint32_t Function::GetSourceLine(size_t symbolIndex) const
{
    assert(symbolIndex < m_symbols.size());
    return m_symbols[symbolIndex]->description();
}

bool Function::IsLocalFunction(size_t symbolIndex) const
{
    assert(symbolIndex < m_symbols.size());
    return ends_with(m_symbols[symbolIndex]->name(), ":f");
}

bool Function::IsGlobalFunction(size_t symbolIndex) const
{
    assert(symbolIndex < m_symbols.size());
    return ends_with(m_symbols[symbolIndex]->name(), ":F");
}
