#pragma once

#ifdef PYSTACK_MACOS

#include <cstdint>
#include <string>

namespace pystack {
namespace macos {

// Search a Mach-O file for a named section and return its runtime address
// given the base address where the binary is loaded in memory.
// Returns 0 if the section is not found.
uintptr_t searchMachOFileForSection(
        const std::string& path,
        const char* section_name,
        uintptr_t base_addr);

// Search a Mach-O file for a symbol and return its runtime address
// given the base address where the binary is loaded in memory.
// Returns 0 if the symbol is not found.
uintptr_t findSymbolInMachO(
        const std::string& path,
        const char* symbol_name,
        uintptr_t base_addr);

}  // namespace macos
}  // namespace pystack

#endif  // PYSTACK_MACOS
