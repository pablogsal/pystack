#pragma once

#ifdef PYSTACK_MACOS

#include <mach/mach.h>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "framehop_ffi.h"
#include "mem.h"
#include "native_frame.h"

namespace pystack {

/// Information about a Mach-O text section
struct MachOTextInfo
{
    uint64_t vm_addr;  // SVMA (Stated Virtual Memory Address)
    uint64_t size;
};

/// Information about a dyld loaded image
struct DyldImageInfo
{
    uint64_t load_address;  // Base AVMA where the library is loaded
    uint64_t end_address;   // End address (load_address + vmsize from __TEXT)
    std::string path;       // Path to the library
};

/// Extract unwind-related sections from a Mach-O file
struct MachOUnwindSections
{
    std::vector<uint8_t> unwind_info;  // __unwind_info section
    std::vector<uint8_t> eh_frame;     // __eh_frame section
    MachOTextInfo text_info;           // __text section info
    uint64_t text_vmaddr;              // __TEXT segment vmaddr (base SVMA)
    bool valid;                        // Whether extraction succeeded
};

/// Native stack unwinder for macOS using framehop
class MacOSUnwinder
{
  public:
    /// Construct an unwinder for a task
    ///
    /// @param task Mach task port for the target process
    /// @param maps Memory maps of the target process
    explicit MacOSUnwinder(mach_port_t task, const std::vector<VirtualMap>& maps);

    /// Destructor
    ~MacOSUnwinder();

    // Non-copyable
    MacOSUnwinder(const MacOSUnwinder&) = delete;
    MacOSUnwinder& operator=(const MacOSUnwinder&) = delete;

    /// Unwind a thread's stack
    ///
    /// @param thread Thread port to unwind
    /// @return Vector of native frames (innermost first)
    std::vector<NativeFrame> unwindThread(thread_act_t thread);

    /// Get thread ports for the task
    ///
    /// @param tid Thread ID to find
    /// @return Thread port, or MACH_PORT_NULL if not found
    thread_act_t getThreadPort(int tid) const;

    /// Read memory from the target process
    ///
    /// @param addr Address to read from
    /// @param value Pointer to store the value
    /// @return true on success, false on error
    bool readMemory(uint64_t addr, uint64_t* value) const;

  private:

    /// Get thread registers
    ///
    /// @param thread Thread port
    /// @param pc Output: program counter
    /// @param lr Output: link register
    /// @param sp Output: stack pointer
    /// @param fp Output: frame pointer
    /// @return true on success, false on error
    bool getThreadRegisters(thread_act_t thread, uint64_t& pc, uint64_t& lr, uint64_t& sp, uint64_t& fp)
            const;

    /// Extract unwind sections from a Mach-O file
    ///
    /// @param path Path to the Mach-O file
    /// @return Extracted sections
    MachOUnwindSections extractUnwindSections(const std::string& path) const;

    /// Extract unwind sections by reading from target process memory
    /// This works for all libraries including shared cache ones
    ///
    /// @param base_avma Base address where the library is loaded
    /// @return Extracted sections
    MachOUnwindSections extractUnwindSectionsFromProcess(uint64_t base_avma) const;

    /// Find a symbol name for an address
    ///
    /// @param addr Address to look up
    /// @return Symbol name, or "???" if not found
    std::string findSymbol(uint64_t addr) const;

    /// Find the library name for an address
    ///
    /// @param addr Address to look up
    /// @return Library path, or "???" if not found
    std::string findLibrary(uint64_t addr) const;

    /// Demangle a symbol name
    ///
    /// @param symbol Mangled symbol name
    /// @return Demangled name, or original if demangling fails
    static std::string demangleSymbol(const std::string& symbol);

    // Data members
    mach_port_t d_task;
    const std::vector<VirtualMap>& d_maps;
    FramehopUnwinder* d_unwinder;
    FramehopCache* d_cache;
    bool d_modules_loaded;

    // Cache for module unwind sections
    mutable std::unordered_map<std::string, MachOUnwindSections> d_unwind_cache;

    // Thread port cache
    mutable std::unordered_map<int, thread_act_t> d_thread_ports;

    // Dyld images for direct address-to-library mapping
    // (sorted by load_address for binary search)
    std::vector<DyldImageInfo> d_dyld_images;

    /// Load modules into the unwinder
    void loadModules();

    /// Load dyld images from the target process
    void loadDyldImages();
};

}  // namespace pystack

#endif  // PYSTACK_MACOS
